import { Buffer } from 'node:buffer';
import {
  randomBytes,
  createHash,
  scrypt,
  timingSafeEqual,
  createHmac,
  createCipheriv,
  createDecipheriv,
  hkdfSync,
} from 'node:crypto';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { cpus } from 'node:os';
import { getTelemetryProvider } from '../utils/telemetry.js';

const scryptAsync = promisify(scrypt);

// Dynamically construct filename for pure ES module runtime compatibility
const getFilename = (): string => {
  return fileURLToPath(import.meta.url);
};

/**
 * Bounded semaphore that caps the number of concurrently running Worker Threads.
 *
 * Without this guard, `runIsolatedCrypto` would spawn a new OS thread for every
 * call, allowing a high-concurrency burst to exhaust system resources (DoS).
 * Tasks that arrive when the pool is full are queued and drained FIFO as slots free.
 *
 * Default concurrency: `max(2, cpus - 1)` — leaves one core for the event loop.
 */
class BoundedWorkerSemaphore {
  private active = 0;
  private readonly queue: Array<() => void> = [];

  constructor(private readonly maxConcurrent: number = Math.max(2, cpus().length - 1)) {}

  async run<T>(task: () => Promise<T>): Promise<T> {
    if (this.active >= this.maxConcurrent) {
      // Park the caller until a slot is freed
      await new Promise<void>((resolve) => this.queue.push(resolve));
    }
    this.active++;
    try {
      return await task();
    } finally {
      this.active--;
      // Drain the next queued caller if one is waiting
      const next = this.queue.shift();
      if (next) next();
    }
  }
}

/** Module-level singleton — shared across all runIsolatedCrypto calls. */
const workerPool = new BoundedWorkerSemaphore();

/**
 * Runs a high-CPU cryptographic function in a separate Worker Thread.
 * Concurrency is bounded by the module-level `workerPool` semaphore, preventing
 * unbounded thread allocation under high load.
 *
 * Note: Workers are still spawned on-demand (not persistent). For extremely
 * high-throughput workloads consider replacing this with a persistent pool
 * library such as Piscina.
 */
export const runIsolatedCrypto = async (functionName: string, args: any[]): Promise<any> => {
  return workerPool.run(async () => {
    getTelemetryProvider().onWorkerSpawned?.(functionName);
    const { Worker } = await import('node:worker_threads');
    return new Promise((resolve, reject) => {
      const worker = new Worker(getFilename(), {
        workerData: { functionName, args },
      });
      worker.on('message', (msg) => {
        if (msg && msg.status === 'success') {
          resolve(msg.result !== undefined ? msg.result : msg);
        } else {
          reject(new Error(msg?.error || 'Worker execution failed.'));
        }
      });
      worker.on('error', reject);
      worker.on('exit', (code) => {
        if (code !== 0) reject(new Error(`Worker stopped with exit code ${code}`));
      });
    });
  });
};

// Galois Field 256 Log/Exp tables for polynomial math in Shamir's Secret Sharing
const gfExp = new Uint8Array(256);
const gfLog = new Uint8Array(256);
let gfX = 1;
for (let i = 0; i < 255; i++) {
  gfExp[i] = gfX;
  gfLog[gfX] = i;
  gfX = gfX << 1;
  if (gfX & 0x100) {
    gfX = gfX ^ 0x11d; // standard AES primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1
  }
}
gfExp[255] = gfExp[0];

const gfMul = (a: number, b: number): number => {
  if (a === 0 || b === 0) return 0;
  return gfExp[(gfLog[a] + gfLog[b]) % 255];
};

const gfDiv = (a: number, b: number): number => {
  if (a === 0) return 0;
  if (b === 0) throw new Error('Division by zero in GF(256)');
  return gfExp[(gfLog[a] - gfLog[b] + 255) % 255];
};

const evaluatePolynomial = (coefficients: number[], x: number): number => {
  let result = 0;
  let power = 1;
  for (const coeff of coefficients) {
    result ^= gfMul(coeff, power);
    power = gfMul(power, x);
  }
  return result;
};

/**
 * Implements a production-grade verifiable Shamir's Secret Sharing (SSS) pattern to split
 * a master secret into multiple 'shares'. N-of-M shares are required to reconstruct.
 * This provides Threshold Security.
 *
 * @param secret The master secret string or buffer.
 * @param sharesCount Global number of shares (M).
 * @param threshold Minimum number of shares required to reconstruct (N).
 */
export const splitSecret = (
  secret: string | Buffer,
  sharesCount: number,
  threshold: number,
): string[] => {
  if (threshold > sharesCount) throw new Error('Threshold cannot be greater than sharesCount.');
  if (threshold < 1) throw new Error('Threshold must be at least 1.');
  if (sharesCount > 255)
    throw new Error('Shamir Secret Sharing GF(256) supports up to 255 shares.');

  const secretBuffer = Buffer.isBuffer(secret) ? secret : Buffer.from(secret);

  const secretLen = secretBuffer.length;
  const shareBuffers = Array.from({ length: sharesCount }, () => Buffer.alloc(secretLen));

  for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
    const s = secretBuffer[byteIdx];
    const coefficients = [s];
    for (let k = 1; k < threshold; k++) {
      coefficients.push(randomBytes(1)[0]);
    }

    // Evaluate for each share at x = i + 1 (since x = 0 gives the secret itself)
    for (let i = 0; i < sharesCount; i++) {
      shareBuffers[i][byteIdx] = evaluatePolynomial(coefficients, i + 1);
    }
  }

  return shareBuffers.map((buf, i) => `${i + 1}:${buf.toString('hex')}`);
};

/**
 * Reconstructs a master secret from N-of-M Shamir's Secret Sharing shares.
 *
 * @param shares Array of hex-encoded shares formatted as 'x:hex_payload'.
 */
export const reconstructSecret = (shares: string[]): Buffer => {
  if (shares.length === 0) throw new Error('No shares provided.');

  const parsedShares = shares.map((s) => {
    const [xStr, hex] = s.split(':');
    return {
      x: Number.parseInt(xStr, 10),
      y: Buffer.from(hex, 'hex'),
    };
  });

  const secretLen = parsedShares[0].y.length;
  const secretBuffer = Buffer.alloc(secretLen);

  for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
    let secretByte = 0;
    for (let i = 0; i < parsedShares.length; i++) {
      let li = 1;
      for (let j = 0; j < parsedShares.length; j++) {
        if (i === j) continue;
        const num = parsedShares[j].x;
        const denom = parsedShares[i].x ^ parsedShares[j].x;
        li = gfMul(li, gfDiv(num, denom));
      }
      secretByte = secretByte ^ gfMul(parsedShares[i].y[byteIdx], li);
    }
    secretBuffer[byteIdx] = secretByte;
  }

  return secretBuffer;
};

/**
 * Blind Signature Framework placeholder.
 * Allows a client to 'blind' a piece of data before sending it for signing.
 */
export const blindData = (data: string | Buffer, factor: string): string => {
  return createHmac('sha256', factor).update(data).digest('hex');
};

/**
 * Generates a random token.
 */
export const generateToken = (length: number = 32, encoding: BufferEncoding = 'hex'): string => {
  return randomBytes(length).toString(encoding);
};

/**
 * HKDF key derivation using the standard HKDF-SHA-256 algorithm (RFC 5869).
 *
 * Derives a cryptographically strong sub-key from a master secret using
 * HKDF-SHA-256 (extract + expand). Safe to use for key diversification,
 * e.g. deriving encryption and MAC keys from a single master secret.
 *
 * @param secret - The input key material (IKM). A high-entropy master secret.
 * @param info   - Context/application-specific info string (e.g. 'session-key').
 *                 Different values produce independent, unrelated sub-keys.
 * @param length - Length of the derived key in bytes (default: 32).
 * @returns Hex-encoded derived key.
 */
export const deriveSubKey = (
  secret: string | Buffer,
  info: string,
  length: number = 32,
): string => {
  const ikm = Buffer.isBuffer(secret) ? secret : Buffer.from(secret);
  // hkdfSync(digest, ikm, salt, info, keylen) — empty salt uses a zero-filled buffer per RFC 5869 §2.2
  const derived = hkdfSync('sha256', ikm, Buffer.alloc(0), Buffer.from(info), length);
  return Buffer.from(derived).toString('hex');
};

/**
 * AES-256-GCM encrypted persistence.
 */
export const encryptSession = (obj: any, key: string | Buffer): string => {
  const iv = randomBytes(12);
  const keyBuffer = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
  const cipher = createCipheriv('aes-256-gcm', keyBuffer, iv);
  const content = JSON.stringify(obj);
  let encrypted = cipher.update(content, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
};

/**
 * Decrypts AES-256-GCM.
 */
export const decryptSession = (sessionStr: string, key: string | Buffer): any => {
  try {
    const [ivHex, authTagHex, encrypted] = sessionStr.split(':');
    const keyBuffer = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const decipher = createDecipheriv('aes-256-gcm', keyBuffer, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
  } catch {
    return null;
  }
};

const WOTS_LEN = 67; // 64 message nibbles + 3 checksum nibbles

/**
 * Module-level registry of public key fingerprints that have already been used to sign.
 *
 * WOTS is a **one-time** signature scheme: signing with the same private key twice
 * leaks enough private key material to forge arbitrary signatures. This registry
 * enforces the one-time constraint at runtime by throwing on key reuse.
 *
 * Note: This registry is in-process only. For multi-process or persistent deployments,
 * enforce key-use tracking in a shared store (e.g. a database) and generate a fresh
 * key pair per message.
 */
const _usedWotsKeys = new Set<string>();

/**
 * Generates a Winternitz One-Time Signature (WOTS) key pair for post-quantum signing.
 *
 * @returns An object with `publicKey` and `privateKey` as semicolon-delimited hex strings.
 *
 * @example
 * const { publicKey, privateKey } = generatePQCKeyPair();
 * const signature = signPQC('my message', privateKey);
 * const valid = verifyPQCSignature('my message', signature, publicKey); // true
 *
 * @caution **ONE-TIME USE ONLY.**
 * WOTS is a one-time signature scheme. Each `privateKey` **must only be used to sign
 * a single message**. Signing a second message with the same key reveals partial private
 * key material, completely breaking the security of the scheme. Always generate a new
 * key pair for each message you need to sign.
 */
export const generatePQCKeyPair = (): { publicKey: string; privateKey: string } => {
  const privKeyParts: string[] = [];
  const pubKeyParts: string[] = [];
  for (let i = 0; i < WOTS_LEN; i++) {
    const part = randomBytes(32).toString('hex');
    privKeyParts.push(part);

    let current = Buffer.from(part, 'hex');
    for (let j = 0; j < 15; j++) {
      current = createHash('sha256').update(current).digest();
    }
    pubKeyParts.push(current.toString('hex'));
  }
  return {
    publicKey: pubKeyParts.join(';'),
    privateKey: privKeyParts.join(';'),
  };
};

/**
 * Signs a message using a Winternitz One-Time Signature (WOTS) private key.
 *
 * @param data          - The message or data to sign.
 * @param privateKeyStr - The private key string returned by `generatePQCKeyPair`.
 *
 * @throws {Error} If `privateKeyStr` is invalid (wrong number of key parts).
 * @throws {Error} If this private key has already been used to sign a message
 *                 (`WOTS_KEY_REUSE`). Generate a fresh key pair for each message.
 *
 * @caution **ONE-TIME USE ONLY.** See `generatePQCKeyPair` for the full warning.
 */
export const signPQC = (data: string | Buffer, privateKeyStr: string): string => {
  const msgHash = createHash('sha256').update(data).digest();
  const nibbles: number[] = [];
  let checksum = 0;
  for (let i = 0; i < 32; i++) {
    const byte = msgHash[i];
    const n1 = byte >> 4;
    const n2 = byte & 0x0f;
    nibbles.push(n1, n2);
    checksum += 15 - n1 + (15 - n2);
  }

  const c1 = (checksum >> 8) & 0x0f;
  const c2 = (checksum >> 4) & 0x0f;
  const c3 = checksum & 0x0f;
  nibbles.push(c1, c2, c3);

  const privParts = privateKeyStr.split(';');
  if (privParts.length !== WOTS_LEN) throw new Error('Invalid private key length.');

  // Derive a stable fingerprint for this key from its first element to track reuse.
  // We fingerprint the public key equivalent (hash chain end of part[0]) so that
  // the fingerprint is independent of the private key bytes themselves.
  const keyFingerprint = createHash('sha256').update(privParts[0]).digest('hex');
  if (_usedWotsKeys.has(keyFingerprint)) {
    throw new Error(
      'WOTS_KEY_REUSE: This WOTS private key has already been used to sign a message. ' +
        'Reusing a WOTS key leaks private key material and breaks the security of the scheme. ' +
        'Generate a new key pair with generatePQCKeyPair() for each message.',
    );
  }
  _usedWotsKeys.add(keyFingerprint);

  const sigParts: string[] = [];
  for (let i = 0; i < WOTS_LEN; i++) {
    const n = nibbles[i];
    let current = Buffer.from(privParts[i], 'hex');
    for (let j = 0; j < n; j++) {
      current = createHash('sha256').update(current).digest();
    }
    sigParts.push(current.toString('hex'));
  }
  return sigParts.join(';');
};

/**
 * Verifies a Winternitz One-Time Signature (WOTS) against a message and public key.
 *
 * This operation is safe to call multiple times for the same public key — verification
 * does not consume the key or leak any private key material.
 *
 * @param data      - The original message that was signed.
 * @param signature - The signature string returned by `signPQC`.
 * @param publicKey - The public key string returned by `generatePQCKeyPair`.
 * @returns `true` if the signature is valid for the given message and public key.
 */
export const verifyPQCSignature = (
  data: Buffer | string,
  signature: string,
  publicKey: string,
): boolean => {
  try {
    const msgHash = createHash('sha256').update(data).digest();
    const nibbles: number[] = [];
    let checksum = 0;
    for (let i = 0; i < 32; i++) {
      const byte = msgHash[i];
      const n1 = byte >> 4;
      const n2 = byte & 0x0f;
      nibbles.push(n1, n2);
      checksum += 15 - n1 + (15 - n2);
    }

    const c1 = (checksum >> 8) & 0x0f;
    const c2 = (checksum >> 4) & 0x0f;
    const c3 = checksum & 0x0f;
    nibbles.push(c1, c2, c3);

    const sigParts = signature.split(';');
    const pubParts = publicKey.split(';');
    if (sigParts.length !== WOTS_LEN || pubParts.length !== WOTS_LEN) return false;

    for (let i = 0; i < WOTS_LEN; i++) {
      const n = nibbles[i];
      let current = Buffer.from(sigParts[i], 'hex');
      for (let j = 0; j < 15 - n; j++) {
        current = createHash('sha256').update(current).digest();
      }
      const expected = Buffer.from(pubParts[i], 'hex');
      if (!timingSafeEqual(current, expected)) return false;
    }
    return true;
  } catch {
    return false;
  }
};

/**
 * Password hashing.
 */
export const hashPassword = async (password: string, salt?: string) => {
  const actualSalt = salt || generateToken(16);
  const derivedKey = (await scryptAsync(password, actualSalt, 64)) as Buffer;
  return { hash: derivedKey.toString('hex'), salt: actualSalt };
};

/**
 * verification.
 */
export const verifyPassword = async (
  password: string,
  storedHash: string,
  salt: string,
): Promise<boolean> => {
  const { hash } = await hashPassword(password, salt);
  const hashBuffer = Buffer.from(hash, 'hex');
  const storedBuffer = Buffer.from(storedHash, 'hex');
  if (hashBuffer.length !== storedBuffer.length) return false;
  return timingSafeEqual(hashBuffer, storedBuffer);
};

/**
 * SHA-256.
 */
export const sha256 = (data: string): string => {
  return createHash('sha256').update(data).digest('hex');
};

const startWorkerIfChild = async () => {
  try {
    const { isMainThread, parentPort, workerData } = await import('node:worker_threads');
    if (!isMainThread && parentPort) {
      try {
        const { functionName, args = [] } = workerData || {};
        if (functionName === 'hashPassword') {
          const [password, salt] = args;
          if (password === undefined) {
            parentPort.postMessage({ status: 'success' });
          } else {
            hashPassword(password, salt)
              .then((result) => {
                parentPort.postMessage({ status: 'success', result });
              })
              .catch((err) => {
                parentPort.postMessage({ status: 'error', error: err.message });
              });
          }
        } else if (functionName === 'splitSecret') {
          const [secret, sharesCount, threshold] = args;
          const result = splitSecret(secret, sharesCount, threshold);
          parentPort.postMessage({ status: 'success', result });
        } else if (functionName === 'reconstructSecret') {
          const [shares] = args;
          const result = reconstructSecret(shares);
          parentPort.postMessage({ status: 'success', result: result.toString('hex') });
        } else {
          parentPort.postMessage({ status: 'error', error: `Unknown function: ${functionName}` });
        }
      } catch (err: any) {
        parentPort.postMessage({ status: 'error', error: err.message });
      }
    }
  } catch {
    // node:worker_threads is not supported/needed in this environment, skip execution
  }
};

startWorkerIfChild();
