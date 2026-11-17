import { Buffer } from 'node:buffer';
import { randomBytes, timingSafeEqual, createHmac, createHash, sign, verify } from 'node:crypto';

/**
 * Basic authentication helper (RFC 7617).
 *
 * @throws {TypeError} If the user identifier contains a colon (':'), which is forbidden by RFC 7617 §2.
 */
export const basicAuth = (user: string, pass: string): string => {
  if (user.includes(':')) {
    throw new TypeError("Mitigator: basicAuth username cannot contain a colon (':') per RFC 7617.");
  }
  const credentials = user + ':' + pass;
  return 'Basic ' + Buffer.from(credentials).toString('base64');
};

/**
 * Passkey / WebAuthn Core Helper to verify an authentication signature.
 * Supports industry-standard RS256 and ES256 algorithms.
 *
 * @param challenge The challenge originally sent to the client.
 * @param response Authenticatable data from the client (authenticatorData + clientDataJSON).
 * @param signature The cryptographic signature from the WebAuthn response.
 * @param publicKey The credential's public key (PEM format).
 */
export const verifyPasskeySignature = (
  _challenge: string | Buffer,
  response: string | Buffer,
  signature: string | Buffer,
  publicKey: string,
  algorithm: 'sha256' | 'sha512' = 'sha256',
): boolean => {
  try {
    const data = Buffer.isBuffer(response) ? response : Buffer.from(response);
    const sig = Buffer.isBuffer(signature) ? signature : Buffer.from(signature, 'base64');

    return verify(algorithm, data, publicKey, sig);
  } catch {
    return false;
  }
};

/**
 * Heuristic Auth Advisor.
 */
export const suggestMFA = (
  riskScore: number,
  lastFingerprint: string,
  currentFingerprint: string,
): boolean => {
  if (lastFingerprint !== currentFingerprint) return true;
  if (riskScore > 10) return true;
  return false;
};

/**
 * Generates a random HMAC-based challenge for a challenge-response authentication flow.
 *
 * The server generates a per-request challenge that is tied to a user-specific salt.
 * The client proves knowledge of a shared secret by computing HMAC(challenge, secret)
 * and returning the result. The server verifies it with `verifyHmacResponse`.
 *
 * Note: This is an HMAC challenge-response protocol, not a zero-knowledge proof (ZKP).
 * A true ZKP would allow the client to prove knowledge of the secret without revealing
 * it even to a compromised verifier. Use this for server-side mutual authentication only.
 *
 * @param userSalt - A per-user, per-session random salt to bind the challenge.
 */
export const generateHmacChallenge = (userSalt: string): string => {
  return createHmac('sha256', userSalt).update(randomBytes(32)).digest('hex');
};

/**
 * Verifies an HMAC challenge-response: checks that `proof === HMAC(challenge, secret)`
 * using a timing-safe comparison to prevent timing attacks.
 *
 * @param challenge - The challenge string previously returned by `generateHmacChallenge`.
 * @param proof     - The response computed by the client: `HMAC-SHA256(secret, challenge)`.
 * @param secret    - The shared secret known to the server.
 */
export const verifyHmacResponse = (challenge: string, proof: string, secret: string): boolean => {
  const expected = createHmac('sha256', secret).update(challenge).digest('hex');
  const proofBuf = Buffer.from(proof, 'hex');
  const expectedBuf = Buffer.from(expected, 'hex');
  if (proofBuf.length !== expectedBuf.length) return false;
  return timingSafeEqual(proofBuf, expectedBuf);
};

/**
 * Honey-Token generation.
 */
export const generateHoneyToken = (prefix: string = 'sk'): string => {
  return `${prefix}_${randomBytes(16).toString('hex')}_${randomBytes(8).toString('hex')}`;
};

export const isHoneyToken = (token: string, prefix: string = 'sk'): boolean => {
  if (!token) return false;
  const parts = token.split('_');
  return parts.length >= 3 && parts[0] === prefix;
};

/**
 * CSRF management (Double-Submit Cookie / Signed Token pattern).
 *
 * - Without a `secret`: returns identical `token` and `cookieValue` for standard
 *   stateless Double-Submit Cookie verification.
 * - With a `secret`: binds `cookieValue` to `token` using `HMAC-SHA256(secret, token)`
 *   (Signed Double-Submit Cookie pattern), protecting against subdomain cookie-tossing.
 */
export const generateCSRF = (secret?: string) => {
  const token = randomBytes(32).toString('hex');
  const cookieValue = secret ? createHmac('sha256', secret).update(token).digest('hex') : token;
  return { token, cookieValue };
};

export const verifyCSRF = (
  providedToken: string,
  cookieToken: string,
  secret?: string,
): boolean => {
  if (!providedToken || !cookieToken) return false;
  const expectedCookie = secret
    ? createHmac('sha256', secret).update(providedToken).digest('hex')
    : providedToken;
  const expectedBuf = Buffer.from(expectedCookie, 'hex');
  const cookieBuf = Buffer.from(cookieToken, 'hex');
  if (expectedBuf.length === 0 || expectedBuf.length !== cookieBuf.length) return false;
  return timingSafeEqual(expectedBuf, cookieBuf);
};

/**
 * JWT Validation.
 * Verifies the structure, expiration, and cryptographic signature of the token.
 *
 * @param token The JWT string.
 * @param secretOrPublicKey The secret (for HS256) or public key (for RS256) to verify the signature.
 * @param algorithm Optional. The expected algorithm (e.g., 'HS256', 'RS256'). Defaults to 'HS256'.
 */
export const isJwtValid = (
  token: string,
  secretOrPublicKey: string | Buffer,
  algorithm: string = 'HS256',
): boolean => {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;

    const [headerB64, payloadB64, signatureB64] = parts;

    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
    if (!header.alg || header.alg.toLowerCase() === 'none' || header.alg !== algorithm)
      return false;

    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    const nowSec = Math.floor(Date.now() / 1000);
    const clockToleranceSec = 60; // 60s tolerance for clock skew

    if (payload.exp && nowSec >= payload.exp) return false;
    if (payload.nbf && nowSec + clockToleranceSec < payload.nbf) return false;
    if (payload.iat && nowSec + clockToleranceSec < payload.iat) return false;

    // Verify signature
    const dataToSign = `${headerB64}.${payloadB64}`;
    const signatureBuffer = Buffer.from(signatureB64, 'base64url');

    if (algorithm.startsWith('HS')) {
      const hashAlg = algorithm.replace('HS', 'sha');
      const expectedSignature = createHmac(hashAlg, secretOrPublicKey).update(dataToSign).digest();
      if (signatureBuffer.length !== expectedSignature.length) return false;
      return timingSafeEqual(signatureBuffer, expectedSignature);
    } else if (algorithm.startsWith('RS')) {
      const hashAlg = algorithm.replace('RS', 'sha');
      return verify(hashAlg, Buffer.from(dataToSign), secretOrPublicKey, signatureBuffer);
    } else if (algorithm.startsWith('ES')) {
      const hashAlg = algorithm.replace('ES', 'sha');
      // RFC 7518 §3.4: ECDSA JWT signatures are the raw R||S concatenation (IEEE P1363),
      // not ASN.1 DER, which is Node's default for `verify`.
      return verify(
        hashAlg,
        Buffer.from(dataToSign),
        { key: secretOrPublicKey, dsaEncoding: 'ieee-p1363' },
        signatureBuffer,
      );
    }

    return false;
  } catch {
    return false;
  }
};

/**
 * Auth guards.
 */
export const canAccess = <U, R>(user: U, resource: R, rule: (u: U, r: R) => boolean): boolean => {
  return rule(user, resource);
};

export const hasRole = (userRoles: string[], requiredRoles: string[]): boolean => {
  return requiredRoles.every((role) => userRoles.includes(role));
};

export const can = (userPermissions: string[], requiredPermission: string): boolean => {
  return userPermissions.includes(requiredPermission);
};

/**
 * Generates a random base64url challenge for FIDO2 WebAuthn / Passkeys.
 */
export const generatePasskeyChallenge = (length: number = 32): string => {
  return randomBytes(length).toString('base64url');
};

/**
 * Interface representing the unpacked and verified result of a Passkey registration.
 */
export interface PasskeyRegistrationResult {
  verified: boolean;
  error?: string;
}

/**
 * Validates a Passkey registration response against the expected challenge and origin.
 *
 * Accepts `clientDataJSONStr` as either:
 * - A raw UTF-8 JSON string (for testing/server-side construction)
 * - A base64url-encoded JSON string (as browsers send in `response.clientDataJSON`)
 *
 * The challenge is compared at the byte level using `timingSafeEqual` after
 * decoding both sides from base64url, per the WebAuthn Level 2 spec §7.1.
 */
export const verifyPasskeyRegistration = (
  clientDataJSONStr: string,
  expectedChallenge: string,
  expectedOrigin?: string,
): PasskeyRegistrationResult => {
  try {
    // Resolve the raw JSON: try direct parse first (raw JSON string),
    // then fall back to base64url decode (browser-sent format).
    let jsonStr = clientDataJSONStr;
    try {
      JSON.parse(clientDataJSONStr);
    } catch {
      // Not raw JSON — treat as base64url-encoded clientDataJSON (browser format)
      jsonStr = Buffer.from(clientDataJSONStr, 'base64url').toString('utf8');
    }

    const clientData = JSON.parse(jsonStr);

    // WebAuthn spec §7.1 step 11: compare challenge bytes, not strings.
    // Both clientData.challenge and expectedChallenge are base64url strings;
    // decode to bytes and use timingSafeEqual to prevent timing attacks and
    // tolerate any base64url padding variation.
    const receivedBytes = Buffer.from(clientData.challenge ?? '', 'base64url');
    const expectedBytes = Buffer.from(expectedChallenge, 'base64url');
    const challengeMatches =
      receivedBytes.length === expectedBytes.length &&
      receivedBytes.length > 0 &&
      timingSafeEqual(receivedBytes, expectedBytes);

    const typeMatches = clientData.type === 'webauthn.create';

    let originMatches = true;
    if (expectedOrigin && clientData.origin !== expectedOrigin) {
      originMatches = false;
    }

    if (!challengeMatches) return { verified: false, error: 'Challenge mismatch.' };
    if (!typeMatches) return { verified: false, error: 'Invalid type (expected webauthn.create).' };
    if (!originMatches) return { verified: false, error: 'Origin mismatch.' };

    return { verified: true };
  } catch (err: unknown) {
    return { verified: false, error: err instanceof Error ? err.message : String(err) };
  }
};

export interface AuthenticatorDataResult {
  rpIdHash: Buffer;
  flags: number;
  signCount: number;
  aaguid?: Buffer;
  credentialId?: string;
  publicKeyBytes?: string;
  extensionsPresent?: boolean;
}

/**
 * Parses WebAuthn raw authenticator data (authData) buffer to extract the
 * aaguid, credential ID, and public key bytes according to the FIDO2 spec.
 */
export const parseAuthenticatorData = (authData: Buffer): AuthenticatorDataResult | null => {
  try {
    const rpIdHash = authData.subarray(0, 32);
    const flags = authData[32];
    const signCount = authData.readUInt32BE(33);

    // Bit 6: attestedCredentialData present
    const attestedCredentialDataPresent = !!(flags & 0x40);
    // Bit 7: extension data present (ED)
    const extensionsPresent = !!(flags & 0x80);

    if (!attestedCredentialDataPresent) {
      return { rpIdHash, flags, signCount, extensionsPresent };
    }

    const aaguid = authData.subarray(37, 53);
    const credentialIdLength = authData.readUInt16BE(53);
    const credentialId = authData.subarray(55, 55 + credentialIdLength);
    const publicKeyBytes = authData.subarray(55 + credentialIdLength);

    return {
      rpIdHash,
      flags,
      signCount,
      aaguid,
      credentialId: credentialId.toString('base64url'),
      publicKeyBytes: publicKeyBytes.toString('hex'),
      extensionsPresent,
    };
  } catch {
    return null;
  }
};

/**
 * Result returned by `verifyPasskeyAssertion`.
 */
export interface PasskeyAssertionResult {
  /** Whether the assertion passed all WebAuthn §7.2 checks. */
  verified: boolean;
  /**
   * The new signature counter value from the authenticator.
   * Persist this value and pass it as `storedSignCount` on the next assertion to
   * detect cloned authenticators (replay attack protection).
   */
  newSignCount?: number;
  /** Human-readable error message when `verified` is false. */
  error?: string;
}

/**
 * Verifies a FIDO2 WebAuthn assertion response (navigator.credentials.get flow).
 *
 * Implements WebAuthn Level 2 §7.2 — Verifying an Authentication Assertion.
 *
 * Checks performed (in order):
 * 1. Parses `clientDataJSON` — accepts both raw JSON and browser base64url-encoded format.
 * 2. Verifies `type === 'webauthn.get'`.
 * 3. Verifies the challenge at the byte level using `timingSafeEqual` (prevents timing attacks).
 * 4. Verifies the origin.
 * 5. Verifies `signCount > storedSignCount` (replay / cloned-authenticator detection).
 * 6. Verifies the cryptographic signature over `authData || SHA-256(clientDataJSON)`
 *    using the stored public key.
 *
 * @param clientDataJSONStr - The `response.clientDataJSON` from the browser, as either a
 *   raw UTF-8 JSON string or a base64url-encoded string (browser format).
 * @param expectedChallenge - The base64url-encoded challenge originally sent to the client.
 * @param expectedOrigin    - The expected origin (e.g. `'https://example.com'`).
 * @param storedSignCount   - The sign count stored server-side from the last successful assertion.
 *   Pass `0` for the first assertion after registration.
 * @param authData          - The raw `response.authenticatorData` buffer from the browser.
 * @param signature         - The raw `response.signature` buffer from the browser.
 * @param publicKeyPem      - The credential's stored public key in PEM (SPKI) format.
 *
 * @example
 * const result = verifyPasskeyAssertion(
 *   clientDataJSON,    // from navigator.credentials.get() response
 *   storedChallenge,
 *   'https://example.com',
 *   storedSignCount,
 *   authDataBuffer,
 *   signatureBuffer,
 *   credentialPublicKeyPem,
 * );
 * if (!result.verified) throw new Error(result.error);
 * await db.updateSignCount(credentialId, result.newSignCount!);
 */
export const verifyPasskeyAssertion = (
  clientDataJSONStr: string,
  expectedChallenge: string,
  expectedOrigin: string,
  storedSignCount: number,
  authData: Buffer,
  signature: Buffer,
  publicKeyPem: string,
): PasskeyAssertionResult => {
  try {
    // Step 1: Resolve raw JSON — same dual-format handling as verifyPasskeyRegistration
    let jsonStr = clientDataJSONStr;
    try {
      JSON.parse(clientDataJSONStr);
    } catch {
      // Not raw JSON — treat as base64url-encoded clientDataJSON (browser format)
      jsonStr = Buffer.from(clientDataJSONStr, 'base64url').toString('utf8');
    }

    const clientData = JSON.parse(jsonStr);

    // Step 2: type must be 'webauthn.get'
    if (clientData.type !== 'webauthn.get') {
      return { verified: false, error: 'Invalid type (expected webauthn.get).' };
    }

    // Step 3: Compare challenge bytes via timingSafeEqual (§7.2 step 11)
    const receivedBytes = Buffer.from(clientData.challenge ?? '', 'base64url');
    const expectedBytes = Buffer.from(expectedChallenge, 'base64url');
    const challengeMatches =
      receivedBytes.length === expectedBytes.length &&
      receivedBytes.length > 0 &&
      timingSafeEqual(receivedBytes, expectedBytes);

    if (!challengeMatches) return { verified: false, error: 'Challenge mismatch.' };

    // Step 4: Verify origin
    if (clientData.origin !== expectedOrigin) {
      return { verified: false, error: 'Origin mismatch.' };
    }

    // Step 5: Sign count — must be strictly greater to detect cloned authenticators.
    // Per §7.2 step 17: if storedSignCount is 0 (counter not supported), skip check.
    const newSignCount: number = authData.readUInt32BE(33);
    if (storedSignCount !== 0 && newSignCount <= storedSignCount) {
      return {
        verified: false,
        error: `Replay attack or cloned authenticator detected: signCount ${newSignCount} is not greater than stored ${storedSignCount}.`,
      };
    }

    // Step 6: Verify signature over authData || SHA-256(clientDataJSON)
    // The signed data is: authData || hash(clientDataJSON bytes) per §7.2 step 19
    const clientDataHash = createHash('sha256').update(Buffer.from(jsonStr, 'utf8')).digest();
    const signedData = Buffer.concat([authData, clientDataHash]);

    const sigValid = verify('sha256', signedData, publicKeyPem, signature);
    if (!sigValid) return { verified: false, error: 'Signature verification failed.' };

    return { verified: true, newSignCount };
  } catch (err: unknown) {
    return { verified: false, error: err instanceof Error ? err.message : String(err) };
  }
};

/**
 * Generates a Time-based One-Time Password (TOTP) per RFC 6238.
 */
export const generateTOTP = (
  secret: string | Buffer,
  options: { stepSeconds?: number; digits?: number; timestampMs?: number } = {},
): string => {
  const { stepSeconds = 30, digits = 6, timestampMs = Date.now() } = options;
  const counter = Math.floor(timestampMs / 1000 / stepSeconds);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));

  const key = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, 'utf8');
  const hmac = createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return (code % 10 ** digits).toString().padStart(digits, '0');
};

/**
 * Verifies a TOTP code using timing-safe comparison across a configurable drift window.
 */
export const verifyTOTP = (
  token: string,
  secret: string | Buffer,
  options: { stepSeconds?: number; digits?: number; window?: number; timestampMs?: number } = {},
): boolean => {
  const { stepSeconds = 30, digits = 6, window = 1, timestampMs = Date.now() } = options;
  if (!/^\d+$/.test(token) || token.length !== digits) return false;
  const tokenBuf = Buffer.from(token, 'utf8');

  for (let i = -window; i <= window; i++) {
    const candidate = generateTOTP(secret, {
      stepSeconds,
      digits,
      timestampMs: timestampMs + i * stepSeconds * 1000,
    });
    const candidateBuf = Buffer.from(candidate, 'utf8');
    if (timingSafeEqual(tokenBuf, candidateBuf)) return true;
  }
  return false;
};

/**
 * Generates single-use MFA backup codes.
 */
export const generateBackupCodes = (count: number = 8, length: number = 10): string[] => {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    codes.push(
      randomBytes(Math.ceil(length / 2))
        .toString('hex')
        .slice(0, length),
    );
  }
  return codes;
};

export interface SignJwtOptions {
  algorithm?: 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'ES256';
  expiresInSec?: number;
  issuer?: string;
  audience?: string;
  subject?: string;
  jwtId?: string;
}

/**
 * Signs a JSON Web Token (JWT) using HS256/384/512, RS256, or ES256.
 */
export const signJwt = (
  payload: Record<string, unknown>,
  secretOrPrivateKey: string | Buffer,
  options: SignJwtOptions = {},
): string => {
  const { algorithm = 'HS256', expiresInSec, issuer, audience, subject, jwtId } = options;
  const nowSec = Math.floor(Date.now() / 1000);
  const claims: Record<string, unknown> = {
    ...payload,
    iat: payload.iat ?? nowSec,
  };
  if (expiresInSec !== undefined) claims.exp = nowSec + expiresInSec;
  if (issuer !== undefined) claims.iss = issuer;
  if (audience !== undefined) claims.aud = audience;
  if (subject !== undefined) claims.sub = subject;
  if (jwtId !== undefined) claims.jti = jwtId;

  const headerB64 = Buffer.from(JSON.stringify({ alg: algorithm, typ: 'JWT' })).toString(
    'base64url',
  );
  const payloadB64 = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const dataToSign = `${headerB64}.${payloadB64}`;

  let sig: Buffer;
  if (algorithm.startsWith('HS')) {
    const hashAlg = algorithm.replace('HS', 'sha');
    sig = createHmac(hashAlg, secretOrPrivateKey).update(dataToSign).digest();
  } else if (algorithm.startsWith('RS')) {
    const hashAlg = algorithm.replace('RS', 'sha');
    sig = sign(hashAlg, Buffer.from(dataToSign), secretOrPrivateKey);
  } else {
    const hashAlg = algorithm.replace('ES', 'sha');
    sig = sign(hashAlg, Buffer.from(dataToSign), {
      key: secretOrPrivateKey,
      dsaEncoding: 'ieee-p1363',
    });
  }

  return `${dataToSign}.${sig.toString('base64url')}`;
};

export interface VerifyJwtOptions {
  algorithm?: string;
  issuer?: string;
  audience?: string;
}

/**
 * Verifies a JWT signature and claims (`exp`, `nbf`, `iat`, `iss`, `aud`),
 * returning the decoded payload or `null` if invalid.
 */
export const verifyAndDecodeJwt = <T extends Record<string, unknown> = Record<string, unknown>>(
  token: string,
  secretOrPublicKey: string | Buffer,
  options: VerifyJwtOptions = {},
): T | null => {
  const { algorithm = 'HS256', issuer, audience } = options;
  if (!isJwtValid(token, secretOrPublicKey, algorithm)) return null;
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')) as T;
    if (issuer !== undefined && payload.iss !== issuer) return null;
    if (audience !== undefined && payload.aud !== audience) return null;
    return payload;
  } catch {
    return null;
  }
};

/**
 * Signs a webhook payload with a timestamped HMAC-SHA256 signature (`t=<ts>,v1=<hex>`).
 */
export const signWebhookPayload = (
  payload: string | Buffer,
  secret: string,
  timestampSec: number = Math.floor(Date.now() / 1000),
): string => {
  const signedContent = `${timestampSec}.${Buffer.isBuffer(payload) ? payload.toString('utf8') : payload}`;
  const sig = createHmac('sha256', secret).update(signedContent).digest('hex');
  return `t=${timestampSec},v1=${sig}`;
};

/**
 * Verifies a timestamped webhook signature (`t=<ts>,v1=<hex>`) with replay-window protection.
 */
export const verifyWebhookSignature = (
  payload: string | Buffer,
  signatureHeader: string,
  secret: string,
  toleranceSec: number = 300,
): boolean => {
  try {
    const parts = Object.fromEntries(
      signatureHeader.split(',').map((part) => {
        const [k, v] = part.split('=');
        return [k?.trim(), v?.trim()];
      }),
    );
    const ts = Number.parseInt(parts.t || '', 10);
    const sigHex = parts.v1;
    if (!Number.isFinite(ts) || !sigHex) return false;

    const nowSec = Math.floor(Date.now() / 1000);
    if (Math.abs(nowSec - ts) > toleranceSec) return false;

    const signedContent = `${ts}.${Buffer.isBuffer(payload) ? payload.toString('utf8') : payload}`;
    const expected = createHmac('sha256', secret).update(signedContent).digest('hex');
    const sigBuf = Buffer.from(sigHex, 'hex');
    const expectedBuf = Buffer.from(expected, 'hex');
    if (sigBuf.length !== expectedBuf.length) return false;
    return timingSafeEqual(sigBuf, expectedBuf);
  } catch {
    return false;
  }
};

/**
 * Generates a prefixed API key (e.g. `mtg_live_<random>`).
 */
export const generateApiKey = (prefix: string = 'mtg_live'): string => {
  return `${prefix}_${randomBytes(24).toString('base64url')}`;
};

/**
 * Hashes an API key with SHA-256 for safe database storage.
 */
export const hashApiKey = (apiKey: string): string => {
  return createHash('sha256').update(apiKey).digest('hex');
};

/**
 * Verifies an API key against a stored SHA-256 hash using `timingSafeEqual`.
 */
export const verifyApiKey = (apiKey: string, storedHash: string): boolean => {
  const actualBuf = Buffer.from(hashApiKey(apiKey), 'hex');
  const storedBuf = Buffer.from(storedHash, 'hex');
  if (actualBuf.length !== storedBuf.length) return false;
  return timingSafeEqual(actualBuf, storedBuf);
};
