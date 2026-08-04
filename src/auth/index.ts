import { Buffer } from 'node:buffer';
import { randomBytes, timingSafeEqual, createHmac, createHash, verify } from 'node:crypto';

/**
 * Basic authentication helper.
 */
export const basicAuth = (user: string, pass: string): string => {
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
 * CSRF management.
 */
export const generateCSRF = () => {
  const token = randomBytes(32).toString('hex');
  const cookieValue = randomBytes(32).toString('hex');
  return { token, cookieValue };
};

export const verifyCSRF = (providedToken: string, cookieToken: string): boolean => {
  if (!providedToken || !cookieToken) return false;
  const tokenBuf = Buffer.from(providedToken, 'hex');
  const cookieBuf = Buffer.from(cookieToken, 'hex');
  if (tokenBuf.length !== cookieBuf.length) return false;
  return timingSafeEqual(tokenBuf, cookieBuf);
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
    if (payload.exp && Date.now() >= payload.exp * 1000) return false;

    // Verify signature
    const dataToSign = `${headerB64}.${payloadB64}`;
    const signatureBuffer = Buffer.from(signatureB64, 'base64url');

    if (algorithm.startsWith('HS')) {
      const hashAlg = algorithm.replace('HS', 'sha');
      const expectedSignature = createHmac(hashAlg, secretOrPublicKey).update(dataToSign).digest();
      if (signatureBuffer.length !== expectedSignature.length) return false;
      return timingSafeEqual(signatureBuffer, expectedSignature);
    } else if (algorithm.startsWith('RS') || algorithm.startsWith('ES')) {
      const hashAlg = algorithm.replace(/RS|ES/, 'sha');
      return verify(hashAlg, Buffer.from(dataToSign), secretOrPublicKey, signatureBuffer);
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
  } catch (err: any) {
    return { verified: false, error: err.message };
  }
};

/**
 * Parses WebAuthn raw authenticator data (authData) buffer to extract the
 * aaguid, credential ID, and public key bytes according to the FIDO2 spec.
 */
export const parseAuthenticatorData = (authData: Buffer) => {
  try {
    const rpIdHash = authData.subarray(0, 32);
    const flags = authData[32];
    const signCount = authData.readUInt32BE(33);

    // Bit 6 of flags indicates if attestedCredentialData is present
    const attestedCredentialDataPresent = !!(flags & 0x40);

    if (!attestedCredentialDataPresent) {
      return { rpIdHash, flags, signCount };
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
  } catch (err: any) {
    return { verified: false, error: err.message };
  }
};
