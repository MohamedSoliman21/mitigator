import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  basicAuth,
  suggestMFA,
  generateHmacChallenge,
  verifyHmacResponse,
  generateHoneyToken,
  isHoneyToken,
  generateCSRF,
  verifyCSRF,
  isJwtValid,
  hasRole,
  verifyPasskeySignature,
  canAccess,
  can,
  generatePasskeyChallenge,
  verifyPasskeyRegistration,
  verifyPasskeyAssertion,
  parseAuthenticatorData,
} from './index.js';

describe('Auth Module', () => {
  describe('basicAuth', () => {
    it('should format basic auth header', () => {
      const header = basicAuth('user', 'pass');
      expect(header).toBe('Basic dXNlcjpwYXNz');
    });
  });

  describe('suggestMFA', () => {
    it('should suggest MFA if fingerprints mismatch', () => {
      expect(suggestMFA(0, 'fp1', 'fp2')).toBe(true);
    });

    it('should suggest MFA if risk score is high', () => {
      expect(suggestMFA(15, 'fp1', 'fp1')).toBe(true);
    });

    it('should NOT suggest MFA for low risk same fingerprint', () => {
      expect(suggestMFA(5, 'fp1', 'fp1')).toBe(false);
    });
  });

  describe('HMAC Challenge-Response (generateHmacChallenge / verifyHmacResponse)', () => {
    it('should generate and verify a challenge using new API names', () => {
      const secret = 'user-secret';
      const salt = 'user-salt';
      const challenge = generateHmacChallenge(salt);

      // Proof is HMAC(challenge, secret)
      const proof = crypto.createHmac('sha256', secret).update(challenge).digest('hex');

      expect(verifyHmacResponse(challenge, proof, secret)).toBe(true);
      expect(verifyHmacResponse(challenge, 'wrong-proof', secret)).toBe(false);
    });
  });

  describe('Honey Tokens', () => {
    it('should generate and detect honey tokens', () => {
      const token = generateHoneyToken('test');
      expect(token).toContain('test_');
      expect(isHoneyToken(token, 'test')).toBe(true);
      expect(isHoneyToken('normal_token', 'test')).toBe(false);
      expect(isHoneyToken('', 'test')).toBe(false);
    });
  });

  describe('CSRF', () => {
    it('should verify matching CSRF tokens', () => {
      const { token } = generateCSRF();
      expect(verifyCSRF(token, token)).toBe(true);
      expect(verifyCSRF(token, 'wrong')).toBe(false);
      expect(verifyCSRF('', token)).toBe(false);
      expect(verifyCSRF(token, '')).toBe(false);
    });
  });

  describe('isJwtValid', () => {
    const secret = 'test-secret-key-12345';

    it('should return true for valid-looking JWT with correct signature', () => {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString(
        'base64url',
      );
      const payload = Buffer.from(
        JSON.stringify({ sub: '123', exp: Math.floor(Date.now() / 1000) + 3600 }),
      ).toString('base64url');
      const dataToSign = `${header}.${payload}`;
      const signature = crypto.createHmac('sha256', secret).update(dataToSign).digest('base64url');
      const token = `${dataToSign}.${signature}`;

      expect(isJwtValid(token, secret)).toBe(true);
    });

    it('should return false for expired JWT', () => {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString(
        'base64url',
      );
      const payload = Buffer.from(
        JSON.stringify({ sub: '123', exp: Math.floor(Date.now() / 1000) - 3600 }),
      ).toString('base64url');
      const dataToSign = `${header}.${payload}`;
      const signature = crypto.createHmac('sha256', secret).update(dataToSign).digest('base64url');
      const token = `${dataToSign}.${signature}`;

      expect(isJwtValid(token, secret)).toBe(false);
    });

    it('should return false for JWT with future nbf', () => {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString(
        'base64url',
      );
      const payload = Buffer.from(
        JSON.stringify({ sub: '123', nbf: Math.floor(Date.now() / 1000) + 3600 }),
      ).toString('base64url');
      const dataToSign = `${header}.${payload}`;
      const signature = crypto.createHmac('sha256', secret).update(dataToSign).digest('base64url');
      const token = `${dataToSign}.${signature}`;

      expect(isJwtValid(token, secret)).toBe(false);
    });

    it('should return false for JWT with future iat beyond tolerance', () => {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString(
        'base64url',
      );
      const payload = Buffer.from(
        JSON.stringify({ sub: '123', iat: Math.floor(Date.now() / 1000) + 3600 }),
      ).toString('base64url');
      const dataToSign = `${header}.${payload}`;
      const signature = crypto.createHmac('sha256', secret).update(dataToSign).digest('base64url');
      const token = `${dataToSign}.${signature}`;

      expect(isJwtValid(token, secret)).toBe(false);
    });

    it('should return true for JWT with valid past nbf and iat', () => {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString(
        'base64url',
      );
      const now = Math.floor(Date.now() / 1000);
      const payload = Buffer.from(
        JSON.stringify({ sub: '123', iat: now - 60, nbf: now - 30, exp: now + 3600 }),
      ).toString('base64url');
      const dataToSign = `${header}.${payload}`;
      const signature = crypto.createHmac('sha256', secret).update(dataToSign).digest('base64url');
      const token = `${dataToSign}.${signature}`;

      expect(isJwtValid(token, secret)).toBe(true);
    });

    it('should return false for alg: none', () => {
      const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ sub: '123' })).toString('base64url');
      const token = `${header}.${payload}.signature`;

      expect(isJwtValid(token, secret, 'none')).toBe(false);
    });

    it('should return false for wrong signature', () => {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString(
        'base64url',
      );
      const payload = Buffer.from(
        JSON.stringify({ sub: '123', exp: Math.floor(Date.now() / 1000) + 3600 }),
      ).toString('base64url');
      const token = `${header}.${payload}.wrong-signature`;

      expect(isJwtValid(token, secret)).toBe(false);
    });

    it('should return true for valid RS256 signed JWT', () => {
      const { generateKeyPairSync, sign } = crypto;
      const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString(
        'base64url',
      );
      const payload = Buffer.from(
        JSON.stringify({ sub: '123', exp: Math.floor(Date.now() / 1000) + 3600 }),
      ).toString('base64url');
      const dataToSign = `${header}.${payload}`;
      const signature = sign('sha256', Buffer.from(dataToSign), privateKey).toString('base64url');
      const token = `${dataToSign}.${signature}`;

      expect(isJwtValid(token, publicKey, 'RS256')).toBe(true);
    });

    it('should return false if token is totally invalid or malformed causing throws', () => {
      expect(isJwtValid('invalid-token', 'secret')).toBe(false);
      expect(isJwtValid('a.b.c', 'secret')).toBe(false);
    });

    it('should return false for unsupported algorithm type', () => {
      const header = Buffer.from(JSON.stringify({ alg: 'XYZ256', typ: 'JWT' })).toString(
        'base64url',
      );
      const payload = Buffer.from(JSON.stringify({ sub: '123' })).toString('base64url');
      const token = `${header}.${payload}.signature`;

      expect(isJwtValid(token, 'secret', 'XYZ256')).toBe(false);
    });
  });

  describe('hasRole', () => {
    it('should return true if all required roles are present', () => {
      expect(hasRole(['admin', 'user'], ['admin'])).toBe(true);
      expect(hasRole(['admin', 'user'], ['admin', 'user'])).toBe(true);
    });

    it('should return false if any required role is missing', () => {
      expect(hasRole(['user'], ['admin'])).toBe(false);
    });
  });

  describe('verifyPasskeySignature', () => {
    const { generateKeyPairSync, sign } = crypto;
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    it('should verify valid passkey signature', () => {
      const challenge = 'test-challenge';
      const signature = sign('sha256', Buffer.from(challenge), privateKey);

      expect(verifyPasskeySignature(challenge, challenge, signature, publicKey)).toBe(true);
    });

    it('should verify valid passkey signature with Buffers', () => {
      const challenge = 'test-challenge';
      const signature = sign('sha256', Buffer.from(challenge), privateKey);

      expect(
        verifyPasskeySignature(
          Buffer.from(challenge),
          Buffer.from(challenge),
          signature,
          publicKey,
        ),
      ).toBe(true);
    });

    it('should return false for invalid passkey signature or malformed public key', () => {
      expect(verifyPasskeySignature('challenge', 'challenge', 'bad-sig', 'bad-key')).toBe(false);
    });
  });

  describe('canAccess', () => {
    it('should execute rule correctly', () => {
      const user = { role: 'admin' };
      const resource = { owner: 'user1' };
      const rule = (u: typeof user, _r: typeof resource) => u.role === 'admin';
      expect(canAccess(user, resource, rule)).toBe(true);
    });
  });

  describe('can', () => {
    it('should check permissions correctly', () => {
      expect(can(['read', 'write'], 'read')).toBe(true);
      expect(can(['read', 'write'], 'delete')).toBe(false);
    });
  });

  describe('FIDO2 WebAuthn / Passkey Registration', () => {
    it('should generate a valid challenge string', () => {
      const challenge = generatePasskeyChallenge();
      expect(challenge).toBeDefined();
      expect(typeof challenge).toBe('string');
      // base64url has no padding or standard slashes
      expect(challenge).not.toContain('+');
      expect(challenge).not.toContain('/');
    });

    it('should verify registration JSON successfully (raw JSON string)', () => {
      // Raw JSON — as used in server-side testing
      const challenge = generatePasskeyChallenge(); // base64url challenge bytes
      const clientDataJSON = JSON.stringify({
        type: 'webauthn.create',
        challenge: challenge,
        origin: 'https://example.com',
      });

      const res = verifyPasskeyRegistration(clientDataJSON, challenge, 'https://example.com');
      expect(res.verified).toBe(true);
    });

    it('should verify registration JSON successfully (base64url-encoded — browser format)', () => {
      // Simulates the real browser flow: clientDataJSON is sent as a base64url-encoded buffer
      const challenge = generatePasskeyChallenge();
      const rawJSON = JSON.stringify({
        type: 'webauthn.create',
        challenge: challenge,
        origin: 'https://example.com',
      });
      // Encode the JSON as base64url, mimicking what browsers send in response.clientDataJSON
      const base64urlEncoded = Buffer.from(rawJSON).toString('base64url');

      const res = verifyPasskeyRegistration(base64urlEncoded, challenge, 'https://example.com');
      expect(res.verified).toBe(true);
    });

    it('should fail verification if parameters mismatch or are invalid', () => {
      const challenge = generatePasskeyChallenge();
      const clientDataJSON = JSON.stringify({
        type: 'webauthn.create',
        challenge: challenge,
        origin: 'https://example.com',
      });

      // Wrong challenge
      expect(verifyPasskeyRegistration(clientDataJSON, generatePasskeyChallenge()).verified).toBe(
        false,
      );
      // Wrong type
      const wrongTypeJSON = JSON.stringify({
        type: 'webauthn.get',
        challenge,
        origin: 'https://example.com',
      });
      expect(verifyPasskeyRegistration(wrongTypeJSON, challenge).verified).toBe(false);
      // Wrong origin
      expect(
        verifyPasskeyRegistration(clientDataJSON, challenge, 'https://different.com').verified,
      ).toBe(false);
      // Invalid JSON (and not valid base64url either)
      expect(verifyPasskeyRegistration('{invalid-not-base64url!!!', challenge).verified).toBe(
        false,
      );
      // Empty challenge in clientData should fail (zero-length guard)
      const emptyChallJSON = JSON.stringify({ type: 'webauthn.create', challenge: '' });
      expect(verifyPasskeyRegistration(emptyChallJSON, challenge).verified).toBe(false);
    });

    it('should parse authenticatorData with attested credential data', () => {
      const rpIdHash = Buffer.alloc(32, 1);
      const flags = 0x40; // attestedCredentialDataPresent
      const signCount = Buffer.alloc(4);
      signCount.writeUInt32BE(100);
      const aaguid = Buffer.alloc(16, 2);
      const credentialIdLength = Buffer.alloc(2);
      credentialIdLength.writeUInt16BE(8);
      const credentialId = Buffer.alloc(8, 3);
      const publicKey = Buffer.alloc(20, 4);

      const authData = Buffer.concat([
        rpIdHash,
        Buffer.from([flags]),
        signCount,
        aaguid,
        credentialIdLength,
        credentialId,
        publicKey,
      ]);

      const parsed = parseAuthenticatorData(authData);
      expect(parsed).not.toBeNull();
      expect(parsed?.rpIdHash.toString('hex')).toBe(rpIdHash.toString('hex'));
      expect(parsed?.flags).toBe(flags);
      expect(parsed?.signCount).toBe(100);
      expect(parsed?.aaguid?.toString('hex')).toBe(aaguid.toString('hex'));
      expect(parsed?.credentialId).toBe(credentialId.toString('base64url'));
      expect(parsed?.publicKeyBytes).toBe(publicKey.toString('hex'));
    });

    it('should parse authenticatorData WITHOUT attested credential data', () => {
      const rpIdHash = Buffer.alloc(32, 1);
      const flags = 0x01; // UP
      const signCount = Buffer.alloc(4);
      signCount.writeUInt32BE(50);

      const authData = Buffer.concat([rpIdHash, Buffer.from([flags]), signCount]);

      const parsed = parseAuthenticatorData(authData);
      expect(parsed).not.toBeNull();
      expect(parsed?.rpIdHash.toString('hex')).toBe(rpIdHash.toString('hex'));
      expect(parsed?.flags).toBe(flags);
      expect(parsed?.signCount).toBe(50);
      expect(parsed?.credentialId).toBeUndefined();
    });

    it('should return null for malformed/short authenticatorData', () => {
      const shortAuthData = Buffer.alloc(10);
      expect(parseAuthenticatorData(shortAuthData)).toBeNull();
    });
  });

  describe('FIDO2 Assertion Verification (verifyPasskeyAssertion)', () => {
    const { generateKeyPairSync, sign } = crypto;
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    /**
     * Build a valid authData buffer with a given signCount.
     * Layout: rpIdHash(32) | flags(1) | signCount(4)
     */
    const makeAuthData = (signCount: number): Buffer => {
      const buf = Buffer.alloc(37);
      buf.fill(0xab, 0, 32); // rpIdHash placeholder
      buf[32] = 0x05; // UP | UV flags
      buf.writeUInt32BE(signCount, 33);
      return buf;
    };

    /**
     * Build a valid clientDataJSON and its base64url-encoded form (browser format).
     */
    const makeClientData = (
      challenge: string,
      type = 'webauthn.get',
      origin = 'https://example.com',
    ) => {
      const raw = JSON.stringify({ type, challenge, origin });
      const base64url = Buffer.from(raw).toString('base64url');
      return { raw, base64url };
    };

    /**
     * Sign the assertion payload: authData || SHA-256(clientDataJSON utf8 bytes)
     */
    const signAssertion = (authData: Buffer, clientDataJSONStr: string): Buffer => {
      const clientDataHash = crypto
        .createHash('sha256')
        .update(Buffer.from(clientDataJSONStr, 'utf8'))
        .digest();
      const signedData = Buffer.concat([authData, clientDataHash]);
      return sign('sha256', signedData, privateKey);
    };

    it('should verify a valid assertion (raw JSON string)', () => {
      const challenge = generatePasskeyChallenge();
      const authData = makeAuthData(5);
      const { raw } = makeClientData(challenge);
      const signature = signAssertion(authData, raw);

      const result = verifyPasskeyAssertion(
        raw,
        challenge,
        'https://example.com',
        4,
        authData,
        signature,
        publicKey,
      );
      expect(result.verified).toBe(true);
      expect(result.newSignCount).toBe(5);
    });

    it('should verify a valid assertion (base64url-encoded browser format)', () => {
      const challenge = generatePasskeyChallenge();
      const authData = makeAuthData(10);
      const { raw, base64url } = makeClientData(challenge);
      const signature = signAssertion(authData, raw);

      const result = verifyPasskeyAssertion(
        base64url,
        challenge,
        'https://example.com',
        9,
        authData,
        signature,
        publicKey,
      );
      expect(result.verified).toBe(true);
      expect(result.newSignCount).toBe(10);
    });

    it('should fail with wrong type (webauthn.create instead of webauthn.get)', () => {
      const challenge = generatePasskeyChallenge();
      const authData = makeAuthData(5);
      const { raw } = makeClientData(challenge, 'webauthn.create');
      const signature = signAssertion(authData, raw);

      const result = verifyPasskeyAssertion(
        raw,
        challenge,
        'https://example.com',
        4,
        authData,
        signature,
        publicKey,
      );
      expect(result.verified).toBe(false);
      expect(result.error).toContain('webauthn.get');
    });

    it('should fail on challenge mismatch', () => {
      const challenge = generatePasskeyChallenge();
      const authData = makeAuthData(5);
      const { raw } = makeClientData(challenge);
      const signature = signAssertion(authData, raw);

      const result = verifyPasskeyAssertion(
        raw,
        generatePasskeyChallenge(),
        'https://example.com',
        4,
        authData,
        signature,
        publicKey,
      );
      expect(result.verified).toBe(false);
      expect(result.error).toContain('Challenge mismatch');
    });

    it('should fail on origin mismatch', () => {
      const challenge = generatePasskeyChallenge();
      const authData = makeAuthData(5);
      const { raw } = makeClientData(challenge, 'webauthn.get', 'https://evil.com');
      const signature = signAssertion(authData, raw);

      const result = verifyPasskeyAssertion(
        raw,
        challenge,
        'https://example.com',
        4,
        authData,
        signature,
        publicKey,
      );
      expect(result.verified).toBe(false);
      expect(result.error).toContain('Origin mismatch');
    });

    it('should fail on replay attack (signCount <= storedSignCount)', () => {
      const challenge = generatePasskeyChallenge();
      const authData = makeAuthData(3); // new signCount = 3
      const { raw } = makeClientData(challenge);
      const signature = signAssertion(authData, raw);

      // storedSignCount = 5 which is greater than the authenticator's 3
      const result = verifyPasskeyAssertion(
        raw,
        challenge,
        'https://example.com',
        5,
        authData,
        signature,
        publicKey,
      );
      expect(result.verified).toBe(false);
      expect(result.error).toContain('Replay attack');
    });

    it('should skip sign count check when storedSignCount is 0', () => {
      const challenge = generatePasskeyChallenge();
      const authData = makeAuthData(0); // authenticator signCount is also 0 (counter not supported)
      const { raw } = makeClientData(challenge);
      const signature = signAssertion(authData, raw);

      const result = verifyPasskeyAssertion(
        raw,
        challenge,
        'https://example.com',
        0,
        authData,
        signature,
        publicKey,
      );
      expect(result.verified).toBe(true);
    });

    it('should fail on bad signature', () => {
      const challenge = generatePasskeyChallenge();
      const authData = makeAuthData(5);
      const { raw } = makeClientData(challenge);

      const result = verifyPasskeyAssertion(
        raw,
        challenge,
        'https://example.com',
        4,
        authData,
        Buffer.from('badsig'),
        publicKey,
      );
      expect(result.verified).toBe(false);
    });

    it('should fail on malformed clientDataJSON', () => {
      const challenge = generatePasskeyChallenge();
      const authData = makeAuthData(5);
      const signature = Buffer.alloc(32);

      const result = verifyPasskeyAssertion(
        '{not-valid-json!!!',
        challenge,
        'https://example.com',
        4,
        authData,
        signature,
        publicKey,
      );
      expect(result.verified).toBe(false);
    });
  });
});
