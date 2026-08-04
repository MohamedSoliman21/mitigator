import { describe, it, expect } from 'vitest';
import {
  isSecure,
  normalizeUrl,
  getHardenedRequestOptions,
  generateFingerprint,
  isSafeRedirect,
  generateSRI,
  projectNoise,
  generateTLSFingerprint,
  analyzeDoSThreat,
} from './index.js';

describe('HTTP Module', () => {
  describe('isSecure', () => {
    it('should return true for https:// URLs', () => {
      expect(isSecure('https://example.com')).toBe(true);
    });

    it('should detect x-forwarded-proto header', () => {
      expect(isSecure('http://example.com', { 'x-forwarded-proto': 'https' })).toBe(true);
    });

    it('should return false for http:// URLs without headers', () => {
      expect(isSecure('http://example.com')).toBe(false);
    });
  });

  describe('normalizeUrl', () => {
    it('should remove duplicate slashes in path', () => {
      expect(normalizeUrl('https://example.com//path//to//res')).toBe(
        'https://example.com/path/to/res',
      );
    });

    it('should handle relative paths too', () => {
      expect(normalizeUrl('/foo//bar')).toBe('/foo/bar');
    });
  });

  describe('getHardenedRequestOptions', () => {
    it('should set TLS 1.3 and strong ciphers', () => {
      const options = getHardenedRequestOptions();
      expect(options.minVersion).toBe('TLSv1.3');
      expect(options.ciphers).toContain('TLS_AES_256_GCM_SHA384');
      expect(options.rejectUnauthorized).toBe(true);
    });
  });

  describe('generateFingerprint', () => {
    it('should return same fingerprint for same client environment', () => {
      const headers = { 'user-agent': 'agent1', 'accept-language': 'en' };
      const ip = '127.0.0.1';
      const fp1 = generateFingerprint(headers, ip);
      const fp2 = generateFingerprint(headers, ip);
      expect(fp1).toBe(fp2);
    });

    it('should handle empty headers gracefully', () => {
      const fp = generateFingerprint({}, '127.0.0.1');
      expect(fp).toBeDefined();
    });

    it('should return different fingerprints for different clients', () => {
      const headers1 = { 'user-agent': 'agent1' };
      const headers2 = { 'user-agent': 'agent2' };
      expect(generateFingerprint(headers1, '1.1.1.1')).not.toBe(
        generateFingerprint(headers2, '1.1.1.1'),
      );
    });
  });

  describe('isSafeRedirect', () => {
    it('should allow relative redirects starting with /', () => {
      expect(isSafeRedirect('/dashboard')).toBe(true);
    });

    it('should block protocol-relative redirects (//)', () => {
      expect(isSafeRedirect('//evil.com')).toBe(false);
    });

    it('should allow absolute redirects if host is whitelisted', () => {
      expect(isSafeRedirect('https://auth.mycompany.com/login', ['auth.mycompany.com'])).toBe(true);
    });

    it('should block absolute redirects if host is NOT whitelisted', () => {
      expect(isSafeRedirect('https://evil.com/login', ['auth.mycompany.com'])).toBe(false);
    });

    it('should return false if URL parsing throws an error', () => {
      expect(isSafeRedirect('not-a-valid-url-at-all', ['auth.mycompany.com'])).toBe(false);
    });
  });

  describe('generateSRI', () => {
    it('should generate correctly formatted SRI string', () => {
      const data = 'alert(1)';
      const sri = generateSRI(data, 'sha256');
      expect(sri).toMatch(/^sha256-[a-zA-Z0-9+/=]+$/);
    });
  });

  describe('projectNoise', () => {
    it('should add noise properties with _sk_ prefix', () => {
      const input = { a: 1 };
      const result = projectNoise(input);
      expect(result.a).toBe(1);
      const keys = Object.keys(result);
      expect(keys.length).toBeGreaterThan(1);
      expect(keys.some((k) => k.startsWith('_sk_'))).toBe(true);
    });

    it('should return non-objects or null immediately', () => {
      expect(projectNoise(null)).toBeNull();
      expect(projectNoise('string')).toBe('string');
      expect(projectNoise(123)).toBe(123);
    });
  });

  describe('generateTLSFingerprint', () => {
    it('should generate consistent TLS fingerprint based on headers', () => {
      const req = {
        headers: {
          'user-agent': 'Mozilla',
          accept: 'text/html',
          'accept-language': 'en-US',
          'accept-encoding': 'gzip',
          connection: 'keep-alive',
          'upgrade-insecure-requests': '1',
        },
      };
      const fp1 = generateTLSFingerprint(req);
      const fp2 = generateTLSFingerprint(req);
      expect(fp1).toBe(fp2);

      const req2 = { headers: {} };
      expect(generateTLSFingerprint(req2)).toBeDefined();
      expect(generateTLSFingerprint({})).toBeDefined();
    });
  });

  describe('analyzeDoSThreat', () => {
    it('should identify DoS threats from conflicting or suspicious headers', () => {
      const threat1 = {
        headers: {
          'transfer-encoding': 'chunked',
          'content-length': '123',
        },
      };
      expect(analyzeDoSThreat(threat1)).toBe(true);

      const threat2 = {
        method: 'POST',
        headers: {
          connection: 'keep-alive',
        },
      };
      expect(analyzeDoSThreat(threat2)).toBe(true);

      const safe = {
        method: 'GET',
        headers: {},
      };
      expect(analyzeDoSThreat(safe)).toBe(false);
      expect(analyzeDoSThreat({})).toBe(false);
    });
  });
});
