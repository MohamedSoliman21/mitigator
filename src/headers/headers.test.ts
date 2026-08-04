import { describe, it, expect } from 'vitest';
import {
  generateNonce,
  buildCSP,
  buildStrictCSP,
  parseCSPReport,
  standardHeaders,
} from './index.js';

describe('Headers Module', () => {
  describe('generateNonce', () => {
    it('should generate a base64 string of correct length', () => {
      const nonce = generateNonce(16);
      expect(typeof nonce).toBe('string');
      // 16 bytes in base64 is 24 chars (including padding)
      expect(Buffer.from(nonce, 'base64').length).toBe(16);
    });
  });

  describe('buildCSP', () => {
    it('should format simple directives', () => {
      const csp = buildCSP({
        'default-src': ["'self'"],
        'img-src': ["'self'", 'https://example.com'],
      });
      expect(csp).toBe("default-src 'self'; img-src 'self' https://example.com");
    });

    it('should inject nonce if provided', () => {
      const nonce = 'test-nonce';
      const csp = buildCSP({ 'script-src': ["'self'"] }, nonce);
      expect(csp).toBe("script-src 'self' 'nonce-test-nonce'");
    });

    it('should filter out empty directives', () => {
      const csp = buildCSP({ 'default-src': ["'self'"], 'font-src': [] });
      expect(csp).toBe("default-src 'self'");
    });
  });

  describe('buildStrictCSP', () => {
    it('should return a secure strict CSP with nonce', () => {
      const nonce = 'abc';
      const csp = buildStrictCSP(nonce);
      expect(csp).toContain("'strict-dynamic'");
      expect(csp).toContain("'nonce-abc'");
      expect(csp).toContain("object-src 'none'");
    });
  });

  describe('parseCSPReport', () => {
    it('should extract CSP report details', () => {
      const reportBody = {
        'csp-report': {
          'document-uri': 'http://example.com',
          'blocked-uri': 'http://evil.com',
          'violated-directive': 'script-src',
          'original-policy': 'default-src self',
          disposition: 'enforce',
          'status-code': 200,
        },
      };
      const report = parseCSPReport(reportBody);
      expect(report?.documentUri).toBe('http://example.com');
      expect(report?.blockedUri).toBe('http://evil.com');
      expect(report?.violatedDirective).toBe('script-src');
    });

    it('should extract CSP report details when body is an array or direct object', () => {
      const arrayBody = [
        {
          'blocked-uri': 'http://evil.com',
          'document-uri': 'http://example.com',
        },
      ];
      const directBody = {
        'blocked-uri': 'http://evil.com',
        'document-uri': 'http://example.com',
      };
      expect(parseCSPReport(arrayBody)?.blockedUri).toBe('http://evil.com');
      expect(parseCSPReport(directBody)?.blockedUri).toBe('http://evil.com');
    });

    it('should return null for invalid report', () => {
      expect(parseCSPReport({})).toBeNull();
      expect(parseCSPReport(null)).toBeNull();
      expect(parseCSPReport({ 'csp-report': {} })).toBeNull();
    });
  });

  describe('standardHeaders', () => {
    it('should define recommended security headers', () => {
      expect(standardHeaders['X-Frame-Options']).toBe('DENY');
      expect(standardHeaders['X-Content-Type-Options']).toBe('nosniff');
    });
  });
});
