import { describe, it, expect, vi } from 'vitest';
import {
  scanForSecrets,
  isWeakPassword,
  enforceSchema,
  isEmail,
  hasInjectionPattern,
  checkPwnedPassword,
  type CheckPwnedResult,
} from './index.js';
import * as https from 'node:https';
import { EventEmitter } from 'node:events';

vi.mock('node:https');

describe('Validation Module', () => {
  describe('scanForSecrets', () => {
    it('should detect AWS access keys', () => {
      expect(scanForSecrets('My key is AKIA1234567890123456')).toBe(true);
    });

    it('should detect GitHub tokens', () => {
      expect(scanForSecrets('ghp_abcdefghijklmnopqrstuvwxyz0123456789')).toBe(true);
    });

    it('should return false for clean input', () => {
      expect(scanForSecrets('normal string')).toBe(false);
    });

    it('should scan nested objects', () => {
      expect(scanForSecrets({ nested: { key: 'ghp_abcdefghijklmnopqrstuvwxyz0123456789' } })).toBe(
        true,
      );
    });

    it('should return false for unsupported types like numbers or booleans', () => {
      expect(scanForSecrets(12345)).toBe(false);
      expect(scanForSecrets(true)).toBe(false);
    });
  });

  describe('isWeakPassword', () => {
    it('should mark short passwords as weak', () => {
      expect(isWeakPassword('abc12!')).toBe(true);
    });

    it('should mark passwords with only one character type as weak', () => {
      expect(isWeakPassword('aaaaaaaaaa')).toBe(true);
      expect(isWeakPassword('1234567890')).toBe(true);
    });

    it('should mark common passwords as weak', () => {
      expect(isWeakPassword('password123')).toBe(true);
      expect(isWeakPassword('12345678')).toBe(true);
    });

    it('should accept strong passwords', () => {
      expect(isWeakPassword('ComplexP@ss123')).toBe(false);
    });
  });

  describe('enforceSchema', () => {
    const schema = {
      name: 'string',
      age: 'number',
      active: 'boolean',
    } as const;

    it('should valid data matching schema', () => {
      const data = { name: 'John', age: 30, active: true, extra: 'field' };
      const result = enforceSchema(data, schema);
      expect(result).toEqual({ name: 'John', age: 30, active: true });
    });

    it('should return null if field is missing', () => {
      const data = { name: 'John', age: 30 };
      expect(enforceSchema(data, schema)).toBeNull();
    });

    it('should return null if type mismatch', () => {
      const data = { name: 'John', age: '30', active: true };
      expect(enforceSchema(data, schema)).toBeNull();
    });

    it('should handle array types and validate them correctly', () => {
      const arrSchema = { tags: 'array' } as const;
      expect(enforceSchema({ tags: ['a', 'b'] }, arrSchema)).toEqual({ tags: ['a', 'b'] });
      expect(enforceSchema({ tags: 'not-array' }, arrSchema)).toBeNull();
    });

    it('should return null for non-objects or invalid data structures', () => {
      expect(enforceSchema(null, schema)).toBeNull();
      expect(enforceSchema(123, schema)).toBeNull();
      expect(enforceSchema([], schema)).toBeNull();
    });
  });

  describe('isEmail', () => {
    it('should validate correct emails', () => {
      expect(isEmail('test@example.com')).toBe(true);
      expect(isEmail('user.name+tag@domain.co.uk')).toBe(true);
    });

    it('should reject invalid emails', () => {
      expect(isEmail('plainaddress')).toBe(false);
      expect(isEmail('@no-user.com')).toBe(false);
    });
  });

  describe('hasInjectionPattern', () => {
    it('should detect SQL injection patterns', () => {
      expect(hasInjectionPattern("' OR '1'='1")).toBe(true);
      expect(hasInjectionPattern("admin' --")).toBe(true);
    });

    it('should detect NoSQL injection patterns', () => {
      expect(hasInjectionPattern("{ $gt: '' }")).toBe(true);
    });

    it('should return false for non-string inputs', () => {
      expect(hasInjectionPattern(123 as any)).toBe(false);
      expect(hasInjectionPattern(null as any)).toBe(false);
    });

    it('should flag excessively long inputs (>8192 chars) to prevent ReDoS', () => {
      const longInput = 'A'.repeat(8193);
      expect(hasInjectionPattern(longInput)).toBe(true);
    });
  });

  describe('checkPwnedPassword', () => {
    it('should return count and apiAvailable=true if password is pwned', async () => {
      const mockRes = new EventEmitter();
      (mockRes as any).statusCode = 200;
      (https.get as any).mockImplementation((_url: unknown, _options: unknown, cb: any) => {
        cb(mockRes);
        // SHA1 of 'password' starts with 5BAA6...
        // Suffix is 1E4C9B93F3F0682250B6CF8331B7EE68FD8
        mockRes.emit('data', '1E4C9B93F3F0682250B6CF8331B7EE68FD8:99\n');
        mockRes.emit('end');
        return new EventEmitter();
      });

      const result: CheckPwnedResult = await checkPwnedPassword('password');
      expect(result.count).toBe(99);
      expect(result.apiAvailable).toBe(true);
    });

    it('should return count=0 and apiAvailable=true if password is NOT pwned', async () => {
      const mockRes = new EventEmitter();
      (mockRes as any).statusCode = 200;
      (https.get as any).mockImplementation((_url: unknown, _options: unknown, cb: any) => {
        cb(mockRes);
        mockRes.emit('data', 'SUFFIX:10\n');
        mockRes.emit('end');
        return new EventEmitter();
      });

      const result = await checkPwnedPassword('secure_password_123');
      expect(result.count).toBe(0);
      expect(result.apiAvailable).toBe(true);
    });

    it('should return count=0 and apiAvailable=false if HIBP returns non-200 status', async () => {
      const mockRes = new EventEmitter();
      (mockRes as any).statusCode = 503;
      (mockRes as any).resume = vi.fn();
      (https.get as any).mockImplementation((_url: unknown, _options: unknown, cb: any) => {
        cb(mockRes);
        return new EventEmitter();
      });

      const result = await checkPwnedPassword('test_pass');
      expect(result.count).toBe(0);
      expect(result.apiAvailable).toBe(false);
      expect((mockRes as any).resume).toHaveBeenCalled();
    });

    it('should return count=0 and apiAvailable=false on timeout', async () => {
      const handlers: Record<string, (arg?: unknown) => void> = {};
      const mockReq = {
        on(event: string, cb: (arg?: unknown) => void) {
          handlers[event] = cb;
          return this;
        },
        destroy: vi.fn(),
      };
      (https.get as any).mockImplementation((_url: unknown, _options: unknown, _cb: any) => {
        return mockReq;
      });

      const promise = checkPwnedPassword('test_pass');
      handlers['timeout']?.();
      const result = await promise;

      expect(result.count).toBe(0);
      expect(result.apiAvailable).toBe(false);
      expect(mockReq.destroy).toHaveBeenCalled();
    });

    it('should return count=0 and apiAvailable=false on HIBP API connection error', async () => {
      const handlers: Record<string, (arg?: unknown) => void> = {};
      const mockReq = {
        on(event: string, cb: (arg?: unknown) => void) {
          handlers[event] = cb;
          return this;
        },
      };
      (https.get as any).mockImplementation((_url: unknown, _options: unknown, _cb: any) => {
        return mockReq;
      });

      const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      const promise = checkPwnedPassword('some_password');
      handlers['error']?.(new Error('network down'));
      const result = await promise;

      expect(result.count).toBe(0);
      expect(result.apiAvailable).toBe(false);
      expect(spy).toHaveBeenCalledWith(
        expect.stringContaining('Mitigator: HIBP API connection unavailable.'),
      );
      spy.mockRestore();
    });
  });
});
