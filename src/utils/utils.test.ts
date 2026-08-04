import { describe, it, expect, vi } from 'vitest';
import {
  redact,
  SecureError,
  normalizeError,
  wipeBuffer,
  enforceSafeQuery,
  deterministicDigitTransform,
  auditConfig,
  lockdownPrototypes,
  startSelfHealingMonitor,
  checkSecureEnv,
  createMTLSOptions,
  type MinimalLogger,
} from './index.js';

describe('Utils Module', () => {
  describe('redact', () => {
    it('should redact sensitive keys', () => {
      const input = {
        username: 'john',
        password: 'secret123',
        nested: {
          token: 'abc-123',
        },
      };
      const result = redact(input);
      expect(result.password).toBe('[REDACTED]');
      expect(result.nested.token).toBe('[REDACTED]');
      expect(result.username).toBe('john');
    });

    it('should handle arrays', () => {
      const input = [{ password: '123' }, { password: '456' }];
      const result = redact(input);
      expect(result[0].password).toBe('[REDACTED]');
      expect(result[1].password).toBe('[REDACTED]');
    });
  });

  describe('SecureError', () => {
    it('should format to JSON correctly', () => {
      const error = new SecureError('internal message', 'AUTH_FAILED', 'Invalid credentials');
      const json = error.toJSON();
      expect(json).toEqual({
        error: true,
        code: 'AUTH_FAILED',
        message: 'Invalid credentials',
      });
    });

    it('should hide stack in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      const error = new SecureError('msg');
      expect(error.stack).toBe('');
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('normalizeError', () => {
    it('should wrap basic errors', () => {
      const error = new Error('raw error');
      const normalized = normalizeError(error);
      expect(normalized).toBeInstanceOf(SecureError);
      expect(normalized.message).toBe('raw error');
    });

    it('should return SecureError as is', () => {
      const error = new SecureError('msg');
      expect(normalizeError(error)).toBe(error);
    });
  });

  describe('wipeBuffer', () => {
    it('should zero out buffer contents', () => {
      const buf = Buffer.from('sensitive data');
      wipeBuffer(buf);
      expect(buf.every((b) => b === 0)).toBe(true);
    });

    it('should zero out Uint8Array contents', () => {
      const arr = new Uint8Array([1, 2, 3, 4]);
      wipeBuffer(arr);
      expect(arr.every((b) => b === 0)).toBe(true);
    });

    it('should zero out array contents', () => {
      const arr = [1, 2, 3, 4];
      wipeBuffer(arr);
      expect(arr.every((b) => b === 0)).toBe(true);
    });
  });

  describe('enforceSafeQuery', () => {
    it('should throw error for suspicious unparameterized queries', () => {
      expect(() => enforceSafeQuery("SELECT * FROM users WHERE id = '1' --", [])).toThrow(
        'Security Violation',
      );
      expect(() =>
        enforceSafeQuery("SELECT * FROM users WHERE id = '1' --", undefined as any),
      ).toThrow('Security Violation');
    });

    it('should allow parameterized queries', () => {
      expect(() => enforceSafeQuery('SELECT * FROM users WHERE id = ?', [1])).not.toThrow();
      expect(() => enforceSafeQuery('SELECT * FROM users', [])).not.toThrow();
    });
  });

  describe('deterministicDigitTransform', () => {
    it('should preserve length and numeric character set', () => {
      const input = '1234567890';
      const secret = 'my-secret';
      const result = deterministicDigitTransform(input, secret);
      expect(result).toHaveLength(input.length);
      expect(result).toMatch(/^\d+$/);
      expect(result).not.toBe(input);
    });

    it('should be deterministic for the same input and secret', () => {
      const input = '9876543210';
      const secret = 'test-key';
      expect(deterministicDigitTransform(input, secret)).toBe(
        deterministicDigitTransform(input, secret),
      );
    });
  });

  describe('auditConfig', () => {
    it('should find issues in db config', () => {
      const config = { ssl: false, port: 5432 };
      const issues = auditConfig(config, 'db');
      expect(issues).toContain('Database SSL is disabled.');
      expect(issues).toContain('Database is using a default port.');

      const config3306 = { ssl: true, port: 3306 };
      const issues3306 = auditConfig(config3306, 'db');
      expect(issues3306).toContain('Database is using a default port.');
      expect(issues3306).not.toContain('Database SSL is disabled.');
    });

    it('should find issues in auth config', () => {
      const config = { allowInsecurePasswordReset: true };
      const issues = auditConfig(config, 'auth');
      expect(issues).toContain('Allowing insecure password reset.');

      const cleanConfig = { allowInsecurePasswordReset: false };
      expect(auditConfig(cleanConfig, 'auth')).toEqual([]);
    });

    it('should ignore other config types', () => {
      expect(auditConfig({}, 'redis')).toEqual([]);
    });
  });

  describe('lockdownPrototypes', () => {
    it('should freeze core prototypes', () => {
      lockdownPrototypes();
      expect(Object.isFrozen(Object.prototype)).toBe(true);
      expect(Object.isFrozen(Array.prototype)).toBe(true);
      expect(Object.isFrozen(String.prototype)).toBe(true);
    });

    it('should log error if lockdownPrototypes fails', () => {
      const originalFreeze = Object.freeze;
      Object.freeze = vi.fn().mockImplementation(() => {
        throw new Error('freeze failed');
      });

      const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
      lockdownPrototypes();

      expect(spy).toHaveBeenCalledWith('Mitigator Error: Failed to lockdown prototypes.');

      Object.freeze = originalFreeze;
      spy.mockRestore();
    });
  });

  describe('startSelfHealingMonitor', () => {
    it('should start self-healing monitor and log config drift issues', () => {
      const config = { ssl: false, port: 5432 };
      const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

      vi.useFakeTimers();
      startSelfHealingMonitor(config, 'db', 1000);

      vi.advanceTimersByTime(1100);
      expect(spy).toHaveBeenCalledWith(
        'MITIGATOR CRITICAL: Self-healing monitor detected insecure config drift!',
      );

      spy.mockRestore();
      vi.useRealTimers();
    });

    it('should start self-healing monitor and not log if config is clean', () => {
      const config = { ssl: true, port: 9999 };
      const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

      vi.useFakeTimers();
      startSelfHealingMonitor(config, 'db', 1000);

      vi.advanceTimersByTime(1100);
      expect(spy).not.toHaveBeenCalled();

      spy.mockRestore();
      vi.useRealTimers();
    });

    it('should use an injected custom logger instead of console', () => {
      const config = { ssl: false, port: 5432 };
      const mockLogger: MinimalLogger = {
        error: vi.fn(),
        warn: vi.fn(),
      };

      vi.useFakeTimers();
      startSelfHealingMonitor(config, 'db', 1000, mockLogger);

      vi.advanceTimersByTime(1100);
      expect(mockLogger.error).toHaveBeenCalledWith(
        'MITIGATOR CRITICAL: Self-healing monitor detected insecure config drift!',
      );
      // console.error must NOT be called when a custom logger is injected
      const consoleSpy = vi.spyOn(console, 'error');
      expect(consoleSpy).not.toHaveBeenCalled();
      consoleSpy.mockRestore();

      vi.useRealTimers();
    });
  });

  describe('checkSecureEnv', () => {
    it('should warn if SESSION_SECRET is insecure in production', () => {
      const originalEnv = process.env.NODE_ENV;
      const originalSecret = process.env.SESSION_SECRET;

      process.env.NODE_ENV = 'production';
      process.env.SESSION_SECRET = 'short';

      const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      checkSecureEnv();

      expect(spy).toHaveBeenCalledWith('Security Warning: SESSION_SECRET is missing or too short.');

      process.env.NODE_ENV = originalEnv;
      process.env.SESSION_SECRET = originalSecret;
      spy.mockRestore();
    });

    it('should NOT warn if SESSION_SECRET is secure in production', () => {
      const originalEnv = process.env.NODE_ENV;
      const originalSecret = process.env.SESSION_SECRET;

      process.env.NODE_ENV = 'production';
      process.env.SESSION_SECRET = 'a'.repeat(32);

      const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      checkSecureEnv();

      expect(spy).not.toHaveBeenCalled();

      process.env.NODE_ENV = originalEnv;
      process.env.SESSION_SECRET = originalSecret;
      spy.mockRestore();
    });

    it('should NOT warn if not in production', () => {
      const originalEnv = process.env.NODE_ENV;
      const originalSecret = process.env.SESSION_SECRET;

      process.env.NODE_ENV = 'development';
      process.env.SESSION_SECRET = 'short';

      const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      checkSecureEnv();

      expect(spy).not.toHaveBeenCalled();

      process.env.NODE_ENV = originalEnv;
      process.env.SESSION_SECRET = originalSecret;
      spy.mockRestore();
    });
  });

  describe('createMTLSOptions', () => {
    it('should return valid TLS options', () => {
      const cert = Buffer.from('cert');
      const key = Buffer.from('key');
      const ca = Buffer.from('ca');
      const options = createMTLSOptions(cert, key, ca);

      expect(options).toEqual({
        cert,
        key,
        ca,
        requestCert: true,
        rejectUnauthorized: true,
      });
    });
  });
});
