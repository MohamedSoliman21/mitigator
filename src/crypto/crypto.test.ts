import { describe, it, expect } from 'vitest';
import {
  splitSecret,
  reconstructSecret,
  blindData,
  generateToken,
  deriveSubKey,
  encryptSession,
  decryptSession,
  hashPassword,
  verifyPassword,
  sha256,
  verifyPQCSignature,
  generatePQCKeyPair,
  signPQC,
} from './index.js';
import { randomBytes } from 'node:crypto';
import { vi } from 'vitest';

describe('Crypto Module', () => {
  describe('Shamir Secret Sharing (GF256)', () => {
    it('should split and reconstruct successfully with exact threshold', () => {
      const secret = 'super-secret-key-12345';
      const shares = splitSecret(secret, 5, 3);

      // Reconstruct with 3 shares (1, 3, 5)
      const subset1 = [shares[0], shares[2], shares[4]];
      const reconstructed1 = reconstructSecret(subset1);
      expect(reconstructed1.toString('utf8')).toBe(secret);

      // Reconstruct with 4 shares (1, 2, 4, 5)
      const subset2 = [shares[0], shares[1], shares[3], shares[4]];
      const reconstructed2 = reconstructSecret(subset2);
      expect(reconstructed2.toString('utf8')).toBe(secret);
    });

    it('should fail or return invalid secret with fewer than threshold shares', () => {
      const secret = 'super-secret-key-12345';
      const shares = splitSecret(secret, 5, 3);

      // Try with 2 shares
      const subset = [shares[0], shares[1]];
      const reconstructed = reconstructSecret(subset);
      expect(reconstructed.toString('utf8')).not.toBe(secret);
    });

    it('should throw errors for invalid inputs', () => {
      expect(() => splitSecret('sec', 3, 5)).toThrow(
        'Threshold cannot be greater than sharesCount.',
      );
      expect(() => splitSecret('sec', 5, 0)).toThrow('Threshold must be at least 1.');
      expect(() => splitSecret('sec', 256, 10)).toThrow(
        'Shamir Secret Sharing GF(256) supports up to 255 shares.',
      );
      expect(() => reconstructSecret([])).toThrow('No shares provided.');
    });
  });

  describe('blindData', () => {
    it('should return a deterministic hash based on data and factor', () => {
      const data = 'my-data';
      const factor = 'my-factor';
      const blinded = blindData(data, factor);
      expect(blinded).toBe(blindData(data, factor));
      expect(blinded).not.toBe(blindData(data, 'other-factor'));
    });
  });

  describe('generateToken', () => {
    it('should generate token of specified length', () => {
      const token = generateToken(16, 'hex');
      expect(token).toHaveLength(32); // 16 bytes = 32 hex chars
    });
  });

  describe('deriveSubKey (HKDF-SHA-256)', () => {
    it('should derive different sub-keys for different info strings', () => {
      const secret = 'master-secret';
      const key1 = deriveSubKey(secret, 'purpose-1');
      const key2 = deriveSubKey(secret, 'purpose-2');
      expect(key1).not.toBe(key2);
    });

    it('should be deterministic — same inputs yield same output', () => {
      const secret = 'master-secret';
      expect(deriveSubKey(secret, 'purpose-1')).toBe(deriveSubKey(secret, 'purpose-1'));
    });

    it('should respect the length parameter', () => {
      const key16 = deriveSubKey('secret', 'info', 16);
      const key32 = deriveSubKey('secret', 'info', 32);
      // 16 bytes = 32 hex chars, 32 bytes = 64 hex chars
      expect(key16).toHaveLength(32);
      expect(key32).toHaveLength(64);
    });
  });

  describe('Session Encryption (AES-GCM)', () => {
    const key = randomBytes(32); // 256-bit key

    it('should encrypt and decrypt an object', () => {
      const obj = { userId: 123, role: 'admin' };
      const encrypted = encryptSession(obj, key);
      const decrypted = decryptSession(encrypted, key);
      expect(decrypted).toEqual(obj);
    });

    it('should return null for invalid key or tampered data', () => {
      const obj = { userId: 123 };
      const encrypted = encryptSession(obj, key);
      const tampered = encrypted.slice(0, -1) + (encrypted.endsWith('0') ? '1' : '0');
      expect(decryptSession(tampered, key)).toBeNull();
      expect(decryptSession(encrypted, randomBytes(32))).toBeNull();
    });
  });

  describe('Password Hashing (Scrypt)', () => {
    it('should hash and verify password', async () => {
      const password = 'my-secure-password';
      const { hash, salt } = await hashPassword(password);
      expect(hash).toBeDefined();
      expect(salt).toBeDefined();

      expect(await verifyPassword(password, hash, salt)).toBe(true);
      expect(await verifyPassword('wrong-password', hash, salt)).toBe(false);
    });
  });

  describe('sha256', () => {
    it('should return valid sha256 hash', () => {
      const data = 'hello';
      const hash = sha256(data);
      expect(hash).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
    });
  });

  describe('Winternitz OTS (PQC Framework)', () => {
    it('should generate valid PQC keypair, sign and verify successfully', () => {
      const { publicKey, privateKey } = generatePQCKeyPair();
      expect(publicKey).toContain(';');
      expect(privateKey).toContain(';');

      const data = 'secure post-quantum data transmission';
      const signature = signPQC(data, privateKey);

      // Verify correct signature
      expect(verifyPQCSignature(data, signature, publicKey)).toBe(true);

      // Verify wrong signature
      const tamperedSig = signature.slice(0, -2) + '00';
      expect(verifyPQCSignature(data, tamperedSig, publicKey)).toBe(false);

      // Verify wrong message
      expect(verifyPQCSignature('different data', signature, publicKey)).toBe(false);

      // Verify wrong public key
      const tamperedPubKey = publicKey.slice(0, -2) + '00';
      expect(verifyPQCSignature(data, signature, tamperedPubKey)).toBe(false);
    });

    it('should throw WOTS_KEY_REUSE if the same private key signs twice', () => {
      const { privateKey } = generatePQCKeyPair();
      // First sign succeeds
      signPQC('first message', privateKey);
      // Second sign with the same key must throw
      expect(() => signPQC('second message', privateKey)).toThrow('WOTS_KEY_REUSE');
    });

    it('should allow signing with a freshly generated key pair', () => {
      const { publicKey: pk1, privateKey: priv1 } = generatePQCKeyPair();
      const { publicKey: pk2, privateKey: priv2 } = generatePQCKeyPair();
      const sig1 = signPQC('msg-a', priv1);
      const sig2 = signPQC('msg-b', priv2);
      expect(verifyPQCSignature('msg-a', sig1, pk1)).toBe(true);
      expect(verifyPQCSignature('msg-b', sig2, pk2)).toBe(true);
    });

    it('should return false for malformed signatures or keys', () => {
      expect(verifyPQCSignature('msg', 'short-sig', 'short-pub')).toBe(false);
      expect(verifyPQCSignature('msg', null as any, 'short-pub')).toBe(false);
    });

    it('should throw if signing with an invalid private key length', () => {
      expect(() => signPQC('msg', 'short-key')).toThrow('Invalid private key length.');
    });
  });

  describe('runIsolatedCrypto & Workers', () => {
    it('should successfully run isolated crypto using mocked worker', async () => {
      vi.resetModules();
      vi.doMock('node:worker_threads', () => {
        class MockWorker {
          public handlers: Record<string, Function[]> = {};
          constructor(
            public filename: string,
            public options: any,
          ) {
            setTimeout(() => {
              this.trigger('message', { status: 'success' });
              this.trigger('exit', 0);
            }, 5);
          }
          on(event: string, cb: Function) {
            if (!this.handlers[event]) this.handlers[event] = [];
            this.handlers[event].push(cb);
            return this;
          }
          trigger(event: string, data: any) {
            this.handlers[event]?.forEach((cb) => cb(data));
          }
        }
        return {
          Worker: MockWorker,
          isMainThread: true,
          parentPort: null,
          workerData: null,
        };
      });

      const { runIsolatedCrypto: run } = await import('./index.js');
      const result = await run('hashPassword', ['pass']);
      expect(result).toEqual({ status: 'success' });
    });

    it('should handle worker errors', async () => {
      vi.resetModules();
      vi.doMock('node:worker_threads', () => {
        class MockWorker {
          public handlers: Record<string, Function[]> = {};
          constructor(
            public filename: string,
            public options: any,
          ) {
            setTimeout(() => {
              this.trigger('error', new Error('worker failed'));
            }, 5);
          }
          on(event: string, cb: Function) {
            if (!this.handlers[event]) this.handlers[event] = [];
            this.handlers[event].push(cb);
            return this;
          }
          trigger(event: string, data: any) {
            this.handlers[event]?.forEach((cb) => cb(data));
          }
        }
        return {
          Worker: MockWorker,
          isMainThread: true,
          parentPort: null,
          workerData: null,
        };
      });

      const { runIsolatedCrypto: run } = await import('./index.js');
      await expect(run('hashPassword', ['pass'])).rejects.toThrow('worker failed');
    });

    it('should handle non-zero exit codes', async () => {
      vi.resetModules();
      vi.doMock('node:worker_threads', () => {
        class MockWorker {
          public handlers: Record<string, Function[]> = {};
          constructor(
            public filename: string,
            public options: any,
          ) {
            setTimeout(() => {
              this.trigger('exit', 1);
            }, 5);
          }
          on(event: string, cb: Function) {
            if (!this.handlers[event]) this.handlers[event] = [];
            this.handlers[event].push(cb);
            return this;
          }
          trigger(event: string, data: any) {
            this.handlers[event]?.forEach((cb) => cb(data));
          }
        }
        return {
          Worker: MockWorker,
          isMainThread: true,
          parentPort: null,
          workerData: null,
        };
      });

      const { runIsolatedCrypto: run } = await import('./index.js');
      await expect(run('hashPassword', ['pass'])).rejects.toThrow(
        'Worker stopped with exit code 1',
      );
    });

    it('should reject if worker returns non-success status', async () => {
      vi.resetModules();
      vi.doMock('node:worker_threads', () => {
        class MockWorker {
          private handlers: Record<string, Function[]> = {};
          constructor() {
            setTimeout(() => {
              this.trigger('message', { status: 'failure', error: 'Custom worker error' });
            }, 5);
          }
          on(event: string, cb: Function) {
            if (!this.handlers[event]) this.handlers[event] = [];
            this.handlers[event].push(cb);
            return this;
          }
          trigger(event: string, data: any) {
            this.handlers[event]?.forEach((cb) => cb(data));
          }
        }
        return {
          Worker: MockWorker,
          isMainThread: true,
          parentPort: null,
          workerData: null,
        };
      });

      const { runIsolatedCrypto: run } = await import('./index.js');
      await expect(run('hashPassword', ['pass'])).rejects.toThrow('Custom worker error');
    });

    it('should run parentPort code in worker context', async () => {
      vi.resetModules();
      const mockPostMessage = vi.fn();
      vi.doMock('node:worker_threads', () => {
        return {
          Worker: class {},
          isMainThread: false,
          parentPort: {
            postMessage: mockPostMessage,
          },
          workerData: { functionName: 'hashPassword' },
        };
      });

      await import('./index.js');
      // Wait for asynchronous dynamic import side-effects to execute
      await new Promise((resolve) => setTimeout(resolve, 5));
      expect(mockPostMessage).toHaveBeenCalledWith({ status: 'success' });
    });

    it('should handle successful hashPassword in worker context', async () => {
      vi.resetModules();
      const mockPostMessage = vi.fn();
      vi.doMock('node:worker_threads', () => {
        return {
          Worker: class {},
          isMainThread: false,
          parentPort: {
            postMessage: mockPostMessage,
          },
          workerData: { functionName: 'hashPassword', args: ['my-pass', 'my-salt'] },
        };
      });

      await import('./index.js');
      await new Promise((resolve) => setTimeout(resolve, 500));
      expect(mockPostMessage).toHaveBeenCalledWith(
        expect.objectContaining({ status: 'success', result: expect.any(Object) }),
      );
    });

    it('should handle failed hashPassword in worker context', async () => {
      vi.resetModules();
      const mockPostMessage = vi.fn();
      vi.doMock('node:worker_threads', () => {
        return {
          Worker: class {},
          isMainThread: false,
          parentPort: {
            postMessage: mockPostMessage,
          },
          workerData: { functionName: 'hashPassword', args: [null, 'my-salt'] },
        };
      });

      await import('./index.js');
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(mockPostMessage).toHaveBeenCalledWith(
        expect.objectContaining({ status: 'error', error: expect.any(String) }),
      );
    });

    it('should handle splitSecret in worker context', async () => {
      vi.resetModules();
      const mockPostMessage = vi.fn();
      vi.doMock('node:worker_threads', () => {
        return {
          Worker: class {},
          isMainThread: false,
          parentPort: {
            postMessage: mockPostMessage,
          },
          workerData: { functionName: 'splitSecret', args: ['my-secret', 3, 2] },
        };
      });

      await import('./index.js');
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(mockPostMessage).toHaveBeenCalledWith(
        expect.objectContaining({ status: 'success', result: expect.any(Array) }),
      );
    });

    it('should handle reconstructSecret in worker context', async () => {
      vi.resetModules();
      const mockPostMessage = vi.fn();
      vi.doMock('node:worker_threads', () => {
        return {
          Worker: class {},
          isMainThread: false,
          parentPort: {
            postMessage: mockPostMessage,
          },
          workerData: { functionName: 'reconstructSecret', args: [['1:01']] },
        };
      });

      await import('./index.js');
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(mockPostMessage).toHaveBeenCalledWith(
        expect.objectContaining({ status: 'success', result: '01' }),
      );
    });

    it('should handle unknown function in worker context', async () => {
      vi.resetModules();
      const mockPostMessage = vi.fn();
      vi.doMock('node:worker_threads', () => {
        return {
          Worker: class {},
          isMainThread: false,
          parentPort: {
            postMessage: mockPostMessage,
          },
          workerData: { functionName: 'unknown' },
        };
      });

      await import('./index.js');
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(mockPostMessage).toHaveBeenCalledWith({
        status: 'error',
        error: 'Unknown function: unknown',
      });
    });

    it('should handle worker errors globally in worker context', async () => {
      vi.resetModules();
      const mockPostMessage = vi.fn();
      vi.doMock('node:worker_threads', () => {
        return {
          Worker: class {},
          isMainThread: false,
          parentPort: {
            postMessage: mockPostMessage,
          },
          workerData: { functionName: 'hashPassword', args: null },
        };
      });

      await import('./index.js');
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(mockPostMessage).toHaveBeenCalledWith({
        status: 'error',
        error: expect.stringContaining('not iterable'),
      });
    });
  });
});
