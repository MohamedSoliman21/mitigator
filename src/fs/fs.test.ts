import { describe, it, expect, vi } from 'vitest';
import { resolveSafePath, verifyMagicNumber, safeRead, isPathSafe } from './index.js';
import * as fs from 'node:fs/promises';
import { resolve } from 'node:path';

vi.mock('node:fs/promises');

describe('Filesystem Module', () => {
  const rootDir = resolve('root');

  describe('resolveSafePath', () => {
    it('should resolve paths within the root', () => {
      const resolved = resolveSafePath(rootDir, 'data.txt');
      expect(resolved).toBe(resolve(rootDir, 'data.txt'));
    });

    it('should throw error for path traversal attempts', () => {
      expect(() => resolveSafePath(rootDir, '../../etc/passwd')).toThrow(
        'Path traversal attempt detected',
      );
      expect(() => resolveSafePath(rootDir, '/etc/passwd')).toThrow(
        'Path traversal attempt detected',
      );
    });

    it('should resolve subdirectory paths correctly', () => {
      const resolved = resolveSafePath(rootDir, 'subdir/data.txt');
      expect(resolved).toBe(resolve(rootDir, 'subdir/data.txt'));
    });
  });

  describe('isPathSafe', () => {
    it('should return true for safe paths', () => {
      expect(isPathSafe(rootDir, 'data.txt')).toBe(true);
    });

    it('should return false for unsafe paths', () => {
      expect(isPathSafe(rootDir, '../../etc/passwd')).toBe(false);
    });
  });

  describe('verifyMagicNumber', () => {
    it('should return true if magic numbers match', async () => {
      const mockHandle = {
        read: vi.fn().mockImplementation((buf: Buffer) => {
          buf[0] = 0x89;
          buf[1] = 0x50;
          buf[2] = 0x4e;
          buf[3] = 0x47;
          return Promise.resolve({ bytesRead: 4, buffer: buf });
        }),
        close: vi.fn().mockResolvedValue(undefined),
      };
      (fs.open as any).mockResolvedValue(mockHandle);

      const result = await verifyMagicNumber('test.png', [0x89, 0x50, 0x4e, 0x47]);
      expect(result).toBe(true);
      expect(mockHandle.read).toHaveBeenCalled();
    });

    it('should return false if magic numbers mismatch', async () => {
      const mockHandle = {
        read: vi.fn().mockImplementation((buf: Buffer) => {
          buf[0] = 0x00;
          return Promise.resolve({ bytesRead: 4, buffer: buf });
        }),
        close: vi.fn().mockResolvedValue(undefined),
      };
      (fs.open as any).mockResolvedValue(mockHandle);

      const result = await verifyMagicNumber('test.png', [0x89, 0x50, 0x4e, 0x47]);
      expect(result).toBe(false);
    });
  });

  describe('safeRead', () => {
    it('should read file if within root', async () => {
      (fs.readFile as any).mockResolvedValue('file content');
      const content = await safeRead(rootDir, 'data.txt');
      expect(content).toBe('file content');
      expect(fs.readFile).toHaveBeenCalledWith(resolve(rootDir, 'data.txt'), 'utf8');
    });

    it('should throw if path is unsafe', async () => {
      await expect(safeRead(rootDir, '../../secret.txt')).rejects.toThrow(
        'Path traversal attempt detected',
      );
    });
  });
});
