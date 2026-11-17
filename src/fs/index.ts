import { resolve, relative, isAbsolute } from 'node:path';

/**
 * Standard Magic Numbers for common file types.
 */
export const MAGIC_NUMBERS = {
  PNG: [0x89, 0x50, 0x4e, 0x47],
  JPEG: [0xff, 0xd8, 0xff],
  PDF: [0x25, 0x50, 0x44, 0x46],
  GIF: [0x47, 0x49, 0x46, 0x38],
  WEBP: [0x52, 0x49, 0x46, 0x46],
  ZIP: [0x50, 0x4b, 0x03, 0x04],
  WASM: [0x00, 0x61, 0x73, 0x6d],
  MP4: [0x66, 0x74, 0x79, 0x70],
  WAV: [0x52, 0x49, 0x46, 0x46],
};

/**
 * Resolves a path relative to a root directory and ensures it doesn't escape the root.
 *
 * Note: This operates lexically on path strings. If the directory may contain untrusted
 * symlinks, use {@link resolveSafeRealPath} or {@link safeRead} to also verify canonical
 * symlink targets on disk.
 */
export const resolveSafePath = (rootDir: string, userInputPath: string): string => {
  if (userInputPath.includes('\0') || rootDir.includes('\0')) {
    throw new Error('Security Error: Null byte injection detected in path.');
  }

  const absoluteRoot = resolve(rootDir);
  const resolvedPath = resolve(absoluteRoot, userInputPath);

  const relativePath = relative(absoluteRoot, resolvedPath);

  if (relativePath.startsWith('..') || isAbsolute(relativePath)) {
    throw new Error('Security Error: Path traversal attempt detected.');
  }

  return resolvedPath;
};

/**
 * Resolves the canonical physical path on disk (following symlinks via `fs.realpath`)
 * and verifies that the target stays strictly within `rootDir`.
 *
 * Defends against both lexical path traversal (`../`) and symlink escape attacks.
 */
export const resolveSafeRealPath = async (
  rootDir: string,
  userInputPath: string,
): Promise<string> => {
  const lexicalTarget = resolveSafePath(rootDir, userInputPath);
  const fs = await import('node:fs/promises');
  const [realRoot, realTarget] = await Promise.all([
    fs.realpath(resolve(rootDir)),
    fs.realpath(lexicalTarget),
  ]);

  const relativeReal = relative(realRoot, realTarget);
  if (relativeReal.startsWith('..') || isAbsolute(relativeReal)) {
    throw new Error('Security Error: Symlink path traversal attempt detected.');
  }

  return realTarget;
};

/**
 * Verifies that a file's magic numbers match the expected type.
 * This is much more secure than trusting file extensions or MIME types.
 *
 * @param filePath The path to the file.
 * @param expectedMagic The array of bytes to match.
 * @returns true if the file matches.
 */
export const verifyMagicNumber = async (
  filePath: string,
  expectedMagic: number[],
): Promise<boolean> => {
  const fs = await import('node:fs/promises');
  const handle = await fs.open(filePath, 'r');
  try {
    const buffer = Buffer.alloc(expectedMagic.length);
    await handle.read(buffer, 0, expectedMagic.length, 0);

    return expectedMagic.every((byte, index) => buffer[index] === byte);
  } finally {
    await handle.close();
  }
};

/**
 * Safely reads a file from a root-locked directory.
 */
export const safeRead = async (rootDir: string, filePath: string): Promise<string> => {
  const fs = await import('node:fs/promises');
  const safePath = resolveSafePath(rootDir, filePath);
  return fs.readFile(safePath, 'utf8');
};

/**
 * Checks if a path is safe (within the root) without throwing.
 */
export const isPathSafe = (rootDir: string, filePath: string): boolean => {
  try {
    resolveSafePath(rootDir, filePath);
    return true;
  } catch {
    return false;
  }
};

const WINDOWS_RESERVED_NAMES = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;

/**
 * Sanitizes an untrusted filename by stripping control characters, bidi overrides,
 * path separators, and Windows reserved device names.
 */
export const sanitizeFilename = (filename: string): string => {
  let cleaned = filename
    // eslint-disable-next-line no-control-regex
    .replaceAll(/[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]/g, '')
    .replaceAll(/[\\/]/g, '_')
    .trim();
  while (cleaned.startsWith('.')) cleaned = cleaned.slice(1);
  while (cleaned.endsWith('.')) cleaned = cleaned.slice(0, -1);
  cleaned = cleaned.trim();

  if (!cleaned || WINDOWS_RESERVED_NAMES.test(cleaned)) {
    return `file_${cleaned || 'unnamed'}`;
  }
  return cleaned;
};

export interface ArchiveEntryMetadata {
  path: string;
  compressedSize: number;
  uncompressedSize: number;
}

/**
 * Validates archive entries against Zip-Slip path traversal and decompression bombs.
 */
export const validateArchiveEntries = (
  entries: ArchiveEntryMetadata[],
  rootDir: string,
  maxCompressionRatio: number = 100,
): boolean => {
  for (const entry of entries) {
    if (!isPathSafe(rootDir, entry.path)) return false;
    if (entry.compressedSize > 0) {
      const ratio = entry.uncompressedSize / entry.compressedSize;
      if (ratio > maxCompressionRatio) return false;
    } else if (entry.uncompressedSize > 0) {
      return false;
    }
  }
  return true;
};
