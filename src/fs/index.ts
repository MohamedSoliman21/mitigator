import { resolve, relative, isAbsolute } from 'node:path';

/**
 * Standard Magic Numbers for common file types.
 */
export const MAGIC_NUMBERS = {
  PNG: [0x89, 0x50, 0x4e, 0x47],
  JPEG: [0xff, 0xd8, 0xff],
  PDF: [0x25, 0x50, 0x44, 0x46],
  GIF: [0x47, 0x49, 0x46, 0x38],
};

/**
 * Resolves a path relative to a root directory and ensures it doesn't escape the root.
 */
export const resolveSafePath = (rootDir: string, userInputPath: string): string => {
  const absoluteRoot = resolve(rootDir);
  const resolvedPath = resolve(absoluteRoot, userInputPath);

  const relativePath = relative(absoluteRoot, resolvedPath);

  if (relativePath.startsWith('..') || isAbsolute(relativePath)) {
    throw new Error('Security Error: Path traversal attempt detected.');
  }

  return resolvedPath;
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
