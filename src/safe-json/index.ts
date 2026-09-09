/**
 * Prototype pollution safe JSON parsing with depth limiting to prevent
 * "JSON Depth" or "Billion Laughs" style DoS attacks.
 */
export const parse = <T = unknown>(text: string, maxDepth: number = 10): T => {
  const obj = JSON.parse(text, (key, value) => {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      return undefined;
    }
    return value;
  });

  if (getDepth(obj) > maxDepth) {
    throw new Error('Security Error: JSON depth limit exceeded (DoS protection).');
  }

  return obj as T;
};

/**
 * Calculates the maximum depth of an object to detect nested-complexity attacks.
 */
export const getDepth = (obj: unknown): number => {
  if (obj === null || typeof obj !== 'object') return 0;

  const record = obj as Record<string, unknown>;
  let max = 0;
  for (const key in record) {
    if (Object.hasOwn(record, key)) {
      max = Math.max(max, getDepth(record[key]));
    }
  }
  return 1 + max;
};

/**
 * Recursively checks an object for prototype pollution keys.
 */
export const containsPollution = (obj: unknown): boolean => {
  if (obj === null || typeof obj !== 'object') return false;

  const record = obj as Record<string, unknown>;
  for (const key in record) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      return true;
    }
    if (containsPollution(record[key])) {
      return true;
    }
  }
  return false;
};
