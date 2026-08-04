/**
 * Prototype pollution safe JSON parsing with depth limiting to prevent
 * "JSON Depth" or "Billion Laughs" style DoS attacks.
 */
export const parse = (text: string, maxDepth: number = 10): any => {
  const obj = JSON.parse(text, (key, value) => {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      return undefined;
    }
    return value;
  });

  if (getDepth(obj) > maxDepth) {
    throw new Error('Security Error: JSON depth limit exceeded (DoS protection).');
  }

  return obj;
};

/**
 * Calculates the maximum depth of an object to detect nested-complexity attacks.
 */
export const getDepth = (obj: any): number => {
  if (obj === null || typeof obj !== 'object') return 0;

  let max = 0;
  for (const key in obj) {
    if (Object.hasOwn(obj, key)) {
      max = Math.max(max, getDepth(obj[key]));
    }
  }
  return 1 + max;
};

/**
 * Recursively checks an object for prototype pollution keys.
 */
export const containsPollution = (obj: any): boolean => {
  if (obj === null || typeof obj !== 'object') return false;

  for (const key in obj) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      return true;
    }
    if (containsPollution(obj[key])) {
      return true;
    }
  }
  return false;
};
