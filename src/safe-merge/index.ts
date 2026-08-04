/**
 * Keys that can be used for prototype pollution attacks.
 */
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Checks if a value is a plain object.
 */
const isObject = (val: any): val is Record<string, any> => {
  return val !== null && typeof val === 'object' && !Array.isArray(val);
};

/**
 * Deep merges source into target securely, preventing:
 * 1. Prototype pollution (key filtering)
 * 2. Infinite loops (circular reference detection)
 *
 * @param target The target object to merge into.
 * @param source The source object to merge from.
 * @param seen WeakSet to track seen objects for circular reference detection.
 * @returns The merged object.
 */
export const merge = <T extends object, S extends object>(
  target: T,
  source: S,
  seen: WeakSet<object> = new WeakSet(),
): T & S => {
  if (seen.has(source)) {
    throw new Error(
      'Security Error: Circular reference detected during deep merge (DoS prevention).',
    );
  }

  const output = { ...target } as any;

  if (isObject(target) && isObject(source)) {
    seen.add(source);

    Object.keys(source).forEach((key) => {
      // Prevent prototype pollution
      if (DANGEROUS_KEYS.has(key)) {
        return;
      }

      const sourceValue = (source as any)[key];
      const targetValue = (target as any)[key];

      if (isObject(sourceValue) && isObject(targetValue)) {
        output[key] = merge(targetValue, sourceValue, seen);
      } else {
        output[key] = sourceValue;
      }
    });
  }

  return output;
};

/**
 * Recursively removes prototype-related keys from an object to sanitize untrusted input.
 */
export const sanitizeObject = <T>(obj: T, seen: WeakSet<object> = new WeakSet()): T => {
  if (obj === null || typeof obj !== 'object') return obj;

  if (seen.has(obj)) {
    throw new Error('Security Error: Circular reference detected during object sanitization.');
  }

  if (Array.isArray(obj)) {
    seen.add(obj);
    return obj.map((item) => sanitizeObject(item, seen)) as any;
  }

  seen.add(obj);
  const result: any = {};
  for (const [key, value] of Object.entries(obj)) {
    if (DANGEROUS_KEYS.has(key)) continue;
    result[key] = sanitizeObject(value, seen);
  }
  return result;
};

/**
 * Deep freezes an object to prevent any modifications.
 */
export const deepFreeze = <T extends object>(obj: T): T => {
  Object.getOwnPropertyNames(obj).forEach((name) => {
    const prop = (obj as any)[name];
    if (prop !== null && typeof prop === 'object') {
      deepFreeze(prop);
    }
  });
  return Object.freeze(obj);
};
