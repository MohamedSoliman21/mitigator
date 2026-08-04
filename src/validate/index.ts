import { createHash } from 'node:crypto';
import * as https from 'node:https';

/**
 * Result returned by `checkPwnedPassword`.
 * Always resolves (never rejects) to preserve fail-open availability semantics.
 */
export interface CheckPwnedResult {
  /** Number of times this password appeared in known data breaches. 0 if not found. */
  count: number;
  /**
   * Whether the HIBP API was reachable during this check.
   * If `false`, the result is inconclusive — the password may or may not be compromised.
   * Callers should treat `apiAvailable: false` as a signal to retry or log a warning.
   */
  apiAvailable: boolean;
}

/**
 * Checks if a password has been leaked in a data breach using the Have I Been Pwned (HIBP) API.
 * Uses k-Anonymity (sending only the first 5 characters of the SHA-1 hash) to ensure
 * the password is never exposed to the API.
 *
 * Always resolves — never rejects. If the API is unreachable, `apiAvailable` will be `false`
 * and `count` will be `0` (inconclusive). Callers should check `apiAvailable` before
 * treating a zero count as "password is clean".
 *
 * @param password The password to check.
 * @returns {Promise<CheckPwnedResult>} Structured result with breach count and API availability.
 *
 * @example
 * const { count, apiAvailable } = await checkPwnedPassword('hunter2');
 * if (!apiAvailable) logger.warn('HIBP API unreachable — skipping pwned check');
 * else if (count > 0) throw new Error('Password found in data breaches');
 */
export const checkPwnedPassword = (password: string): Promise<CheckPwnedResult> => {
  return new Promise((resolve) => {
    const hash = createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    https
      .get(`https://api.pwnedpasswords.com/range/${prefix}`, (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          const lines = data.split('\n');
          for (const line of lines) {
            const [hashSuffix, count] = line.split(':');
            if (hashSuffix === suffix) {
              return resolve({ count: Number.parseInt(count.trim()), apiAvailable: true });
            }
          }
          resolve({ count: 0, apiAvailable: true });
        });
      })
      .on('error', (err) => {
        // Fail-open: don't block authentication when HIBP is unreachable.
        // apiAvailable: false lets the caller decide how to handle the degraded state.
        console.error('Mitigator: HIBP API connection error.', err);
        resolve({ count: 0, apiAvailable: false });
      });
  });
};

/**
 * Patterns for secrets.
 */
export const SECRET_PATTERNS = [
  /AKIA[0-9A-Z]{16}/,
  /-----BEGIN (RSA|OPENSSH|EC|PGP) PRIVATE KEY-----/,
  /ghp_[a-zA-Z0-9]{36}/,
  /sk_live_[a-zA-Z0-9]{24}/,
];

/**
 * Scans for secrets.
 */
export const scanForSecrets = (input: any): boolean => {
  if (typeof input === 'string') {
    return SECRET_PATTERNS.some((pattern) => pattern.test(input));
  }
  if (typeof input === 'object' && input !== null) {
    return Object.values(input).some(scanForSecrets);
  }
  return false;
};

/**
 * Weak password check.
 */
export const isWeakPassword = (password: string): boolean => {
  if (password.length < 8) return true;
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSpecial = /[^a-zA-Z0-9]/.test(password);
  const types = [hasLower, hasUpper, hasNumber, hasSpecial].filter(Boolean).length;
  if (types < 2) return true;
  const common = ['password', '123456', 'qwerty', 'admin123', 'password123', '12345678'];
  if (common.includes(password.toLowerCase())) return true;
  return false;
};

/**
 * Schema types.
 */
export type Schema = {
  [key: string]: 'string' | 'number' | 'boolean' | 'object' | 'array';
};

/**
 * Type validation.
 */
export const isType = (val: any, type: Schema[keyof Schema]): boolean => {
  if (type === 'array') return Array.isArray(val);
  return typeof val === type && val !== null;
};

/**
 * Schema enforcement.
 */
export const enforceSchema = <T extends Record<string, any>>(
  data: any,
  schema: Schema,
): T | null => {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) return null;
  const result: any = {};
  for (const key of Object.keys(schema)) {
    const expectedType = schema[key];
    const value = data[key];
    if (value === undefined || !isType(value, expectedType)) return null;
    result[key] = value;
  }
  return result;
};

/**
 * Email validation.
 */
export const isEmail = (input: string): boolean => {
  return /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(
    input,
  );
};

/**
 * Injection pattern detection (Heuristic).
 * Detects common SQL, NoSQL, and Command Injection payloads.
 */
export const hasInjectionPattern = (input: string): boolean => {
  if (typeof input !== 'string') return false;

  const dangerousPatterns = [
    // SQL Injection
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|UNION|ALL|ANY|SOME)\b.*\b(FROM|INTO|SET|TABLE|DATABASE)\b)/i,
    /'\s*OR\s+'?1'?\s*=\s*'?1/i,
    /"\s*OR\s+"?1"?\s*=\s*"?1/i,
    /--\s*$/,
    /;\s*(WAITFOR|DELAY|SLEEP)/i,
    /;\s*(EXEC|EXECUTE)\b/i,
    // NoSQL Injection
    /\$(where|gt|lt|gte|lte|ne|in|nin|regex|expr|eq)/i,
    /\{\s*\$ne\s*:/i,
    // Command Injection
    /(;|\||&&|\|\||`|\$)\s*(cat|ls|pwd|whoami|id|echo|bash|sh|ping|curl|wget)/i,
  ];
  return dangerousPatterns.some((pattern) => pattern.test(input));
};
