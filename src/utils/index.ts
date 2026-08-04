import { createHash } from 'node:crypto';

/**
 * Common sensitive keys for redaction.
 */
export const SENSITIVE_KEYS = new Set([
  'password',
  'token',
  'secret',
  'key',
  'authorization',
  'apiKey',
  'access_token',
  'refresh_token',
  'cvv',
  'card_number',
  'ssn',
]);

/**
 * Redacts sensitive keys.
 */
export const redact = <T>(obj: T, redactKeys: Set<string> = SENSITIVE_KEYS): T => {
  if (obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map((item) => redact(item, redactKeys)) as any;
  const result: any = {};
  for (const [key, value] of Object.entries(obj)) {
    if (redactKeys.has(key.toLowerCase())) {
      result[key] = '[REDACTED]';
    } else if (typeof value === 'object') {
      result[key] = redact(value, redactKeys);
    } else {
      result[key] = value;
    }
  }
  return result;
};

/**
 * SecureError wrapper.
 */
export class SecureError extends Error {
  public readonly code: string;
  public readonly userMessage: string;
  constructor(
    message: string,
    code: string = 'INTERNAL_ERROR',
    userMessage: string = 'An unexpected error occurred.',
  ) {
    super(message);
    this.name = 'SecureError';
    this.code = code;
    this.userMessage = userMessage;
    if (process.env.NODE_ENV === 'production') this.stack = '';
  }
  toJSON() {
    return { error: true, code: this.code, message: this.userMessage };
  }
}

/**
 * Normalizes an error.
 */
export const normalizeError = (error: any): SecureError => {
  if (error instanceof SecureError) return error;
  return new SecureError(error?.message || 'Unknown error');
};

/**
 * Memory-Wiping (Anti-Forensics) utility.
 * Explicitly overwrites the content of a Buffer or Uint8Array with zero bytes.
 * This is the ultimate "last step" for protecting high-entropy key material.
 *
 * @param buf The Buffer or Uint8Array to zero-out.
 */
export const wipeBuffer = (buf: Buffer | Uint8Array | any[]): void => {
  if (Array.isArray(buf)) {
    for (let i = 0; i < buf.length; i++) buf[i] = 0;
  } else if (buf instanceof Buffer || buf instanceof Uint8Array) {
    buf.fill(0);
  }
};

/**
 * Minimal logger interface for dependency injection.
 * Any object with `error` and `warn` methods satisfies this —
 * e.g. `console`, `winston`, `pino`, or a custom OTEL-aware logger.
 */
export interface MinimalLogger {
  error(message: string, ...args: unknown[]): void;
  warn(message: string, ...args: unknown[]): void;
}

/**
 * Self-healing configuration monitor.
 *
 * Runs `auditConfig` on the supplied configuration at a fixed interval and
 * logs any detected drift through the provided `logger`.
 *
 * @param config  The configuration object to audit.
 * @param type    The configuration type ('db' | 'redis' | 'auth').
 * @param intervalMs  How often to run the audit (default: 10 minutes).
 * @param logger  Optional logger to receive drift alerts. Defaults to `console`.
 *                Inject a structured logger (Winston, Pino, OTEL) for production.
 *
 * @example
 * // Default — uses console
 * startSelfHealingMonitor(dbConfig, 'db');
 *
 * // Production — inject your logger
 * startSelfHealingMonitor(dbConfig, 'db', 600_000, pinoLogger);
 */
export const startSelfHealingMonitor = (
  config: Parameters<typeof auditConfig>[0],
  type: Parameters<typeof auditConfig>[1],
  intervalMs: number = 600000,
  logger: MinimalLogger = console,
): void => {
  setInterval(() => {
    const issues = auditConfig(config, type);
    if (issues.length > 0) {
      logger.error('MITIGATOR CRITICAL: Self-healing monitor detected insecure config drift!');
      issues.forEach((issue) => logger.error(`- ${issue}`));
    }
  }, intervalMs).unref();
};

/**
 * SQL Injection Hardening.
 */
export const enforceSafeQuery = (query: string, params: any[]): void => {
  if ((!params || params.length === 0) && query.toLowerCase().includes('where')) {
    const suspicious = ["'", '"', '=', '--', ';'];
    if (suspicious.some((char) => query.includes(char))) {
      throw new SecureError(
        'Security Violation: Unparameterized query detected.',
        'SQL_INJECTION_RISK',
      );
    }
  }
};

/**
 * Deterministic digit substitution using SHA-256 offset encoding.
 *
 * @remarks
 * **This is NOT Format-Preserving Encryption (FPE).**
 * It does NOT implement NIST SP 800-38G (FF1/FF3-1). It is a lightweight,
 * deterministic digit-level obfuscation function suitable for display masking
 * and non-compliance-grade transformations only.
 *
 * Do NOT use this for PCI-DSS, HIPAA, or any standard requiring certified FPE.
 *
 * @param input A string of decimal digit characters (0–9) to transform.
 * @param secret A secret key string used to derive the substitution offsets.
 * @returns A digit-length-preserving transformed string.
 */
export const deterministicDigitTransform = (input: string, secret: string): string => {
  const hash = createHash('sha256').update(input).update(secret).digest('hex');
  let result = '';
  for (let i = 0; i < input.length; i++) {
    const digit = Number.parseInt(input[i]);
    const offset = Number.parseInt(hash[i % hash.length], 16);
    result += ((digit + offset) % 10).toString();
  }
  return result;
};

/**
 * Environment security check.
 */
export const checkSecureEnv = (): void => {
  const isProd = process.env.NODE_ENV === 'production';
  if (isProd) {
    if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
      console.warn('Security Warning: SESSION_SECRET is missing or too short.');
    }
  }
};

/**
 * Configuration Auditor.
 */
export const auditConfig = (config: any, type: 'db' | 'redis' | 'auth'): string[] => {
  const issues: string[] = [];
  if (type === 'db') {
    if (config.ssl === false) issues.push('Database SSL is disabled.');
    if (config.port === 3306 || config.port === 5432)
      issues.push('Database is using a default port.');
  } else if (type === 'auth') {
    if (config.allowInsecurePasswordReset) issues.push('Allowing insecure password reset.');
  }
  return issues;
};

/**
 * Global prototype lockdown.
 */
export const lockdownPrototypes = (): void => {
  try {
    Object.freeze(Object.prototype);
    Object.freeze(Array.prototype);
    Object.freeze(String.prototype);
  } catch {
    console.error('Mitigator Error: Failed to lockdown prototypes.');
  }
};

/**
 * mTLS Helper.
 */
export const createMTLSOptions = (serverCert: Buffer, serverKey: Buffer, caCert: Buffer) => {
  return {
    cert: serverCert,
    key: serverKey,
    ca: caCert,
    requestCert: true,
    rejectUnauthorized: true,
  };
};

/**
 * Security preset.
 */
export const standardSecurityPreset = {
  trustProxy: true,
  strictTransportSecurity: { maxAge: 31536000, includeSubDomains: true, preload: true },
  contentSecurityPolicy: true,
  referrerPolicy: 'strict-origin-when-cross-origin' as const,
};
