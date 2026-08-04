import { createHash } from 'node:crypto';
import { SecureError, redact } from './index.js';
import * as headers from '../headers/index.js';
import * as sanitize from '../sanitize/index.js';
import * as safeJson from '../safe-json/index.js';
import * as validate from '../validate/index.js';

import { RateLimiter, MemoryStore } from '../rate-limit/index.js';

/**
 * A lightweight Express middleware preset.
 */
export const expressMiddleware = (
  options: { rateLimit?: boolean; rateLimitWindowMs?: number; rateLimitMax?: number } = {},
) => {
  const limiter = options.rateLimit
    ? new RateLimiter(
        options.rateLimitMax || 100,
        options.rateLimitWindowMs || 60000,
        new MemoryStore(options.rateLimitWindowMs || 60000),
      )
    : null;

  return async (req: any, res: any, next: any) => {
    Object.entries(headers.standardHeaders).forEach(([key, value]) => {
      res.setHeader(key, value);
    });

    if (limiter) {
      const ip = req.ip || req.connection.remoteAddress || 'unknown';
      if (await limiter.isLimited(ip)) {
        return res.status(429).json({ error: 'Too Many Requests' });
      }
    }

    try {
      if (req.body && typeof req.body === 'object') {
        if (validate.scanForSecrets(req.body)) {
          return next(
            new SecureError('Security Violation: Potential secret leakage detected.', 'BAD_INPUT'),
          );
        }
      }
    } catch {
      return next(new SecureError('Security Violation: Suspicious input detected.', 'BAD_INPUT'));
    }
    req.mitigator = {
      sanitize: (html: string) => sanitize.sanitizeHtml(html),
      safeJson: (text: string) => safeJson.parse(text),
    };
    next();
  };
};

/**
 * Next.js Edge Middleware Preset.
 * Note: Next.js edge runtime doesn't support all Node APIs, so we keep it lightweight.
 */
export const nextJsMiddleware = (_req: any, res: any) => {
  Object.entries(headers.standardHeaders).forEach(([key, value]) => {
    res.headers.set(key, value);
  });
  return res;
};

/**
 * Global response error handler for Express.
 */
export const expressErrorHandler = (err: any, _req: any, res: any, _next: any) => {
  const secureErr = err instanceof SecureError ? err : new SecureError(err.message);
  res.status(secureErr.code === 'BAD_INPUT' ? 400 : 500).json(secureErr.toJSON());
};

/**
 * Secure Logger with Cryptographic Hash-Chain (Tamper-Proof Logs).
 * Every entry is linked to the previous one via a SHA-256 hash, making it
 * mathematically detectable if an attacker deletes or modifies log entries.
 */
export class SecureLoggerChain {
  private lastHash: string = '';

  constructor(private readonly baseLogger: { info: Function; error: Function; warn: Function }) {
    // Initialize with a unique "seed" hash
    this.lastHash = createHash('sha256').update(Date.now().toString()).digest('hex');
  }

  private chain(msg: string, data: any): string {
    const payload = JSON.stringify({ msg, data, prev: this.lastHash });
    this.lastHash = createHash('sha256').update(payload).digest('hex');
    return this.lastHash;
  }

  info(msg: string, data?: any) {
    const hash = this.chain(msg, data);
    this.baseLogger.info(`[CHAIN:${hash}] ${msg}`, redact(data));
  }

  warn(msg: string, data?: any) {
    if (validate.scanForSecrets(data)) {
      this.baseLogger.warn('CRITICAL: Secret leakage blocked!');
      return;
    }
    const hash = this.chain(msg, data);
    this.baseLogger.warn(`[CHAIN:${hash}] ${msg}`, redact(data));
  }

  error(msg: string, err?: any) {
    const secureErr = err instanceof SecureError ? err : new SecureError(err?.message || 'Error');
    const hash = this.chain(msg, secureErr.toJSON());
    this.baseLogger.error(`[CHAIN:${hash}] ${msg}`, redact(secureErr.toJSON()));
  }
}

/**
 * Convenience logger creator.
 */
export const createSecureLogger = (baseLogger: any) => new SecureLoggerChain(baseLogger);

/**
 * Fastify Plugin Preset.
 * Fastify hooks to inject secure headers, rate limiter, and scan inputs.
 */
export const fastifyPlugin = (
  options: { rateLimit?: boolean; rateLimitWindowMs?: number; rateLimitMax?: number } = {},
) => {
  const limiter = options.rateLimit
    ? new RateLimiter(
        options.rateLimitMax || 100,
        options.rateLimitWindowMs || 60000,
        new MemoryStore(options.rateLimitWindowMs || 60000),
      )
    : null;

  return async (fastify: any) => {
    fastify.addHook('onRequest', async (req: any, reply: any) => {
      Object.entries(headers.standardHeaders).forEach(([key, value]) => {
        reply.header(key, value);
      });

      if (limiter) {
        const ip = req.ip || 'unknown';
        if (await limiter.isLimited(ip)) {
          reply.code(429).send({ error: 'Too Many Requests' });
          return reply;
        }
      }
    });

    fastify.addHook('preHandler', async (req: any, reply: any) => {
      try {
        if (req.body && typeof req.body === 'object') {
          if (validate.scanForSecrets(req.body)) {
            throw new SecureError(
              'Security Violation: Potential secret leakage detected.',
              'BAD_INPUT',
            );
          }
        }
      } catch (err: any) {
        const secureErr =
          err instanceof SecureError ? err : new SecureError(err.message, 'BAD_INPUT');
        reply.code(400).send(secureErr.toJSON());
        return reply;
      }

      req.mitigator = {
        sanitize: (html: string) => sanitize.sanitizeHtml(html),
        safeJson: (text: string) => safeJson.parse(text),
      };
    });
  };
};

/**
 * NestJS Guard / Middleware class creator.
 * Dynamic NestJS Middleware to apply Mitigator protections.
 */
export class NestJsMitigatorMiddleware {
  private static limiter: RateLimiter | null = null;

  static configure(
    options: { rateLimit?: boolean; rateLimitWindowMs?: number; rateLimitMax?: number } = {},
  ) {
    if (options.rateLimit) {
      this.limiter = new RateLimiter(
        options.rateLimitMax || 100,
        options.rateLimitWindowMs || 60000,
        new MemoryStore(options.rateLimitWindowMs || 60000),
      );
    }
  }

  async use(req: any, res: any, next: () => void) {
    Object.entries(headers.standardHeaders).forEach(([key, value]) => {
      res.setHeader(key, value);
    });

    if (NestJsMitigatorMiddleware.limiter) {
      const ip = req.ip || req.connection?.remoteAddress || 'unknown';
      if (await NestJsMitigatorMiddleware.limiter.isLimited(ip)) {
        res.status(429).json({ error: 'Too Many Requests' });
        return;
      }
    }

    try {
      if (req.body && typeof req.body === 'object') {
        if (validate.scanForSecrets(req.body)) {
          throw new SecureError(
            'Security Violation: Potential secret leakage detected.',
            'BAD_INPUT',
          );
        }
      }
    } catch (err: any) {
      const secureErr =
        err instanceof SecureError ? err : new SecureError(err.message, 'BAD_INPUT');
      res.status(400).json(secureErr.toJSON());
      return;
    }

    req.mitigator = {
      sanitize: (html: string) => sanitize.sanitizeHtml(html),
      safeJson: (text: string) => safeJson.parse(text),
    };
    next();
  }
}
