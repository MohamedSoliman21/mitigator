import { createHash } from 'node:crypto';
import { SecureError, redact } from './index.js';
import * as headers from '../headers/index.js';
import * as sanitize from '../sanitize/index.js';
import * as safeJson from '../safe-json/index.js';
import * as validate from '../validate/index.js';

import { RateLimiter, MemoryStore } from '../rate-limit/index.js';

export interface ExpressRequestLike {
  ip?: string;
  connection?: { remoteAddress?: string };
  body?: unknown;
  mitigator?: {
    sanitize: (html: string) => string;
    safeJson: <T = unknown>(text: string) => T;
  };
}

export interface ExpressResponseLike {
  setHeader(name: string, value: string): void;
  status(code: number): {
    json(body: unknown): void;
  };
}

export type ExpressNextFunction = (err?: unknown) => void;

export interface NextJsResponseLike {
  headers: {
    set(name: string, value: string): void;
  };
}

export interface BaseLoggerLike {
  info: (message: string, ...args: unknown[]) => void;
  error: (message: string, ...args: unknown[]) => void;
  warn: (message: string, ...args: unknown[]) => void;
}

export interface FastifyRequestLike {
  ip?: string;
  body?: unknown;
  mitigator?: {
    sanitize: (html: string) => string;
    safeJson: <T = unknown>(text: string) => T;
  };
}

export interface FastifyReplyLike {
  header(name: string, value: string): FastifyReplyLike;
  code(statusCode: number): {
    send(payload: unknown): FastifyReplyLike;
  };
}

export interface FastifyInstanceLike {
  addHook(
    name: 'onRequest' | 'preHandler',
    hook: (req: FastifyRequestLike, reply: FastifyReplyLike) => Promise<unknown> | void,
  ): void;
}

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

  return async (req: ExpressRequestLike, res: ExpressResponseLike, next: ExpressNextFunction) => {
    Object.entries(headers.standardHeaders).forEach(([key, value]) => {
      res.setHeader(key, value);
    });

    if (limiter) {
      const ip = req.ip || req.connection?.remoteAddress || 'unknown';
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
export const nextJsMiddleware = (_req: unknown, res: NextJsResponseLike) => {
  Object.entries(headers.standardHeaders).forEach(([key, value]) => {
    res.headers.set(key, value);
  });
  return res;
};

/**
 * Global response error handler for Express.
 */
export const expressErrorHandler = (
  err: unknown,
  _req: ExpressRequestLike,
  res: ExpressResponseLike,
  _next: ExpressNextFunction,
) => {
  const secureErr =
    err instanceof SecureError
      ? err
      : new SecureError(err instanceof Error ? err.message : String(err));
  res.status(secureErr.code === 'BAD_INPUT' ? 400 : 500).json(secureErr.toJSON());
};

/**
 * Secure Logger with Cryptographic Hash-Chain (Tamper-Proof Logs).
 * Every entry is linked to the previous one via a SHA-256 hash, making it
 * mathematically detectable if an attacker deletes or modifies log entries.
 */
export class SecureLoggerChain {
  private lastHash: string = '';

  constructor(private readonly baseLogger: BaseLoggerLike) {
    // Initialize with a unique "seed" hash
    this.lastHash = createHash('sha256').update(Date.now().toString()).digest('hex');
  }

  private chain(msg: string, data: unknown): string {
    const payload = JSON.stringify({ msg, data, prev: this.lastHash });
    this.lastHash = createHash('sha256').update(payload).digest('hex');
    return this.lastHash;
  }

  info(msg: string, data?: unknown) {
    const hash = this.chain(msg, data);
    this.baseLogger.info(`[CHAIN:${hash}] ${msg}`, redact(data));
  }

  warn(msg: string, data?: unknown) {
    if (validate.scanForSecrets(data)) {
      this.baseLogger.warn('CRITICAL: Secret leakage blocked!');
      return;
    }
    const hash = this.chain(msg, data);
    this.baseLogger.warn(`[CHAIN:${hash}] ${msg}`, redact(data));
  }

  error(msg: string, err?: unknown) {
    const secureErr =
      err instanceof SecureError
        ? err
        : new SecureError(err instanceof Error ? err.message : String(err || 'Error'));
    const hash = this.chain(msg, secureErr.toJSON());
    this.baseLogger.error(`[CHAIN:${hash}] ${msg}`, redact(secureErr.toJSON()));
  }
}

/**
 * Convenience logger creator.
 */
export const createSecureLogger = (baseLogger: BaseLoggerLike) => new SecureLoggerChain(baseLogger);

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

  return async (fastify: FastifyInstanceLike) => {
    fastify.addHook('onRequest', async (req: FastifyRequestLike, reply: FastifyReplyLike) => {
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

    fastify.addHook('preHandler', async (req: FastifyRequestLike, reply: FastifyReplyLike) => {
      try {
        if (req.body && typeof req.body === 'object') {
          if (validate.scanForSecrets(req.body)) {
            throw new SecureError(
              'Security Violation: Potential secret leakage detected.',
              'BAD_INPUT',
            );
          }
        }
      } catch (err: unknown) {
        const secureErr =
          err instanceof SecureError
            ? err
            : new SecureError(err instanceof Error ? err.message : String(err), 'BAD_INPUT');
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

  async use(req: ExpressRequestLike, res: ExpressResponseLike, next: () => void) {
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
    } catch (err: unknown) {
      const secureErr =
        err instanceof SecureError
          ? err
          : new SecureError(err instanceof Error ? err.message : String(err), 'BAD_INPUT');
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
