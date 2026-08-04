import { describe, it, expect, vi } from 'vitest';
import {
  expressMiddleware,
  nextJsMiddleware,
  expressErrorHandler,
  createSecureLogger,
  SecureLoggerChain,
  fastifyPlugin,
  NestJsMitigatorMiddleware,
} from './presets.js';
import { SecureError } from './index.js';

describe('Presets Module', () => {
  describe('expressMiddleware', () => {
    it('should set security headers', async () => {
      const req = {};
      const res = {
        setHeader: vi.fn(),
      };
      const next = vi.fn();

      const middleware = expressMiddleware();
      await middleware(req, res, next);

      expect(res.setHeader).toHaveBeenCalled();
      expect(next).toHaveBeenCalled();
      expect((req as any).mitigator).toBeDefined();
      expect((req as any).mitigator.sanitize('<p>Hello <b>World</b></p>')).toBe(
        '<p>Hello <b>World</b></p>',
      );
      expect((req as any).mitigator.safeJson('{"a": 1}')).toEqual({ a: 1 });
    });

    it('should rate limit if configured and threshold exceeded', async () => {
      const req = { ip: '127.0.0.1' };
      const res = {
        setHeader: vi.fn(),
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
      };
      const next = vi.fn();

      const middleware = expressMiddleware({
        rateLimit: true,
        rateLimitMax: 1,
        rateLimitWindowMs: 5000,
      });

      // First request passes
      await middleware(req, res, next);
      expect(next).toHaveBeenCalledTimes(1);

      // Second request is limited
      await middleware(req, res, next);
      expect(res.status).toHaveBeenCalledWith(429);
      expect(res.json).toHaveBeenCalledWith({ error: 'Too Many Requests' });
    });

    it('should block secret leakage in req.body', async () => {
      const req = {
        body: { token: 'ghp_123456789012345678901234567890123456' },
      };
      const res = {
        setHeader: vi.fn(),
      };
      const next = vi.fn();

      const middleware = expressMiddleware();
      await middleware(req, res, next);

      expect(next).toHaveBeenCalledWith(expect.any(SecureError));
    });

    it('should handle body parsing errors gracefully', async () => {
      const req = {
        get body() {
          throw new Error('parsing error');
        },
      };
      const res = {
        setHeader: vi.fn(),
      };
      const next = vi.fn();

      const middleware = expressMiddleware();
      await middleware(req, res, next);

      expect(next).toHaveBeenCalledWith(expect.any(SecureError));
    });
  });

  describe('nextJsMiddleware', () => {
    it('should set headers in response object', () => {
      const req = {};
      const res = {
        headers: {
          set: vi.fn(),
        },
      };

      const result = nextJsMiddleware(req, res);
      expect(res.headers.set).toHaveBeenCalled();
      expect(result).toBe(res);
    });
  });

  describe('expressErrorHandler', () => {
    it('should handle SecureError with BAD_INPUT', () => {
      const err = new SecureError('test', 'BAD_INPUT', 'bad input');
      const req = {};
      const res = {
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
      };
      const next = vi.fn();

      expressErrorHandler(err, req, res, next);
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(err.toJSON());
    });

    it('should handle generic errors', () => {
      const err = new Error('generic');
      const req = {};
      const res = {
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
      };
      const next = vi.fn();

      expressErrorHandler(err, req, res, next);
      expect(res.status).toHaveBeenCalledWith(500);
    });
  });

  describe('SecureLoggerChain', () => {
    it('should cryptographically chain logs', () => {
      const baseLogger = {
        info: vi.fn(),
        warn: vi.fn(),
        error: vi.fn(),
      };

      const logger = createSecureLogger(baseLogger);
      logger.info('test info', { meta: 'data' });
      expect(baseLogger.info).toHaveBeenCalledWith(
        expect.stringContaining('[CHAIN:'),
        expect.anything(),
      );

      logger.warn('test warn', { meta: 'data' });
      expect(baseLogger.warn).toHaveBeenCalledWith(
        expect.stringContaining('[CHAIN:'),
        expect.anything(),
      );

      logger.error('test error', new Error('fail'));
      expect(baseLogger.error).toHaveBeenCalledWith(
        expect.stringContaining('[CHAIN:'),
        expect.anything(),
      );
    });

    it('should block secret leakage in warnings', () => {
      const baseLogger = {
        info: vi.fn(),
        warn: vi.fn(),
        error: vi.fn(),
      };

      const logger = new SecureLoggerChain(baseLogger);
      logger.warn('test leak', { token: 'ghp_123456789012345678901234567890123456' });
      expect(baseLogger.warn).toHaveBeenCalledWith('CRITICAL: Secret leakage blocked!');
    });

    it('should allow normal warnings without secret leakage', () => {
      const baseLogger = {
        info: vi.fn(),
        warn: vi.fn(),
        error: vi.fn(),
      };

      const logger = new SecureLoggerChain(baseLogger);
      logger.warn('normal warn', { clean: 'data' });
      expect(baseLogger.warn).toHaveBeenCalledWith(expect.stringContaining('[CHAIN:'), {
        clean: 'data',
      });
    });
  });

  describe('fastifyPlugin', () => {
    it('should register hooks and set security headers', async () => {
      const hooks: Record<string, Function> = {};
      const mockFastify = {
        addHook: vi.fn((event, cb) => {
          hooks[event] = cb;
        }),
      };

      const plugin = fastifyPlugin({ rateLimit: true, rateLimitMax: 1 });
      await plugin(mockFastify);

      expect(mockFastify.addHook).toHaveBeenCalledWith('onRequest', expect.any(Function));
      expect(mockFastify.addHook).toHaveBeenCalledWith('preHandler', expect.any(Function));

      // Test onRequest hook sets headers
      const mockReq = { ip: '127.0.0.1' };
      const mockReply = {
        header: vi.fn(),
        code: vi.fn().mockReturnThis(),
        send: vi.fn(),
      };

      await hooks['onRequest'](mockReq, mockReply);
      expect(mockReply.header).toHaveBeenCalled();

      // Test rate limiting 429
      await hooks['onRequest'](mockReq, mockReply);
      expect(mockReply.code).toHaveBeenCalledWith(429);
      expect(mockReply.send).toHaveBeenCalledWith({ error: 'Too Many Requests' });
    });

    it('should block secret leakage in preHandler and allow clean requests', async () => {
      const hooks: Record<string, Function> = {};
      const mockFastify = {
        addHook: vi.fn((event, cb) => {
          hooks[event] = cb;
        }),
      };

      const plugin = fastifyPlugin();
      await plugin(mockFastify);

      const mockReq = {
        body: { token: 'ghp_123456789012345678901234567890123456' },
        mitigator: undefined,
      };
      const mockReply = {
        code: vi.fn().mockReturnThis(),
        send: vi.fn(),
      };

      // Case 1: Secret leak in body
      await hooks['preHandler'](mockReq, mockReply);
      expect(mockReply.code).toHaveBeenCalledWith(400);

      // Case 2: Clean request
      const mockCleanReq = { body: { clean: 'data' } } as any;
      await hooks['preHandler'](mockCleanReq, mockReply);
      expect(mockCleanReq.mitigator).toBeDefined();
      expect(mockCleanReq.mitigator.sanitize('<p>xss</p>')).toBe('<p>xss</p>');
      expect(mockCleanReq.mitigator.safeJson('{"a":1}')).toEqual({ a: 1 });
    });
  });

  describe('NestJsMitigatorMiddleware', () => {
    it('should set headers and allow safe next calls', async () => {
      NestJsMitigatorMiddleware.configure({ rateLimit: true, rateLimitMax: 1 });
      const middleware = new NestJsMitigatorMiddleware();

      const mockReq = { ip: '127.0.0.1', body: { a: 1 }, mitigator: undefined } as any;
      const mockRes = {
        setHeader: vi.fn(),
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
      } as any;
      const next = vi.fn();

      // First call passes
      await middleware.use(mockReq, mockRes, next);
      expect(mockRes.setHeader).toHaveBeenCalled();
      expect(next).toHaveBeenCalledTimes(1);
      expect(mockReq.mitigator).toBeDefined();
      expect(mockReq.mitigator.sanitize('<p>xss</p>')).toBe('<p>xss</p>');
      expect(mockReq.mitigator.safeJson('{"a":1}')).toEqual({ a: 1 });

      // Second call limits 429
      await middleware.use(mockReq, mockRes, next);
      expect(mockRes.status).toHaveBeenCalledWith(429);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Too Many Requests' });
    });

    it('should reject with 400 for secret leakage or body errors', async () => {
      NestJsMitigatorMiddleware.configure({ rateLimit: false });
      const middleware = new NestJsMitigatorMiddleware();

      const mockReq = {
        body: { token: 'ghp_123456789012345678901234567890123456' },
      } as any;
      const mockRes = {
        setHeader: vi.fn(),
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
      } as any;
      const next = vi.fn();

      await middleware.use(mockReq, mockRes, next);
      expect(mockRes.status).toHaveBeenCalledWith(400);

      // Trigger error in body access
      const mockErrReq = {
        get body() {
          throw new Error('parsing error');
        },
      } as any;
      await middleware.use(mockErrReq, mockRes, next);
      expect(mockRes.status).toHaveBeenCalledWith(400);
    });

    it('should configure with default values and handle missing body and various IP sources', async () => {
      NestJsMitigatorMiddleware.configure({ rateLimit: true });
      const middleware = new NestJsMitigatorMiddleware();

      const mockReq = {
        connection: { remoteAddress: '192.168.1.1' },
        mitigator: undefined,
      } as any;
      const mockRes = {
        setHeader: vi.fn(),
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
      } as any;
      const next = vi.fn();

      await middleware.use(mockReq, mockRes, next);
      expect(next).toHaveBeenCalled();

      // Test with totally missing IP
      const mockReqNoIp = {
        mitigator: undefined,
      } as any;
      await middleware.use(mockReqNoIp, mockRes, next);
      expect(next).toHaveBeenCalled();
    });
  });
});
