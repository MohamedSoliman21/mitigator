import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { MemoryStore, RateLimiter, TokenBucket, AdaptiveRateLimiter, RedisStore } from './index.js';

describe('Rate Limiting Module', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('MemoryStore', () => {
    it('should increment and return count', async () => {
      const store = new MemoryStore(1000);
      expect(await store.increment('test')).toBe(1);
      expect(await store.increment('test')).toBe(2);
      store.destroy();
    });

    it('should call unref on gcInterval if present', async () => {
      vi.useRealTimers();
      const store = new MemoryStore(1000);
      store.destroy();
      vi.useFakeTimers();
    });

    it('should expire hits after windowMs', async () => {
      const store = new MemoryStore(1000);
      await store.increment('test');
      vi.advanceTimersByTime(1100);
      expect(await store.increment('test')).toBe(1);
      store.destroy();
    });

    it('should garbage collect expired hits', async () => {
      const store = new MemoryStore(1000);
      await store.increment('expire-me');
      vi.advanceTimersByTime(65000);
      expect(await store.get('expire-me')).toBeUndefined();
      store.destroy();
    });

    it('should reset hits on a key', async () => {
      const store = new MemoryStore(1000);
      await store.increment('reset-me');
      await store.reset('reset-me');
      expect(await store.get('reset-me')).toBeUndefined();
      store.destroy();
    });
  });

  describe('RedisStore', () => {
    it('should correctly increment, get, reset and setTTL', async () => {
      const mockMulti = {
        incrby: vi.fn().mockReturnThis(),
        pttl: vi.fn().mockReturnThis(),
        exec: vi.fn().mockResolvedValue([
          [null, '5'],
          [null, '1000'],
        ]),
      };
      const mockRedisClient = {
        multi: vi.fn().mockReturnValue(mockMulti),
        get: vi.fn().mockResolvedValue('10'),
        del: vi.fn().mockResolvedValue(1),
        set: vi.fn().mockResolvedValue('OK'),
        pexpire: vi.fn().mockResolvedValue(1),
      };

      const store = new RedisStore(mockRedisClient, 1000);

      expect(await store.increment('test-key')).toBe(5);
      expect(mockRedisClient.multi).toHaveBeenCalled();
      expect(mockMulti.incrby).toHaveBeenCalledWith('rl:test-key', 1);

      expect(await store.get('test-key')).toBe(10);
      expect(mockRedisClient.get).toHaveBeenCalledWith('rl:test-key');

      await store.reset('test-key');
      expect(mockRedisClient.del).toHaveBeenCalledWith('rl:test-key');

      await store.setTTL('test-key', 42, 5000);
      expect(mockRedisClient.set).toHaveBeenCalledWith('rl:test-key', 42, 'PX', 5000);
    });

    it('should set pexpire if ttl is -1', async () => {
      const mockMulti = {
        incrby: vi.fn().mockReturnThis(),
        pttl: vi.fn().mockReturnThis(),
        exec: vi.fn().mockResolvedValue([
          [null, '5'],
          [null, '-1'],
        ]),
      };
      const mockRedisClient = {
        multi: vi.fn().mockReturnValue(mockMulti),
        pexpire: vi.fn().mockResolvedValue(1),
      };
      const store = new RedisStore(mockRedisClient, 1000);
      expect(await store.increment('test-key')).toBe(5);
      expect(mockRedisClient.pexpire).toHaveBeenCalledWith('rl:test-key', 1000);
    });

    it('should return undefined if get returns null', async () => {
      const mockRedisClient = {
        get: vi.fn().mockResolvedValue(null),
      };
      const store = new RedisStore(mockRedisClient, 1000);
      expect(await store.get('k')).toBeUndefined();
    });
  });

  describe('RateLimiter', () => {
    it('should allow requests within limit', async () => {
      const limiter = new RateLimiter(2, 1000);
      expect(await limiter.isLimited('user1')).toBe(false);
      expect(await limiter.isLimited('user1')).toBe(false);
      expect(await limiter.isLimited('user1')).toBe(true);
    });

    it('should reset limit after windowMs', async () => {
      const limiter = new RateLimiter(1, 1000);
      await limiter.isLimited('user1');
      expect(await limiter.isLimited('user1')).toBe(true);
      vi.advanceTimersByTime(1100);
      expect(await limiter.isLimited('user1')).toBe(false);
    });
  });

  describe('TokenBucket', () => {
    it('should refill tokens over time', async () => {
      const bucket = new TokenBucket(5, 1); // 5 capacity, 1 token/sec

      // Consume all
      for (let i = 0; i < 5; i++) {
        expect(await bucket.consume('a')).toBe(true);
      }
      expect(await bucket.consume('a')).toBe(false);

      // Wait 1 second -> 1 token
      vi.advanceTimersByTime(1000);
      expect(await bucket.consume('a')).toBe(true);
      expect(await bucket.consume('a')).toBe(false);
    });

    it('should return false if requested tokens exceeds capacity', async () => {
      const bucket = new TokenBucket(5, 1);
      expect(await bucket.consume('a', 10)).toBe(false);
    });
  });

  describe('AdaptiveRateLimiter', () => {
    it('should apply penalty limit for high risk users', async () => {
      const limiter = new AdaptiveRateLimiter({
        standardLimit: 5,
        penaltyLimit: 2,
        windowMs: 1000,
        securityThreshold: 3,
        burstThreshold: 10,
      });

      // Normal user
      for (let i = 0; i < 5; i++) {
        expect(await limiter.isLimited('normal')).toBe(false);
      }
      expect(await limiter.isLimited('normal')).toBe(true);

      // High risk user (due to security events)
      await limiter.recordSecurityEvent('attacker', 4);
      expect(await limiter.isHighRisk('attacker')).toBe(true);

      expect(await limiter.isLimited('attacker')).toBe(false);
      expect(await limiter.isLimited('attacker')).toBe(false);
      expect(await limiter.isLimited('attacker')).toBe(true); // Limited at 2 instead of 5
    });

    it('should trigger global kill switch', async () => {
      const limiter = new AdaptiveRateLimiter({
        standardLimit: 5,
        penaltyLimit: 2,
        windowMs: 1000,
        securityThreshold: 3,
        burstThreshold: 10,
      });

      await limiter.triggerGlobalKillSwitch('banned-user');
      expect(await limiter.isLimited('banned-user')).toBe(true);
      expect(await limiter.isHighRisk('banned-user')).toBe(true);
    });

    it('should evaluate isHighRisk correctly for various conditions', async () => {
      const limiter = new AdaptiveRateLimiter({
        standardLimit: 5,
        penaltyLimit: 2,
        windowMs: 1000,
        securityThreshold: 3,
        burstThreshold: 2,
      });

      // 1. Low risk
      expect(await limiter.isHighRisk('user-safe')).toBe(false);

      // 2. High security score
      await limiter.recordSecurityEvent('user-risk', 4);
      expect(await limiter.isHighRisk('user-risk')).toBe(true);

      // 3. High bursts
      const burstStore = (limiter as any).burstStore;
      await burstStore.increment('user-burst:bursts', 3);
      expect(await limiter.isHighRisk('user-burst')).toBe(true);
    });

    it('should register IP checkers and limit requests if checker returns true', async () => {
      const limiter = new AdaptiveRateLimiter({
        standardLimit: 5,
        penaltyLimit: 2,
        windowMs: 1000,
        securityThreshold: 3,
        burstThreshold: 10,
      });

      limiter.registerIPChecker(async (ip) => ip === '1.2.3.4');

      expect(await limiter.isLimited('1.2.3.4')).toBe(true);
      expect(await limiter.isLimited('5.6.7.8')).toBe(false);
    });
  });
});
