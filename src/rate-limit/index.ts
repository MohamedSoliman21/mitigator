import { getTelemetryProvider } from '../utils/telemetry.js';

/**
 * A simple in-memory Store for the rate limiter.
 */
export interface RateLimitStore {
  increment(key: string, amount?: number): Promise<number>;
  get(key: string): Promise<number | undefined>;
  reset(key: string): Promise<void>;
  setTTL(key: string, value: number, ttlMs: number): Promise<void>;
}

export class MemoryStore implements RateLimitStore {
  private readonly hits = new Map<string, { count: number; expires: number }>();
  private readonly gcInterval: NodeJS.Timeout;

  constructor(private readonly windowMs: number) {
    // Run Garbage Collection every minute
    this.gcInterval = setInterval(() => this.gc(), 60000);
    // Ensure the timer doesn't keep the Node.js event loop alive
    /* v8 ignore next 3 */
    if (this.gcInterval.unref) {
      this.gcInterval.unref();
    }
  }

  private gc() {
    const now = Date.now();
    for (const [key, hit] of this.hits.entries()) {
      if (now > hit.expires) {
        this.hits.delete(key);
      }
    }
  }

  async increment(key: string, amount: number = 1): Promise<number> {
    const now = Date.now();
    const hit = this.hits.get(key);

    if (!hit || now > hit.expires) {
      this.hits.set(key, { count: amount, expires: now + this.windowMs });
      return amount;
    }

    hit.count += amount;
    return hit.count;
  }

  async get(key: string): Promise<number | undefined> {
    const hit = this.hits.get(key);
    if (!hit || Date.now() > hit.expires) return undefined;
    return hit.count;
  }

  async reset(key: string): Promise<void> {
    this.hits.delete(key);
  }

  async setTTL(key: string, value: number, ttlMs: number): Promise<void> {
    this.hits.set(key, { count: value, expires: Date.now() + ttlMs });
  }

  // Cleanup method if needed
  destroy() {
    clearInterval(this.gcInterval);
  }
}

/**
 * Redis Store implementation for the rate limiter.
 * Expects a Redis-compatible client (e.g., from 'ioredis' or 'redis').
 */
/**
 * Minimal structural interface for a Redis-compatible client.
 *
 * This is intentionally narrow — it describes only the API surface that
 * `RedisStore` actually uses. Any client that satisfies this interface
 * (e.g. `ioredis`, `node-redis` v4) will work without importing their
 * types as a dependency.
 */
export interface RedisMultiChain {
  incrby(key: string, amount: number): RedisMultiChain;
  pttl(key: string): RedisMultiChain;
  exec(): Promise<Array<[error: Error | null, result: unknown]>>;
}

export interface RedisClientLike {
  multi(): RedisMultiChain;
  get(key: string): Promise<string | null>;
  del(key: string): Promise<number>;
  set(key: string, value: number | string, mode: 'PX', ttlMs: number): Promise<string | null>;
  pexpire(key: string, ttlMs: number): Promise<number>;
}

/**
 * Redis Store implementation for the rate limiter.
 * Accepts any `RedisClientLike`-compatible client (e.g. `ioredis`, `redis` v4).
 */
export class RedisStore implements RateLimitStore {
  constructor(
    private readonly redisClient: RedisClientLike,
    private readonly windowMs: number,
    private readonly prefix: string = 'rl:',
  ) {}

  async increment(key: string, amount: number = 1): Promise<number> {
    const prefixedKey = this.prefix + key;
    const multi = this.redisClient.multi();
    multi.incrby(prefixedKey, amount);
    multi.pttl(prefixedKey);
    const results = await multi.exec();

    // Exact structure of results depends on the redis client (ioredis vs redis v4).
    // Assuming standard ioredis format: [[null, value], [null, ttl]]
    const count = Number.parseInt(results[0][1] as string, 10);
    const ttl = Number.parseInt(results[1][1] as string, 10);

    if (ttl === -1) {
      await this.redisClient.pexpire(prefixedKey, this.windowMs);
    }
    return count;
  }

  async get(key: string): Promise<number | undefined> {
    const val = await this.redisClient.get(this.prefix + key);
    return val ? Number.parseInt(val, 10) : undefined;
  }

  async reset(key: string): Promise<void> {
    await this.redisClient.del(this.prefix + key);
  }

  async setTTL(key: string, value: number, ttlMs: number): Promise<void> {
    const prefixedKey = this.prefix + key;
    await this.redisClient.set(prefixedKey, value, 'PX', ttlMs);
  }
}

/**
 * TokenBucket implementation for smooth rate limiting.
 */
export class TokenBucket {
  private readonly buckets = new Map<string, { tokens: number; lastRefill: number }>();

  constructor(
    private readonly capacity: number,
    private readonly refillRatePerSecond: number,
  ) {}

  async consume(id: string, tokens: number = 1): Promise<boolean> {
    const now = Date.now();
    let bucket = this.buckets.get(id);

    if (bucket) {
      const delta = (now - bucket.lastRefill) / 1000;
      const refill = delta * this.refillRatePerSecond;
      bucket.tokens = Math.min(this.capacity, bucket.tokens + refill);
      bucket.lastRefill = now;
    } else {
      bucket = { tokens: this.capacity, lastRefill: now };
      this.buckets.set(id, bucket);
    }

    if (bucket.tokens >= tokens) {
      bucket.tokens -= tokens;
      return true;
    }

    return false;
  }
}

/**
 * Adaptive RateLimiter implementation with Global Kill-Switch and IR Hook support.
 */
export class AdaptiveRateLimiter {
  private readonly store: RateLimitStore;
  private readonly securityStore: RateLimitStore;
  private readonly burstStore: RateLimitStore;
  private readonly ipCheckers: ((ip: string) => Promise<boolean>)[] = [];

  constructor(
    private readonly config: {
      standardLimit: number;
      penaltyLimit: number;
      windowMs: number;
      securityThreshold: number;
      burstThreshold: number;
    },
    store?: RateLimitStore,
    securityStore?: RateLimitStore,
    burstStore?: RateLimitStore,
  ) {
    this.store = store || new MemoryStore(config.windowMs);
    this.securityStore = securityStore || new MemoryStore(config.windowMs);
    this.burstStore = burstStore || new MemoryStore(config.windowMs * 10);
  }

  /**
   * Automates Incident Response by globally "killing" a session or IP.
   * This sets an infinite (effectively 1-year) block on the ID.
   *
   * @param id The client ID to block.
   *
   * @remarks
   * **Persistence warning**: If the underlying store is `MemoryStore` (the default),
   * the block is held in process memory and will be **lost on process restart**.
   * For a persistent kill-switch that survives restarts and works across multiple
   * instances, pass a `RedisStore` as the `store` and `securityStore` arguments
   * to the `AdaptiveRateLimiter` constructor.
   *
   * @see {@link RedisStore} for a production-grade persistent store.
   */
  async triggerGlobalKillSwitch(id: string): Promise<void> {
    getTelemetryProvider().onKillSwitchTriggered?.(id);
    const ONE_YEAR_MS = 365 * 24 * 60 * 60 * 1000;
    await this.securityStore.setTTL(`${id}:score`, 99999, ONE_YEAR_MS);
    await this.store.setTTL(id, 99999, ONE_YEAR_MS);
    console.warn(`Mitigator: Global Kill-Switch triggered for actor: ${id}`);
  }

  registerIPChecker(checker: (ip: string) => Promise<boolean>): void {
    this.ipCheckers.push(checker);
  }

  async recordSecurityEvent(id: string, weight: number = 1): Promise<void> {
    getTelemetryProvider().onSecurityEvent?.(id, weight);
    await this.securityStore.increment(`${id}:score`, weight);
  }

  async isLimited(id: string): Promise<boolean> {
    for (const checker of this.ipCheckers) {
      if (await checker(id)) return true;
    }

    const score = (await this.securityStore.get(`${id}:score`)) || 0;
    const bursts = (await this.burstStore.get(`${id}:bursts`)) || 0;

    const isCompromised =
      score >= this.config.securityThreshold || bursts >= this.config.burstThreshold;
    const currentLimit = isCompromised ? this.config.penaltyLimit : this.config.standardLimit;

    const count = await this.store.increment(id);

    if (count > currentLimit) {
      if (count === currentLimit + 1) {
        await this.burstStore.increment(`${id}:bursts`, 1);
      }
      getTelemetryProvider().onRateLimitBlocked?.(id, isCompromised ? 'penalty' : 'standard');
      return true;
    }

    return false;
  }

  async isHighRisk(id: string): Promise<boolean> {
    const score = (await this.securityStore.get(`${id}:score`)) || 0;
    const bursts = (await this.burstStore.get(`${id}:bursts`)) || 0;
    return score >= this.config.securityThreshold || bursts >= this.config.burstThreshold;
  }
}

/**
 * Basic Sliding Window RateLimiter for backward compatibility.
 */
export class RateLimiter {
  private readonly store: RateLimitStore;

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    store?: RateLimitStore,
  ) {
    this.store = store || new MemoryStore(windowMs);
  }

  async isLimited(id: string): Promise<boolean> {
    const count = await this.store.increment(id);
    return count > this.limit;
  }
}
