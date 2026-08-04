import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  setTelemetryProvider,
  resetTelemetryProvider,
  getTelemetryProvider,
  type MitigatorTelemetryProvider,
} from './telemetry.js';

describe('Telemetry Module', () => {
  beforeEach(() => {
    resetTelemetryProvider();
  });

  describe('setTelemetryProvider / getTelemetryProvider', () => {
    it('should use no-op provider by default (hooks are callable, no throws)', () => {
      const provider = getTelemetryProvider();
      // All hooks should be no-ops — calling them must not throw
      expect(() => provider.onRateLimitBlocked?.('ip', 'standard')).not.toThrow();
      expect(() => provider.onSecurityEvent?.('ip', 1)).not.toThrow();
      expect(() => provider.onKillSwitchTriggered?.('ip')).not.toThrow();
      expect(() => provider.onWorkerSpawned?.('hashPassword')).not.toThrow();
    });

    it('should call registered onRateLimitBlocked with correct severity', () => {
      const onRateLimitBlocked = vi.fn();
      setTelemetryProvider({ onRateLimitBlocked });

      getTelemetryProvider().onRateLimitBlocked?.('192.168.1.1', 'penalty');
      expect(onRateLimitBlocked).toHaveBeenCalledWith('192.168.1.1', 'penalty');

      getTelemetryProvider().onRateLimitBlocked?.('10.0.0.1', 'standard');
      expect(onRateLimitBlocked).toHaveBeenCalledWith('10.0.0.1', 'standard');
    });

    it('should call registered onSecurityEvent', () => {
      const onSecurityEvent = vi.fn();
      setTelemetryProvider({ onSecurityEvent });

      getTelemetryProvider().onSecurityEvent?.('user-123', 3);
      expect(onSecurityEvent).toHaveBeenCalledWith('user-123', 3);
    });

    it('should call registered onKillSwitchTriggered', () => {
      const onKillSwitchTriggered = vi.fn();
      setTelemetryProvider({ onKillSwitchTriggered });

      getTelemetryProvider().onKillSwitchTriggered?.('banned-ip');
      expect(onKillSwitchTriggered).toHaveBeenCalledWith('banned-ip');
    });

    it('should call registered onWorkerSpawned', () => {
      const onWorkerSpawned = vi.fn();
      setTelemetryProvider({ onWorkerSpawned });

      getTelemetryProvider().onWorkerSpawned?.('hashPassword');
      expect(onWorkerSpawned).toHaveBeenCalledWith('hashPassword');
    });

    it('should support partial providers (only some hooks implemented)', () => {
      // Only onRateLimitBlocked implemented — other hooks must not throw
      const onRateLimitBlocked = vi.fn();
      const partial: MitigatorTelemetryProvider = { onRateLimitBlocked };
      setTelemetryProvider(partial);

      const provider = getTelemetryProvider();
      expect(() => provider.onRateLimitBlocked?.('ip', 'standard')).not.toThrow();
      expect(() => provider.onSecurityEvent?.('ip', 1)).not.toThrow();
      expect(() => provider.onKillSwitchTriggered?.('ip')).not.toThrow();
      expect(() => provider.onWorkerSpawned?.('fn')).not.toThrow();
      expect(onRateLimitBlocked).toHaveBeenCalledOnce();
    });

    it('should replace a previously registered provider', () => {
      const first = vi.fn();
      const second = vi.fn();

      setTelemetryProvider({ onSecurityEvent: first });
      setTelemetryProvider({ onSecurityEvent: second });

      getTelemetryProvider().onSecurityEvent?.('id', 1);
      expect(first).not.toHaveBeenCalled();
      expect(second).toHaveBeenCalledOnce();
    });
  });

  describe('resetTelemetryProvider', () => {
    it('should restore no-op behavior after reset', () => {
      const onSecurityEvent = vi.fn();
      setTelemetryProvider({ onSecurityEvent });
      resetTelemetryProvider();

      getTelemetryProvider().onSecurityEvent?.('id', 1);
      expect(onSecurityEvent).not.toHaveBeenCalled();
    });
  });

  describe('Integration: telemetry hooks fired by AdaptiveRateLimiter', () => {
    it('should emit onRateLimitBlocked when a standard actor is limited', async () => {
      const { AdaptiveRateLimiter } = await import('../rate-limit/index.js');
      const onRateLimitBlocked = vi.fn();
      setTelemetryProvider({ onRateLimitBlocked });

      const limiter = new AdaptiveRateLimiter({
        standardLimit: 1,
        penaltyLimit: 1,
        windowMs: 60000,
        securityThreshold: 99,
        burstThreshold: 99,
      });

      await limiter.isLimited('user'); // count = 1, allowed
      await limiter.isLimited('user'); // count = 2, blocked
      expect(onRateLimitBlocked).toHaveBeenCalledWith('user', 'standard');
    });

    it('should emit onSecurityEvent when recordSecurityEvent is called', async () => {
      const { AdaptiveRateLimiter } = await import('../rate-limit/index.js');
      const onSecurityEvent = vi.fn();
      setTelemetryProvider({ onSecurityEvent });

      const limiter = new AdaptiveRateLimiter({
        standardLimit: 100,
        penaltyLimit: 1,
        windowMs: 60000,
        securityThreshold: 99,
        burstThreshold: 99,
      });

      await limiter.recordSecurityEvent('attacker', 5);
      expect(onSecurityEvent).toHaveBeenCalledWith('attacker', 5);
    });

    it('should emit onKillSwitchTriggered when triggerGlobalKillSwitch is called', async () => {
      const { AdaptiveRateLimiter } = await import('../rate-limit/index.js');
      const onKillSwitchTriggered = vi.fn();
      setTelemetryProvider({ onKillSwitchTriggered });

      const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      const limiter = new AdaptiveRateLimiter({
        standardLimit: 100,
        penaltyLimit: 1,
        windowMs: 60000,
        securityThreshold: 99,
        burstThreshold: 99,
      });

      await limiter.triggerGlobalKillSwitch('bad-actor');
      expect(onKillSwitchTriggered).toHaveBeenCalledWith('bad-actor');
      spy.mockRestore();
    });
  });
});
