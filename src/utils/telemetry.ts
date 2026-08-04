/**
 * Lightweight OpenTelemetry-compatible telemetry hook system for Mitigator.
 *
 * This module provides a zero-dependency, zero-overhead telemetry integration point.
 * By default all hooks are no-ops. Consumers inject their own tracer/metrics provider
 * via `setTelemetryProvider()` — works with any OTEL SDK, Datadog, Prometheus, or custom.
 *
 * @example
 * ```ts
 * import { setTelemetryProvider } from 'mitigator/telemetry';
 * import { trace, metrics } from '@opentelemetry/api';
 *
 * const tracer = trace.getTracer('mitigator');
 * const meter  = metrics.getMeter('mitigator');
 * const rateLimitCounter = meter.createCounter('mitigator.rate_limit.blocked');
 * const securityEventCounter = meter.createCounter('mitigator.security.events');
 *
 * setTelemetryProvider({
 *   onRateLimitBlocked(id, severity) {
 *     rateLimitCounter.add(1, { id, severity });
 *   },
 *   onSecurityEvent(id, weight) {
 *     securityEventCounter.add(weight, { id });
 *   },
 *   onKillSwitchTriggered(id) {
 *     const span = tracer.startSpan('mitigator.kill_switch');
 *     span.setAttribute('actor.id', id);
 *     span.end();
 *   },
 *   onWorkerSpawned(functionName) {
 *     // track worker thread usage
 *   },
 * });
 * ```
 */

/**
 * Telemetry event hooks that Mitigator calls at key security decision points.
 * All methods are optional — implement only what your observability stack needs.
 */
export interface MitigatorTelemetryProvider {
  /**
   * Called when a request is blocked by `AdaptiveRateLimiter.isLimited()`.
   * @param id       The client ID (IP, session, etc.) that was blocked.
   * @param severity `'penalty'` if the actor is high-risk, `'standard'` otherwise.
   */
  onRateLimitBlocked?(id: string, severity: 'standard' | 'penalty'): void;

  /**
   * Called when `AdaptiveRateLimiter.recordSecurityEvent()` is invoked.
   * @param id     The client ID receiving the security score increment.
   * @param weight The weight of the security event.
   */
  onSecurityEvent?(id: string, weight: number): void;

  /**
   * Called immediately before `AdaptiveRateLimiter.triggerGlobalKillSwitch()` writes.
   * @param id The client ID being permanently blocked.
   */
  onKillSwitchTriggered?(id: string): void;

  /**
   * Called each time `runIsolatedCrypto` acquires a worker thread slot.
   * @param functionName The crypto function being dispatched to the worker.
   */
  onWorkerSpawned?(functionName: string): void;
}

/** No-op provider used when no telemetry is configured. */
const NOOP_PROVIDER: Required<MitigatorTelemetryProvider> = {
  onRateLimitBlocked: () => {},
  onSecurityEvent: () => {},
  onKillSwitchTriggered: () => {},
  onWorkerSpawned: () => {},
};

let _provider: MitigatorTelemetryProvider = NOOP_PROVIDER;

/**
 * Registers a telemetry provider that Mitigator will call at key security events.
 *
 * Call this once at application startup, before any Mitigator functions are used.
 * Replaces any previously registered provider.
 *
 * @param provider An object implementing any subset of `MitigatorTelemetryProvider`.
 */
export const setTelemetryProvider = (provider: MitigatorTelemetryProvider): void => {
  _provider = provider;
};

/**
 * Resets the telemetry provider to the built-in no-op (useful in tests).
 */
export const resetTelemetryProvider = (): void => {
  _provider = NOOP_PROVIDER;
};

/**
 * Internal accessor used by Mitigator modules to emit telemetry events.
 * Not part of the public API — use `setTelemetryProvider` instead.
 *
 * @internal
 */
export const getTelemetryProvider = (): MitigatorTelemetryProvider => _provider;
