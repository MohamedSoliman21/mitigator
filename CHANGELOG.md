# Changelog

All notable changes to **Mitigator** will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Fixed

- **`isJwtValid`** now validates the `nbf` (not-before) claim and rejects tokens with
  future `iat` (issued-at) timestamps exceeding a 60-second clock skew tolerance.
- **`TokenBucket`** fixed an issue where initial bucket consumption logic was
  redundant and could handle new bucket creation inconsistently.
- **`verifyPasskeyRegistration`** now correctly handles browser-format (base64url-encoded)
  `clientDataJSON` in addition to raw JSON strings. Challenge bytes are compared using
  `timingSafeEqual` per WebAuthn Level 2 spec §7.1, preventing timing attacks and encoding
  mismatch false negatives.
- **`runIsolatedCrypto`** is now protected by a module-level `BoundedWorkerSemaphore` that
  caps concurrent Worker Thread spawning at `max(2, cpus - 1)`. Previously, a concurrency
  burst could spawn unbounded OS threads (DoS risk).

### Changed

- **`checkPwnedPassword`** now returns a `CheckPwnedResult` object `{ count, apiAvailable }`
  instead of a bare `number`. Callers can now distinguish "password is clean" (`apiAvailable: true,
count: 0`) from "HIBP API was unreachable" (`apiAvailable: false`).
  > ⚠️ **Breaking change** for callers reading the return value as a number directly.
  > Update: `const count = await checkPwnedPassword(p)` → `const { count } = await checkPwnedPassword(p)`.
- **`encryptFPE`** renamed to `deterministicDigitTransform` with a JSDoc correction making
  clear this is NOT NIST SP 800-38G (FF1/FF3-1) FPE. The old name is kept as a `@deprecated`
  re-export for backward compatibility.
- **`RedisStore`** constructor parameter `redisClient` typed from `any` to the new exported
  `RedisClientLike` interface, which describes the minimal Redis API surface used internally.

### Added

- `SECURITY.md` — vulnerability disclosure policy, response timeline, scope, CVSS severity
  classification, and safe harbor statement.
- `CHANGELOG.md` — this file.
- `engines` field in `package.json` declaring `>=18.0.0` as the minimum supported Node.js version.
- `npm audit --audit-level=high` step added to the GitHub Actions CI pipeline.
- `keywords` array in `package.json` for npm discoverability.
- `CheckPwnedResult` interface exported from `validate` module.
- `RedisClientLike` interface exported from `rate-limit` module.

---

## [1.0.0] — 2026-05-17

### Added

- Initial release.
- `sanitize` — HTML escaping, tag stripping, DOM Clobbering prevention via `sanitize-html`.
- `validate` — Schema enforcement, HIBP pwned password check (k-Anonymity), secret scanning,
  injection pattern detection (SQL, NoSQL, command).
- `headers` — Standard security headers, CSP builder with nonce support, strict CSP helper,
  CSP violation report parser.
- `auth` — WebAuthn/Passkey challenge generation and registration verification, FIDO2
  authenticatorData binary parser, JWT validation (HS256/RS256/ES256), CSRF, ZKP,
  honey tokens, RBAC helpers.
- `crypto` — AES-256-GCM session encryption, Shamir's Secret Sharing over GF(256),
  WOTS post-quantum key pair generation/signing/verification, scrypt password hashing,
  Worker Thread isolation for CPU-intensive operations, HKDF-like key derivation.
- `fs` — Root-locked path resolution (path traversal prevention), magic number file
  type verification.
- `http` — URL normalization, TLS fingerprinting, SRI hash generation.
- `rateLimit` — `MemoryStore` (with GC and `.unref()`), `RedisStore` (pipelining),
  `TokenBucket`, `AdaptiveRateLimiter` (security scoring, burst tracking, IP checker
  hooks, global kill-switch).
- `safeJson` — DoS-resistant JSON parsing (max depth/size), prototype pollution defense.
- `safeMerge` — Deep object merge protected against prototype pollution.
- `utils` — Sensitive data redaction, `SecureError`, prototype lockdown, buffer wiping,
  self-healing config monitor, environment security check, mTLS helpers.
- `presets` — Express, Fastify, NestJS, and Next.js Edge middleware presets with rate
  limiting, security headers, and cryptographically-chained secure logger.
- `mitigator-audit` CLI — Recursive directory scanner for hardcoded secrets, path
  traversal risks, prototype pollution patterns, and missing security headers.
- 200 unit tests across all modules. 100% line coverage.
- GitHub Actions CI with Node.js 18/20/22 matrix, lint, format check, build, and coverage.

[Unreleased]: https://github.com/MohamedSoliman21/mitigator/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/MohamedSoliman21/mitigator/releases/tag/v1.0.0
