# Changelog

All notable changes to **Mitigator** will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [1.0.3] — 2026-09-07

### Security & Hardening

- **`checkPwnedPassword`**:
  - Hardened against Server-Side Request Forgery (CWE-918) with strict 5-character hexadecimal regex validation (`HIBP_PREFIX_REGEX = /^[0-9A-F]{5}$/`) and locked origin check (`api.pwnedpasswords.com`).
  - Added a 5,000ms request timeout with connection abort (`req.destroy()`) to prevent resource exhaustion and hanging socket leaks (CWE-400).
  - Explicitly validates HTTP status `200 OK` and drains unread response streams (`res.resume()`) on unexpected statuses before early termination.
  - Sanitized error handling in `catch` blocks to prevent sensitive stack trace or internal diagnostic exposure in logs (CWE-209 / CWE-532).
- **`resolveSafePath`**:
  - Added explicit rejection of null-byte characters (`\0`) to prevent null-byte injection and path canonicalization bypasses (CWE-22 / CWE-23).

### Quality & Static Analysis

- **`rate-limit.test.ts`**:
  - Added assertion verification for `MemoryStore` garbage collection unref test.
  - Strongly typed mock Redis client to conform to `RedisClientLike` interface.
- **`crypto`**:
  - Refactored message status check to optional chaining (`msg?.status`).
  - Converted worker child bootstrap initialization to top-level `await`.
- **SonarQube Refactoring**:
  - Converted duplicate test suites in `src/safe-json/safe-json.test.ts` and `src/sanitize/sanitize.test.ts` into parameterized `it.each` suites.
  - Used `.toHaveLength(16)` assertion in `src/headers/headers.test.ts` for improved diagnostic reporting.

### Fixed

- **`basicAuth`** now validates that the username does not contain a colon (`:`), throwing a `TypeError` per RFC 7617 §2.
- **`hasInjectionPattern`** now enforces an input length cap (8192 characters) and bounded regex quantifiers to prevent ReDoS attacks from oversized or crafted inputs.
- **`parseAuthenticatorData`** now parses the extension data present flag (bit 7) and returns `extensionsPresent` in `AuthenticatorDataResult`.

---

## [1.0.1] — 2026-09-02

### Fixed

- **`isJwtValid`** now validates the `nbf` (not-before) claim and rejects tokens with
  future `iat` (issued-at) timestamps exceeding a 60-second clock skew tolerance.
- **`TokenBucket`** fixed an issue where initial bucket consumption logic was
  redundant and could handle new bucket creation inconsistently.
- **`parseAuthenticatorData`** now exports an explicit TypeScript return interface
  `AuthenticatorDataResult` for complete type safety.
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

[Unreleased]: https://github.com/MohamedSoliman21/mitigator/compare/v1.0.2...HEAD
[1.0.2]: https://github.com/MohamedSoliman21/mitigator/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/MohamedSoliman21/mitigator/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/MohamedSoliman21/mitigator/releases/tag/v1.0.0
