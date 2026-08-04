# Mitigator Project Roadmap 🛡️

This document outlines the development path, completed security milestones, and planned future expansions for the **Mitigator** project.

---

## 🚀 Completed Milestones (v1.0.0)

### 1. 🛡️ HTML Sanitization Hardening

- [x] **Industry Standard Engine**: Replaced fragile custom tag regex parser in `src/sanitize/` with the robust, extensively battle-tested `sanitize-html` package.
- [x] **DOM Clobbering Defense**: Implemented namespaced identifier prepending (`sk-`) on element IDs/Names to prevent clobbering attacks on the `window` object.
- [x] **XSS Safe Filtering**: Enabled deep escaping and tag whitelist management out-of-the-box.

### 2. 🔐 JWT Cryptographic Verification

- [x] **Anti-Token Forgery**: Rewrote `isJwtValid` to perform cryptographic signature verification against both HMAC (`HS256`, `HS384`, `HS512`) and RSA/ECDSA (`RS256`, `ES256`, etc.) signatures using Node's `node:crypto`.
- [x] **Safe Decoding**: Protected token payload decoding from `base64url` to prevent formatting and decoding bypasses.

### 3. 🚦 Adaptive Rate Limiting & Storage

- [x] **Active GC MemoryStore**: Added a self-healing background pruner (`setInterval` with `.unref()`) to `MemoryStore` to remove expired hits, preventing potential Out-Of-Memory (OOM) memory leaks.
- [x] **Production RedisStore**: Implemented a production-ready `RedisStore` conforming to the `RateLimitStore` interface, leveraging multi-command pipelining (`incrby` + `pttl`) for maximum efficiency.
- [x] **IP Checkers**: Added support for custom asynchronous IP checker callbacks for immediate blocking and threat evaluation.

### 4. 🧬 Expanded Injection Defense Heuristics

- [x] **Advanced Threat Analysis**: Wrote sophisticated regex-based matchers covering SQL, MongoDB NoSQL, and Shell command injection structures in request validation.

### 5. 🏗️ High-level Middleware Presets

- [x] **Express Preset**: Added Express global middleware covering rate limits, security headers, and active secret scanners. Added a tamper-proof cryptographically chained secure logger.
- [x] **Next.js Edge Middleware**: Created an environment-agnostic preset suitable for Cloudflare Workers, Next.js Edge runtime, and other V8-based serverless environments.

### 6. 🧪 100% Comprehensive Line Coverage

- [x] **Bulletproof Quality**: Wrote 160+ unit tests with mocked workers, mock Redis, dynamic runtime module re-evaluation, and process environments to hit **100% line coverage** across every file in the package.

---

## 🔮 Future Roadmap & Enhancements

### Phase 2: Production Cryptography & WebAuthn Extension

- [x] **Production PQC Implementations**: Replaced the naive experimental signature placeholder in `src/crypto/` with a complete, fully functional, pure TypeScript implementation of **Winternitz One-Time Signatures (WOTS)** with checksum verification for true quantum-resistant security.
- [x] **Secret Sharing Extensions**: Replaced the simplified prototype with a production-grade **Shamir's Secret Sharing (SSS)** over Galois Field $GF(256)$, implementing Lagrange polynomial interpolation and full verifiable multi-share reconstruction.
- [x] **Passkey (WebAuthn) Expansion**: Added complete native FIDO2 registration challenge verification helpers, a random challenge builder, and a custom **Authenticator Data (authData) binary parser** to extract credentials and AAGUID keys from native web credentials.

### Phase 3: Developer Tooling & Integrations

- [x] **CLI Security Audit Tool**: Implemented a recursive directory command-line scanner (`mitigator-audit`) supporting plaintext secret leaks, prototype pollution risks, missing HTTP security headers, and path traversal vulnerabilities with colored outputs and proper pipeline exit status codes.
- [x] **Fastify & NestJS presets**: Added native high-performance presets for **Fastify** (using lifecycle hook plugins) and **NestJS** (using standard middleware configurations) to round out full support for major framework runtimes.
