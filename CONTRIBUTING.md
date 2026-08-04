# Contributing to Mitigator 🛡️

Thank you for taking the time to contribute to Mitigator! This guide explains how to set up the project, submit changes, and meet our quality bar.

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.  
For **security vulnerabilities**, follow the process in [SECURITY.md](SECURITY.md) — **do not open a public issue**.

---

## 🚀 Getting Started

### Prerequisites

- **Node.js** `>=18.0.0` (see `.node-version` or the `engines` field in `package.json`)
- **npm** `>=9`

### Setup

```bash
# Clone the repository
git clone https://github.com/MohamedSoliman21/mitigator.git
cd mitigator

# Install dependencies (exact versions from lockfile)
npm ci

# Build the package
npm run build

# Run all tests
npm test
```

---

## 🗂️ Project Structure

```
src/
├── auth/           # WebAuthn, JWT, CSRF, ZKP, RBAC
├── bin/            # mitigator-audit CLI
├── crypto/         # AES-GCM, Shamir SSS, WOTS PQC, Worker Threads
├── fs/             # Path traversal prevention, magic number checks
├── headers/        # CSP, security headers
├── http/           # URL normalization, TLS fingerprinting, SRI
├── rate-limit/     # AdaptiveRateLimiter, TokenBucket, Redis/MemoryStore
├── safe-json/      # DoS-resistant, prototype-pollution-safe JSON parsing
├── safe-merge/     # Prototype-pollution-safe deep merge
├── sanitize/       # XSS / HTML sanitization
├── utils/          # Redaction, SecureError, telemetry, presets
└── validate/       # Schema enforcement, HIBP, injection detection
```

Each module has its implementation in `index.ts` and tests colocated in `*.test.ts`.

---

## 🧪 Testing

```bash
# Run all tests once
npm test

# Run in watch mode during development
npm run test:watch

# Run with coverage report
npm run test:coverage
```

All PRs **must maintain 100% line coverage**. The CI pipeline will fail if coverage drops.

---

## 🔍 Linting & Formatting

```bash
# Check for lint errors
npm run lint

# Auto-format code
npm run format

# Verify formatting (used in CI)
npm run format:check
```

We use **ESLint** with `typescript-eslint` and **Prettier**. Both run automatically in CI.

---

## 📝 Making Changes

1. **Fork** the repository and create a feature branch from `main`:

   ```bash
   git checkout -b feat/your-feature-name
   ```

2. **Write your code** following the patterns in the existing modules.

3. **Write or update tests** — every new code path must be covered.

4. **Update documentation** — add JSDoc to new exports. If the change affects the public API, update `README.md`.

5. **Update `CHANGELOG.md`** — add your change under `## [Unreleased]` using the appropriate category (`Added`, `Changed`, `Fixed`, `Deprecated`, `Removed`, `Security`).

6. **Run the full quality gate locally** before opening a PR:
   ```bash
   npm run lint && npm run format:check && npm run build && npm run test:coverage
   ```

---

## 📐 Coding Standards

- **TypeScript strict mode** is enforced — avoid `any` at API boundaries.
- **Security-critical code** (auth, crypto, validate) must use `timingSafeEqual` for comparisons.
- **No new runtime dependencies** without prior discussion in an issue. Mitigator deliberately has only one runtime dependency (`sanitize-html`).
- **Naming**: exported functions use `camelCase`, exported classes use `PascalCase`, exported types/interfaces use `PascalCase`.
- Use the `MinimalLogger` interface for any internal logging — never `console.log/error` directly.
- Telemetry events should be emitted via `getTelemetryProvider()` at key security decision points.

---

## 🔀 Pull Request Process

1. Ensure CI passes on your branch (lint, format, build, tests, audit).
2. Keep PRs **focused** — one logical change per PR.
3. PR titles should follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat: add FIDO2 assertion verification`
   - `fix: use timingSafeEqual in verifyCSRF`
   - `docs: add HIBP usage example to README`
   - `security: fix prototype pollution in safeJson`
4. Fill out the PR template completely.
5. A review from at least **one CODEOWNER** (see `.github/CODEOWNERS`) is required before merging.

---

## 🏷️ Releasing

Releases are automated via the `.github/workflows/publish.yml` workflow.

1. Update `package.json` version following [Semantic Versioning](https://semver.org/).
2. Move `## [Unreleased]` changes to a new versioned section in `CHANGELOG.md`.
3. Commit: `git commit -m "chore: release v1.2.3"`.
4. Tag: `git tag v1.2.3 && git push origin v1.2.3`.
5. The publish workflow will automatically run the full quality gate and publish to npm with provenance attestation.
