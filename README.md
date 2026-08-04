# Mitigator 🛡️

**Mitigator** is a production-grade, security-first TypeScript library designed to eliminate common vulnerabilities and implement advanced defense-in-depth patterns in Node.js applications.

Unlike generic utility libraries, Mitigator is built with a "Zero-Trust" philosophy, providing tools specifically hardened against XSS, Prototype Pollution, Path Traversal, SQL Injection, and more.

## 🛡️ Mitigated Risks

Mitigator provides built-in defenses against the most critical web vulnerabilities, mapping directly to OWASP Top 10 categories:

- **Cross-Site Scripting (XSS)**: Automatic HTML escaping and allowlist-based sanitization prevent malicious scripts from executing in the user's browser.
- **Prototype Pollution**: Strict filtering of `__proto__` and `constructor` keys during JSON parsing and object merging prevents attackers from compromising the Node.js runtime.
- **Path Traversal (LFI)**: Root-locked path resolution ensures that file system operations cannot escape designated directories.
- **Injection Attacks**: Heuristic detection of SQL/NoSQL injection patterns and enforcement of parameterized-like query structures.
- **Broken Authentication**: Protection against credential stuffing via HIBP leak checks and support for modern, phishing-resistant WebAuthn (Passkeys).
- **Denial of Service (DoS)**: Rate limiting, JSON depth analysis, and circular reference detection prevent resource exhaustion attacks.
- **Sensitive Data Exposure**: Automated redaction of secrets in logs and secure, encrypted session management (AES-256-GCM).

---

## ✨ Key Features

- 🛡️ **XSS Protection**: Robust HTML sanitization powered by `sanitize-html` and DOM clobbering prevention.
- ⚡ **Prototype Pollution Defense**: Secure object merging and safe JSON parsing.
- 📂 **Path Traversal Mitigation**: Root-locked file system operations.
- 🔐 **Advanced Auth**: WebAuthn/Passkey verification, JWT signature validation, ZKP challenges, and CSRF protection.
- 🧬 **Cryptographic Hardening**: AES-256-GCM sessions, strict scrypt hashing.
- 🚀 **Performance**: CPU-intensive crypto offloaded to Worker Threads.
- 🚦 **Adaptive Rate Limiting**: Security-aware throttling with Redis cluster support and global kill-switch.

---

## 🚀 Installation

```bash
npm install mitigator-node
```

> [!WARNING]
> **Browser / Edge runtime — `crypto` namespace collision.**
> The `crypto` named export shadows the browser's built-in `globalThis.crypto` (Web Crypto API)
> within the importing module's scope. Use a named alias in browser or edge runtimes:
>
> ```typescript
> import { crypto as mitigatorCrypto } from 'mitigator-node';
> ```

---

## 📦 Modules Overview

| Module      | Description                                                                |
| :---------- | :------------------------------------------------------------------------- |
| `sanitize`  | HTML escaping, tag stripping, and robust sanitization (XSS defense).       |
| `validate`  | Schema enforcement, secret scanning, and pwned password checks.            |
| `headers`   | Security headers (CSP, HSTS, etc.) and strict CSP builders.                |
| `auth`      | WebAuthn, HMAC challenge-response, CSRF, JWT validation, and RBAC helpers. |
| `crypto`    | AES session encryption, SSS, and PQC.                                      |
| `fs`        | Secure path resolution and magic number file type verification.            |
| `http`      | URL normalization, TLS fingerprinting, and SRI generation.                 |
| `rateLimit` | Adaptive rate limiting and Token Bucket implementations.                   |
| `safeJson`  | DoS-resistant and prototype-pollution safe JSON parsing.                   |
| `safeMerge` | Deep merging protected against prototype pollution.                        |
| `utils`     | Sensitive data redaction, secure error handling, and prototype lockdown.   |

---

## 🛠️ Detailed Usage

### 1. Input Sanitization (`sanitize`)

Prevent XSS by cleaning untrusted HTML or escaping characters. Backed by `sanitize-html`.

```typescript
import { sanitize } from 'mitigator-node';

// Basic HTML escaping
const escaped = sanitize.escapeHtml('<script>alert("xss")</script>');

// Robust HTML sanitization with allowlist
const clean = sanitize.sanitizeHtml('<p>Hello <script>bad()</script> <b>World</b></p>');
// Output: <p>Hello  <b>World</b></p>

// Prevent DOM Clobbering by namespacing IDs/Names
const safeHtml = sanitize.preventDOMClobbering('<img id="config">');
// Output: <img id="sk-config">
```

### 2. Secure File Operations (`fs`)

Stop path traversal attacks by locking file operations to a root directory.

```typescript
import { fs } from 'mitigator-node';

const root = './uploads';

// This will throw if the path attempts to escape './uploads' (e.g., '../../etc/passwd')
const safePath = fs.resolveSafePath(root, 'user-data.json');

// Verify file type by Magic Numbers (more secure than extension check)
const isPNG = await fs.verifyMagicNumber('image.bin', fs.MAGIC_NUMBERS.PNG);
```

### 3. Adaptive Rate Limiting (`rateLimit`)

Automatically penalize high-risk actors based on security events.

```typescript
import { rateLimit } from 'mitigator-node';

const limiter = new rateLimit.AdaptiveRateLimiter({
  standardLimit: 100,
  penaltyLimit: 10, // Strict limit for suspicious users
  windowMs: 60000, // 1 minute
  securityThreshold: 5, // Max security events before penalty
  burstThreshold: 3, // Max bursts before penalty
});

if (await limiter.isLimited('user-ip')) {
  throw new Error('Too many requests');
}

// Record a suspicious event (e.g., failed login)
await limiter.recordSecurityEvent('user-ip', 1);
```

### 4. Safe Object Handling (`safeJson` & `safeMerge`)

Protect your application from Prototype Pollution.

```typescript
import { safeJson, safeMerge } from 'mitigator-node';

// Parse JSON while stripping __proto__ and constructor keys
const data = safeJson.parse(untrustedString);

// Deep merge objects without risking prototype pollution
const config = safeMerge.merge(defaultConfig, userConfig);
```

### 5. Advanced Cryptography (`crypto` & `auth`)

Implement high-level security and quantum-resistant patterns with ease.

#### Shamir's Secret Sharing (SSS)

Split sensitive keys into $M$ cryptographic shares where any $T$ shares can exactly reconstruct the original secret, but fewer than $T$ yields only garbage. Built over Galois Field $GF(256)$ with AES primitive polynomial arithmetic.

```typescript
import { crypto } from 'mitigator-node';

// Split secret key into 5 shares with a threshold of 3
const shares = crypto.splitSecret('master-key-content', 5, 3);

// Reconstruct with any 3 shares
const reconstructed = crypto.reconstructSecret([shares[0], shares[2], shares[4]]);
console.log(reconstructed.toString('utf8')); // 'master-key-content'
```

#### Post-Quantum Cryptography (PQC)

Phishing-resistant, quantum-resistant one-time signatures powered by the standard **Winternitz One-Time Signatures (WOTS)** nibble-chaining hash framework.

> [!CAUTION]
> **WOTS is a ONE-TIME signature scheme.** Each `privateKey` **must only ever sign a single
> message**. Signing a second message with the same private key leaks enough key material
> to forge arbitrary signatures, completely breaking the security of the scheme.
>
> **Always generate a fresh key pair with `generatePQCKeyPair()` for every message you sign.**
> Mitigator enforces this at runtime — `signPQC()` throws `WOTS_KEY_REUSE` if you attempt
> to reuse a private key within the same process.

```typescript
import { crypto as mitigatorCrypto } from 'mitigator-node';

// Generate key pair
const { publicKey, privateKey } = mitigatorCrypto.generatePQCKeyPair();

// Sign and verify message — each key pair can only sign ONCE
const signature = mitigatorCrypto.signPQC('quantum-secure-payload', privateKey);
const isValid = mitigatorCrypto.verifyPQCSignature('quantum-secure-payload', signature, publicKey); // true

// ❌ This will throw WOTS_KEY_REUSE:
// mitigatorCrypto.signPQC('second message', privateKey);
```

#### HMAC Challenge-Response

Server-side mutual authentication using an HMAC challenge-response flow.

```typescript
import { auth } from 'mitigator-node';

const salt = 'per-user-random-salt';
const challenge = auth.generateHmacChallenge(salt);

// Client computes: HMAC-SHA256(secret, challenge) and sends it back
const proof = computeClientProof(challenge, sharedSecret);
const verified = auth.verifyHmacResponse(challenge, proof, sharedSecret); // true
```

#### FIDO2 WebAuthn / Passkeys

Phishing-resistant browser authentication helpers — both registration and assertion flows.

```typescript
import { auth } from 'mitigator-node';

// Generate base64url registration challenge
const challenge = auth.generatePasskeyChallenge();

// Verify client registration response against expected challenge and origin
const regResult = auth.verifyPasskeyRegistration(clientDataJSON, challenge, 'https://example.com');

// Parse binary authenticatorData buffer to extract credentialIds and keys
const credentials = auth.parseAuthenticatorData(authDataBuffer);

// Verify an authentication assertion (navigator.credentials.get flow)
// This implements WebAuthn Level 2 §7.2 including replay attack protection.
const assertResult = auth.verifyPasskeyAssertion(
  clientDataJSON, // from browser response.clientDataJSON
  storedChallenge, // challenge you sent to the browser
  'https://example.com', // expected origin
  storedSignCount, // signCount from DB (pass 0 on first use)
  authDataBuffer, // from browser response.authenticatorData
  signatureBuffer, // from browser response.signature
  credentialPublicKeyPem, // public key stored during registration
);
if (!assertResult.verified) throw new Error(assertResult.error);
await db.updateSignCount(credentialId, assertResult.newSignCount!);
```

---

## 🏗️ Framework Integration

Mitigator comes with built-in presets for Express, Fastify, NestJS, and Next.js.

### Express

```typescript
import express from 'express';
import { presets } from 'mitigator-node';

const app = express();

// Global security middleware (Headers, Rate Limiting, Secret Scanning)
app.use(presets.expressMiddleware({ rateLimit: true, rateLimitMax: 100 }));

// Secure Logger Chain (Tamper-proof logs via cryptographic linking)
const logger = presets.createSecureLogger(console);
logger.info('User logged in', { userId: 123 });

// Global Secure Error Handler
app.use(presets.expressErrorHandler);
```

### Fastify

```typescript
import Fastify from 'fastify';
import { presets } from 'mitigator-node';

const fastify = Fastify();

// Register the security hook/plugin preset
fastify.register(presets.fastifyPlugin({ rateLimit: true, rateLimitMax: 100 }));
```

### NestJS

```typescript
import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { presets } from 'mitigator-node';

@Module({})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    // Configure rate limits
    presets.NestJsMitigatorMiddleware.configure({ rateLimit: true, rateLimitMax: 100 });

    // Apply globally
    consumer.apply(presets.NestJsMitigatorMiddleware).forRoutes('*');
  }
}
```

### Next.js Edge Middleware

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import { presets } from 'mitigator-node';

export function middleware(request) {
  const response = NextResponse.next();
  return presets.nextJsMiddleware(request, response);
}
```

---

## 🛡️ Automated Security Audit CLI

Mitigator features a recursive command-line security scanner (`mitigator-audit`) to check your configurations and files automatically in pre-commit hooks or CI/CD pipelines.

### Usage

```bash
# Scan the current directory
npx mitigator-audit

# Scan a specific directory
npx mitigator-audit ./src
```

### Checks Performed

- **Hardcoded Secret Detection**: Scans for high-entropy tokens and plain-text API credentials.
- **Potential Path Traversal**: Scans for raw user inputs mapped directly to file system operations.
- **Prototype Pollution Risks**: Scans for raw `JSON.parse` or `Object.assign` calls without Prototype Pollution filters.
- **Header Drift Detection**: Scans for express instances without security headers presets.

---

## 🧪 Safety & Best Practices

### Prototype Lockdown

Prevent many prototype pollution attacks globally by freezing core prototypes. **Warning**: This may break some legacy libraries that modify built-ins.

```typescript
import { utils } from 'mitigator-node';

utils.lockdownPrototypes(); // Freezes Object.prototype, Array.prototype, etc.
```

### Memory Wiping

For extremely sensitive data (like decrypted keys), overwrite the buffer once finished.

```typescript
import { utils } from 'mitigator-node';

const keyBuffer = Buffer.from('high-entropy-secret');
// ... use key ...
utils.wipeBuffer(keyBuffer); // Fills buffer with zeros
```

---

## 📜 License

ISC License - see [LICENSE](LICENSE) for details.
