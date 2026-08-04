export * as sanitize from './sanitize/index.js';
export * as validate from './validate/index.js';
export * as headers from './headers/index.js';
export * as auth from './auth/index.js';
/**
 * Mitigator cryptography module.
 *
 * @warning **Browser / Edge runtime namespace collision.**
 * Importing `crypto` from `mitigator` shadows the browser's built-in global `crypto`
 * (the Web Crypto API) within the importing module's scope. To avoid conflicts, use
 * a named alias when importing in browser or edge environments:
 *
 * ```typescript
 * import { crypto as mitigatorCrypto } from 'mitigator';
 * ```
 *
 * In pure Node.js server environments (where `globalThis.crypto` is Node's Web Crypto),
 * the shadow is local to the module and does not affect other files.
 */
export * as crypto from './crypto/index.js';
export * as fs from './fs/index.js';
export * as http from './http/index.js';
export * as rateLimit from './rate-limit/index.js';
export * as safeJson from './safe-json/index.js';
export * as safeMerge from './safe-merge/index.js';
export * as utils from './utils/index.js';
export * as presets from './utils/presets.js';
export * as telemetry from './utils/telemetry.js';
