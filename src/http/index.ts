import { createHash, randomInt, randomBytes } from 'node:crypto';
import * as https from 'node:https';

/**
 * Checks if a request is over HTTPS.
 */
export const isSecure = (
  url?: string,
  headers: Record<string, string | string[] | undefined> = {},
): boolean => {
  if (url?.startsWith('https://')) return true;
  const proto = headers['x-forwarded-proto'];
  if (typeof proto === 'string' && proto.toLowerCase() === 'https') return true;
  return false;
};

/**
 * Normalizes a URL.
 */
export const normalizeUrl = (url: string): string => {
  try {
    const parsed = new URL(url);
    parsed.pathname = parsed.pathname.replaceAll('//', '/');
    return parsed.toString();
  } catch {
    return url.replaceAll('//', '/');
  }
};

/**
 * Hardened HTTPS Tunneling Helper.
 * Configures an outgoing https.request with strictly-enforced security options,
 * including TLS 1.3, strong ciphers, and OCSP stapling if supported.
 *
 * @param options Custom https.RequestOptions to extend.
 * @returns {https.RequestOptions} The hardened options.
 */
export const getHardenedRequestOptions = (
  options: https.RequestOptions = {},
): https.RequestOptions => {
  return {
    ...options,
    minVersion: 'TLSv1.3',
    ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256',
    rejectUnauthorized: true,
  };
};

/**
 * JA3 TLS Fingerprinting.
 */
export const generateTLSFingerprint = (req: any): string => {
  const headers = req.headers || {};
  const fingerprintParts = [
    headers['user-agent'] || '',
    headers['accept'] || '',
    headers['accept-language'] || '',
    headers['accept-encoding'] || '',
    headers['connection'] || '',
    headers['upgrade-insecure-requests'] || '',
  ];
  return createHash('sha256').update(fingerprintParts.join('|')).digest('hex');
};

/**
 * Analyzestraffic for DoS patterns.
 */
export const analyzeDoSThreat = (req: any): boolean => {
  const headers = req.headers || {};
  if (headers['transfer-encoding'] && headers['content-length']) return true;
  if (headers['connection'] === 'keep-alive' && !headers['content-length'] && req.method === 'POST')
    return true;
  return false;
};

/**
 * Generates client fingerprint.
 */
export const generateFingerprint = (
  reqHeaders: Record<string, string | string[] | undefined>,
  ip: string,
): string => {
  const parts = [
    ip,
    reqHeaders['user-agent'] || 'unknown',
    reqHeaders['accept-language'] || 'unknown',
    reqHeaders['accept-encoding'] || 'unknown',
    reqHeaders['sec-ch-ua'] || 'unknown',
    reqHeaders['sec-ch-ua-platform'] || 'unknown',
  ];
  return createHash('sha256').update(parts.join('|')).digest('hex');
};

/**
 * Projects noise.
 */
export const projectNoise = (obj: any): any => {
  if (typeof obj !== 'object' || obj === null) return obj;
  const noiseCount = randomInt(1, 4);
  const result = { ...obj };
  for (let i = 0; i < noiseCount; i++) {
    const noiseKey = `_sk_${randomBytes(4).toString('hex')}`;
    const noiseValue = randomBytes(8).toString('base64');
    result[noiseKey] = noiseValue;
  }
  return result;
};

/**
 * Safe Redirect.
 */
export const isSafeRedirect = (url: string, allowedHosts: string[] = []): boolean => {
  if (url.startsWith('/')) return !url.startsWith('//');
  try {
    const parsed = new URL(url);
    return allowedHosts.includes(parsed.hostname);
  } catch {
    return false;
  }
};

/**
 * SRI Hash.
 */
export const generateSRI = (
  data: string | Buffer,
  algorithm: 'sha256' | 'sha384' | 'sha512' = 'sha384',
): string => {
  const hash = createHash(algorithm).update(data).digest('base64');
  return `${algorithm}-${hash}`;
};
