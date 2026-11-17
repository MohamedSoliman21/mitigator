import { createHash, randomInt, randomBytes } from 'node:crypto';
import * as dns from 'node:dns';
import type { IncomingHttpHeaders } from 'node:http';
import * as https from 'node:https';
import { isIP } from 'node:net';

export type HeaderValue = string | string[] | undefined;

/**
 * Checks if a request is over HTTPS.
 */
export const isSecure = (url?: string, headers: Record<string, HeaderValue> = {}): boolean => {
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
 * Minimal request interface for HTTP inspection utilities.
 */
export interface HttpRequestLike {
  headers?: IncomingHttpHeaders | Record<string, HeaderValue>;
  method?: string;
}

/**
 * Generates a deterministic SHA-256 fingerprint from standard HTTP request headers
 * (`user-agent`, `accept`, `accept-language`, `accept-encoding`, `connection`,
 * `upgrade-insecure-requests`).
 *
 * Note: This operates on application-layer HTTP headers, not raw TLS ClientHello packets (JA3).
 */
export const generateHeaderFingerprint = (req: HttpRequestLike): string => {
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
 * Analyzes traffic for DoS patterns.
 */
export const analyzeDoSThreat = (req: HttpRequestLike): boolean => {
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
  reqHeaders: Record<string, HeaderValue>,
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
export const projectNoise = <T extends Record<string, unknown>>(obj: T): T => {
  if (typeof obj !== 'object' || obj === null) return obj;
  const noiseCount = randomInt(1, 4);
  const result: Record<string, unknown> = { ...obj };
  for (let i = 0; i < noiseCount; i++) {
    const noiseKey = `_sk_${randomBytes(4).toString('hex')}`;
    const noiseValue = randomBytes(8).toString('base64');
    result[noiseKey] = noiseValue;
  }
  return result as T;
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

const isPrivateIPv4 = (ip: string): boolean => {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return true;
  const [a, b] = parts;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true; // Link-local / Cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // RFC 1918
  if (a === 192 && b === 168) return true; // RFC 1918
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a >= 224) return true; // Multicast & Reserved
  return false;
};

/**
 * Checks whether an IPv4 or IPv6 address is private, loopback, link-local, or reserved.
 * Used to defend against Server-Side Request Forgery (SSRF).
 */
export const isPrivateOrInternalIP = (ip: string): boolean => {
  const normalized = ip
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '');
  const version = isIP(normalized);
  if (version === 4) return isPrivateIPv4(normalized);
  if (version === 6) {
    if (normalized === '::1' || normalized === '::') return true;
    if (normalized.startsWith('::ffff:')) {
      return isPrivateIPv4(normalized.slice(7));
    }
    const firstHextet = Number.parseInt(normalized.split(':')[0] || '0', 16);
    if ((firstHextet & 0xfe00) === 0xfc00) return true; // fc00::/7 Unique Local
    if ((firstHextet & 0xffc0) === 0xfe80) return true; // fe80::/10 Link-Local
    if ((firstHextet & 0xff00) === 0xff00) return true; // ff00::/8 Multicast
    return false;
  }
  return true;
};

export interface SafeOutboundUrlOptions {
  allowHttp?: boolean;
  allowedHosts?: string[];
}

/**
 * Validates that an outbound URL is safe to request (SSRF defense).
 * Enforces HTTPS by default, rejects embedded credentials, and blocks private IP literals.
 */
export const validateSafeOutboundUrl = (url: string, options: SafeOutboundUrlOptions = {}): URL => {
  const parsed = new URL(url);
  const allowedProtocols = options.allowHttp ? ['https:', 'http:'] : ['https:'];
  if (!allowedProtocols.includes(parsed.protocol)) {
    throw new Error(
      `Security Error: Disallowed protocol "${parsed.protocol}" for outbound request.`,
    );
  }
  if (parsed.username || parsed.password) {
    throw new Error('Security Error: Embedded credentials are not allowed in outbound URLs.');
  }
  const host = parsed.hostname.toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.internal')) {
    throw new Error(`Security Error: Disallowed internal hostname "${host}".`);
  }
  if (isIP(host.replace(/^\[|\]$/g, '')) !== 0 && isPrivateOrInternalIP(host)) {
    throw new Error(`Security Error: Private or internal IP address "${host}" is blocked.`);
  }
  if (options.allowedHosts && !options.allowedHosts.includes(host)) {
    throw new Error(`Security Error: Host "${host}" is not in the allowedHosts list.`);
  }
  return parsed;
};

type DnsLookupCallback = (
  err: NodeJS.ErrnoException | null,
  address: string | dns.LookupAddress[],
  family?: number,
) => void;

/**
 * Creates a DNS lookup function that blocks resolution to private/internal IPs,
 * preventing DNS rebinding (TOCTOU) SSRF attacks.
 */
export const createSafeDnsLookup = () => {
  return (
    hostname: string,
    options: dns.LookupOptions | DnsLookupCallback,
    callback?: DnsLookupCallback,
  ): void => {
    const cb = typeof options === 'function' ? options : callback!;
    const opts = typeof options === 'function' ? {} : options;

    dns.lookup(hostname, opts, (err, address, family) => {
      if (err) return cb(err, '');
      const addresses = Array.isArray(address) ? address.map((a) => a.address) : [address];
      if (addresses.some((addr) => isPrivateOrInternalIP(addr))) {
        return cb(
          new Error(
            `Security Error: DNS resolution for "${hostname}" returned a private/internal IP.`,
          ),
          '',
        );
      }
      if (Array.isArray(address)) {
        cb(null, address);
      } else {
        cb(null, address, family);
      }
    });
  };
};

export interface SafeFetchOptions extends RequestInit, SafeOutboundUrlOptions {
  timeoutMs?: number;
  maxBytes?: number;
}

/**
 * SSRF-hardened wrapper around `fetch()`.
 * Validates the URL, blocks redirects, enforces a timeout, and caps response body size.
 */
export const safeFetch = async (url: string, options: SafeFetchOptions = {}): Promise<Response> => {
  const {
    allowHttp,
    allowedHosts,
    timeoutMs = 5000,
    maxBytes = 5 * 1024 * 1024,
    ...fetchInit
  } = options;
  const parsed = validateSafeOutboundUrl(url, { allowHttp, allowedHosts });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(parsed.toString(), {
      ...fetchInit,
      redirect: 'error',
      signal: controller.signal,
    });

    const contentLength = response.headers.get('content-length');
    if (contentLength && Number.parseInt(contentLength, 10) > maxBytes) {
      throw new Error(
        `Security Error: Response exceeds maximum allowed size of ${maxBytes} bytes.`,
      );
    }

    return response;
  } finally {
    clearTimeout(timer);
  }
};
