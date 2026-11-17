import { randomBytes } from 'node:crypto';

/**
 * Standard security header presets.
 */
export const standardHeaders = {
  'Content-Security-Policy':
    "default-src 'self'; img-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; object-src 'none'",
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'Cross-Origin-Resource-Policy': 'same-origin',
};

/**
 * CSP Directive Map type.
 */
export type CSPDirectives = {
  'default-src'?: string[];
  'script-src'?: string[];
  'style-src'?: string[];
  'img-src'?: string[];
  'connect-src'?: string[];
  'font-src'?: string[];
  'object-src'?: string[];
  'media-src'?: string[];
  'frame-src'?: string[];
  sandbox?: string[];
  'report-uri'?: string[];
  'child-src'?: string[];
  'form-action'?: string[];
  'frame-ancestors'?: string[];
  'plugin-types'?: string[];
  'base-uri'?: string[];
  'report-to'?: string[];
  'worker-src'?: string[];
  'manifest-src'?: string[];
  'prefetch-src'?: string[];
  'navigate-to'?: string[];
};

/**
 * Generates a random nonce for CSP headers.
 */
export const generateNonce = (length: number = 16): string => {
  return randomBytes(length).toString('base64');
};

/**
 * Builds a CSP string.
 */
export const buildCSP = (directives: CSPDirectives, nonce?: string): string => {
  return Object.entries(directives)
    .filter((entry): entry is [string, string[]] => {
      const sources = entry[1];
      return Array.isArray(sources) && sources.length > 0;
    })
    .map(([directive, sources]) => {
      const updatedSources =
        nonce && (directive === 'script-src' || directive === 'style-src')
          ? [...sources, `'nonce-${nonce}'`]
          : sources;
      return `${directive} ${updatedSources.join(' ')}`;
    })
    .join('; ');
};

/**
 * Builds a 'Strict CSP' which is the industry gold standard.
 * It uses 'strict-dynamic' and nonces, rendering 99.9% of XSS impossible.
 *
 * @param nonce The nonce generated for the current request.
 * @returns {string} The formatted Strict CSP string.
 */
export const buildStrictCSP = (nonce: string): string => {
  return buildCSP({
    'object-src': ["'none'"],
    'script-src': ["'strict-dynamic'", `'nonce-${nonce}'`, "'unsafe-inline'", 'http:', 'https:'],
    'base-uri': ["'none'"],
  });
};

/**
 * Parses CSP violation report.
 */
export const parseCSPReport = (reportBody: unknown) => {
  if (!reportBody || typeof reportBody !== 'object') return null;
  const bodyRecord = reportBody as Record<string, unknown>;
  const report =
    (bodyRecord['csp-report'] as Record<string, unknown> | undefined) ||
    (Array.isArray(reportBody) ? (reportBody[0] as Record<string, unknown>) : bodyRecord);
  if (!report?.['blocked-uri']) return null;
  return {
    documentUri: report['document-uri'],
    referrer: report['referrer'],
    blockedUri: report['blocked-uri'],
    violatedDirective: report['violated-directive'],
    originalPolicy: report['original-policy'],
    disposition: report['disposition'],
    statusCode: report['status-code'],
    timestamp: new Date().toISOString(),
  };
};

/**
 * Returns a secure-by-default CSP string.
 */
export const secureCSP = buildCSP({
  'default-src': ["'none'"],
  'script-src': ["'self'"],
  'style-src': ["'self'"],
  'img-src': ["'self'"],
  'connect-src': ["'self'"],
  'font-src': ["'self'"],
  'object-src': ["'none'"],
  'base-uri': ["'none'"],
  'form-action': ["'self'"],
  'frame-ancestors': ["'none'"],
});

/**
 * Cross-Origin Isolation headers (Spectre / SharedArrayBuffer defense).
 * Opt-in preset for applications that can enforce strict cross-origin isolation.
 */
export const crossOriginIsolationHeaders = {
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'Cross-Origin-Resource-Policy': 'same-origin',
} as const;

/**
 * Builds a `Permissions-Policy` header value from a directive map.
 *
 * @example
 * buildPermissionsPolicy({ camera: [], microphone: [], geolocation: ['self'] })
 * // => "camera=(), microphone=(), geolocation=(self)"
 */
export const buildPermissionsPolicy = (directives: Record<string, string[]>): string => {
  return Object.entries(directives)
    .map(([feature, allowlist]) => {
      const formatted = allowlist
        .map((origin) => (origin === 'self' || origin === '*' ? origin : `"${origin}"`))
        .join(' ');
      return `${feature}=(${formatted})`;
    })
    .join(', ');
};

export interface CorsGuardOptions {
  allowedOrigins: string[];
  allowCredentials?: boolean;
  allowedMethods?: string[];
  allowedHeaders?: string[];
  maxAge?: number;
}

/**
 * Creates a strict CORS header generator that only emits CORS headers for
 * explicitly allowlisted origins (never reflects arbitrary `Origin` headers).
 *
 * @throws {Error} If `allowedOrigins` includes `'*'` while `allowCredentials` is `true`.
 */
export const createCorsGuard = (options: CorsGuardOptions) => {
  const {
    allowedOrigins,
    allowCredentials = false,
    allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders = ['Content-Type', 'Authorization'],
    maxAge = 86400,
  } = options;

  if (allowCredentials && allowedOrigins.includes('*')) {
    throw new Error(
      'Security Error: Wildcard "*" origin cannot be combined with allowCredentials: true.',
    );
  }

  return (requestOrigin?: string): Record<string, string> | null => {
    if (!requestOrigin) return null;
    const isWildcard = allowedOrigins.includes('*');
    if (!isWildcard && !allowedOrigins.includes(requestOrigin)) {
      return null;
    }

    const headers: Record<string, string> = {
      'Access-Control-Allow-Origin': isWildcard ? '*' : requestOrigin,
      'Access-Control-Allow-Methods': allowedMethods.join(', '),
      'Access-Control-Allow-Headers': allowedHeaders.join(', '),
      'Access-Control-Max-Age': String(maxAge),
      Vary: 'Origin',
    };

    if (allowCredentials) {
      headers['Access-Control-Allow-Credentials'] = 'true';
    }

    return headers;
  };
};
