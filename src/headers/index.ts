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
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
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
  return buildCSP(
    {
      'object-src': ["'none'"],
      'script-src': ["'strict-dynamic'", `'nonce-${nonce}'`, "'unsafe-inline'", 'http:', 'https:'],
      'base-uri': ["'none'"],
    },
    nonce,
  );
};

/**
 * Parses CSP violation report.
 */
export const parseCSPReport = (reportBody: any) => {
  if (!reportBody) return null;
  const report =
    reportBody['csp-report'] || (Array.isArray(reportBody) ? reportBody[0] : reportBody);
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
