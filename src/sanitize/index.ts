/**
 * Basic HTML escaping for common characters.
 */
export const escapeHtml = (input: string): string => {
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  };
  return input.replaceAll(/[&<>"']/g, (m) => map[m]!);
};

/**
 * Strips all HTML tags from a string.
 */
export const stripTags = (input: string): string => {
  return input.replaceAll(/<[^>]*>?/gm, '');
};

import sanitizeHtmlLib from 'sanitize-html';

/**
 * Standard allowlist for "clean" HTML sanitization.
 */
export const ALLOWLIST: Record<string, string[]> = {
  b: [],
  i: [],
  em: [],
  strong: [],
  p: ['style'],
  a: ['href', 'title', 'target'],
  ul: [],
  ol: [],
  li: [],
  br: [],
  span: ['style'],
};

/**
 * Robust HTML sanitizer.
 * Uses the industry-standard `sanitize-html` library.
 */
export const sanitizeHtml = (html: string, rules: Record<string, string[]> = ALLOWLIST): string => {
  return sanitizeHtmlLib(html, {
    allowedTags: Object.keys(rules),
    allowedAttributes: rules,
    allowedSchemes: ['http', 'https', 'mailto', 'tel'],
    allowProtocolRelative: false,
    enforceHtmlBoundary: true,
  });
};

/**
 * Defensive post-processor that namespaces 'id' and 'name' attributes to prevent DOM Clobbering attacks.
 * Attackers use clobbering to overwrite global variables (window.foo) by naming an element 'id=foo'.
 *
 * @param html The HTML string to process.
 * @param prefix The unique namespace prefix (default: sk-).
 */
export const preventDOMClobbering = (html: string, prefix: string = 'sk-'): string => {
  const attrRegex = /(\s(id|name)\s*=\s*)(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;

  return html.replaceAll(attrRegex, (_match, attrPrefix, _attrName, val1, val2, val3) => {
    const value = val1 || val2 || val3;

    let quote: string;
    if (val3) {
      quote = '';
    } else if (val1) {
      quote = '"';
    } else {
      quote = "'";
    }

    return `${attrPrefix}${quote}${prefix}${value}${quote}`;
  });
};

/**
 * Basic SVG & MathML sanitization.
 */
export const sanitizeMediaTags = (html: string): string => {
  const dangerousTags = [
    'script',
    'animate',
    'set',
    'animateMotion',
    'animateTransform',
    'handler',
    'discard',
    'foreignObject',
  ];
  let result = html;
  dangerousTags.forEach((tag) => {
    const regex = new RegExp(String.raw`<${tag}[^>]*>[\s\S]*?<\/${tag}>|<${tag}[^>]*\/>`, 'gi');
    result = result.replaceAll(regex, '');
  });
  return result;
};

/**
 * Validates if a string is a safe URL.
 */
export const isSafeUrl = (url: string): boolean => {
  const allowedProtocols = ['https:', 'http:', 'mailto:', 'tel:'];
  try {
    const parsed = new URL(url);
    return allowedProtocols.includes(parsed.protocol);
  } catch {
    const low = url.trim().toLowerCase();
    return (
      !low.startsWith('javascript:') &&
      !low.startsWith('//') &&
      (low.startsWith('/') || low.startsWith('.'))
    );
  }
};
