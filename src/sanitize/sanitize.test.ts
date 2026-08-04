import { describe, it, expect } from 'vitest';
import {
  escapeHtml,
  stripTags,
  sanitizeHtml,
  preventDOMClobbering,
  sanitizeMediaTags,
  isSafeUrl,
} from './index.js';

describe('Sanitization Module', () => {
  describe('escapeHtml', () => {
    it('should escape basic HTML characters', () => {
      expect(escapeHtml('<script>alert("XSS")</script>')).toBe(
        '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;',
      );
      expect(escapeHtml("' OR 1=1 --")).toBe('&#39; OR 1=1 --');
      expect(escapeHtml('foo & bar')).toBe('foo &amp; bar');
    });

    it('should return empty string for empty input', () => {
      expect(escapeHtml('')).toBe('');
    });
  });

  describe('stripTags', () => {
    it('should strip all HTML tags', () => {
      expect(stripTags('<p>Hello <b>World</b>!</p>')).toBe('Hello World!');
      expect(stripTags('<script>alert(1)</script>')).toBe('alert(1)');
    });

    it('should handle nested tags', () => {
      expect(stripTags('<div><span>nested</span></div>')).toBe('nested');
    });
  });

  describe('sanitizeHtml', () => {
    it('should allow whitelisted tags and attributes', () => {
      const input =
        '<p style="color:red">Hello <a href="https://example.com" title="link">World</a></p>';
      const sanitized = sanitizeHtml(input);
      expect(sanitized).toContain('<p style="color:red">');
      expect(sanitized).toContain('<a href="https://example.com" title="link">');
    });

    it('should block dangerous scripts and event handlers', () => {
      const input = '<p onclick="alert(1)">Text</p><script>evil()</script>';
      const sanitized = sanitizeHtml(input);
      expect(sanitized).toBe('<p>Text</p>');
    });

    it('should block malicious href protocols', () => {
      const input = '<a href="javascript:alert(1)">Link</a>';
      const sanitized = sanitizeHtml(input);
      expect(sanitized).toBe('<a>Link</a>');
    });

    it('should block unknown tags', () => {
      const input = '<unknown>Tag</unknown>';
      const sanitized = sanitizeHtml(input);
      expect(sanitized).toBe('Tag');
    });
  });

  describe('preventDOMClobbering', () => {
    it('should prefix id and name attributes', () => {
      const input = '<div id="foo" name="bar"></div>';
      const sanitized = preventDOMClobbering(input, 'test-');
      expect(sanitized).toBe('<div id="test-foo" name="test-bar"></div>');
    });

    it('should use default prefix sk-', () => {
      const input = '<div id="foo"></div>';
      const sanitized = preventDOMClobbering(input);
      expect(sanitized).toBe('<div id="sk-foo"></div>');
    });

    it('should handle single quotes', () => {
      const input = "<div id='foo'></div>";
      const sanitized = preventDOMClobbering(input);
      expect(sanitized).toBe("<div id='sk-foo'></div>");
    });

    it('should handle no quotes', () => {
      const input = '<div id=foo></div>';
      const sanitized = preventDOMClobbering(input);
      expect(sanitized).toBe('<div id=sk-foo></div>');
    });
  });

  describe('sanitizeMediaTags', () => {
    it('should remove dangerous SVG elements', () => {
      const input = '<svg><script>alert(1)</script><circle cx="50" cy="50" r="40" /></svg>';
      const sanitized = sanitizeMediaTags(input);
      expect(sanitized).not.toContain('<script>');
      expect(sanitized).toContain('<circle cx="50" cy="50" r="40" />');
    });

    it('should remove animate tags', () => {
      const input = '<animate attributeName="href" values="javascript:alert(1)" />';
      const sanitized = sanitizeMediaTags(input);
      expect(sanitized).toBe('');
    });
  });

  describe('isSafeUrl', () => {
    it('should allow safe protocols', () => {
      expect(isSafeUrl('https://google.com')).toBe(true);
      expect(isSafeUrl('mailto:user@example.com')).toBe(true);
      expect(isSafeUrl('tel:+123456789')).toBe(true);
    });

    it('should block javascript: protocol', () => {
      expect(isSafeUrl('javascript:alert(1)')).toBe(false);
      expect(isSafeUrl(' JAVASCRIPT:alert(1)')).toBe(false);
    });

    it('should allow relative paths', () => {
      expect(isSafeUrl('/path/to/resource')).toBe(true);
      expect(isSafeUrl('./local')).toBe(true);
    });

    it('should block data: and blob: (not in whitelist)', () => {
      expect(isSafeUrl('data:text/html,evil')).toBe(false);
    });
  });
});
