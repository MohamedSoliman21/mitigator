import { describe, it, expect } from 'vitest';
import { parse, getDepth, containsPollution } from './index.js';

describe('Safe JSON Module', () => {
  describe('parse', () => {
    it('should parse valid JSON', () => {
      const input = '{"foo": "bar", "num": 123}';
      expect(parse(input)).toEqual({ foo: 'bar', num: 123 });
    });

    it('should strip prototype pollution keys', () => {
      const input =
        '{"foo": "bar", "__proto__": {"polluted": true}, "constructor": {"polluted": true}}';
      const result = parse(input);
      expect(result.foo).toBe('bar');
      expect(Object.hasOwn(result, '__proto__')).toBe(false);
      expect(Object.hasOwn(result, 'constructor')).toBe(false);
      expect(Object.hasOwn(result, 'prototype')).toBe(false);
    });

    it('should throw error if max depth exceeded', () => {
      const deep = '{"a":{"a":{"a":{"a":{"a":{"a":{"a":1}}}}}}}'; // Depth 7
      expect(() => parse(deep, 5)).toThrow('Security Error: JSON depth limit exceeded');
    });
  });

  describe('getDepth', () => {
    it('should return 0 for non-objects', () => {
      expect(getDepth(123)).toBe(0);
      expect(getDepth('str')).toBe(0);
      expect(getDepth(null)).toBe(0);
    });

    it('should calculate depth of object', () => {
      expect(getDepth({})).toBe(1);
      expect(getDepth({ a: 1 })).toBe(1);
      expect(getDepth({ a: { b: 1 } })).toBe(2);
      expect(getDepth({ a: { b: { c: 1 } } })).toBe(3);
    });

    it('should handle multiple keys at the same level', () => {
      expect(getDepth({ a: 1, b: { c: 2 } })).toBe(2);
    });

    it('should ignore inherited properties', () => {
      const obj = Object.create({ inherited: { depth: 10 } });
      obj.own = 2;
      expect(getDepth(obj)).toBe(1);
    });
  });

  describe('containsPollution', () => {
    it('should return false for clean objects', () => {
      expect(containsPollution({ a: 1, b: { c: 2 } })).toBe(false);
    });

    it('should detect __proto__ key', () => {
      const polluted = JSON.parse('{"__proto__": {"polluted": true}}');
      expect(containsPollution(polluted)).toBe(true);
    });

    it('should detect constructor key', () => {
      const polluted = JSON.parse('{"constructor": {"polluted": true}}');
      expect(containsPollution(polluted)).toBe(true);
    });

    it('should detect prototype key', () => {
      const polluted = JSON.parse('{"prototype": {"polluted": true}}');
      expect(containsPollution(polluted)).toBe(true);
    });

    it('should detect pollution in nested objects', () => {
      const polluted = JSON.parse('{"a": {"b": {"__proto__": {}}}}');
      expect(containsPollution(polluted)).toBe(true);
    });
  });
});
