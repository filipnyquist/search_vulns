import { describe, test, expect } from '@jest/globals';
import { validateQuery, sanitizeQuery, validateCPE, isVulnerabilityId } from '../validation.js';

describe('Validation', () => {
  describe('validateQuery', () => {
    test('should accept valid queries', () => {
      expect(() => validateQuery('Apache 2.4.39')).not.toThrow();
      expect(() => validateQuery('cpe:2.3:a:apache:http_server:2.4.39')).not.toThrow();
      expect(() => validateQuery('CVE-2023-1234')).not.toThrow();
    });

    test('should reject empty queries', () => {
      expect(() => validateQuery('')).toThrow('Query cannot be empty');
      expect(() => validateQuery('   ')).toThrow('Query cannot be empty');
    });

    test('should reject overly long queries', () => {
      const longQuery = 'a'.repeat(300);
      expect(() => validateQuery(longQuery)).toThrow('Query length is limited to');
    });

    test('should reject suspicious patterns', () => {
      expect(() => validateQuery('<script>alert(1)</script>')).toThrow('Query contains invalid characters');
      expect(() => validateQuery('javascript:alert(1)')).toThrow('Query contains invalid characters');
    });
  });

  describe('sanitizeQuery', () => {
    test('should trim whitespace', () => {
      expect(sanitizeQuery('  Apache 2.4.39  ')).toBe('Apache 2.4.39');
    });
  });

  describe('validateCPE', () => {
    test('should validate correct CPE strings', () => {
      expect(validateCPE('cpe:2.3:a:apache:http_server:2.4.39:*:*:*:*:*:*:*')).toBe(true);
      expect(validateCPE('cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*')).toBe(true);
    });

    test('should reject invalid CPE strings', () => {
      expect(validateCPE('invalid-cpe')).toBe(false);
      expect(validateCPE('cpe:2.2:a:apache:http_server')).toBe(false);
    });
  });

  describe('isVulnerabilityId', () => {
    test('should identify CVE IDs', () => {
      expect(isVulnerabilityId('CVE-2023-1234')).toBe(true);
      expect(isVulnerabilityId('CVE-2023-12345')).toBe(true);
    });

    test('should identify GHSA IDs', () => {
      expect(isVulnerabilityId('GHSA-xxxx-yyyy-zzzz')).toBe(true);
    });

    test('should reject non-vulnerability strings', () => {
      expect(isVulnerabilityId('Apache 2.4.39')).toBe(false);
      expect(isVulnerabilityId('random-string')).toBe(false);
    });
  });
});