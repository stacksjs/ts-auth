import { describe, expect, it } from 'bun:test'
import {
  validateEmail,
  validateUrl,
  validateRedirectUri,
  validateRpId,
  validateBase32,
  validateJwtAlgorithm,
  validateDuration,
  validateLength,
  validateRequired,
  validatePositiveNumber,
  validateProviderName,
  validateOAuthCredentials,
  sanitizeString,
  validateUsername,
  validateScopes,
} from '../src/validation'
import { ValidationError, InvalidEmailError, InvalidUrlError } from '../src/errors'

describe('Validation Module', () => {
  describe('validateEmail()', () => {
    it('should accept valid emails', () => {
      expect(() => validateEmail('user@example.com')).not.toThrow()
      expect(() => validateEmail('user.name@example.com')).not.toThrow()
      expect(() => validateEmail('user+tag@example.com')).not.toThrow()
      expect(() => validateEmail('user@subdomain.example.com')).not.toThrow()
    })

    it('should reject invalid emails', () => {
      expect(() => validateEmail('')).toThrow(InvalidEmailError)
      expect(() => validateEmail('invalid')).toThrow(InvalidEmailError)
      expect(() => validateEmail('user@')).toThrow(InvalidEmailError)
      expect(() => validateEmail('@example.com')).toThrow(InvalidEmailError)
    })
  })

  describe('validateUrl()', () => {
    it('should accept valid URLs', () => {
      expect(() => validateUrl('https://example.com')).not.toThrow()
      expect(() => validateUrl('http://localhost:3000')).not.toThrow()
      expect(() => validateUrl('https://example.com/path?query=value')).not.toThrow()
    })

    it('should reject invalid URLs', () => {
      expect(() => validateUrl('')).toThrow(InvalidUrlError)
      expect(() => validateUrl('not-a-url')).toThrow(InvalidUrlError)
      expect(() => validateUrl('ftp://example.com')).toThrow(InvalidUrlError)
    })
  })

  describe('validateRedirectUri()', () => {
    it('should accept valid redirect URIs', () => {
      expect(() => validateRedirectUri('https://example.com/callback')).not.toThrow()
      expect(() => validateRedirectUri('http://localhost:3000/auth')).not.toThrow()
    })

    it('should reject redirect URIs with fragments', () => {
      expect(() => validateRedirectUri('https://example.com/callback#fragment')).toThrow(ValidationError)
    })

    it('should reject invalid URLs', () => {
      expect(() => validateRedirectUri('not-a-url')).toThrow(InvalidUrlError)
    })
  })

  describe('validateRpId()', () => {
    it('should accept valid RP IDs', () => {
      expect(() => validateRpId('example.com')).not.toThrow()
      expect(() => validateRpId('subdomain.example.com')).not.toThrow()
      expect(() => validateRpId('localhost')).not.toThrow()
    })

    it('should reject invalid RP IDs', () => {
      expect(() => validateRpId('')).toThrow(ValidationError)
      expect(() => validateRpId('invalid!')).toThrow(ValidationError)
    })
  })

  describe('validateBase32()', () => {
    it('should accept valid Base32 strings', () => {
      expect(() => validateBase32('JBSWY3DPEHPK3PXP')).not.toThrow()
      expect(() => validateBase32('ABCDEFGHIJKLMNOP')).not.toThrow()
    })

    it('should reject invalid Base32 strings', () => {
      expect(() => validateBase32('')).toThrow(ValidationError)
      expect(() => validateBase32('invalid!')).toThrow(ValidationError)
      expect(() => validateBase32('short')).toThrow(ValidationError) // too short
    })
  })

  describe('validateJwtAlgorithm()', () => {
    it('should accept valid algorithms', () => {
      expect(() => validateJwtAlgorithm('HS256')).not.toThrow()
      expect(() => validateJwtAlgorithm('HS384')).not.toThrow()
      expect(() => validateJwtAlgorithm('HS512')).not.toThrow()
      expect(() => validateJwtAlgorithm('RS256')).not.toThrow()
      expect(() => validateJwtAlgorithm('RS384')).not.toThrow()
      expect(() => validateJwtAlgorithm('RS512')).not.toThrow()
      expect(() => validateJwtAlgorithm('ES256')).not.toThrow()
      expect(() => validateJwtAlgorithm('ES384')).not.toThrow()
      expect(() => validateJwtAlgorithm('ES512')).not.toThrow()
    })

    it('should reject invalid algorithms', () => {
      expect(() => validateJwtAlgorithm('HS128')).toThrow(ValidationError)
      expect(() => validateJwtAlgorithm('INVALID')).toThrow(ValidationError)
      expect(() => validateJwtAlgorithm('')).toThrow(ValidationError)
    })
  })

  describe('validateDuration()', () => {
    it('should accept valid durations', () => {
      expect(() => validateDuration('30s')).not.toThrow()
      expect(() => validateDuration('15m')).not.toThrow()
      expect(() => validateDuration('24h')).not.toThrow()
      expect(() => validateDuration('7d')).not.toThrow()
      expect(() => validateDuration('1w')).not.toThrow()
    })

    it('should reject invalid durations', () => {
      expect(() => validateDuration('')).toThrow(ValidationError)
      expect(() => validateDuration('abc')).toThrow(ValidationError)
    })
  })

  describe('validateLength()', () => {
    it('should accept valid string lengths', () => {
      expect(() => validateLength('hello', 'field', { min: 1, max: 10 })).not.toThrow()
      expect(() => validateLength('test', 'field', { min: 3 })).not.toThrow()
      expect(() => validateLength('hi', 'field', { max: 5 })).not.toThrow()
    })

    it('should reject strings too short', () => {
      expect(() => validateLength('hi', 'field', { min: 3 })).toThrow(ValidationError)
    })

    it('should reject strings too long', () => {
      expect(() => validateLength('hello world', 'field', { max: 5 })).toThrow(ValidationError)
    })
  })

  describe('validateRequired()', () => {
    it('should accept non-empty values', () => {
      expect(() => validateRequired('hello', 'field')).not.toThrow()
      expect(() => validateRequired(0, 'field')).not.toThrow()
      expect(() => validateRequired(false, 'field')).not.toThrow()
      expect(() => validateRequired([], 'field')).not.toThrow()
    })

    it('should reject empty values', () => {
      expect(() => validateRequired('', 'field')).toThrow(ValidationError)
      expect(() => validateRequired(null, 'field')).toThrow(ValidationError)
      expect(() => validateRequired(undefined, 'field')).toThrow(ValidationError)
    })
  })

  describe('validatePositiveNumber()', () => {
    it('should accept positive numbers', () => {
      expect(() => validatePositiveNumber(1, 'field')).not.toThrow()
      expect(() => validatePositiveNumber(100, 'field')).not.toThrow()
      expect(() => validatePositiveNumber(0.5, 'field')).not.toThrow()
    })

    it('should reject non-positive numbers', () => {
      expect(() => validatePositiveNumber(0, 'field')).toThrow(ValidationError)
      expect(() => validatePositiveNumber(-1, 'field')).toThrow(ValidationError)
      expect(() => validatePositiveNumber(Number.NaN, 'field')).toThrow(ValidationError)
    })
  })

  describe('validateProviderName()', () => {
    it('should accept valid provider names', () => {
      expect(() => validateProviderName('google')).not.toThrow()
      expect(() => validateProviderName('my-provider')).not.toThrow()
      expect(() => validateProviderName('my123')).not.toThrow()
    })

    it('should reject invalid provider names', () => {
      expect(() => validateProviderName('')).toThrow(ValidationError)
      expect(() => validateProviderName('my provider')).toThrow(ValidationError)
      expect(() => validateProviderName('my@provider')).toThrow(ValidationError)
    })
  })

  describe('validateOAuthCredentials()', () => {
    it('should accept valid credentials', () => {
      expect(() => validateOAuthCredentials('abc123', 'secret456')).not.toThrow()
    })

    it('should reject missing clientId', () => {
      expect(() => validateOAuthCredentials('', 'secret456')).toThrow(ValidationError)
    })

    it('should reject missing clientSecret', () => {
      expect(() => validateOAuthCredentials('abc123', '')).toThrow(ValidationError)
    })
  })

  describe('sanitizeString()', () => {
    it('should remove control characters', () => {
      expect(sanitizeString('hello\x00world')).toBe('helloworld')
      expect(sanitizeString('test\x1Fvalue')).toBe('testvalue')
    })

    it('should preserve normal text', () => {
      expect(sanitizeString('hello world')).toBe('hello world')
    })

    it('should handle null and undefined', () => {
      expect(sanitizeString(null as any)).toBe('')
      expect(sanitizeString(undefined as any)).toBe('')
    })
  })

  describe('validateUsername()', () => {
    it('should accept and sanitize valid usernames', () => {
      expect(validateUsername('john_doe')).toBe('john_doe')
      expect(validateUsername('john123')).toBe('john123')
      expect(validateUsername('JohnDoe')).toBe('JohnDoe')
    })

    it('should reject empty usernames', () => {
      expect(() => validateUsername('')).toThrow(ValidationError)
    })
  })

  describe('validateScopes()', () => {
    it('should accept and return valid scopes array', () => {
      const scopes = validateScopes(['openid', 'email', 'profile'])
      expect(scopes).toEqual(['openid', 'email', 'profile'])
    })

    it('should parse string scopes', () => {
      const scopes = validateScopes('read write')
      expect(scopes).toEqual(['read', 'write'])
    })

    it('should reject invalid scope format', () => {
      expect(() => validateScopes(['valid', ''])).toThrow(ValidationError)
    })

    it('should accept empty array (parsed from empty string)', () => {
      const scopes = validateScopes('')
      expect(scopes).toEqual([])
    })
  })
})
