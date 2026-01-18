import { describe, expect, it } from 'bun:test'
import {
  hash,
  verify as verifyHash,
  needsRehash,
  createHasher,
  generateRandomString,
  generateToken,
} from '../src/hash'

describe('Hash Module', () => {
  describe('hash()', () => {
    it('should hash a password', async () => {
      const password = 'testPassword123!'
      const hashed = await hash(password)

      expect(hashed).toBeDefined()
      expect(typeof hashed).toBe('string')
      expect(hashed).not.toBe(password)
      expect(hashed.includes('$')).toBe(true)
    })

    it('should produce different hashes for the same password', async () => {
      const password = 'testPassword123!'
      const hash1 = await hash(password)
      const hash2 = await hash(password)

      expect(hash1).not.toBe(hash2)
    })

    it('should work with custom iterations', async () => {
      const password = 'testPassword123!'
      const hashed = await hash(password, { iterations: 50000 })

      expect(hashed).toBeDefined()
      expect(hashed.includes('50000')).toBe(true)
    })

    it('should work with custom salt length', async () => {
      const password = 'testPassword123!'
      const hashed = await hash(password, { saltLength: 32 })

      expect(hashed).toBeDefined()
    })
  })

  describe('verify()', () => {
    it('should verify a correct password', async () => {
      const password = 'testPassword123!'
      const hashed = await hash(password)

      const isValid = await verifyHash(password, hashed)
      expect(isValid).toBe(true)
    })

    it('should reject an incorrect password', async () => {
      const password = 'testPassword123!'
      const hashed = await hash(password)

      const isValid = await verifyHash('wrongPassword', hashed)
      expect(isValid).toBe(false)
    })

    it('should handle empty password', async () => {
      const password = ''
      const hashed = await hash(password)

      const isValid = await verifyHash(password, hashed)
      expect(isValid).toBe(true)
    })

    it('should handle special characters', async () => {
      const password = '!@#$%^&*()_+-=[]{}|;:,.<>?'
      const hashed = await hash(password)

      const isValid = await verifyHash(password, hashed)
      expect(isValid).toBe(true)
    })

    it('should handle unicode characters', async () => {
      const password = 'пароль密码كلمة'
      const hashed = await hash(password)

      const isValid = await verifyHash(password, hashed)
      expect(isValid).toBe(true)
    })
  })

  describe('needsRehash()', () => {
    it('should return false for freshly hashed password', async () => {
      const password = 'testPassword123!'
      const hashed = await hash(password)

      const needs = needsRehash(hashed)
      expect(needs).toBe(false)
    })

    it('should return true when iterations differ', async () => {
      const password = 'testPassword123!'
      const hashed = await hash(password, { iterations: 50000 })

      const needs = needsRehash(hashed, { iterations: 100000 })
      expect(needs).toBe(true)
    })

    it('should return true for malformed hash', () => {
      const needs = needsRehash('invalid-hash')
      expect(needs).toBe(true)
    })
  })

  describe('createHasher()', () => {
    it('should create a hasher with custom options', async () => {
      const hasher = createHasher({ iterations: 50000 })

      const password = 'testPassword123!'
      const hashed = await hasher.make(password)

      expect(hashed).toBeDefined()

      const isValid = await hasher.check(password, hashed)
      expect(isValid).toBe(true)
    })
  })

  describe('generateRandomString()', () => {
    it('should generate a hex string from specified bytes', () => {
      const str = generateRandomString(16)

      expect(str).toBeDefined()
      expect(typeof str).toBe('string')
      // 16 bytes = 32 hex characters (2 chars per byte)
      expect(str.length).toBe(32)
      expect(/^[a-f0-9]+$/.test(str)).toBe(true)
    })

    it('should generate different strings each time', () => {
      const str1 = generateRandomString(16)
      const str2 = generateRandomString(16)

      expect(str1).not.toBe(str2)
    })

    it('should generate hex string by default', () => {
      const str = generateRandomString(16)

      // Should be valid hex
      expect(/^[a-f0-9]+$/.test(str)).toBe(true)
    })
  })

  describe('generateToken()', () => {
    it('should generate a URL-safe base64 token', () => {
      const token = generateToken()

      expect(token).toBeDefined()
      expect(typeof token).toBe('string')
      // 32 bytes in base64 is ~43 chars (without padding)
      expect(token.length).toBeGreaterThan(40)
      // Should be URL-safe (no + or /)
      expect(token).not.toContain('+')
      expect(token).not.toContain('/')
    })

    it('should generate tokens of varying lengths', () => {
      const token16 = generateToken(16)
      const token32 = generateToken(32)

      // Larger input should produce longer output
      expect(token32.length).toBeGreaterThan(token16.length)
    })

    it('should generate unique tokens', () => {
      const tokens = new Set<string>()
      for (let i = 0; i < 100; i++) {
        tokens.add(generateToken())
      }

      expect(tokens.size).toBe(100)
    })
  })
})
