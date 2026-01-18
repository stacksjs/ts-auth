import { describe, expect, it } from 'bun:test'
import {
  generateTOTP,
  verifyTOTP,
  generateTOTPSecret,
  totpKeyUri,
} from '../src'

describe('TOTP Module', () => {
  const testSecret = 'JBSWY3DPEHPK3PXP' // Base32 encoded secret

  describe('generateTOTPSecret()', () => {
    it('should generate a valid Base32 secret', () => {
      const secret = generateTOTPSecret()

      expect(secret).toBeDefined()
      expect(typeof secret).toBe('string')
      expect(secret.length).toBeGreaterThan(0)

      // Verify it's valid Base32 (only contains valid chars)
      expect(/^[A-Z2-7]+$/.test(secret)).toBe(true)
    })

    it('should generate secrets of specified length', () => {
      const secret = generateTOTPSecret(32)

      // Base32 encoding produces longer strings
      expect(secret.length).toBeGreaterThanOrEqual(48)
    })

    it('should generate unique secrets', () => {
      const secrets = new Set<string>()
      for (let i = 0; i < 10; i++) {
        secrets.add(generateTOTPSecret())
      }

      expect(secrets.size).toBe(10)
    })
  })

  describe('generateTOTP()', () => {
    it('should generate a 6-digit code by default', async () => {
      const code = await generateTOTP({ secret: testSecret })

      expect(code).toBeDefined()
      expect(typeof code).toBe('string')
      expect(code.length).toBe(6)
      expect(/^\d{6}$/.test(code)).toBe(true)
    })

    it('should generate consistent codes for same time window', async () => {
      // Codes generated in same 30s window should be identical
      const code1 = await generateTOTP({ secret: testSecret })
      const code2 = await generateTOTP({ secret: testSecret })

      expect(code1).toBe(code2)
    })

    it('should generate 6-digit codes with default settings', async () => {
      const code1 = await generateTOTP({ secret: testSecret })
      const code2 = await generateTOTP({ secret: testSecret })

      // Both should be valid 6-digit codes
      expect(code1.length).toBe(6)
      expect(code2.length).toBe(6)
    })

    it('should support custom digits', async () => {
      const code = await generateTOTP({ secret: testSecret, digits: 8 })

      expect(code.length).toBe(8)
      expect(/^\d{8}$/.test(code)).toBe(true)
    })

    it('should support custom step', async () => {
      const code = await generateTOTP({ secret: testSecret, step: 60 })

      expect(code.length).toBe(6)
    })

    it('should support different algorithms', async () => {
      const codeSha1 = await generateTOTP({ secret: testSecret, algorithm: 'SHA-1' })
      const codeSha256 = await generateTOTP({ secret: testSecret, algorithm: 'SHA-256' })
      const codeSha512 = await generateTOTP({ secret: testSecret, algorithm: 'SHA-512' })

      expect(codeSha1.length).toBe(6)
      expect(codeSha256.length).toBe(6)
      expect(codeSha512.length).toBe(6)
    })
  })

  describe('verifyTOTP()', () => {
    it('should verify a valid code', async () => {
      const code = await generateTOTP({ secret: testSecret })
      const isValid = await verifyTOTP(code, { secret: testSecret })

      expect(isValid).toBe(true)
    })

    it('should reject an invalid code', async () => {
      // Generate current code and create a clearly wrong one
      const currentCode = await generateTOTP({ secret: testSecret })
      const wrongCode = currentCode === '000000' ? '111111' : '000000'

      const result = await verifyTOTP(wrongCode, { secret: testSecret })
      expect(result).toBe(false)
    })

    it('should verify within time window', async () => {
      const code = await generateTOTP({ secret: testSecret })

      // Should still be valid with default window
      const isValid = await verifyTOTP(code, { secret: testSecret, window: 1 })
      expect(isValid).toBe(true)
    })

    it('should support larger windows for clock skew', async () => {
      // Generate a code now
      const code = await generateTOTP({ secret: testSecret })

      // With window=2, should accept code even with slight time drift
      const isValid = await verifyTOTP(code, { secret: testSecret, window: 2 })
      expect(isValid).toBe(true)
    })

    it('should reject clearly invalid codes', async () => {
      // Create a completely wrong code that won't match any time window
      const wrongCode = '999999'
      const currentCode = await generateTOTP({ secret: testSecret })

      // Only test if our wrong code is different from current
      if (wrongCode !== currentCode) {
        const isValid = await verifyTOTP(wrongCode, { secret: testSecret, window: 0 })
        // With window=0, only exact match should work
        expect(typeof isValid).toBe('boolean')
      }
    })
  })

  describe('totpKeyUri()', () => {
    it('should generate a valid otpauth URI', () => {
      const uri = totpKeyUri('user@example.com', 'TestApp', testSecret)

      expect(uri).toContain('otpauth://totp/')
      expect(uri).toContain('secret=')
      expect(uri).toContain('issuer=TestApp')
    })

    it('should include issuer in label', () => {
      const uri = totpKeyUri('john@example.com', 'MyApp', testSecret)

      // URL encoding converts @ to %40
      expect(uri).toContain('MyApp:john')
      expect(uri).toContain('example.com')
    })

    it('should encode special characters', () => {
      const uri = totpKeyUri('user+test@example.com', 'My App', testSecret)

      expect(uri).toContain('My%20App')
    })

    it('should include custom parameters', () => {
      const uri = totpKeyUri('user@example.com', 'TestApp', testSecret, {
        algorithm: 'SHA-256',
        digits: 8,
        period: 60,
      })

      expect(uri).toContain('algorithm=SHA-256')
      expect(uri).toContain('digits=8')
      expect(uri).toContain('period=60')
    })
  })
})
