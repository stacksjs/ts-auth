import { describe, expect, it, beforeEach } from 'bun:test'
import {
  signJwt,
  verifyJwt,
  decodeJwt,
  createTokenPair,
  parseDuration,
  TokenManager,
  createTokenManager,
} from '../src'

describe('JWT Module', () => {
  const secret = 'test-secret-key-that-is-at-least-32-bytes-long'

  describe('parseDuration()', () => {
    it('should parse seconds', () => {
      expect(parseDuration('30s')).toBe(30)
      expect(parseDuration('1s')).toBe(1)
    })

    it('should parse minutes', () => {
      expect(parseDuration('5m')).toBe(300)
      expect(parseDuration('1m')).toBe(60)
    })

    it('should parse hours', () => {
      expect(parseDuration('2h')).toBe(7200)
      expect(parseDuration('1h')).toBe(3600)
    })

    it('should parse days', () => {
      expect(parseDuration('7d')).toBe(604800)
      expect(parseDuration('1d')).toBe(86400)
    })

    it('should parse weeks', () => {
      expect(parseDuration('1w')).toBe(604800)
      expect(parseDuration('2w')).toBe(1209600)
    })

    it('should throw for invalid format', () => {
      expect(() => parseDuration('invalid')).toThrow()
    })
  })

  describe('signJwt()', () => {
    it('should sign a payload with HS256', async () => {
      const payload = { sub: '123', name: 'John Doe' }
      const token = await signJwt(payload, secret)

      expect(token).toBeDefined()
      expect(typeof token).toBe('string')
      expect(token.split('.').length).toBe(3)
    })

    it('should sign with custom expiration', async () => {
      const payload = { sub: '123' }
      const token = await signJwt(payload, secret, { expiresIn: '1h' })

      const decoded = await verifyJwt(token, secret)
      expect(decoded.exp).toBeDefined()
    })

    it('should include custom claims', async () => {
      const payload = { sub: '123', role: 'admin', permissions: ['read', 'write'] }
      const token = await signJwt(payload, secret)

      const decoded = await verifyJwt(token, secret)
      expect(decoded.sub).toBe('123')
      expect(decoded.role).toBe('admin')
      expect(decoded.permissions).toEqual(['read', 'write'])
    })

    it('should set issuer', async () => {
      const payload = { sub: '123' }
      const token = await signJwt(payload, secret, { issuer: 'test-app' })

      const decoded = await verifyJwt(token, secret)
      expect(decoded.iss).toBe('test-app')
    })

    it('should set audience', async () => {
      const payload = { sub: '123' }
      const token = await signJwt(payload, secret, { audience: 'test-audience' })

      const decoded = await verifyJwt(token, secret)
      expect(decoded.aud).toBe('test-audience')
    })
  })

  describe('verifyJwt()', () => {
    it('should verify a valid token', async () => {
      const payload = { sub: '123', name: 'John' }
      const token = await signJwt(payload, secret)

      const decoded = await verifyJwt(token, secret)
      expect(decoded.sub).toBe('123')
      expect(decoded.name).toBe('John')
    })

    it('should reject token with wrong secret', async () => {
      const payload = { sub: '123' }
      const token = await signJwt(payload, secret)

      await expect(verifyJwt(token, 'wrong-secret-that-is-also-32-bytes')).rejects.toThrow()
    })

    it('should reject expired token', async () => {
      // Create a token with exp in the past
      const pastTime = Math.floor(Date.now() / 1000) - 3600 // 1 hour ago
      const payload = { sub: '123', exp: pastTime }
      const token = await signJwt(payload, secret)

      await expect(verifyJwt(token, secret)).rejects.toThrow()
    })

    it('should verify issuer', async () => {
      const payload = { sub: '123' }
      const token = await signJwt(payload, secret, { issuer: 'test-app' })

      const decoded = await verifyJwt(token, secret, { issuer: 'test-app' })
      expect(decoded.iss).toBe('test-app')
    })

    it('should reject wrong issuer', async () => {
      const payload = { sub: '123' }
      const token = await signJwt(payload, secret, { issuer: 'test-app' })

      await expect(verifyJwt(token, secret, { issuer: 'other-app' })).rejects.toThrow()
    })
  })

  describe('decodeJwt()', () => {
    it('should decode a token without verification', async () => {
      const payload = { sub: '123', name: 'John' }
      const token = await signJwt(payload, secret)

      const decoded = decodeJwt(token)
      expect(decoded).not.toBeNull()
      expect(decoded!.payload.sub).toBe('123')
      expect(decoded!.payload.name).toBe('John')
    })

    it('should decode header and payload', async () => {
      const payload = { sub: '123' }
      const token = await signJwt(payload, secret)

      const decoded = decodeJwt(token)
      expect(decoded).not.toBeNull()
      expect(decoded!.header).toBeDefined()
      expect(decoded!.payload).toBeDefined()
      expect(decoded!.header.alg).toBe('HS256')
    })
  })

  describe('createTokenPair()', () => {
    it('should create access and refresh tokens', async () => {
      const pair = await createTokenPair('123', secret, {
        expiry: '15m',
        refresh: true,
        refreshExpiry: '7d',
      })

      expect(pair.accessToken).toBeDefined()
      expect(pair.refreshToken).toBeDefined()
      expect(pair.accessToken).not.toBe(pair.refreshToken)
    })

    it('should set different expirations', async () => {
      const pair = await createTokenPair('123', secret, {
        expiry: '15m',
        refresh: true,
        refreshExpiry: '7d',
      })

      const accessDecoded = await verifyJwt(pair.accessToken, secret)
      const refreshDecoded = await verifyJwt(pair.refreshToken!, secret)

      expect(refreshDecoded.exp).toBeGreaterThan(accessDecoded.exp!)
    })
  })

  describe('TokenManager', () => {
    let manager: TokenManager

    beforeEach(() => {
      manager = createTokenManager(secret, {
        expiry: '15m',
        refresh: true,
        refreshExpiry: '7d',
      })
    })

    it('should create personal access token', async () => {
      const result = await manager.createToken('123', 'test-token', ['read', 'write'])

      expect(result.token).toBeDefined()
      expect(result.plainTextToken).toBeDefined()
      expect(result.token.userId).toBe('123')
      expect(result.token.name).toBe('test-token')
      expect(result.token.abilities).toEqual(['read', 'write'])
    })

    it('should find token by plain text', async () => {
      const result = await manager.createToken('123', 'test-token')
      const found = await manager.findToken(result.plainTextToken)

      expect(found).not.toBeNull()
      expect(found!.userId).toBe('123')
    })

    it('should create JWT token pair', async () => {
      const pair = await manager.createJwtTokenPair('123', { role: 'user' })

      expect(pair.accessToken).toBeDefined()
      expect(pair.refreshToken).toBeDefined()

      const accessDecoded = await manager.verifyJwtToken(pair.accessToken)
      expect(accessDecoded.sub).toBe('123')
    })

    it('should refresh JWT tokens', async () => {
      const pair = await manager.createJwtTokenPair('123')

      const newPair = await manager.refreshJwtTokenPair(pair.refreshToken!)

      expect(newPair.accessToken).toBeDefined()
      expect(newPair.accessToken).not.toBe(pair.accessToken)
    })

    it('should check token abilities', async () => {
      const result = await manager.createToken('123', 'limited', ['read'])

      expect(manager.tokenCan(result.token, 'read')).toBe(true)
      expect(manager.tokenCan(result.token, 'write')).toBe(false)
      expect(manager.tokenCannot(result.token, 'delete')).toBe(true)
    })

    it('should revoke tokens', async () => {
      const result = await manager.createToken('123', 'to-revoke')

      expect(manager.revokeToken(result.token.id)).toBe(true)

      const found = await manager.findToken(result.plainTextToken)
      expect(found).toBeNull()
    })
  })
})
