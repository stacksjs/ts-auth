import { describe, expect, it, beforeEach, afterEach } from 'bun:test'
import {
  TokenBlacklist,
  MemoryTokenBlacklist,
  createTokenBlacklist,
  tokenBlacklistMiddleware,
} from '../src/token-blacklist'

describe('Token Blacklist Module', () => {
  describe('MemoryTokenBlacklist', () => {
    let blacklist: MemoryTokenBlacklist

    beforeEach(() => {
      blacklist = new MemoryTokenBlacklist({ cleanupIntervalMs: 60000 })
    })

    afterEach(async () => {
      await blacklist.close()
    })

    it('should add a token to the blacklist', async () => {
      const tokenId = 'test-token-123'
      const expiresAt = Date.now() + 3600000 // 1 hour from now

      await blacklist.add(tokenId, expiresAt)

      const isBlacklisted = await blacklist.has(tokenId)
      expect(isBlacklisted).toBe(true)
    })

    it('should return false for non-blacklisted token', async () => {
      const isBlacklisted = await blacklist.has('unknown-token')
      expect(isBlacklisted).toBe(false)
    })

    it('should return false for expired blacklist entry', async () => {
      const tokenId = 'expired-token'
      const expiresAt = Date.now() - 1000 // Already expired

      await blacklist.add(tokenId, expiresAt)

      const isBlacklisted = await blacklist.has(tokenId)
      expect(isBlacklisted).toBe(false)
    })

    it('should count blacklisted tokens', async () => {
      await blacklist.add('token-1', Date.now() + 3600000)
      await blacklist.add('token-2', Date.now() + 3600000)
      await blacklist.add('token-3', Date.now() + 3600000)

      const count = await blacklist.count()
      expect(count).toBe(3)
    })

    it('should clear all tokens', async () => {
      await blacklist.add('token-1', Date.now() + 3600000)
      await blacklist.add('token-2', Date.now() + 3600000)

      await blacklist.clear()

      const count = await blacklist.count()
      expect(count).toBe(0)
    })

    it('should cleanup expired tokens', async () => {
      await blacklist.add('valid-token', Date.now() + 3600000)
      await blacklist.add('expired-token-1', Date.now() - 1000)
      await blacklist.add('expired-token-2', Date.now() - 2000)

      const cleaned = await blacklist.cleanup()
      expect(cleaned).toBe(2)

      const count = await blacklist.count()
      expect(count).toBe(1)
    })
  })

  describe('TokenBlacklist Manager', () => {
    let manager: TokenBlacklist

    beforeEach(() => {
      manager = createTokenBlacklist()
    })

    afterEach(async () => {
      await manager.close()
    })

    it('should revoke a token by ID', async () => {
      const tokenId = 'test-token'
      const expiresAt = new Date(Date.now() + 3600000)

      await manager.revoke(tokenId, expiresAt)

      const isRevoked = await manager.isRevoked(tokenId)
      expect(isRevoked).toBe(true)
    })

    it('should revoke a token by ID with timestamp', async () => {
      const tokenId = 'test-token'
      const expiresAt = Date.now() + 3600000

      await manager.revoke(tokenId, expiresAt)

      const isRevoked = await manager.isRevoked(tokenId)
      expect(isRevoked).toBe(true)
    })

    it('should revoke a token from payload', async () => {
      const payload = {
        jti: 'unique-token-id',
        exp: Math.floor(Date.now() / 1000) + 3600,
      }

      const success = await manager.revokeToken(payload)
      expect(success).toBe(true)

      const isRevoked = await manager.isTokenRevoked(payload)
      expect(isRevoked).toBe(true)
    })

    it('should return false when revoking token without jti', async () => {
      const payload = {
        sub: '123',
      }

      const success = await manager.revokeToken(payload)
      expect(success).toBe(false)
    })

    it('should return false when checking token without jti', async () => {
      const isRevoked = await manager.isTokenRevoked({ sub: '123' })
      expect(isRevoked).toBe(false)
    })
  })

  describe('tokenBlacklistMiddleware', () => {
    let blacklist: TokenBlacklist

    beforeEach(() => {
      blacklist = createTokenBlacklist()
    })

    afterEach(async () => {
      await blacklist.close()
    })

    it('should allow non-blacklisted token', async () => {
      const middleware = tokenBlacklistMiddleware(
        blacklist,
        async (_request) => 'valid-token',
      )

      const request = new Request('http://localhost/api')
      const next = (_req: Request) => new Response('OK')

      const response = await middleware(request, next)
      expect(response.status).toBe(200)
    })

    it('should block blacklisted token', async () => {
      await blacklist.revoke('blocked-token', Date.now() + 3600000)

      const middleware = tokenBlacklistMiddleware(
        blacklist,
        async (_request) => 'blocked-token',
      )

      const request = new Request('http://localhost/api')
      const next = (_req: Request) => new Response('OK')

      const response = await middleware(request, next)
      expect(response.status).toBe(401)

      const body = await response.json()
      expect(body.code).toBe('TOKEN_REVOKED')
    })

    it('should allow request when token ID is null', async () => {
      const middleware = tokenBlacklistMiddleware(
        blacklist,
        async (_request) => null,
      )

      const request = new Request('http://localhost/api')
      const next = (_req: Request) => new Response('OK')

      const response = await middleware(request, next)
      expect(response.status).toBe(200)
    })
  })
})
