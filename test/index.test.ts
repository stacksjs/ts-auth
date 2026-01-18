/**
 * ts-auth Integration Tests
 *
 * This file tests that all exports are properly available and
 * demonstrates common usage patterns for the library.
 */
import { describe, expect, it, beforeEach, afterEach } from 'bun:test'
import {
  // Auth Manager
  createAuthManager,
  AuthenticationManager,

  // Session
  SessionManager,
  createSession,
  sessionMiddleware,
  csrfMiddleware,

  // JWT
  signJwt,
  verifyJwt,
  decodeJwt,
  createTokenPair,

  // Hash
  hash,
  verifyHash,
  generateToken,

  // TOTP
  generateTOTP,
  verifyTOTP,
  generateTOTPSecret,

  // Rate Limiting
  AuthRateLimiter,
  createAuthRateLimiter,
  AccountLockoutManager,
  createAccountLockout,

  // Token Blacklist
  TokenBlacklist,
  createTokenBlacklist,

  // Audit
  AuditLogger,
  createAuditLogger,

  // Validation
  validateEmail,
  validateUrl,

  // Errors
  AuthError,
  TokenExpiredError,
  InvalidCredentialsError,
} from '../src'

describe('ts-auth Library', () => {
  describe('Exports', () => {
    it('should export Auth Manager', () => {
      expect(createAuthManager).toBeDefined()
      expect(AuthenticationManager).toBeDefined()
    })

    it('should export Session utilities', () => {
      expect(SessionManager).toBeDefined()
      expect(createSession).toBeDefined()
      expect(sessionMiddleware).toBeDefined()
      expect(csrfMiddleware).toBeDefined()
    })

    it('should export JWT utilities', () => {
      expect(signJwt).toBeDefined()
      expect(verifyJwt).toBeDefined()
      expect(decodeJwt).toBeDefined()
      expect(createTokenPair).toBeDefined()
    })

    it('should export Hash utilities', () => {
      expect(hash).toBeDefined()
      expect(verifyHash).toBeDefined()
      expect(generateToken).toBeDefined()
    })

    it('should export TOTP utilities', () => {
      expect(generateTOTP).toBeDefined()
      expect(verifyTOTP).toBeDefined()
      expect(generateTOTPSecret).toBeDefined()
    })

    it('should export Rate Limiting utilities', () => {
      expect(AuthRateLimiter).toBeDefined()
      expect(createAuthRateLimiter).toBeDefined()
      expect(AccountLockoutManager).toBeDefined()
      expect(createAccountLockout).toBeDefined()
    })

    it('should export Token Blacklist utilities', () => {
      expect(TokenBlacklist).toBeDefined()
      expect(createTokenBlacklist).toBeDefined()
    })

    it('should export Audit utilities', () => {
      expect(AuditLogger).toBeDefined()
      expect(createAuditLogger).toBeDefined()
    })

    it('should export Validation utilities', () => {
      expect(validateEmail).toBeDefined()
      expect(validateUrl).toBeDefined()
    })

    it('should export Error classes', () => {
      expect(AuthError).toBeDefined()
      expect(TokenExpiredError).toBeDefined()
      expect(InvalidCredentialsError).toBeDefined()
    })
  })

  describe('Integration: Authentication Flow', () => {
    const secret = 'test-secret-that-is-at-least-32-bytes-long!'
    let blacklist: TokenBlacklist
    let auditLogger: AuditLogger

    beforeEach(() => {
      blacklist = createTokenBlacklist()
      auditLogger = createAuditLogger()
    })

    afterEach(async () => {
      await blacklist.close()
      await auditLogger.close()
    })

    it('should complete a login flow with JWT', async () => {
      // 1. Hash and verify password
      const password = 'securePassword123!'
      const hashedPassword = await hash(password)
      const isValidPassword = await verifyHash(password, hashedPassword)
      expect(isValidPassword).toBe(true)

      // 2. Issue tokens using createTokenPair
      const userId = 'user-123'
      const tokens = await createTokenPair(userId, secret, {
        expiry: '15m',
        refresh: true,
        refreshExpiry: '7d',
      }, { role: 'user' })
      expect(tokens.accessToken).toBeDefined()
      expect(tokens.refreshToken).toBeDefined()

      // 3. Log the event
      await auditLogger.logLoginSuccess(userId)

      // 4. Verify the access token
      const payload = await verifyJwt(tokens.accessToken, secret)
      expect(payload.sub).toBe(userId)

      // 5. Verify audit log
      const logs = await auditLogger.query({ userId })
      expect(logs.length).toBeGreaterThan(0)
      expect(logs[0].event).toBe('login.success')
    })

    it('should handle token revocation', async () => {
      // Issue a token using signJwt
      const token = await signJwt(
        { sub: 'user-456' },
        secret,
        { jwtId: 'unique-token-id', expiresIn: '1h' },
      )

      // Verify it works
      const payload = await verifyJwt(token, secret)
      expect(payload.sub).toBe('user-456')

      // Revoke the token
      await blacklist.revoke('unique-token-id', Date.now() + 3600000)

      // Check if revoked
      const isRevoked = await blacklist.isRevoked('unique-token-id')
      expect(isRevoked).toBe(true)
    })

    it('should handle 2FA with TOTP', async () => {
      // Generate a secret for user
      const totpSecret = generateTOTPSecret()
      expect(totpSecret).toBeDefined()

      // Generate and verify code
      const code = await generateTOTP({ secret: totpSecret })
      const isValid = await verifyTOTP(code, { secret: totpSecret })
      expect(isValid).toBe(true)
    })
  })

  describe('Integration: Rate Limiting & Lockout', () => {
    let rateLimiter: AuthRateLimiter
    let lockoutManager: AccountLockoutManager

    beforeEach(() => {
      rateLimiter = createAuthRateLimiter({
        login: { maxRequests: 3, windowMs: 1000 },
      })
      lockoutManager = createAccountLockout({
        maxAttempts: 3,
        lockoutDuration: 1000,
      })
    })

    afterEach(() => {
      rateLimiter.dispose()
    })

    it('should enforce rate limits and lock accounts', async () => {
      const email = 'attacker@example.com'
      const request = new Request('http://localhost/login', {
        headers: { 'x-forwarded-for': '10.0.0.1' },
      })

      // First 3 attempts should be allowed by rate limiter
      for (let i = 0; i < 3; i++) {
        const result = await rateLimiter.checkLogin(request)
        expect(result.allowed).toBe(true)

        // Record failed attempt for lockout
        lockoutManager.recordFailedAttempt(email)
      }

      // 4th rate limit check should be blocked
      const blockedResult = await rateLimiter.checkLogin(request)
      expect(blockedResult.allowed).toBe(false)

      // Account should be locked
      const lockStatus = lockoutManager.isLocked(email)
      expect(lockStatus.locked).toBe(true)
    })
  })

  describe('Integration: Validation', () => {
    it('should validate user input', () => {
      // validateEmail throws on invalid, returns void on valid
      expect(() => validateEmail('user@example.com')).not.toThrow()
      expect(() => validateEmail('invalid')).toThrow()

      // validateUrl throws on invalid, returns void on valid
      expect(() => validateUrl('https://example.com')).not.toThrow()
      expect(() => validateUrl('not-a-url')).toThrow()
    })
  })

  describe('Integration: Error Handling', () => {
    it('should provide meaningful error information', () => {
      const error = new TokenExpiredError('Token expired', new Date())

      expect(error.code).toBe('TOKEN_EXPIRED')
      expect(error.expiredAt).toBeDefined()
      expect(error instanceof AuthError).toBe(true)
      expect(error instanceof Error).toBe(true)
    })

    it('should handle invalid credentials error', () => {
      const error = new InvalidCredentialsError()

      expect(error.code).toBe('INVALID_CREDENTIALS')
      expect(error.message).toBe('Invalid credentials provided')
    })
  })
})
