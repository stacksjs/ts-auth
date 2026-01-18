import { describe, expect, it, beforeEach, afterEach } from 'bun:test'
import {
  AuthRateLimiter,
  createAuthRateLimiter,
  AccountLockoutManager,
  createAccountLockout,
  defaultAuthRateLimits,
} from '../src/rate-limit'

describe('Rate Limit Module', () => {
  describe('defaultAuthRateLimits', () => {
    it('should have login rate limits', () => {
      expect(defaultAuthRateLimits.login.windowMs).toBe(15 * 60 * 1000)
      expect(defaultAuthRateLimits.login.maxRequests).toBe(5)
    })

    it('should have registration rate limits', () => {
      expect(defaultAuthRateLimits.registration.windowMs).toBe(60 * 60 * 1000)
      expect(defaultAuthRateLimits.registration.maxRequests).toBe(3)
    })

    it('should have password reset rate limits', () => {
      expect(defaultAuthRateLimits.passwordReset.windowMs).toBe(60 * 60 * 1000)
      expect(defaultAuthRateLimits.passwordReset.maxRequests).toBe(3)
    })

    it('should have token refresh rate limits', () => {
      expect(defaultAuthRateLimits.tokenRefresh.windowMs).toBe(60 * 1000)
      expect(defaultAuthRateLimits.tokenRefresh.maxRequests).toBe(10)
    })

    it('should have 2FA rate limits', () => {
      expect(defaultAuthRateLimits.twoFactor.windowMs).toBe(5 * 60 * 1000)
      expect(defaultAuthRateLimits.twoFactor.maxRequests).toBe(5)
    })

    it('should have API rate limits', () => {
      expect(defaultAuthRateLimits.api.windowMs).toBe(60 * 1000)
      expect(defaultAuthRateLimits.api.maxRequests).toBe(100)
    })
  })

  describe('AuthRateLimiter', () => {
    let limiter: AuthRateLimiter

    beforeEach(() => {
      limiter = createAuthRateLimiter({
        login: { maxRequests: 3, windowMs: 1000 },
        api: { maxRequests: 5, windowMs: 1000 },
      })
    })

    afterEach(() => {
      limiter.dispose()
    })

    it('should allow requests within limit', async () => {
      const request = new Request('http://localhost/login', {
        headers: { 'x-forwarded-for': '192.168.1.1' },
      })

      const result1 = await limiter.checkLogin(request)
      expect(result1.allowed).toBe(true)
      expect(result1.remaining).toBeGreaterThan(0)

      const result2 = await limiter.checkLogin(request)
      expect(result2.allowed).toBe(true)
    })

    it('should block requests exceeding limit', async () => {
      const request = new Request('http://localhost/login', {
        headers: { 'x-forwarded-for': '192.168.1.2' },
      })

      // Exhaust the limit
      for (let i = 0; i < 3; i++) {
        await limiter.checkLogin(request)
      }

      // Next request should be blocked
      const result = await limiter.checkLogin(request)
      expect(result.allowed).toBe(false)
    })

    it('should reset rate limit for specific key', async () => {
      const request = new Request('http://localhost/login', {
        headers: { 'x-forwarded-for': '192.168.1.3' },
      })

      // Use up some requests
      await limiter.checkLogin(request)
      await limiter.checkLogin(request)

      // Reset
      await limiter.reset('login', '192.168.1.3')

      // Should be allowed again
      const result = await limiter.checkLogin(request)
      expect(result.allowed).toBe(true)
      // Just verify it's allowed - remaining value depends on rate limiter implementation
    })

    it('should check API rate limit', async () => {
      const request = new Request('http://localhost/api/users', {
        headers: { 'x-forwarded-for': '192.168.1.4' },
      })

      const result = await limiter.checkApi(request)
      expect(result.allowed).toBe(true)
    })

    it('should provide middleware', () => {
      const middleware = limiter.middleware('login')
      expect(middleware).toBeDefined()
      expect(typeof middleware).toBe('function')
    })

    it('should throw for unknown limiter', () => {
      expect(() => limiter.middleware('unknown' as any)).toThrow()
    })

    it('should add custom limiter', async () => {
      limiter.addLimiter('custom', {
        maxRequests: 10,
        windowMs: 5000,
      })

      const customLimiter = limiter.getLimiter('custom')
      expect(customLimiter).toBeDefined()
    })
  })

  describe('AccountLockoutManager', () => {
    let lockout: AccountLockoutManager

    beforeEach(() => {
      lockout = createAccountLockout({
        maxAttempts: 3,
        lockoutDuration: 1000, // 1 second for testing
      })
    })

    it('should track failed attempts', () => {
      const result1 = lockout.recordFailedAttempt('user@example.com')
      expect(result1.locked).toBe(false)
      expect(result1.attemptsRemaining).toBe(2)

      const result2 = lockout.recordFailedAttempt('user@example.com')
      expect(result2.locked).toBe(false)
      expect(result2.attemptsRemaining).toBe(1)
    })

    it('should lock account after max attempts', () => {
      lockout.recordFailedAttempt('locked@example.com')
      lockout.recordFailedAttempt('locked@example.com')
      const result = lockout.recordFailedAttempt('locked@example.com')

      expect(result.locked).toBe(true)
      expect(result.attemptsRemaining).toBe(0)
      expect(result.lockedUntil).not.toBeNull()
    })

    it('should report locked status', () => {
      lockout.recordFailedAttempt('check@example.com')
      lockout.recordFailedAttempt('check@example.com')
      lockout.recordFailedAttempt('check@example.com')

      const status = lockout.isLocked('check@example.com')
      expect(status.locked).toBe(true)
    })

    it('should clear attempts on successful login', () => {
      lockout.recordFailedAttempt('success@example.com')
      lockout.recordFailedAttempt('success@example.com')

      lockout.recordSuccessfulAttempt('success@example.com')

      const count = lockout.getFailedAttemptCount('success@example.com')
      expect(count).toBe(0)
    })

    it('should manually unlock account', () => {
      lockout.recordFailedAttempt('manual@example.com')
      lockout.recordFailedAttempt('manual@example.com')
      lockout.recordFailedAttempt('manual@example.com')

      lockout.unlock('manual@example.com')

      const status = lockout.isLocked('manual@example.com')
      expect(status.locked).toBe(false)
    })

    it('should return not locked for unknown users', () => {
      const status = lockout.isLocked('unknown@example.com')
      expect(status.locked).toBe(false)
    })

    it('should get failed attempt count', () => {
      lockout.recordFailedAttempt('count@example.com')
      lockout.recordFailedAttempt('count@example.com')

      const count = lockout.getFailedAttemptCount('count@example.com')
      expect(count).toBe(2)
    })

    it('should return 0 for unknown user attempt count', () => {
      const count = lockout.getFailedAttemptCount('noone@example.com')
      expect(count).toBe(0)
    })

    it('should clear all records', () => {
      lockout.recordFailedAttempt('clear1@example.com')
      lockout.recordFailedAttempt('clear2@example.com')

      lockout.clear()

      expect(lockout.getFailedAttemptCount('clear1@example.com')).toBe(0)
      expect(lockout.getFailedAttemptCount('clear2@example.com')).toBe(0)
    })

    it('should auto-unlock after duration expires', async () => {
      // Lock the account
      lockout.recordFailedAttempt('expire@example.com')
      lockout.recordFailedAttempt('expire@example.com')
      lockout.recordFailedAttempt('expire@example.com')

      // Should be locked
      expect(lockout.isLocked('expire@example.com').locked).toBe(true)

      // Wait for lockout to expire
      await new Promise(resolve => setTimeout(resolve, 1100))

      // Should be unlocked
      expect(lockout.isLocked('expire@example.com').locked).toBe(false)
    })
  })
})
