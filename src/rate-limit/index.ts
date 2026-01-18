/**
 * Rate limiting integration for authentication
 * Uses ts-rate-limiter for high-performance rate limiting
 */

import { RateLimiter, MemoryStorage } from 'ts-rate-limiter'
import type { RateLimiterOptions, RateLimitResult, StorageProvider } from 'ts-rate-limiter'

export { RateLimiter, MemoryStorage, RateLimitResult }
export type { RateLimiterOptions, StorageProvider }

/**
 * Pre-configured rate limiters for common auth operations
 */

export interface AuthRateLimitConfig {
  /**
   * Login attempt rate limiting
   */
  login?: {
    windowMs?: number
    maxRequests?: number
    keyGenerator?: (request: Request) => string
  }

  /**
   * Registration rate limiting
   */
  registration?: {
    windowMs?: number
    maxRequests?: number
    keyGenerator?: (request: Request) => string
  }

  /**
   * Password reset rate limiting
   */
  passwordReset?: {
    windowMs?: number
    maxRequests?: number
    keyGenerator?: (request: Request) => string
  }

  /**
   * Token refresh rate limiting
   */
  tokenRefresh?: {
    windowMs?: number
    maxRequests?: number
    keyGenerator?: (request: Request) => string
  }

  /**
   * 2FA verification rate limiting
   */
  twoFactor?: {
    windowMs?: number
    maxRequests?: number
    keyGenerator?: (request: Request) => string
  }

  /**
   * API rate limiting
   */
  api?: {
    windowMs?: number
    maxRequests?: number
    keyGenerator?: (request: Request) => string
  }

  /**
   * Custom storage provider
   */
  storage?: StorageProvider
}

/**
 * Default rate limit configurations for auth operations
 */
export const defaultAuthRateLimits = {
  login: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5, // 5 attempts per 15 minutes
  },
  registration: {
    windowMs: 60 * 60 * 1000, // 1 hour
    maxRequests: 3, // 3 registrations per hour
  },
  passwordReset: {
    windowMs: 60 * 60 * 1000, // 1 hour
    maxRequests: 3, // 3 reset requests per hour
  },
  tokenRefresh: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 10, // 10 refreshes per minute
  },
  twoFactor: {
    windowMs: 5 * 60 * 1000, // 5 minutes
    maxRequests: 5, // 5 attempts per 5 minutes
  },
  api: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 100, // 100 requests per minute
  },
}

/**
 * Auth Rate Limiter Manager
 * Manages multiple rate limiters for different auth operations
 */
export class AuthRateLimiter {
  private limiters: Map<string, RateLimiter> = new Map()
  private storage: StorageProvider
  private config: AuthRateLimitConfig

  constructor(config: AuthRateLimitConfig = {}) {
    this.config = config
    this.storage = config.storage ?? new MemoryStorage({ enableAutoCleanup: true })
    this.initializeLimiters()
  }

  private initializeLimiters(): void {
    // Login limiter
    const loginConfig = { ...defaultAuthRateLimits.login, ...this.config.login }
    this.limiters.set('login', new RateLimiter({
      windowMs: loginConfig.windowMs,
      maxRequests: loginConfig.maxRequests,
      storage: this.storage,
      keyGenerator: loginConfig.keyGenerator ?? this.defaultKeyGenerator,
      handler: this.createBlockedHandler('Too many login attempts'),
    }))

    // Registration limiter
    const regConfig = { ...defaultAuthRateLimits.registration, ...this.config.registration }
    this.limiters.set('registration', new RateLimiter({
      windowMs: regConfig.windowMs,
      maxRequests: regConfig.maxRequests,
      storage: this.storage,
      keyGenerator: regConfig.keyGenerator ?? this.defaultKeyGenerator,
      handler: this.createBlockedHandler('Too many registration attempts'),
    }))

    // Password reset limiter
    const resetConfig = { ...defaultAuthRateLimits.passwordReset, ...this.config.passwordReset }
    this.limiters.set('passwordReset', new RateLimiter({
      windowMs: resetConfig.windowMs,
      maxRequests: resetConfig.maxRequests,
      storage: this.storage,
      keyGenerator: resetConfig.keyGenerator ?? this.defaultKeyGenerator,
      handler: this.createBlockedHandler('Too many password reset attempts'),
    }))

    // Token refresh limiter
    const refreshConfig = { ...defaultAuthRateLimits.tokenRefresh, ...this.config.tokenRefresh }
    this.limiters.set('tokenRefresh', new RateLimiter({
      windowMs: refreshConfig.windowMs,
      maxRequests: refreshConfig.maxRequests,
      storage: this.storage,
      keyGenerator: refreshConfig.keyGenerator ?? this.defaultKeyGenerator,
      handler: this.createBlockedHandler('Too many token refresh attempts'),
    }))

    // 2FA limiter
    const twoFactorConfig = { ...defaultAuthRateLimits.twoFactor, ...this.config.twoFactor }
    this.limiters.set('twoFactor', new RateLimiter({
      windowMs: twoFactorConfig.windowMs,
      maxRequests: twoFactorConfig.maxRequests,
      storage: this.storage,
      keyGenerator: twoFactorConfig.keyGenerator ?? this.defaultKeyGenerator,
      handler: this.createBlockedHandler('Too many 2FA attempts'),
    }))

    // API limiter
    const apiConfig = { ...defaultAuthRateLimits.api, ...this.config.api }
    this.limiters.set('api', new RateLimiter({
      windowMs: apiConfig.windowMs,
      maxRequests: apiConfig.maxRequests,
      storage: this.storage,
      keyGenerator: apiConfig.keyGenerator ?? this.defaultKeyGenerator,
      handler: this.createBlockedHandler('API rate limit exceeded'),
    }))
  }

  private defaultKeyGenerator = (request: Request): string => {
    // Use X-Forwarded-For or fall back to a default
    const forwarded = request.headers.get('x-forwarded-for')
    if (forwarded) {
      return forwarded.split(',')[0].trim()
    }

    // Try X-Real-IP
    const realIp = request.headers.get('x-real-ip')
    if (realIp) {
      return realIp
    }

    // Fall back to a hash of the request URL (not ideal but works)
    return 'unknown'
  }

  private createBlockedHandler(message: string) {
    return (_request: Request, result: RateLimitResult): Response => {
      const retryAfter = Math.ceil(result.remaining / 1000)
      return new Response(
        JSON.stringify({
          error: 'Too Many Requests',
          message,
          retryAfter,
        }),
        {
          status: 429,
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': String(retryAfter),
            'X-RateLimit-Limit': String(result.limit),
            'X-RateLimit-Remaining': String(0),
            'X-RateLimit-Reset': String(Math.ceil(result.resetTime / 1000)),
          },
        },
      )
    }
  }

  /**
   * Check login rate limit
   */
  async checkLogin(request: Request): Promise<RateLimitResult> {
    return this.limiters.get('login')!.check(request)
  }

  /**
   * Check registration rate limit
   */
  async checkRegistration(request: Request): Promise<RateLimitResult> {
    return this.limiters.get('registration')!.check(request)
  }

  /**
   * Check password reset rate limit
   */
  async checkPasswordReset(request: Request): Promise<RateLimitResult> {
    return this.limiters.get('passwordReset')!.check(request)
  }

  /**
   * Check token refresh rate limit
   */
  async checkTokenRefresh(request: Request): Promise<RateLimitResult> {
    return this.limiters.get('tokenRefresh')!.check(request)
  }

  /**
   * Check 2FA rate limit
   */
  async checkTwoFactor(request: Request): Promise<RateLimitResult> {
    return this.limiters.get('twoFactor')!.check(request)
  }

  /**
   * Check API rate limit
   */
  async checkApi(request: Request): Promise<RateLimitResult> {
    return this.limiters.get('api')!.check(request)
  }

  /**
   * Check rate limit by key (for custom use cases)
   */
  async checkByKey(limiterName: string, key: string): Promise<RateLimitResult> {
    const limiter = this.limiters.get(limiterName)
    if (!limiter) {
      throw new Error(`Rate limiter '${limiterName}' not found`)
    }
    return limiter.consume(key)
  }

  /**
   * Get middleware for a specific limiter
   */
  middleware(limiterName: 'login' | 'registration' | 'passwordReset' | 'tokenRefresh' | 'twoFactor' | 'api') {
    const limiter = this.limiters.get(limiterName)
    if (!limiter) {
      throw new Error(`Rate limiter '${limiterName}' not found`)
    }
    return limiter.middleware()
  }

  /**
   * Reset rate limit for a specific key
   */
  async reset(limiterName: string, key: string): Promise<void> {
    const limiter = this.limiters.get(limiterName)
    if (limiter) {
      await limiter.reset(key)
    }
  }

  /**
   * Reset all rate limits
   */
  async resetAll(): Promise<void> {
    for (const limiter of this.limiters.values()) {
      await limiter.resetAll()
    }
  }

  /**
   * Dispose all rate limiters
   */
  dispose(): void {
    for (const limiter of this.limiters.values()) {
      limiter.dispose()
    }
    this.limiters.clear()
  }

  /**
   * Add a custom rate limiter
   */
  addLimiter(name: string, options: RateLimiterOptions): void {
    this.limiters.set(name, new RateLimiter({
      ...options,
      storage: options.storage ?? this.storage,
    }))
  }

  /**
   * Get a specific limiter
   */
  getLimiter(name: string): RateLimiter | undefined {
    return this.limiters.get(name)
  }
}

/**
 * Create an auth rate limiter instance
 */
export function createAuthRateLimiter(config?: AuthRateLimitConfig): AuthRateLimiter {
  return new AuthRateLimiter(config)
}

/**
 * Rate limit decorator for protecting async functions
 */
export function withRateLimit<T extends (...args: unknown[]) => Promise<unknown>>(
  limiter: RateLimiter,
  keyExtractor: (...args: Parameters<T>) => string,
  fn: T,
): T {
  return (async (...args: Parameters<T>) => {
    const key = keyExtractor(...args)
    const result = await limiter.consume(key)

    if (!result.allowed) {
      const error = new Error('Rate limit exceeded') as Error & { rateLimitResult: RateLimitResult }
      error.rateLimitResult = result
      throw error
    }

    return fn(...args)
  }) as T
}

/**
 * Account lockout manager
 * Tracks failed attempts and locks accounts after threshold
 */
export class AccountLockoutManager {
  private failedAttempts: Map<string, { count: number, lockedUntil: number | null }> = new Map()
  private maxAttempts: number
  private lockoutDuration: number

  constructor(options: { maxAttempts?: number, lockoutDuration?: number } = {}) {
    this.maxAttempts = options.maxAttempts ?? 5
    this.lockoutDuration = options.lockoutDuration ?? 15 * 60 * 1000 // 15 minutes
  }

  /**
   * Record a failed login attempt
   */
  recordFailedAttempt(identifier: string): { locked: boolean, attemptsRemaining: number, lockedUntil: Date | null } {
    const record = this.failedAttempts.get(identifier) ?? { count: 0, lockedUntil: null }

    // Check if currently locked
    if (record.lockedUntil && record.lockedUntil > Date.now()) {
      return {
        locked: true,
        attemptsRemaining: 0,
        lockedUntil: new Date(record.lockedUntil),
      }
    }

    // Reset if lock has expired
    if (record.lockedUntil && record.lockedUntil <= Date.now()) {
      record.count = 0
      record.lockedUntil = null
    }

    record.count++

    // Lock account if max attempts exceeded
    if (record.count >= this.maxAttempts) {
      record.lockedUntil = Date.now() + this.lockoutDuration
      this.failedAttempts.set(identifier, record)
      return {
        locked: true,
        attemptsRemaining: 0,
        lockedUntil: new Date(record.lockedUntil),
      }
    }

    this.failedAttempts.set(identifier, record)

    return {
      locked: false,
      attemptsRemaining: this.maxAttempts - record.count,
      lockedUntil: null,
    }
  }

  /**
   * Record a successful login (clears failed attempts)
   */
  recordSuccessfulAttempt(identifier: string): void {
    this.failedAttempts.delete(identifier)
  }

  /**
   * Check if an account is locked
   */
  isLocked(identifier: string): { locked: boolean, lockedUntil: Date | null } {
    const record = this.failedAttempts.get(identifier)

    if (!record || !record.lockedUntil) {
      return { locked: false, lockedUntil: null }
    }

    if (record.lockedUntil <= Date.now()) {
      // Lock has expired
      record.count = 0
      record.lockedUntil = null
      this.failedAttempts.set(identifier, record)
      return { locked: false, lockedUntil: null }
    }

    return {
      locked: true,
      lockedUntil: new Date(record.lockedUntil),
    }
  }

  /**
   * Manually unlock an account
   */
  unlock(identifier: string): void {
    this.failedAttempts.delete(identifier)
  }

  /**
   * Get failed attempt count for an identifier
   */
  getFailedAttemptCount(identifier: string): number {
    return this.failedAttempts.get(identifier)?.count ?? 0
  }

  /**
   * Clear all lockout records
   */
  clear(): void {
    this.failedAttempts.clear()
  }
}

/**
 * Create an account lockout manager
 */
export function createAccountLockout(options?: { maxAttempts?: number, lockoutDuration?: number }): AccountLockoutManager {
  return new AccountLockoutManager(options)
}
