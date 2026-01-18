/**
 * Token Blacklist for JWT Revocation
 * Provides multiple storage backends for tracking revoked tokens
 */

/**
 * Token blacklist storage interface
 */
export interface TokenBlacklistStorage {
  /**
   * Add a token to the blacklist
   */
  add(tokenId: string, expiresAt: number): Promise<void>

  /**
   * Check if a token is blacklisted
   */
  has(tokenId: string): Promise<boolean>

  /**
   * Remove expired entries (garbage collection)
   */
  cleanup(): Promise<number>

  /**
   * Clear all blacklisted tokens
   */
  clear(): Promise<void>

  /**
   * Get the count of blacklisted tokens
   */
  count(): Promise<number>

  /**
   * Close/dispose the storage
   */
  close(): Promise<void>
}

/**
 * In-memory token blacklist storage
 * Suitable for single-instance deployments or testing
 */
export class MemoryTokenBlacklist implements TokenBlacklistStorage {
  private tokens: Map<string, number> = new Map() // tokenId -> expiresAt
  private cleanupInterval: ReturnType<typeof setInterval> | null = null

  constructor(options: { cleanupIntervalMs?: number } = {}) {
    const interval = options.cleanupIntervalMs ?? 60 * 1000 // 1 minute default
    this.cleanupInterval = setInterval(() => {
      this.cleanup()
    }, interval)
  }

  async add(tokenId: string, expiresAt: number): Promise<void> {
    this.tokens.set(tokenId, expiresAt)
  }

  async has(tokenId: string): Promise<boolean> {
    const expiresAt = this.tokens.get(tokenId)
    if (expiresAt === undefined) {
      return false
    }

    // Check if expired (can be removed)
    if (expiresAt < Date.now()) {
      this.tokens.delete(tokenId)
      return false
    }

    return true
  }

  async cleanup(): Promise<number> {
    const now = Date.now()
    let count = 0

    for (const [tokenId, expiresAt] of this.tokens) {
      if (expiresAt < now) {
        this.tokens.delete(tokenId)
        count++
      }
    }

    return count
  }

  async clear(): Promise<void> {
    this.tokens.clear()
  }

  async count(): Promise<number> {
    return this.tokens.size
  }

  async close(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval)
      this.cleanupInterval = null
    }
    this.tokens.clear()
  }
}

/**
 * Redis token blacklist storage
 * Suitable for distributed/multi-instance deployments
 */
export interface RedisClient {
  set(key: string, value: string, options?: { EX?: number, PX?: number }): Promise<unknown>
  setex?(key: string, seconds: number, value: string): Promise<unknown>
  get(key: string): Promise<string | null>
  del(key: string): Promise<number>
  keys(pattern: string): Promise<string[]>
  quit?(): Promise<unknown>
  disconnect?(): Promise<unknown>
}

export class RedisTokenBlacklist implements TokenBlacklistStorage {
  private client: RedisClient
  private prefix: string

  constructor(client: RedisClient, options: { prefix?: string } = {}) {
    this.client = client
    this.prefix = options.prefix ?? 'token:blacklist:'
  }

  async add(tokenId: string, expiresAt: number): Promise<void> {
    const key = this.getKey(tokenId)
    const ttlMs = expiresAt - Date.now()

    if (ttlMs <= 0) {
      // Token already expired, no need to blacklist
      return
    }

    const ttlSeconds = Math.ceil(ttlMs / 1000)

    if (this.client.setex) {
      await this.client.setex(key, ttlSeconds, '1')
    }
    else {
      await this.client.set(key, '1', { EX: ttlSeconds })
    }
  }

  async has(tokenId: string): Promise<boolean> {
    const key = this.getKey(tokenId)
    const result = await this.client.get(key)
    return result !== null
  }

  async cleanup(): Promise<number> {
    // Redis handles TTL automatically, so no cleanup needed
    return 0
  }

  async clear(): Promise<void> {
    const keys = await this.client.keys(`${this.prefix}*`)
    for (const key of keys) {
      await this.client.del(key)
    }
  }

  async count(): Promise<number> {
    const keys = await this.client.keys(`${this.prefix}*`)
    return keys.length
  }

  async close(): Promise<void> {
    if (this.client.quit) {
      await this.client.quit()
    }
    else if (this.client.disconnect) {
      await this.client.disconnect()
    }
  }

  private getKey(tokenId: string): string {
    return `${this.prefix}${tokenId}`
  }
}

/**
 * Token Blacklist Manager
 * Main interface for managing token revocation
 */
export class TokenBlacklist {
  private storage: TokenBlacklistStorage

  constructor(storage?: TokenBlacklistStorage) {
    this.storage = storage ?? new MemoryTokenBlacklist()
  }

  /**
   * Revoke a token by its ID (jti claim)
   */
  async revoke(tokenId: string, expiresAt: Date | number): Promise<void> {
    const expiry = typeof expiresAt === 'number' ? expiresAt : expiresAt.getTime()
    await this.storage.add(tokenId, expiry)
  }

  /**
   * Revoke a token by extracting the jti from the payload
   */
  async revokeToken(payload: { jti?: string, exp?: number }): Promise<boolean> {
    if (!payload.jti) {
      return false // Cannot revoke token without jti
    }

    const expiresAt = payload.exp ? payload.exp * 1000 : Date.now() + 24 * 60 * 60 * 1000
    await this.storage.add(payload.jti, expiresAt)
    return true
  }

  /**
   * Check if a token has been revoked
   */
  async isRevoked(tokenId: string): Promise<boolean> {
    return this.storage.has(tokenId)
  }

  /**
   * Check if a token payload has been revoked
   */
  async isTokenRevoked(payload: { jti?: string }): Promise<boolean> {
    if (!payload.jti) {
      return false // Cannot check without jti
    }
    return this.storage.has(payload.jti)
  }

  /**
   * Revoke all tokens for a user (requires tracking user-token associations)
   * This is a placeholder - implement with your user-token tracking
   */
  async revokeAllUserTokens(_userId: string | number): Promise<void> {
    // This requires additional tracking of which tokens belong to which user
    // Implement based on your specific needs
    console.warn('revokeAllUserTokens requires additional user-token tracking implementation')
  }

  /**
   * Clean up expired entries
   */
  async cleanup(): Promise<number> {
    return this.storage.cleanup()
  }

  /**
   * Clear all revoked tokens
   */
  async clear(): Promise<void> {
    return this.storage.clear()
  }

  /**
   * Get count of revoked tokens
   */
  async count(): Promise<number> {
    return this.storage.count()
  }

  /**
   * Close/dispose the blacklist
   */
  async close(): Promise<void> {
    return this.storage.close()
  }
}

/**
 * Create a token blacklist with memory storage
 */
export function createTokenBlacklist(options?: { cleanupIntervalMs?: number }): TokenBlacklist {
  return new TokenBlacklist(new MemoryTokenBlacklist(options))
}

/**
 * Create a token blacklist with Redis storage
 */
export function createRedisTokenBlacklist(
  client: RedisClient,
  options?: { prefix?: string },
): TokenBlacklist {
  return new TokenBlacklist(new RedisTokenBlacklist(client, options))
}

/**
 * Middleware to check token blacklist
 */
export function tokenBlacklistMiddleware(
  blacklist: TokenBlacklist,
  extractTokenId: (request: Request) => Promise<string | null>,
) {
  return async (
    request: Request,
    next: (request: Request) => Promise<Response> | Response,
  ): Promise<Response> => {
    const tokenId = await extractTokenId(request)

    if (tokenId && await blacklist.isRevoked(tokenId)) {
      return new Response(
        JSON.stringify({
          error: 'Token has been revoked',
          code: 'TOKEN_REVOKED',
        }),
        {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        },
      )
    }

    return next(request)
  }
}
