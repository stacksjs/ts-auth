import type { SessionHandler } from '../../types'
import { SessionStorageError } from '../../errors'

/**
 * Redis client interface
 * Compatible with ioredis, node-redis, and similar clients
 */
export interface RedisClient {
  get(key: string): Promise<string | null>
  set(key: string, value: string, options?: { EX?: number }): Promise<unknown>
  setex?(key: string, seconds: number, value: string): Promise<unknown>
  del(key: string | string[]): Promise<number>
  keys(pattern: string): Promise<string[]>
  ttl?(key: string): Promise<number>
  quit?(): Promise<unknown>
  disconnect?(): Promise<unknown>
}

export interface RedisSessionOptions {
  /**
   * Key prefix for session keys (default: 'session:')
   */
  prefix?: string

  /**
   * TTL in seconds (default: 7200 = 2 hours)
   */
  ttl?: number
}

/**
 * Redis session handler
 * Works with any Redis client that implements the RedisClient interface
 */
export class RedisSessionHandler implements SessionHandler {
  private client: RedisClient
  private prefix: string
  private ttl: number

  constructor(client: RedisClient, options: RedisSessionOptions = {}) {
    this.client = client
    this.prefix = options.prefix ?? 'session:'
    this.ttl = options.ttl ?? 7200
  }

  async open(_savePath: string, _sessionName: string): Promise<boolean> {
    return true
  }

  async close(): Promise<boolean> {
    try {
      if (this.client.quit) {
        await this.client.quit()
      }
      else if (this.client.disconnect) {
        await this.client.disconnect()
      }
      return true
    }
    catch {
      return false
    }
  }

  async read(sessionId: string): Promise<string> {
    try {
      const key = this.getKey(sessionId)
      const data = await this.client.get(key)
      return data ?? ''
    }
    catch (error) {
      throw new SessionStorageError(`Failed to read session from Redis: ${error}`)
    }
  }

  async write(sessionId: string, data: string): Promise<boolean> {
    try {
      const key = this.getKey(sessionId)

      // Try setex first (older clients), fall back to set with EX option
      if (this.client.setex) {
        await this.client.setex(key, this.ttl, data)
      }
      else {
        await this.client.set(key, data, { EX: this.ttl })
      }

      return true
    }
    catch (error) {
      throw new SessionStorageError(`Failed to write session to Redis: ${error}`)
    }
  }

  async destroy(sessionId: string): Promise<boolean> {
    try {
      const key = this.getKey(sessionId)
      const result = await this.client.del(key)
      return result > 0
    }
    catch (error) {
      throw new SessionStorageError(`Failed to destroy session in Redis: ${error}`)
    }
  }

  async gc(_maxLifetime: number): Promise<number> {
    // Redis handles TTL automatically, so no garbage collection needed
    // However, we can still scan for any orphaned keys if needed
    return 0
  }

  /**
   * Get all session IDs (useful for admin purposes)
   */
  async getAllSessionIds(): Promise<string[]> {
    try {
      const keys = await this.client.keys(`${this.prefix}*`)
      return keys.map(key => key.slice(this.prefix.length))
    }
    catch (error) {
      throw new SessionStorageError(`Failed to get session IDs from Redis: ${error}`)
    }
  }

  /**
   * Delete all sessions (useful for admin purposes)
   */
  async deleteAllSessions(): Promise<number> {
    try {
      const keys = await this.client.keys(`${this.prefix}*`)
      if (keys.length === 0) {
        return 0
      }
      return await this.client.del(keys)
    }
    catch (error) {
      throw new SessionStorageError(`Failed to delete all sessions from Redis: ${error}`)
    }
  }

  /**
   * Get the remaining TTL for a session
   */
  async getSessionTTL(sessionId: string): Promise<number> {
    if (!this.client.ttl) {
      return -1
    }

    try {
      const key = this.getKey(sessionId)
      return await this.client.ttl(key)
    }
    catch {
      return -1
    }
  }

  /**
   * Update the TTL for a session (touch)
   */
  async touchSession(sessionId: string): Promise<boolean> {
    try {
      const key = this.getKey(sessionId)
      const data = await this.client.get(key)

      if (!data) {
        return false
      }

      // Re-set with fresh TTL
      if (this.client.setex) {
        await this.client.setex(key, this.ttl, data)
      }
      else {
        await this.client.set(key, data, { EX: this.ttl })
      }

      return true
    }
    catch {
      return false
    }
  }

  private getKey(sessionId: string): string {
    return `${this.prefix}${sessionId}`
  }
}

/**
 * Create a Redis session handler
 */
export function createRedisSessionHandler(
  client: RedisClient,
  options?: RedisSessionOptions,
): RedisSessionHandler {
  return new RedisSessionHandler(client, options)
}
