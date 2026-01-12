import type { AccessToken, JWTPayload, TokenConfig, TokenResult } from '../types'
import { createTokenPair, decode, generateJwtId, verify } from './jwt'

/**
 * Personal Access Token Manager (Laravel Sanctum-style)
 */
export class TokenManager {
  private tokens: Map<string, AccessToken> = new Map()
  private secret: string
  private config: TokenConfig

  constructor(secret: string, config: TokenConfig) {
    this.secret = secret
    this.config = config
  }

  /**
   * Create a new personal access token for a user
   */
  async createToken(
    userId: string | number,
    name: string,
    abilities: string[] = ['*'],
    expiresAt?: Date,
  ): Promise<{ token: AccessToken, plainTextToken: string }> {
    const id = generateJwtId()
    const now = new Date()

    // Generate a random token
    const bytes = new Uint8Array(32)
    crypto.getRandomValues(bytes)
    const plainTextToken = Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')

    // Hash the token for storage
    const encoder = new TextEncoder()
    const data = encoder.encode(plainTextToken)
    const hashBuffer = await crypto.subtle.digest('SHA-256', data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashedToken = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')

    const token: AccessToken = {
      id,
      userId,
      name,
      token: hashedToken,
      abilities,
      lastUsedAt: null,
      expiresAt: expiresAt ?? null,
      createdAt: now,
    }

    this.tokens.set(id, token)

    return {
      token,
      plainTextToken: `${id}|${plainTextToken}`,
    }
  }

  /**
   * Find a token by its plain text value
   */
  async findToken(plainTextToken: string): Promise<AccessToken | null> {
    const parts = plainTextToken.split('|')
    if (parts.length !== 2) {
      return null
    }

    const [id, tokenValue] = parts
    const token = this.tokens.get(id)

    if (!token) {
      return null
    }

    // Hash the provided token and compare
    const encoder = new TextEncoder()
    const data = encoder.encode(tokenValue)
    const hashBuffer = await crypto.subtle.digest('SHA-256', data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashedToken = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')

    if (!timingSafeEqual(token.token, hashedToken)) {
      return null
    }

    // Check expiration
    if (token.expiresAt && token.expiresAt < new Date()) {
      return null
    }

    // Update last used at
    token.lastUsedAt = new Date()

    return token
  }

  /**
   * Check if a token has a specific ability
   */
  tokenCan(token: AccessToken, ability: string): boolean {
    if (token.abilities.includes('*')) {
      return true
    }
    return token.abilities.includes(ability)
  }

  /**
   * Check if a token cannot perform an ability
   */
  tokenCannot(token: AccessToken, ability: string): boolean {
    return !this.tokenCan(token, ability)
  }

  /**
   * Revoke a token
   */
  revokeToken(id: string): boolean {
    return this.tokens.delete(id)
  }

  /**
   * Revoke all tokens for a user
   */
  revokeAllTokens(userId: string | number): number {
    let count = 0
    for (const [id, token] of this.tokens) {
      if (token.userId === userId) {
        this.tokens.delete(id)
        count++
      }
    }
    return count
  }

  /**
   * Get all tokens for a user
   */
  getTokensForUser(userId: string | number): AccessToken[] {
    const tokens: AccessToken[] = []
    for (const token of this.tokens.values()) {
      if (token.userId === userId) {
        tokens.push(token)
      }
    }
    return tokens
  }

  /**
   * Create a JWT token pair
   */
  async createJwtTokenPair(
    userId: string | number,
    claims: Record<string, unknown> = {},
  ): Promise<TokenResult> {
    return createTokenPair(userId, this.secret, this.config, claims)
  }

  /**
   * Verify a JWT token
   */
  async verifyJwtToken<T extends JWTPayload = JWTPayload>(token: string): Promise<T> {
    return verify<T>(token, this.secret, {
      algorithms: [this.config.algorithm ?? 'HS256'],
      issuer: this.config.issuer,
      audience: this.config.audience,
    })
  }

  /**
   * Decode a JWT token without verification
   */
  decodeJwtToken<T extends JWTPayload = JWTPayload>(token: string): {
    header: { alg: string, typ?: string }
    payload: T
  } | null {
    return decode<T>(token)
  }

  /**
   * Refresh a JWT token pair
   */
  async refreshJwtTokenPair(refreshToken: string): Promise<TokenResult> {
    // Verify the refresh token
    const payload = await this.verifyJwtToken<JWTPayload & { type?: string }>(refreshToken)

    if (payload.type !== 'refresh') {
      throw new Error('Invalid refresh token')
    }

    // Create a new token pair
    return this.createJwtTokenPair(payload.sub)
  }
}

/**
 * Timing-safe string comparison
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false
  }

  let result = 0
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }

  return result === 0
}

/**
 * Create a token manager instance
 */
export function createTokenManager(secret: string, config?: Partial<TokenConfig>): TokenManager {
  const defaultConfig: TokenConfig = {
    expiry: '1h',
    refresh: true,
    refreshExpiry: '7d',
    algorithm: 'HS256',
  }

  return new TokenManager(secret, { ...defaultConfig, ...config })
}
