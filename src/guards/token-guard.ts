import type { Authenticatable, Credentials, Guard, GuardConfig, UserProvider } from '../types'
import type { TokenManager } from '../jwt/token-manager'

/**
 * Token-based authentication guard (API tokens / Sanctum-style)
 */
export class TokenGuard implements Guard {
  private name: string
  private provider: UserProvider
  private config: GuardConfig
  private tokenManager: TokenManager
  private currentUser: Authenticatable | null = null
  private userResolved = false
  private request: Request | null = null

  constructor(
    name: string,
    provider: UserProvider,
    tokenManager: TokenManager,
    config: GuardConfig,
  ) {
    this.name = name
    this.provider = provider
    this.tokenManager = tokenManager
    this.config = config
  }

  /**
   * Set the current request (for extracting token)
   */
  setRequest(request: Request): void {
    this.request = request
    this.userResolved = false
    this.currentUser = null
  }

  /**
   * Attempt to authenticate a user using the given credentials
   */
  async attempt(credentials: Credentials): Promise<boolean> {
    const user = await this.provider.retrieveByCredentials(credentials)

    if (!user) {
      return false
    }

    const valid = await this.provider.validateCredentials(user, credentials)

    if (valid) {
      this.setUser(user)
      return true
    }

    return false
  }

  /**
   * Log a user into the application (not supported for token guard)
   */
  async login(_user: Authenticatable): Promise<void> {
    throw new Error('Token guard does not support login. Use createToken instead.')
  }

  /**
   * Log the user out of the application
   */
  async logout(): Promise<void> {
    // For token guard, logout means invalidating the current token
    // This would typically revoke the token in storage
    this.currentUser = null
    this.userResolved = true
  }

  /**
   * Get the currently authenticated user
   */
  async user(): Promise<Authenticatable | null> {
    if (this.userResolved) {
      return this.currentUser
    }

    // Get token from request
    const token = this.getTokenFromRequest()

    if (!token) {
      this.userResolved = true
      return null
    }

    // Find and validate token
    const accessToken = await this.tokenManager.findToken(token)

    if (!accessToken) {
      this.userResolved = true
      return null
    }

    // Get user by ID
    this.currentUser = await this.provider.retrieveById(accessToken.userId)
    this.userResolved = true

    return this.currentUser
  }

  /**
   * Get the ID for the currently authenticated user
   */
  async id(): Promise<string | number | null> {
    const user = await this.user()
    return user?.getAuthIdentifier() ?? null
  }

  /**
   * Determine if the current user is authenticated
   */
  async check(): Promise<boolean> {
    const user = await this.user()
    return user !== null
  }

  /**
   * Determine if the current user is a guest
   */
  async guest(): Promise<boolean> {
    return !(await this.check())
  }

  /**
   * Validate a user's credentials
   */
  async validate(credentials: Credentials): Promise<boolean> {
    const user = await this.provider.retrieveByCredentials(credentials)
    if (!user) {
      return false
    }
    return this.provider.validateCredentials(user, credentials)
  }

  /**
   * Set the current user
   */
  setUser(user: Authenticatable): void {
    this.currentUser = user
    this.userResolved = true
  }

  /**
   * Get the user provider
   */
  getProvider(): UserProvider {
    return this.provider
  }

  /**
   * Set the user provider
   */
  setProvider(provider: UserProvider): void {
    this.provider = provider
  }

  /**
   * Create a new personal access token for a user
   */
  async createToken(
    user: Authenticatable,
    name: string,
    abilities: string[] = ['*'],
    expiresAt?: Date,
  ): Promise<{ token: import('../types').AccessToken, plainTextToken: string }> {
    return this.tokenManager.createToken(
      user.getAuthIdentifier(),
      name,
      abilities,
      expiresAt,
    )
  }

  /**
   * Check if the current token has a specific ability
   */
  async tokenCan(ability: string): Promise<boolean> {
    const token = this.getTokenFromRequest()
    if (!token) {
      return false
    }

    const accessToken = await this.tokenManager.findToken(token)
    if (!accessToken) {
      return false
    }

    return this.tokenManager.tokenCan(accessToken, ability)
  }

  /**
   * Check if the current token cannot perform an ability
   */
  async tokenCannot(ability: string): Promise<boolean> {
    return !(await this.tokenCan(ability))
  }

  /**
   * Revoke a specific token
   */
  revokeToken(tokenId: string): boolean {
    return this.tokenManager.revokeToken(tokenId)
  }

  /**
   * Revoke all tokens for a user
   */
  revokeAllTokens(userId: string | number): number {
    return this.tokenManager.revokeAllTokens(userId)
  }

  /**
   * Get token from request
   */
  private getTokenFromRequest(): string | null {
    if (!this.request) {
      return null
    }

    // Check Authorization header
    const authHeader = this.request.headers.get('Authorization')
    if (authHeader?.startsWith('Bearer ')) {
      return authHeader.slice(7)
    }

    // Check query parameter (configurable)
    const inputKey = this.config.inputKey ?? 'api_token'
    const url = new URL(this.request.url)
    const queryToken = url.searchParams.get(inputKey)
    if (queryToken) {
      return queryToken
    }

    return null
  }
}
