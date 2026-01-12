import type { OAuthProvider, OAuthProviderConfig, OAuthTokens, OAuthUser } from '../types'

/**
 * Base OAuth Provider implementation
 * Extend this class to implement specific OAuth providers
 */
export abstract class BaseOAuthProvider implements OAuthProvider {
  protected config: OAuthProviderConfig
  protected scopes: string[]
  protected state: string | null = null

  // Override these in subclasses
  protected abstract authorizationUrl: string
  protected abstract tokenUrl: string
  protected abstract userInfoUrl: string
  protected scopeSeparator = ' '

  constructor(config: OAuthProviderConfig) {
    this.config = config
    this.scopes = config.scopes ?? this.getDefaultScopes()
  }

  /**
   * Get default scopes for this provider
   */
  protected abstract getDefaultScopes(): string[]

  /**
   * Get the authorization URL
   */
  getAuthorizationUrl(state?: string): string {
    this.state = state ?? this.generateState()

    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      scope: this.scopes.join(this.scopeSeparator),
      state: this.state,
      ...this.config.parameters,
    })

    return `${this.authorizationUrl}?${params.toString()}`
  }

  /**
   * Exchange authorization code for tokens
   */
  async getAccessToken(code: string): Promise<OAuthTokens> {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      code,
      redirect_uri: this.config.redirectUri,
      grant_type: 'authorization_code',
    })

    const response = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      },
      body: params.toString(),
    })

    if (!response.ok) {
      const error = await response.text()
      throw new Error(`Failed to get access token: ${error}`)
    }

    const data = await response.json()
    return this.mapTokenResponse(data)
  }

  /**
   * Map token response to OAuthTokens
   */
  protected mapTokenResponse(data: Record<string, unknown>): OAuthTokens {
    return {
      accessToken: data.access_token as string,
      tokenType: (data.token_type as string) ?? 'Bearer',
      expiresIn: (data.expires_in as number) ?? 3600,
      refreshToken: data.refresh_token as string | undefined,
      scope: data.scope as string | undefined,
    }
  }

  /**
   * Get user information from the provider
   */
  abstract getUser(accessToken: string): Promise<OAuthUser>

  /**
   * Refresh the access token
   */
  async refreshToken(refreshToken: string): Promise<OAuthTokens> {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      refresh_token: refreshToken,
      grant_type: 'refresh_token',
    })

    const response = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      },
      body: params.toString(),
    })

    if (!response.ok) {
      const error = await response.text()
      throw new Error(`Failed to refresh token: ${error}`)
    }

    const data = await response.json()
    return this.mapTokenResponse(data)
  }

  /**
   * Revoke the access token
   */
  abstract revokeToken(token: string): Promise<void>

  /**
   * Generate a random state parameter
   */
  protected generateState(): string {
    const bytes = new Uint8Array(32)
    crypto.getRandomValues(bytes)
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
  }

  /**
   * Get the current state
   */
  getState(): string | null {
    return this.state
  }

  /**
   * Verify state parameter from callback
   */
  verifyState(state: string): boolean {
    return this.state !== null && this.state === state
  }

  /**
   * Set scopes
   */
  setScopes(scopes: string[]): this {
    this.scopes = scopes
    return this
  }

  /**
   * Add scopes
   */
  addScopes(scopes: string[]): this {
    this.scopes = [...new Set([...this.scopes, ...scopes])]
    return this
  }
}

/**
 * OAuth Manager for handling multiple providers
 */
export class OAuthManager {
  private providers: Map<string, BaseOAuthProvider> = new Map()

  /**
   * Register a provider
   */
  register(name: string, provider: BaseOAuthProvider): void {
    this.providers.set(name, provider)
  }

  /**
   * Get a provider by name
   */
  driver(name: string): BaseOAuthProvider {
    const provider = this.providers.get(name)
    if (!provider) {
      throw new Error(`OAuth provider '${name}' not registered`)
    }
    return provider
  }

  /**
   * Check if a provider is registered
   */
  hasProvider(name: string): boolean {
    return this.providers.has(name)
  }

  /**
   * Get all registered provider names
   */
  getProviders(): string[] {
    return Array.from(this.providers.keys())
  }
}

/**
 * Create an OAuth manager instance
 */
export function createOAuthManager(): OAuthManager {
  return new OAuthManager()
}
