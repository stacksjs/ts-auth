import type { OAuthProviderConfig, OAuthUser } from '../../types'
import { BaseOAuthProvider } from '../provider'

/**
 * Twitter (X) OAuth 2.0 Provider
 */
export class TwitterProvider extends BaseOAuthProvider {
  protected authorizationUrl = 'https://twitter.com/i/oauth2/authorize'
  protected tokenUrl = 'https://api.twitter.com/2/oauth2/token'
  protected userInfoUrl = 'https://api.twitter.com/2/users/me'
  protected scopeSeparator = ' '
  private codeVerifier: string | null = null

  constructor(config: OAuthProviderConfig) {
    super(config)
  }

  protected getDefaultScopes(): string[] {
    return ['tweet.read', 'users.read', 'offline.access']
  }

  /**
   * Get the authorization URL with PKCE
   */
  override getAuthorizationUrl(state?: string): string {
    this.state = state ?? this.generateState()
    this.codeVerifier = this.generateCodeVerifier()
    const codeChallenge = this.generateCodeChallenge(this.codeVerifier)

    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      scope: this.scopes.join(this.scopeSeparator),
      state: this.state,
      code_challenge: codeChallenge,
      code_challenge_method: 'plain', // Using plain for simplicity, should use S256 in production
      ...this.config.parameters,
    })

    return `${this.authorizationUrl}?${params.toString()}`
  }

  /**
   * Exchange authorization code for tokens
   */
  override async getAccessToken(code: string): Promise<import('../../types').OAuthTokens> {
    if (!this.codeVerifier) {
      throw new Error('Code verifier not set. Call getAuthorizationUrl first.')
    }

    const params = new URLSearchParams({
      code,
      redirect_uri: this.config.redirectUri,
      grant_type: 'authorization_code',
      client_id: this.config.clientId,
      code_verifier: this.codeVerifier,
    })

    const response = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        'Authorization': `Basic ${btoa(`${this.config.clientId}:${this.config.clientSecret}`)}`,
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

  async getUser(accessToken: string): Promise<OAuthUser> {
    const params = new URLSearchParams({
      'user.fields': 'id,name,username,profile_image_url',
    })

    const response = await fetch(`${this.userInfoUrl}?${params.toString()}`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    })

    if (!response.ok) {
      throw new Error('Failed to get user info from Twitter')
    }

    const { data } = await response.json()

    return {
      id: data.id,
      name: data.name ?? null,
      email: null, // Twitter doesn't provide email by default
      avatar: data.profile_image_url?.replace('_normal', '') ?? null,
      nickname: data.username,
      raw: data,
    }
  }

  async revokeToken(token: string): Promise<void> {
    const params = new URLSearchParams({
      token,
      token_type_hint: 'access_token',
      client_id: this.config.clientId,
    })

    const response = await fetch('https://api.twitter.com/2/oauth2/revoke', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${btoa(`${this.config.clientId}:${this.config.clientSecret}`)}`,
      },
      body: params.toString(),
    })

    if (!response.ok) {
      throw new Error('Failed to revoke token')
    }
  }

  private generateCodeVerifier(): string {
    const bytes = new Uint8Array(32)
    crypto.getRandomValues(bytes)
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
  }

  private generateCodeChallenge(verifier: string): string {
    // For simplicity, using plain method
    // In production, should use S256 with SHA-256 hash
    return verifier
  }
}

/**
 * Create a Twitter OAuth provider instance
 */
export function createTwitterProvider(config: OAuthProviderConfig): TwitterProvider {
  return new TwitterProvider(config)
}
