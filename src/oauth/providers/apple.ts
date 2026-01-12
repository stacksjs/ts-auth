import type { OAuthProviderConfig, OAuthUser } from '../../types'
import { BaseOAuthProvider } from '../provider'

/**
 * Apple OAuth Provider (Sign in with Apple)
 */
export class AppleProvider extends BaseOAuthProvider {
  protected authorizationUrl = 'https://appleid.apple.com/auth/authorize'
  protected tokenUrl = 'https://appleid.apple.com/auth/token'
  protected userInfoUrl = '' // Apple doesn't have a userinfo endpoint

  constructor(config: OAuthProviderConfig) {
    super(config)
  }

  protected getDefaultScopes(): string[] {
    return ['name', 'email']
  }

  override getAuthorizationUrl(state?: string): string {
    this.state = state ?? this.generateState()

    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      scope: this.scopes.join(' '),
      state: this.state,
      response_mode: 'form_post',
      ...this.config.parameters,
    })

    return `${this.authorizationUrl}?${params.toString()}`
  }

  async getUser(accessToken: string): Promise<OAuthUser> {
    // Apple includes user info in the ID token, not via a separate endpoint
    // The ID token is a JWT that needs to be decoded
    const parts = accessToken.split('.')
    if (parts.length !== 3) {
      throw new Error('Invalid ID token')
    }

    // Decode the payload (middle part)
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')))

    return {
      id: payload.sub,
      name: null, // Apple only sends name on first authentication
      email: payload.email ?? null,
      avatar: null, // Apple doesn't provide avatars
      raw: payload,
    }
  }

  async revokeToken(token: string): Promise<void> {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      token,
      token_type_hint: 'access_token',
    })

    const response = await fetch('https://appleid.apple.com/auth/revoke', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    })

    if (!response.ok) {
      throw new Error('Failed to revoke token')
    }
  }
}

/**
 * Create an Apple OAuth provider instance
 */
export function createAppleProvider(config: OAuthProviderConfig): AppleProvider {
  return new AppleProvider(config)
}
