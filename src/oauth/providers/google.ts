import type { OAuthProviderConfig, OAuthUser } from '../../types'
import { BaseOAuthProvider } from '../provider'

/**
 * Google OAuth Provider
 */
export class GoogleProvider extends BaseOAuthProvider {
  protected authorizationUrl = 'https://accounts.google.com/o/oauth2/v2/auth'
  protected tokenUrl = 'https://oauth2.googleapis.com/token'
  protected userInfoUrl = 'https://www.googleapis.com/oauth2/v3/userinfo'

  constructor(config: OAuthProviderConfig) {
    super(config)
  }

  protected getDefaultScopes(): string[] {
    return ['openid', 'email', 'profile']
  }

  async getUser(accessToken: string): Promise<OAuthUser> {
    const response = await fetch(this.userInfoUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    })

    if (!response.ok) {
      throw new Error('Failed to get user info from Google')
    }

    const data = await response.json()

    return {
      id: data.sub,
      name: data.name ?? null,
      email: data.email ?? null,
      avatar: data.picture ?? null,
      raw: data,
    }
  }

  async revokeToken(token: string): Promise<void> {
    const response = await fetch(`https://oauth2.googleapis.com/revoke?token=${token}`, {
      method: 'POST',
    })

    if (!response.ok) {
      throw new Error('Failed to revoke token')
    }
  }
}

/**
 * Create a Google OAuth provider instance
 */
export function createGoogleProvider(config: OAuthProviderConfig): GoogleProvider {
  return new GoogleProvider(config)
}
