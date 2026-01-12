import type { OAuthProviderConfig, OAuthUser } from '../../types'
import { BaseOAuthProvider } from '../provider'

/**
 * Facebook OAuth Provider
 */
export class FacebookProvider extends BaseOAuthProvider {
  protected authorizationUrl = 'https://www.facebook.com/v18.0/dialog/oauth'
  protected tokenUrl = 'https://graph.facebook.com/v18.0/oauth/access_token'
  protected userInfoUrl = 'https://graph.facebook.com/v18.0/me'
  protected scopeSeparator = ','

  constructor(config: OAuthProviderConfig) {
    super(config)
  }

  protected getDefaultScopes(): string[] {
    return ['email', 'public_profile']
  }

  async getUser(accessToken: string): Promise<OAuthUser> {
    const fields = 'id,name,email,picture.type(large)'
    const response = await fetch(
      `${this.userInfoUrl}?fields=${fields}&access_token=${accessToken}`,
      {
        headers: {
          Accept: 'application/json',
        },
      },
    )

    if (!response.ok) {
      throw new Error('Failed to get user info from Facebook')
    }

    const data = await response.json()

    return {
      id: data.id,
      name: data.name ?? null,
      email: data.email ?? null,
      avatar: data.picture?.data?.url ?? null,
      raw: data,
    }
  }

  async revokeToken(token: string): Promise<void> {
    const response = await fetch(
      `https://graph.facebook.com/v18.0/me/permissions?access_token=${token}`,
      {
        method: 'DELETE',
      },
    )

    if (!response.ok) {
      throw new Error('Failed to revoke token')
    }
  }
}

/**
 * Create a Facebook OAuth provider instance
 */
export function createFacebookProvider(config: OAuthProviderConfig): FacebookProvider {
  return new FacebookProvider(config)
}
