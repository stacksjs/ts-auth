import type { OAuthProviderConfig, OAuthUser } from '../../types'
import { BaseOAuthProvider } from '../provider'

/**
 * LinkedIn OAuth Provider
 */
export class LinkedInProvider extends BaseOAuthProvider {
  protected authorizationUrl = 'https://www.linkedin.com/oauth/v2/authorization'
  protected tokenUrl = 'https://www.linkedin.com/oauth/v2/accessToken'
  protected userInfoUrl = 'https://api.linkedin.com/v2/userinfo'

  constructor(config: OAuthProviderConfig) {
    super(config)
  }

  protected getDefaultScopes(): string[] {
    return ['openid', 'profile', 'email']
  }

  async getUser(accessToken: string): Promise<OAuthUser> {
    const response = await fetch(this.userInfoUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    })

    if (!response.ok) {
      throw new Error('Failed to get user info from LinkedIn')
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

  async revokeToken(_token: string): Promise<void> {
    // LinkedIn doesn't support token revocation via API
    // The token will expire naturally
    console.warn('LinkedIn does not support programmatic token revocation')
  }
}

/**
 * Create a LinkedIn OAuth provider instance
 */
export function createLinkedInProvider(config: OAuthProviderConfig): LinkedInProvider {
  return new LinkedInProvider(config)
}
