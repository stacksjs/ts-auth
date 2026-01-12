import type { OAuthProviderConfig, OAuthUser } from '../../types'
import { BaseOAuthProvider } from '../provider'

/**
 * Bitbucket OAuth Provider
 */
export class BitbucketProvider extends BaseOAuthProvider {
  protected authorizationUrl = 'https://bitbucket.org/site/oauth2/authorize'
  protected tokenUrl = 'https://bitbucket.org/site/oauth2/access_token'
  protected userInfoUrl = 'https://api.bitbucket.org/2.0/user'

  constructor(config: OAuthProviderConfig) {
    super(config)
  }

  protected getDefaultScopes(): string[] {
    return ['account', 'email']
  }

  async getUser(accessToken: string): Promise<OAuthUser> {
    // Get user profile
    const userResponse = await fetch(this.userInfoUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    })

    if (!userResponse.ok) {
      throw new Error('Failed to get user info from Bitbucket')
    }

    const userData = await userResponse.json()

    // Get user email
    let email: string | null = null
    const emailResponse = await fetch('https://api.bitbucket.org/2.0/user/emails', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    })

    if (emailResponse.ok) {
      const emailData = await emailResponse.json()
      const primaryEmail = emailData.values?.find((e: { is_primary: boolean }) => e.is_primary)
      email = primaryEmail?.email ?? emailData.values?.[0]?.email ?? null
    }

    // Get avatar URL from links
    let avatar: string | null = null
    if (userData.links?.avatar?.href) {
      avatar = userData.links.avatar.href
    }

    return {
      id: userData.uuid,
      name: userData.display_name ?? null,
      email,
      avatar,
      nickname: userData.username,
      raw: userData,
    }
  }

  async revokeToken(_token: string): Promise<void> {
    // Bitbucket doesn't support token revocation via API
    console.warn('Bitbucket does not support programmatic token revocation')
  }
}

/**
 * Create a Bitbucket OAuth provider instance
 */
export function createBitbucketProvider(config: OAuthProviderConfig): BitbucketProvider {
  return new BitbucketProvider(config)
}
