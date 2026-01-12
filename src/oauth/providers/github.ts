import type { OAuthProviderConfig, OAuthUser } from '../../types'
import { BaseOAuthProvider } from '../provider'

/**
 * GitHub OAuth Provider
 */
export class GitHubProvider extends BaseOAuthProvider {
  protected authorizationUrl = 'https://github.com/login/oauth/authorize'
  protected tokenUrl = 'https://github.com/login/oauth/access_token'
  protected userInfoUrl = 'https://api.github.com/user'
  protected scopeSeparator = ' '

  constructor(config: OAuthProviderConfig) {
    super(config)
  }

  protected getDefaultScopes(): string[] {
    return ['read:user', 'user:email']
  }

  async getUser(accessToken: string): Promise<OAuthUser> {
    // Get user profile
    const userResponse = await fetch(this.userInfoUrl, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/vnd.github.v3+json',
      },
    })

    if (!userResponse.ok) {
      throw new Error('Failed to get user info from GitHub')
    }

    const userData = await userResponse.json()

    // Get user email if not public
    let email = userData.email
    if (!email) {
      const emailResponse = await fetch('https://api.github.com/user/emails', {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/vnd.github.v3+json',
        },
      })

      if (emailResponse.ok) {
        const emails = await emailResponse.json()
        const primaryEmail = emails.find((e: { primary: boolean }) => e.primary)
        email = primaryEmail?.email ?? emails[0]?.email ?? null
      }
    }

    return {
      id: String(userData.id),
      name: userData.name ?? userData.login,
      email,
      avatar: userData.avatar_url ?? null,
      nickname: userData.login,
      raw: userData,
    }
  }

  async revokeToken(token: string): Promise<void> {
    const response = await fetch(`https://api.github.com/applications/${this.config.clientId}/token`, {
      method: 'DELETE',
      headers: {
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': `Basic ${btoa(`${this.config.clientId}:${this.config.clientSecret}`)}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ access_token: token }),
    })

    if (!response.ok && response.status !== 204) {
      throw new Error('Failed to revoke token')
    }
  }
}

/**
 * Create a GitHub OAuth provider instance
 */
export function createGitHubProvider(config: OAuthProviderConfig): GitHubProvider {
  return new GitHubProvider(config)
}
