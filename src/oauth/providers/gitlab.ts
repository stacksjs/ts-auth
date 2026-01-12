import type { OAuthProviderConfig, OAuthUser } from '../../types'
import { BaseOAuthProvider } from '../provider'

/**
 * GitLab OAuth Provider
 */
export class GitLabProvider extends BaseOAuthProvider {
  protected authorizationUrl = 'https://gitlab.com/oauth/authorize'
  protected tokenUrl = 'https://gitlab.com/oauth/token'
  protected userInfoUrl = 'https://gitlab.com/api/v4/user'
  private baseUrl: string

  constructor(config: OAuthProviderConfig, baseUrl = 'https://gitlab.com') {
    super(config)
    this.baseUrl = baseUrl
    this.authorizationUrl = `${baseUrl}/oauth/authorize`
    this.tokenUrl = `${baseUrl}/oauth/token`
    this.userInfoUrl = `${baseUrl}/api/v4/user`
  }

  protected getDefaultScopes(): string[] {
    return ['read_user']
  }

  async getUser(accessToken: string): Promise<OAuthUser> {
    const response = await fetch(this.userInfoUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    })

    if (!response.ok) {
      throw new Error('Failed to get user info from GitLab')
    }

    const data = await response.json()

    return {
      id: String(data.id),
      name: data.name ?? null,
      email: data.email ?? null,
      avatar: data.avatar_url ?? null,
      nickname: data.username,
      raw: data,
    }
  }

  async revokeToken(token: string): Promise<void> {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      token,
    })

    const response = await fetch(`${this.baseUrl}/oauth/revoke`, {
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
 * Create a GitLab OAuth provider instance
 */
export function createGitLabProvider(config: OAuthProviderConfig, baseUrl?: string): GitLabProvider {
  return new GitLabProvider(config, baseUrl)
}
