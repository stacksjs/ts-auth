import type { OAuthProviderConfig, OAuthUser } from '../../types'
import { BaseOAuthProvider } from '../provider'

/**
 * Slack OAuth Provider
 */
export class SlackProvider extends BaseOAuthProvider {
  protected authorizationUrl = 'https://slack.com/oauth/v2/authorize'
  protected tokenUrl = 'https://slack.com/api/oauth.v2.access'
  protected userInfoUrl = 'https://slack.com/api/users.identity'
  protected scopeSeparator = ','

  constructor(config: OAuthProviderConfig) {
    super(config)
  }

  protected getDefaultScopes(): string[] {
    return ['users:read', 'users:read.email']
  }

  override getAuthorizationUrl(state?: string): string {
    this.state = state ?? this.generateState()

    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: '', // Slack uses user_scope for user permissions
      user_scope: this.scopes.join(this.scopeSeparator),
      state: this.state,
      ...this.config.parameters,
    })

    return `${this.authorizationUrl}?${params.toString()}`
  }

  async getUser(accessToken: string): Promise<OAuthUser> {
    const response = await fetch(`${this.userInfoUrl}?token=${accessToken}`)

    if (!response.ok) {
      throw new Error('Failed to get user info from Slack')
    }

    const data = await response.json()

    if (!data.ok) {
      throw new Error(`Slack API error: ${data.error}`)
    }

    return {
      id: data.user.id,
      name: data.user.name ?? null,
      email: data.user.email ?? null,
      avatar: data.user.image_512 ?? data.user.image_192 ?? data.user.image_72 ?? null,
      raw: data,
    }
  }

  async revokeToken(token: string): Promise<void> {
    const response = await fetch(`https://slack.com/api/auth.revoke?token=${token}`, {
      method: 'POST',
    })

    if (!response.ok) {
      throw new Error('Failed to revoke token')
    }

    const data = await response.json()
    if (!data.ok) {
      throw new Error(`Failed to revoke token: ${data.error}`)
    }
  }
}

/**
 * Create a Slack OAuth provider instance
 */
export function createSlackProvider(config: OAuthProviderConfig): SlackProvider {
  return new SlackProvider(config)
}
