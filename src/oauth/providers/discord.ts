import type { OAuthProviderConfig, OAuthUser } from '../../types'
import { BaseOAuthProvider } from '../provider'

/**
 * Discord OAuth Provider
 */
export class DiscordProvider extends BaseOAuthProvider {
  protected authorizationUrl = 'https://discord.com/oauth2/authorize'
  protected tokenUrl = 'https://discord.com/api/oauth2/token'
  protected userInfoUrl = 'https://discord.com/api/users/@me'

  constructor(config: OAuthProviderConfig) {
    super(config)
  }

  protected getDefaultScopes(): string[] {
    return ['identify', 'email']
  }

  async getUser(accessToken: string): Promise<OAuthUser> {
    const response = await fetch(this.userInfoUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    })

    if (!response.ok) {
      throw new Error('Failed to get user info from Discord')
    }

    const data = await response.json()

    // Build avatar URL
    let avatar: string | null = null
    if (data.avatar) {
      const format = data.avatar.startsWith('a_') ? 'gif' : 'png'
      avatar = `https://cdn.discordapp.com/avatars/${data.id}/${data.avatar}.${format}`
    }

    return {
      id: data.id,
      name: data.global_name ?? data.username,
      email: data.email ?? null,
      avatar,
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

    const response = await fetch('https://discord.com/api/oauth2/token/revoke', {
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
 * Create a Discord OAuth provider instance
 */
export function createDiscordProvider(config: OAuthProviderConfig): DiscordProvider {
  return new DiscordProvider(config)
}
