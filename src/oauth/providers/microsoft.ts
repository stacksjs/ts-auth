import type { OAuthProviderConfig, OAuthUser } from '../../types'
import { BaseOAuthProvider } from '../provider'

/**
 * Microsoft OAuth Provider (Azure AD / Microsoft Account)
 */
export class MicrosoftProvider extends BaseOAuthProvider {
  protected authorizationUrl = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
  protected tokenUrl = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
  protected userInfoUrl = 'https://graph.microsoft.com/v1.0/me'

  constructor(config: OAuthProviderConfig) {
    super(config)
  }

  protected getDefaultScopes(): string[] {
    return ['openid', 'email', 'profile', 'User.Read']
  }

  async getUser(accessToken: string): Promise<OAuthUser> {
    const response = await fetch(this.userInfoUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    })

    if (!response.ok) {
      throw new Error('Failed to get user info from Microsoft')
    }

    const data = await response.json()

    // Try to get profile photo
    let avatar: string | null = null
    try {
      const photoResponse = await fetch('https://graph.microsoft.com/v1.0/me/photo/$value', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      })
      if (photoResponse.ok) {
        const blob = await photoResponse.blob()
        const buffer = await blob.arrayBuffer()
        const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)))
        avatar = `data:image/jpeg;base64,${base64}`
      }
    }
    catch {
      // Photo not available
    }

    return {
      id: data.id,
      name: data.displayName ?? null,
      email: data.mail ?? data.userPrincipalName ?? null,
      avatar,
      raw: data,
    }
  }

  async revokeToken(_token: string): Promise<void> {
    // Microsoft doesn't support token revocation via API for consumer accounts
    // Enterprise accounts can use the /logout endpoint
    console.warn('Microsoft consumer accounts do not support programmatic token revocation')
  }
}

/**
 * Create a Microsoft OAuth provider instance
 */
export function createMicrosoftProvider(config: OAuthProviderConfig): MicrosoftProvider {
  return new MicrosoftProvider(config)
}
