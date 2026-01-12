import type { AuthConfig } from './types'
import { loadConfig } from 'bunfig'

export const defaultConfig: AuthConfig = {
  verbose: false,

  defaults: {
    guard: 'web',
  },

  guards: {
    web: {
      driver: 'session',
      provider: 'users',
    },
    api: {
      driver: 'token',
      provider: 'users',
    },
  },

  providers: {
    users: {
      driver: 'database',
      table: 'users',
    },
  },

  tokens: {
    expiry: '1h',
    refresh: true,
    refreshExpiry: '7d',
    algorithm: 'HS256',
  },

  session: {
    driver: 'memory',
    lifetime: 120,
    expireOnClose: false,
    encrypt: false,
    cookie: 'session',
    path: '/',
    domain: null,
    secure: true,
    httpOnly: true,
    sameSite: 'lax',
  },
}

// Lazy-loaded config to avoid top-level await (enables bun --compile)
let _config: AuthConfig | null = null

export async function getConfig(): Promise<AuthConfig> {
  if (!_config) {
    _config = await loadConfig({
      name: 'auth',
      defaultConfig,
    })
  }
  return _config
}

// For backwards compatibility - synchronous access with default fallback
export const config: AuthConfig = defaultConfig
