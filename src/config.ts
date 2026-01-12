import type { AuthConfig } from './types'
import { loadConfig } from 'bunfig'

export const defaultConfig: AuthConfig = {
  verbose: true,
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
