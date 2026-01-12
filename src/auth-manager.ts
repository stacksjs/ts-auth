import type {
  AuthConfig,
  AuthManager,
  Guard,
  GuardConfig,
  GuardFactory,
  ProviderConfig,
  ProviderFactory,
  TokenConfig,
  UserProvider,
} from './types'
import { SessionGuard } from './guards/session-guard'
import { TokenGuard } from './guards/token-guard'
import { JwtGuard } from './guards/jwt-guard'
import { SessionManager } from './session/session'
import { createTokenManager, TokenManager } from './jwt/token-manager'
import { DatabaseUserProvider, InMemoryUserProvider } from './providers/database-provider'

/**
 * Auth Manager - Laravel-style authentication orchestration
 */
export class AuthenticationManager implements AuthManager {
  private config: AuthConfig
  private guards: Map<string, Guard> = new Map()
  private customGuardDrivers: Map<string, GuardFactory> = new Map()
  private customProviders: Map<string, ProviderFactory> = new Map()
  private providers: Map<string, UserProvider> = new Map()
  private session: SessionManager | null = null
  private tokenManager: TokenManager | null = null

  constructor(config: AuthConfig) {
    this.config = config
  }

  /**
   * Set the session manager (required for session-based auth)
   */
  setSession(session: SessionManager): void {
    this.session = session
  }

  /**
   * Set the token manager (required for token/JWT auth)
   */
  setTokenManager(tokenManager: TokenManager): void {
    this.tokenManager = tokenManager
  }

  /**
   * Get the default guard name
   */
  getDefaultDriver(): string {
    return this.config.defaults.guard
  }

  /**
   * Set the default guard name
   */
  setDefaultDriver(name: string): void {
    this.config.defaults.guard = name
  }

  /**
   * Get a guard instance by name
   */
  guard(name?: string): Guard {
    const guardName = name ?? this.getDefaultDriver()

    // Return cached guard if exists
    if (this.guards.has(guardName)) {
      return this.guards.get(guardName)!
    }

    // Create new guard
    const guard = this.resolve(guardName)
    this.guards.set(guardName, guard)

    return guard
  }

  /**
   * Resolve a guard instance
   */
  private resolve(name: string): Guard {
    const config = this.config.guards[name]

    if (!config) {
      throw new Error(`Guard [${name}] is not defined.`)
    }

    // Check for custom driver
    if (this.customGuardDrivers.has(config.driver)) {
      const factory = this.customGuardDrivers.get(config.driver)!
      return factory(name, config)
    }

    // Use built-in drivers
    switch (config.driver) {
      case 'session':
        return this.createSessionDriver(name, config)
      case 'token':
        return this.createTokenDriver(name, config)
      case 'jwt':
        return this.createJwtDriver(name, config)
      default:
        throw new Error(`Guard driver [${config.driver}] is not supported.`)
    }
  }

  /**
   * Create a session guard
   */
  createSessionDriver(name: string, config: GuardConfig): Guard {
    if (!this.session) {
      throw new Error('Session manager not set. Call setSession() first.')
    }

    const provider = this.createUserProvider(config.provider)
    if (!provider) {
      throw new Error(`Provider [${config.provider}] is not defined.`)
    }

    return new SessionGuard(name, provider, this.session, config)
  }

  /**
   * Create a token guard (API tokens)
   */
  createTokenDriver(name: string, config: GuardConfig): Guard {
    if (!this.tokenManager) {
      // Create default token manager if not set
      const secret = this.config.tokens?.secret ?? this.generateSecret()
      this.tokenManager = createTokenManager(secret, this.config.tokens)
    }

    const provider = this.createUserProvider(config.provider)
    if (!provider) {
      throw new Error(`Provider [${config.provider}] is not defined.`)
    }

    return new TokenGuard(name, provider, this.tokenManager, config)
  }

  /**
   * Create a JWT guard
   */
  createJwtDriver(name: string, config: GuardConfig): Guard {
    if (!this.tokenManager) {
      // Create default token manager if not set
      const secret = this.config.tokens?.secret ?? this.generateSecret()
      this.tokenManager = createTokenManager(secret, this.config.tokens)
    }

    const provider = this.createUserProvider(config.provider)
    if (!provider) {
      throw new Error(`Provider [${config.provider}] is not defined.`)
    }

    return new JwtGuard(name, provider, this.tokenManager, config)
  }

  /**
   * Get a user provider by name
   */
  createUserProvider(name: string): UserProvider | null {
    // Return cached provider if exists
    if (this.providers.has(name)) {
      return this.providers.get(name)!
    }

    const config = this.config.providers[name]

    if (!config) {
      return null
    }

    // Check for custom provider
    if (this.customProviders.has(config.driver)) {
      const factory = this.customProviders.get(config.driver)!
      const provider = factory(config)
      this.providers.set(name, provider)
      return provider
    }

    // Use built-in providers
    let provider: UserProvider

    switch (config.driver) {
      case 'database':
        // For database provider, we need external dependencies
        // Return a placeholder that throws helpful errors
        throw new Error(
          'Database provider requires external configuration. '
          + 'Register a custom provider using auth.provider() or use InMemoryUserProvider for testing.',
        )
      case 'eloquent':
        // Eloquent is Laravel-specific, provide helpful error
        throw new Error(
          'Eloquent provider is not available in ts-auth. '
          + 'Use database driver with a custom queryUser function instead.',
        )
      default:
        throw new Error(`Provider driver [${config.driver}] is not supported.`)
    }
  }

  /**
   * Register a custom guard driver
   */
  extend(driver: string, callback: GuardFactory): void {
    this.customGuardDrivers.set(driver, callback)
  }

  /**
   * Register a custom user provider
   */
  provider(name: string, callback: ProviderFactory): void {
    this.customProviders.set(name, callback)
  }

  /**
   * Register an in-memory provider (useful for testing)
   */
  registerInMemoryProvider(name: string, users: Record<string, unknown>[] = []): void {
    const provider = new InMemoryUserProvider(users)
    this.providers.set(name, provider)
  }

  /**
   * Register a database provider with custom functions
   */
  registerDatabaseProvider(
    name: string,
    config: ProviderConfig,
    options: {
      hashPassword: (password: string) => Promise<string>
      verifyPassword: (password: string, hash: string) => Promise<boolean>
      queryUser: (table: string, query: Record<string, unknown>) => Promise<Record<string, unknown> | null>
      updateUser: (table: string, id: string | number, data: Record<string, unknown>) => Promise<void>
    },
  ): void {
    const provider = new DatabaseUserProvider(config, options)
    this.providers.set(name, provider)
  }

  /**
   * Generate a random secret for JWT signing
   */
  private generateSecret(): string {
    const bytes = new Uint8Array(32)
    crypto.getRandomValues(bytes)
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
  }

  /**
   * Get the token manager instance
   */
  getTokenManager(): TokenManager | null {
    return this.tokenManager
  }

  /**
   * Get the session manager instance
   */
  getSession(): SessionManager | null {
    return this.session
  }
}

/**
 * Create an auth manager instance
 */
export function createAuthManager(config: AuthConfig): AuthenticationManager {
  return new AuthenticationManager(config)
}

/**
 * Default auth configuration
 */
export const defaultAuthConfig: AuthConfig = {
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
