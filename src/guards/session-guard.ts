import type { Authenticatable, Credentials, Guard, GuardConfig, UserProvider } from '../types'
import type { SessionManager } from '../session/session'

/**
 * Session-based authentication guard (Laravel-style)
 */
export class SessionGuard implements Guard {
  private name: string
  private provider: UserProvider
  private session: SessionManager
  private config: GuardConfig
  private currentUser: Authenticatable | null = null
  private userResolved = false
  private loggedOut = false

  constructor(
    name: string,
    provider: UserProvider,
    session: SessionManager,
    config: GuardConfig,
  ) {
    this.name = name
    this.provider = provider
    this.session = session
    this.config = config
  }

  /**
   * Attempt to authenticate a user using the given credentials
   */
  async attempt(credentials: Credentials, remember = false): Promise<boolean> {
    const user = await this.provider.retrieveByCredentials(credentials)

    if (!user) {
      return false
    }

    // Validate credentials
    const valid = await this.provider.validateCredentials(user, credentials)

    if (valid) {
      await this.login(user, remember)
      return true
    }

    return false
  }

  /**
   * Log a user into the application
   */
  async login(user: Authenticatable, remember = false): Promise<void> {
    // Store user ID in session
    const id = user.getAuthIdentifier()
    this.session.put(this.getSessionKey(), id)

    // Handle remember me
    if (remember) {
      await this.ensureRememberTokenIsSet(user)
      // Store remember token in cookie (handled by middleware)
      this.session.put(this.getRememberKey(), user.getRememberToken())
    }

    // Regenerate session to prevent session fixation
    await this.session.regenerate(false)

    this.setUser(user)
    this.loggedOut = false
  }

  /**
   * Log the user out of the application
   */
  async logout(): Promise<void> {
    const user = await this.user()

    // Clear remember token if exists
    if (user) {
      await this.clearRememberToken(user)
    }

    // Clear session
    this.session.forget(this.getSessionKey())
    this.session.forget(this.getRememberKey())

    // Invalidate and regenerate session
    await this.session.invalidate()

    this.currentUser = null
    this.userResolved = true
    this.loggedOut = true
  }

  /**
   * Get the currently authenticated user
   */
  async user(): Promise<Authenticatable | null> {
    if (this.loggedOut) {
      return null
    }

    if (this.userResolved) {
      return this.currentUser
    }

    // Try to get user from session
    const id = this.session.get<string | number>(this.getSessionKey())

    if (id !== null) {
      this.currentUser = await this.provider.retrieveById(id)
    }

    // Try remember me token if no session user
    if (!this.currentUser) {
      const rememberToken = this.session.get<string>(this.getRememberKey())
      if (rememberToken && id) {
        this.currentUser = await this.provider.retrieveByToken(id, rememberToken)
      }
    }

    this.userResolved = true
    return this.currentUser
  }

  /**
   * Get the ID for the currently authenticated user
   */
  async id(): Promise<string | number | null> {
    const user = await this.user()
    return user?.getAuthIdentifier() ?? null
  }

  /**
   * Determine if the current user is authenticated
   */
  async check(): Promise<boolean> {
    const user = await this.user()
    return user !== null
  }

  /**
   * Determine if the current user is a guest
   */
  async guest(): Promise<boolean> {
    return !(await this.check())
  }

  /**
   * Validate a user's credentials
   */
  async validate(credentials: Credentials): Promise<boolean> {
    const user = await this.provider.retrieveByCredentials(credentials)
    if (!user) {
      return false
    }
    return this.provider.validateCredentials(user, credentials)
  }

  /**
   * Set the current user
   */
  setUser(user: Authenticatable): void {
    this.currentUser = user
    this.userResolved = true
    this.loggedOut = false
  }

  /**
   * Get the user provider
   */
  getProvider(): UserProvider {
    return this.provider
  }

  /**
   * Set the user provider
   */
  setProvider(provider: UserProvider): void {
    this.provider = provider
  }

  /**
   * Login as the given user ID
   */
  async loginUsingId(id: string | number, remember = false): Promise<Authenticatable | null> {
    const user = await this.provider.retrieveById(id)
    if (user) {
      await this.login(user, remember)
      return user
    }
    return null
  }

  /**
   * Log the user in for a single request (no session)
   */
  once(user: Authenticatable): void {
    this.setUser(user)
  }

  /**
   * Log the user in using credentials for a single request
   */
  async onceUsingId(id: string | number): Promise<Authenticatable | null> {
    const user = await this.provider.retrieveById(id)
    if (user) {
      this.once(user)
      return user
    }
    return null
  }

  /**
   * Determine if the user was authenticated via "remember me" cookie
   */
  viaRemember(): boolean {
    return this.session.has(this.getRememberKey())
  }

  private getSessionKey(): string {
    return `auth_${this.name}`
  }

  private getRememberKey(): string {
    return `auth_${this.name}_remember`
  }

  private async ensureRememberTokenIsSet(user: Authenticatable): Promise<void> {
    if (!user.getRememberToken()) {
      const token = this.generateRememberToken()
      user.setRememberToken(token)
      await this.provider.updateRememberToken(user, token)
    }
  }

  private async clearRememberToken(user: Authenticatable): Promise<void> {
    user.setRememberToken('')
    await this.provider.updateRememberToken(user, '')
  }

  private generateRememberToken(): string {
    const bytes = new Uint8Array(64)
    crypto.getRandomValues(bytes)
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
  }
}
