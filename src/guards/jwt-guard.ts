import type { Authenticatable, Credentials, Guard, GuardConfig, JWTPayload, TokenResult, UserProvider } from '../types'
import type { TokenManager } from '../jwt/token-manager'

/**
 * JWT-based authentication guard
 */
export class JwtGuard implements Guard {
  private name: string
  private provider: UserProvider
  private config: GuardConfig
  private tokenManager: TokenManager
  private currentUser: Authenticatable | null = null
  private userResolved = false
  private request: Request | null = null
  private currentPayload: JWTPayload | null = null

  constructor(
    name: string,
    provider: UserProvider,
    tokenManager: TokenManager,
    config: GuardConfig,
  ) {
    this.name = name
    this.provider = provider
    this.tokenManager = tokenManager
    this.config = config
  }

  /**
   * Set the current request (for extracting token)
   */
  setRequest(request: Request): void {
    this.request = request
    this.userResolved = false
    this.currentUser = null
    this.currentPayload = null
  }

  /**
   * Attempt to authenticate a user using the given credentials
   */
  async attempt(credentials: Credentials): Promise<boolean> {
    const user = await this.provider.retrieveByCredentials(credentials)

    if (!user) {
      return false
    }

    const valid = await this.provider.validateCredentials(user, credentials)

    if (valid) {
      this.setUser(user)
      return true
    }

    return false
  }

  /**
   * Log a user into the application and return JWT tokens
   */
  async login(user: Authenticatable): Promise<void> {
    this.setUser(user)
  }

  /**
   * Log the user out of the application
   */
  async logout(): Promise<void> {
    // For JWT guard, logout typically means client-side token deletion
    // Optionally, you could implement token blacklisting here
    this.currentUser = null
    this.currentPayload = null
    this.userResolved = true
  }

  /**
   * Get the currently authenticated user
   */
  async user(): Promise<Authenticatable | null> {
    if (this.userResolved) {
      return this.currentUser
    }

    // Get token from request
    const token = this.getTokenFromRequest()

    if (!token) {
      this.userResolved = true
      return null
    }

    try {
      // Verify and decode token
      const payload = await this.tokenManager.verifyJwtToken<JWTPayload>(token)
      this.currentPayload = payload

      // Get user by subject ID
      this.currentUser = await this.provider.retrieveById(payload.sub)
    }
    catch {
      // Token verification failed
      this.currentUser = null
      this.currentPayload = null
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
   * Issue JWT tokens for a user
   */
  async issueTokens(user: Authenticatable, claims: Record<string, unknown> = {}): Promise<TokenResult> {
    return this.tokenManager.createJwtTokenPair(user.getAuthIdentifier(), claims)
  }

  /**
   * Refresh tokens using a refresh token
   */
  async refreshTokens(refreshToken: string): Promise<TokenResult> {
    return this.tokenManager.refreshJwtTokenPair(refreshToken)
  }

  /**
   * Get the current JWT payload
   */
  getPayload(): JWTPayload | null {
    return this.currentPayload
  }

  /**
   * Get a specific claim from the JWT payload
   */
  getClaim<T>(key: string): T | null {
    return (this.currentPayload?.[key] as T) ?? null
  }

  /**
   * Check if a custom claim exists in the token
   */
  hasClaim(key: string): boolean {
    return this.currentPayload !== null && key in this.currentPayload
  }

  /**
   * Login using credentials and return tokens
   */
  async attemptAndIssue(
    credentials: Credentials,
    claims: Record<string, unknown> = {},
  ): Promise<TokenResult | null> {
    if (await this.attempt(credentials)) {
      const user = await this.user()
      if (user) {
        return this.issueTokens(user, claims)
      }
    }
    return null
  }

  /**
   * Get token from request
   */
  private getTokenFromRequest(): string | null {
    if (!this.request) {
      return null
    }

    // Check Authorization header (Bearer token)
    const authHeader = this.request.headers.get('Authorization')
    if (authHeader?.startsWith('Bearer ')) {
      return authHeader.slice(7)
    }

    // Check query parameter
    const inputKey = this.config.inputKey ?? 'token'
    const url = new URL(this.request.url)
    const queryToken = url.searchParams.get(inputKey)
    if (queryToken) {
      return queryToken
    }

    // Check cookie
    const cookieHeader = this.request.headers.get('Cookie')
    if (cookieHeader) {
      const cookies = parseCookies(cookieHeader)
      const cookieKey = this.config.storageKey ?? 'jwt_token'
      if (cookies[cookieKey]) {
        return cookies[cookieKey]
      }
    }

    return null
  }
}

/**
 * Parse cookies from header
 */
function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {}
  const pairs = cookieHeader.split(';')

  for (const pair of pairs) {
    const [name, ...rest] = pair.trim().split('=')
    if (name) {
      cookies[name] = rest.join('=')
    }
  }

  return cookies
}
