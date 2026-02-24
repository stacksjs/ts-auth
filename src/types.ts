// ============================================
// Core Auth Config Types (Laravel-style)
// ============================================

export interface AuthConfig {
  verbose: boolean

  /**
   * Default authentication guard
   */
  defaults: {
    guard: string
    passwords?: string
  }

  /**
   * Authentication guards configuration
   * Guards define how users are authenticated for each request
   */
  guards: Record<string, GuardConfig>

  /**
   * User providers configuration
   * Providers define how users are retrieved from storage
   */
  providers: Record<string, ProviderConfig>

  /**
   * Token configuration for API authentication
   */
  tokens?: TokenConfig

  /**
   * Session configuration
   */
  session?: SessionConfig

  /**
   * OAuth providers configuration
   */
  oauth?: Record<string, OAuthProviderConfig>

  /**
   * WebAuthn configuration
   */
  webauthn?: WebAuthnConfig

  /**
   * TOTP configuration
   */
  totp?: TOTPConfig
}

export type AuthOptions = Partial<AuthConfig>

// ============================================
// Guard Types
// ============================================

export type GuardDriver = 'session' | 'token' | 'jwt' | 'webauthn'

export interface GuardConfig {
  driver: GuardDriver
  provider: string
  hash?: boolean
  inputKey?: string
  storageKey?: string
}

export interface Guard {
  /**
   * Attempt to authenticate a user using the given credentials
   */
  attempt(credentials: Credentials): Promise<boolean>

  /**
   * Log a user into the application
   */
  login(user: Authenticatable): Promise<void>

  /**
   * Log the user out of the application
   */
  logout(): Promise<void>

  /**
   * Get the currently authenticated user
   */
  user(): Promise<Authenticatable | null>

  /**
   * Get the ID for the currently authenticated user
   */
  id(): Promise<string | number | null>

  /**
   * Determine if the current user is authenticated
   */
  check(): Promise<boolean>

  /**
   * Determine if the current user is a guest
   */
  guest(): Promise<boolean>

  /**
   * Validate a user's credentials
   */
  validate(credentials: Credentials): Promise<boolean>

  /**
   * Set the current user
   */
  setUser(user: Authenticatable): void
}

// ============================================
// Provider Types
// ============================================

export type ProviderDriver = 'database' | 'eloquent' | 'custom'

export interface ProviderConfig {
  driver: ProviderDriver
  model?: string
  table?: string
  connection?: string
}

export interface UserProvider {
  /**
   * Retrieve a user by their unique identifier
   */
  retrieveById(identifier: string | number): Promise<Authenticatable | null>

  /**
   * Retrieve a user by their unique identifier and "remember me" token
   */
  retrieveByToken(identifier: string | number, token: string): Promise<Authenticatable | null>

  /**
   * Update the "remember me" token for the given user
   */
  updateRememberToken(user: Authenticatable, token: string): Promise<void>

  /**
   * Retrieve a user by the given credentials
   */
  retrieveByCredentials(credentials: Credentials): Promise<Authenticatable | null>

  /**
   * Validate a user against the given credentials
   */
  validateCredentials(user: Authenticatable, credentials: Credentials): Promise<boolean>
}

// ============================================
// Authenticatable Interface
// ============================================

export interface Authenticatable {
  /**
   * Get the unique identifier for the user
   */
  getAuthIdentifier(): string | number

  /**
   * Get the name of the unique identifier column
   */
  getAuthIdentifierName(): string

  /**
   * Get the password for the user
   */
  getAuthPassword(): string

  /**
   * Get the "remember me" token value
   */
  getRememberToken(): string | null

  /**
   * Set the "remember me" token value
   */
  setRememberToken(value: string): void

  /**
   * Get the column name for the "remember me" token
   */
  getRememberTokenName(): string
}

export interface Credentials {
  [key: string]: unknown
  email?: string
  username?: string
  password?: string
}

// ============================================
// Token Types (JWT & API Tokens)
// ============================================

export interface TokenConfig {
  /**
   * Token expiration time (e.g., '7d', '1h', '30m')
   */
  expiry: string

  /**
   * Enable refresh tokens
   */
  refresh: boolean

  /**
   * Refresh token expiration time
   */
  refreshExpiry?: string

  /**
   * JWT secret key (for JWT driver)
   */
  secret?: string

  /**
   * JWT algorithm
   */
  algorithm?: JWTAlgorithm

  /**
   * Token issuer
   */
  issuer?: string

  /**
   * Token audience
   */
  audience?: string
}

export type JWTAlgorithm = 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512'

export interface JWTPayload {
  /**
   * Subject (user identifier)
   */
  sub: string | number

  /**
   * Issued at timestamp
   */
  iat: number

  /**
   * Expiration timestamp
   */
  exp: number

  /**
   * Not before timestamp
   */
  nbf?: number

  /**
   * Issuer
   */
  iss?: string

  /**
   * Audience
   */
  aud?: string

  /**
   * JWT ID
   */
  jti?: string

  /**
   * Custom claims
   */
  [key: string]: unknown
}

export interface TokenResult {
  accessToken: string
  tokenType: 'Bearer'
  expiresIn: number
  refreshToken?: string
}

export interface AccessToken {
  id: string
  userId: string | number
  name: string
  token: string
  abilities: string[]
  lastUsedAt: Date | null
  expiresAt: Date | null
  createdAt: Date
}

// ============================================
// Session Types
// ============================================

export type SessionDriver = 'file' | 'cookie' | 'database' | 'redis' | 'memory' | 'array'

export interface SessionConfig {
  /**
   * Session driver
   */
  driver: SessionDriver

  /**
   * Session lifetime in minutes
   */
  lifetime: number

  /**
   * Expire session on close
   */
  expireOnClose: boolean

  /**
   * Encrypt session data
   */
  encrypt: boolean

  /**
   * Session cookie name
   */
  cookie: string

  /**
   * Session cookie path
   */
  path: string

  /**
   * Session cookie domain
   */
  domain: string | null

  /**
   * HTTPS only cookies
   */
  secure: boolean

  /**
   * HTTP only access
   */
  httpOnly: boolean

  /**
   * Same site cookie attribute
   */
  sameSite: 'lax' | 'strict' | 'none'

  /**
   * Session storage table (for database driver)
   */
  table?: string

  /**
   * Session storage connection (for database driver)
   */
  connection?: string

  /**
   * Redis connection (for redis driver)
   */
  redisConnection?: string

  /**
   * File storage path (for file driver)
   */
  files?: string
}

export interface Session {
  /**
   * Get the session ID
   */
  getId(): string

  /**
   * Set the session ID
   */
  setId(id: string): void

  /**
   * Start the session
   */
  start(): Promise<boolean>

  /**
   * Save the session data
   */
  save(): Promise<void>

  /**
   * Get all session data
   */
  all(): Record<string, unknown>

  /**
   * Check if key exists in session
   */
  has(key: string): boolean

  /**
   * Get an item from the session
   */
  get<T = unknown>(key: string, defaultValue?: T): T | null

  /**
   * Put an item in the session
   */
  put(key: string, value: unknown): void

  /**
   * Get an item and remove it from the session
   */
  pull<T = unknown>(key: string, defaultValue?: T): T | null

  /**
   * Remove an item from the session
   */
  forget(key: string): void

  /**
   * Remove all items from the session
   */
  flush(): void

  /**
   * Regenerate the session ID
   */
  regenerate(destroy?: boolean): Promise<boolean>

  /**
   * Invalidate the session
   */
  invalidate(): Promise<boolean>

  /**
   * Flash data to the session
   */
  flash(key: string, value: unknown): void

  /**
   * Get the CSRF token
   */
  token(): string

  /**
   * Regenerate the CSRF token
   */
  regenerateToken(): string
}

export interface SessionHandler {
  open(savePath: string, sessionName: string): Promise<boolean>
  close(): Promise<boolean>
  read(sessionId: string): Promise<string>
  write(sessionId: string, data: string): Promise<boolean>
  destroy(sessionId: string): Promise<boolean>
  gc(maxLifetime: number): Promise<number>
}

// ============================================
// OAuth Types
// ============================================

export interface OAuthProviderConfig {
  /**
   * OAuth client ID
   */
  clientId: string

  /**
   * OAuth client secret
   */
  clientSecret: string

  /**
   * OAuth redirect URI
   */
  redirectUri: string

  /**
   * OAuth scopes
   */
  scopes?: string[]

  /**
   * Additional parameters
   */
  parameters?: Record<string, string>
}

export interface OAuthProvider {
  /**
   * Get the authorization URL
   */
  getAuthorizationUrl(state?: string): string

  /**
   * Exchange authorization code for tokens
   */
  getAccessToken(code: string): Promise<OAuthTokens>

  /**
   * Get user information from the provider
   */
  getUser(accessToken: string): Promise<OAuthUser>

  /**
   * Refresh the access token
   */
  refreshToken(refreshToken: string): Promise<OAuthTokens>

  /**
   * Revoke the access token
   */
  revokeToken(token: string): Promise<void>
}

export interface OAuthTokens {
  accessToken: string
  tokenType: string
  expiresIn: number
  refreshToken?: string
  scope?: string
}

export interface OAuthUser {
  id: string
  name: string | null
  email: string | null
  avatar: string | null
  nickname?: string | null
  raw: Record<string, unknown>
}

export type OAuthProviderType =
  | 'google'
  | 'github'
  | 'facebook'
  | 'twitter'
  | 'linkedin'
  | 'apple'
  | 'microsoft'
  | 'discord'
  | 'slack'
  | 'gitlab'
  | 'bitbucket'

// ============================================
// WebAuthn Types
// ============================================

export interface WebAuthnConfig {
  /**
   * Relying Party name
   */
  rpName: string

  /**
   * Relying Party ID (domain)
   */
  rpID: string

  /**
   * Attestation type
   */
  attestationType?: 'none' | 'indirect' | 'direct'

  /**
   * Authenticator selection criteria
   */
  authenticatorSelection?: AuthenticatorSelectionCriteria

  /**
   * Timeout in milliseconds
   */
  timeout?: number
}

export interface AuthenticatorSelectionCriteria {
  authenticatorAttachment?: 'platform' | 'cross-platform'
  residentKey?: 'discouraged' | 'preferred' | 'required'
  requireResidentKey?: boolean
  userVerification?: 'required' | 'preferred' | 'discouraged'
}

// ============================================
// TOTP Types
// ============================================

export interface TOTPConfig {
  /**
   * Issuer name (shown in authenticator app)
   */
  issuer: string

  /**
   * HMAC algorithm
   */
  algorithm?: 'SHA-1' | 'SHA-256' | 'SHA-512'

  /**
   * Number of digits in the code
   */
  digits?: number

  /**
   * Time step in seconds
   */
  period?: number

  /**
   * Time window for verification (number of periods)
   */
  window?: number
}

// ============================================
// Auth Manager Types
// ============================================

export interface AuthManager {
  /**
   * Get the default guard name
   */
  getDefaultDriver(): string

  /**
   * Get a guard instance by name
   */
  guard(name?: string): Guard

  /**
   * Create a session guard
   */
  createSessionDriver(name: string, config: GuardConfig): Guard

  /**
   * Create a token guard
   */
  createTokenDriver(name: string, config: GuardConfig): Guard

  /**
   * Create a JWT guard
   */
  createJwtDriver(name: string, config: GuardConfig): Guard

  /**
   * Get a user provider by name
   */
  createUserProvider(provider: string): UserProvider | null

  /**
   * Set the default guard name
   */
  setDefaultDriver(name: string): void

  /**
   * Register a custom guard driver
   */
  extend(driver: string, callback: GuardFactory): void

  /**
   * Register a custom user provider
   */
  provider(name: string, callback: ProviderFactory): void
}

export type GuardFactory = (_name: string, _config: GuardConfig) => Guard
export type ProviderFactory = (_config: ProviderConfig) => UserProvider

// ============================================
// Password Hashing Types
// ============================================

export interface Hasher {
  /**
   * Hash the given value
   */
  make(value: string): Promise<string>

  /**
   * Check the given plain value against a hash
   */
  check(value: string, hashedValue: string): Promise<boolean>

  /**
   * Check if the given hash has been hashed using the given options
   */
  needsRehash(hashedValue: string): boolean
}

// ============================================
// Auth Events
// ============================================

export interface AuthEvents {
  /**
   * Fired when a user is authenticated
   */
  authenticated: { user: Authenticatable; guard: string }

  /**
   * Fired when authentication attempt occurs
   */
  attempting: { credentials: Credentials; guard: string; remember: boolean }

  /**
   * Fired when authentication fails
   */
  failed: { credentials: Credentials; guard: string }

  /**
   * Fired when a user logs out
   */
  logout: { user: Authenticatable; guard: string }

  /**
   * Fired when a user is validated
   */
  validated: { user: Authenticatable; guard: string }

  /**
   * Fired when login is locked out
   */
  lockout: { credentials: Credentials; guard: string }

  /**
   * Fired when a new session is created
   */
  sessionStarted: { session: Session }

  /**
   * Fired when session is regenerated
   */
  sessionRegenerated: { session: Session }
}
