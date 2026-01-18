export * from './config'
export * from './types'
export * from './errors'
export * from './validation'

// Auth Manager
export * from './auth-manager'

// Session exports
export * from './session'

// JWT exports
export * from './jwt'

// OAuth exports
export * from './oauth'

// Guards exports
export * from './guards'

// Providers exports
export * from './providers'

// Hash exports
export * from './hash'

// Rate Limiting exports
export * from './rate-limit'

// Token Blacklist exports
export * from './token-blacklist'

// Audit Logging exports
export * from './audit'

// WebAuthn exports
export * from './webauthn'

// OTP exports
export * from './otp'

// Utility exports
export * from './utils'

// Re-export commonly used items for convenience

// Auth Manager
export {
  createAuthManager,
  AuthenticationManager,
  defaultAuthConfig,
} from './auth-manager'

// Session
export {
  SessionManager,
  createSession,
} from './session/session'

export {
  sessionMiddleware,
  csrfMiddleware,
} from './session/middleware'

// JWT
export {
  sign as signJwt,
  verify as verifyJwt,
  decode as decodeJwt,
  createTokenPair,
  parseDuration,
} from './jwt/jwt'

export {
  TokenManager,
  createTokenManager,
} from './jwt/token-manager'

// OAuth
export {
  BaseOAuthProvider,
  OAuthManager,
  createOAuthManager,
} from './oauth/provider'

export {
  createGoogleProvider,
  createGitHubProvider,
  createFacebookProvider,
  createTwitterProvider,
  createLinkedInProvider,
  createAppleProvider,
  createMicrosoftProvider,
  createDiscordProvider,
  createSlackProvider,
  createGitLabProvider,
  createBitbucketProvider,
} from './oauth'

// Guards
export {
  SessionGuard,
} from './guards/session-guard'

export {
  TokenGuard,
} from './guards/token-guard'

export {
  JwtGuard,
} from './guards/jwt-guard'

// Providers
export {
  GenericUser,
  DatabaseUserProvider,
  InMemoryUserProvider,
} from './providers/database-provider'

// WebAuthn
export {
  generateRegistrationOptions,
  generateAuthenticationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} from './webauthn/server'

export {
  startRegistration,
  startAuthentication,
  platformAuthenticatorIsAvailable,
  browserSupportsWebAuthn,
  browserSupportsWebAuthnAutofill,
} from './webauthn/browser'

// TOTP
export {
  generate as generateTOTP,
  verify as verifyTOTP,
  generateSecret as generateTOTPSecret,
  keyuri as totpKeyUri,
} from './otp/totp'

// Hash
export {
  hash,
  verify as verifyHash,
  needsRehash,
  createHasher,
  generateRandomString,
  generateToken,
} from './hash'

// Validation
export {
  validateEmail,
  validateUrl,
  validateRedirectUri,
  validateRpId,
  validateBase32,
  validateJwtAlgorithm,
  validateDuration,
  validateLength,
  validateRequired,
  validatePositiveNumber,
  validateProviderName,
  validateOAuthCredentials,
  sanitizeString,
  validateUsername,
  validateScopes,
} from './validation'

// Error Classes
export {
  AuthError,
  AuthenticationError,
  InvalidCredentialsError,
  UserNotFoundError,
  AccountLockedError,
  SessionExpiredError,
  TokenError,
  TokenExpiredError,
  TokenInvalidError,
  TokenMalformedError,
  TokenSignatureError,
  TokenNotBeforeError,
  TokenRevokedError,
  OAuthError,
  OAuthStateError,
  OAuthTokenError,
  OAuthUserInfoError,
  OAuthProviderNotFoundError,
  WebAuthnError,
  WebAuthnRegistrationError,
  WebAuthnAuthenticationError,
  WebAuthnChallengeError,
  WebAuthnOriginError,
  WebAuthnRpIdError,
  WebAuthnCounterError,
  TOTPError,
  TOTPInvalidCodeError,
  TOTPSecretError,
  SessionError,
  SessionNotStartedError,
  SessionStorageError,
  CSRFError,
  CSRFTokenMissingError,
  CSRFTokenMismatchError,
  ValidationError,
  InvalidEmailError,
  InvalidUrlError,
  GuardError,
  GuardNotFoundError,
  ProviderError,
  ProviderNotFoundError,
  ConfigurationError,
  MissingSecretError,
  InvalidConfigurationError,
} from './errors'

// Rate Limiting
export {
  AuthRateLimiter,
  createAuthRateLimiter,
  AccountLockoutManager,
  createAccountLockout,
  defaultAuthRateLimits,
  withRateLimit,
} from './rate-limit'

// Token Blacklist
export {
  TokenBlacklist,
  MemoryTokenBlacklist,
  RedisTokenBlacklist,
  createTokenBlacklist,
  createRedisTokenBlacklist,
  tokenBlacklistMiddleware,
} from './token-blacklist'

// Audit Logging
export {
  AuditLogger,
  MemoryAuditLogStorage,
  ConsoleAuditLogStorage,
  CallbackAuditLogStorage,
  createAuditLogger,
  createConsoleAuditLogger,
  createCallbackAuditLogger,
} from './audit'
