export * from './config'
export * from './types'

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

// WebAuthn exports
export * from './webauthn'

// OTP exports
export * from './otp'

// QR Code exports
export * from './qr'

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

// QR
export {
  generateQRCodeSVG,
  generateQRCodeDataURL,
  createQRCode,
  QRErrorCorrection,
} from './qr'
