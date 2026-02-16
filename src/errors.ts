/**
 * Custom error classes for ts-auth
 * Provides detailed error information for debugging and error handling
 */

/**
 * Base error class for all auth errors
 */
export class AuthError extends Error {
  public readonly code: string
  public readonly statusCode: number

  constructor(message: string, code: string, statusCode: number = 500) {
    super(message)
    this.name = 'AuthError'
    this.code = code
    this.statusCode = statusCode
    Error.captureStackTrace?.(this, this.constructor)
  }

  toJSON(): { name: string, message: string, code: string, statusCode: number } {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      statusCode: this.statusCode,
    }
  }
}

// ============================================
// Authentication Errors
// ============================================

export class AuthenticationError extends AuthError {
  constructor(message: string, code: string = 'AUTH_FAILED') {
    super(message, code, 401)
    this.name = 'AuthenticationError'
  }
}

export class InvalidCredentialsError extends AuthenticationError {
  constructor(message: string = 'Invalid credentials provided') {
    super(message, 'INVALID_CREDENTIALS')
  }
}

export class UserNotFoundError extends AuthenticationError {
  constructor(message: string = 'User not found') {
    super(message, 'USER_NOT_FOUND')
  }
}

export class AccountLockedError extends AuthenticationError {
  public readonly lockedUntil?: Date

  constructor(message: string = 'Account is locked', lockedUntil?: Date) {
    super(message, 'ACCOUNT_LOCKED')
    this.name = 'AccountLockedError'
    this.lockedUntil = lockedUntil
  }
}

export class SessionExpiredError extends AuthenticationError {
  constructor(message: string = 'Session has expired') {
    super(message, 'SESSION_EXPIRED')
  }
}

// ============================================
// Token Errors
// ============================================

export class TokenError extends AuthError {
  constructor(message: string, code: string = 'TOKEN_ERROR') {
    super(message, code, 401)
    this.name = 'TokenError'
  }
}

export class TokenExpiredError extends TokenError {
  public readonly expiredAt: Date

  constructor(message: string = 'Token has expired', expiredAt?: Date) {
    super(message, 'TOKEN_EXPIRED')
    this.name = 'TokenExpiredError'
    this.expiredAt = expiredAt ?? new Date()
  }
}

export class TokenInvalidError extends TokenError {
  constructor(message: string = 'Token is invalid') {
    super(message, 'TOKEN_INVALID')
    this.name = 'TokenInvalidError'
  }
}

export class TokenMalformedError extends TokenError {
  constructor(message: string = 'Token is malformed') {
    super(message, 'TOKEN_MALFORMED')
    this.name = 'TokenMalformedError'
  }
}

export class TokenSignatureError extends TokenError {
  constructor(message: string = 'Token signature verification failed') {
    super(message, 'TOKEN_SIGNATURE_INVALID')
    this.name = 'TokenSignatureError'
  }
}

export class TokenNotBeforeError extends TokenError {
  public readonly notBefore: Date

  constructor(message: string = 'Token is not yet valid', notBefore?: Date) {
    super(message, 'TOKEN_NOT_BEFORE')
    this.name = 'TokenNotBeforeError'
    this.notBefore = notBefore ?? new Date()
  }
}

export class TokenRevokedError extends TokenError {
  constructor(message: string = 'Token has been revoked') {
    super(message, 'TOKEN_REVOKED')
    this.name = 'TokenRevokedError'
  }
}

// ============================================
// OAuth Errors
// ============================================

export class OAuthError extends AuthError {
  public readonly provider: string

  constructor(message: string, provider: string, code: string = 'OAUTH_ERROR') {
    super(message, code, 400)
    this.name = 'OAuthError'
    this.provider = provider
  }
}

export class OAuthStateError extends OAuthError {
  constructor(provider: string, message: string = 'OAuth state validation failed') {
    super(message, provider, 'OAUTH_STATE_INVALID')
    this.name = 'OAuthStateError'
  }
}

export class OAuthTokenError extends OAuthError {
  constructor(provider: string, message: string = 'Failed to obtain OAuth token') {
    super(message, provider, 'OAUTH_TOKEN_ERROR')
    this.name = 'OAuthTokenError'
  }
}

export class OAuthUserInfoError extends OAuthError {
  constructor(provider: string, message: string = 'Failed to get user info from OAuth provider') {
    super(message, provider, 'OAUTH_USER_INFO_ERROR')
    this.name = 'OAuthUserInfoError'
  }
}

export class OAuthProviderNotFoundError extends OAuthError {
  constructor(provider: string) {
    super(`OAuth provider '${provider}' is not registered`, provider, 'OAUTH_PROVIDER_NOT_FOUND')
    this.name = 'OAuthProviderNotFoundError'
  }
}

// ============================================
// WebAuthn Errors
// ============================================

export class WebAuthnError extends AuthError {
  constructor(message: string, code: string = 'WEBAUTHN_ERROR') {
    super(message, code, 400)
    this.name = 'WebAuthnError'
  }
}

export class WebAuthnRegistrationError extends WebAuthnError {
  constructor(message: string = 'WebAuthn registration failed') {
    super(message, 'WEBAUTHN_REGISTRATION_FAILED')
    this.name = 'WebAuthnRegistrationError'
  }
}

export class WebAuthnAuthenticationError extends WebAuthnError {
  constructor(message: string = 'WebAuthn authentication failed') {
    super(message, 'WEBAUTHN_AUTHENTICATION_FAILED')
    this.name = 'WebAuthnAuthenticationError'
  }
}

export class WebAuthnChallengeError extends WebAuthnError {
  constructor(message: string = 'WebAuthn challenge verification failed') {
    super(message, 'WEBAUTHN_CHALLENGE_INVALID')
    this.name = 'WebAuthnChallengeError'
  }
}

export class WebAuthnOriginError extends WebAuthnError {
  public readonly expectedOrigin: string
  public readonly actualOrigin: string

  constructor(expectedOrigin: string, actualOrigin: string) {
    super(`Origin mismatch: expected ${expectedOrigin}, got ${actualOrigin}`, 'WEBAUTHN_ORIGIN_INVALID')
    this.name = 'WebAuthnOriginError'
    this.expectedOrigin = expectedOrigin
    this.actualOrigin = actualOrigin
  }
}

export class WebAuthnRpIdError extends WebAuthnError {
  public readonly expectedRpId: string
  public readonly actualRpId: string

  constructor(expectedRpId: string, actualRpId: string) {
    super(`RP ID mismatch: expected ${expectedRpId}, got ${actualRpId}`, 'WEBAUTHN_RPID_INVALID')
    this.name = 'WebAuthnRpIdError'
    this.expectedRpId = expectedRpId
    this.actualRpId = actualRpId
  }
}

export class WebAuthnCounterError extends WebAuthnError {
  public readonly expectedCounter: number
  public readonly actualCounter: number

  constructor(expectedCounter: number, actualCounter: number) {
    super(
      `Counter replay detected: expected > ${expectedCounter}, got ${actualCounter}`,
      'WEBAUTHN_COUNTER_INVALID',
    )
    this.name = 'WebAuthnCounterError'
    this.expectedCounter = expectedCounter
    this.actualCounter = actualCounter
  }
}

// ============================================
// TOTP Errors
// ============================================

export class TOTPError extends AuthError {
  constructor(message: string, code: string = 'TOTP_ERROR') {
    super(message, code, 400)
    this.name = 'TOTPError'
  }
}

export class TOTPInvalidCodeError extends TOTPError {
  constructor(message: string = 'Invalid TOTP code') {
    super(message, 'TOTP_CODE_INVALID')
    this.name = 'TOTPInvalidCodeError'
  }
}

export class TOTPSecretError extends TOTPError {
  constructor(message: string = 'Invalid TOTP secret') {
    super(message, 'TOTP_SECRET_INVALID')
    this.name = 'TOTPSecretError'
  }
}

// ============================================
// Session Errors
// ============================================

export class SessionError extends AuthError {
  constructor(message: string, code: string = 'SESSION_ERROR') {
    super(message, code, 500)
    this.name = 'SessionError'
  }
}

export class SessionNotStartedError extends SessionError {
  constructor(message: string = 'Session has not been started') {
    super(message, 'SESSION_NOT_STARTED')
    this.name = 'SessionNotStartedError'
  }
}

export class SessionStorageError extends SessionError {
  constructor(message: string = 'Session storage operation failed') {
    super(message, 'SESSION_STORAGE_ERROR')
    this.name = 'SessionStorageError'
  }
}

// ============================================
// CSRF Errors
// ============================================

export class CSRFError extends AuthError {
  constructor(message: string = 'CSRF token validation failed', code: string = 'CSRF_ERROR') {
    super(message, code, 419)
    this.name = 'CSRFError'
  }
}

export class CSRFTokenMissingError extends CSRFError {
  constructor(message: string = 'CSRF token is missing') {
    super(message, 'CSRF_TOKEN_MISSING')
    this.name = 'CSRFTokenMissingError'
  }
}

export class CSRFTokenMismatchError extends CSRFError {
  constructor(message: string = 'CSRF token mismatch') {
    super(message, 'CSRF_TOKEN_MISMATCH')
    this.name = 'CSRFTokenMismatchError'
  }
}

// ============================================
// Validation Errors
// ============================================

export class ValidationError extends AuthError {
  public readonly field?: string
  public readonly value?: unknown

  constructor(message: string, field?: string, value?: unknown) {
    super(message, 'VALIDATION_ERROR', 400)
    this.name = 'ValidationError'
    this.field = field
    this.value = value
  }
}

export class InvalidEmailError extends ValidationError {
  constructor(email: string) {
    super(`Invalid email format: ${email}`, 'email', email)
    this.name = 'InvalidEmailError'
  }
}

export class InvalidUrlError extends ValidationError {
  constructor(url: string, field: string = 'url') {
    super(`Invalid URL format: ${url}`, field, url)
    this.name = 'InvalidUrlError'
  }
}

// ============================================
// Guard/Provider Errors
// ============================================

export class GuardError extends AuthError {
  public readonly guard: string

  constructor(message: string, guard: string, code: string = 'GUARD_ERROR') {
    super(message, code, 500)
    this.name = 'GuardError'
    this.guard = guard
  }
}

export class GuardNotFoundError extends GuardError {
  constructor(guard: string) {
    super(`Guard '${guard}' is not defined`, guard, 'GUARD_NOT_FOUND')
    this.name = 'GuardNotFoundError'
  }
}

export class ProviderError extends AuthError {
  public readonly provider: string

  constructor(message: string, provider: string, code: string = 'PROVIDER_ERROR') {
    super(message, code, 500)
    this.name = 'ProviderError'
    this.provider = provider
    this.guard = provider
  }

  private guard: string
}

export class ProviderNotFoundError extends ProviderError {
  constructor(provider: string) {
    super(`Provider '${provider}' is not defined`, provider, 'PROVIDER_NOT_FOUND')
    this.name = 'ProviderNotFoundError'
  }
}

// ============================================
// Configuration Errors
// ============================================

export class ConfigurationError extends AuthError {
  constructor(message: string, code: string = 'CONFIG_ERROR') {
    super(message, code, 500)
    this.name = 'ConfigurationError'
  }
}

export class MissingSecretError extends ConfigurationError {
  constructor(message: string = 'Secret key is not configured') {
    super(message, 'SECRET_MISSING')
    this.name = 'MissingSecretError'
  }
}

export class InvalidConfigurationError extends ConfigurationError {
  public readonly configKey: string

  constructor(configKey: string, message?: string) {
    super(message ?? `Invalid configuration for '${configKey}'`, 'CONFIG_INVALID')
    this.name = 'InvalidConfigurationError'
    this.configKey = configKey
  }
}
