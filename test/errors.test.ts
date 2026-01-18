import { describe, expect, it } from 'bun:test'
import {
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
} from '../src/errors'

describe('Error Classes', () => {
  describe('AuthError (Base)', () => {
    it('should create base auth error', () => {
      const error = new AuthError('Test error', 'TEST_CODE')

      expect(error.message).toBe('Test error')
      expect(error.code).toBe('TEST_CODE')
      expect(error.name).toBe('AuthError')
      expect(error instanceof Error).toBe(true)
    })

    it('should have toJSON method', () => {
      const error = new AuthError('Test', 'CODE', 400)
      const json = error.toJSON()

      expect(json.name).toBe('AuthError')
      expect(json.message).toBe('Test')
      expect(json.code).toBe('CODE')
      expect(json.statusCode).toBe(400)
    })
  })

  describe('Authentication Errors', () => {
    it('should create AuthenticationError', () => {
      const error = new AuthenticationError('Auth failed')

      expect(error.message).toBe('Auth failed')
      expect(error.code).toBe('AUTH_FAILED')
      expect(error.name).toBe('AuthenticationError')
      expect(error.statusCode).toBe(401)
    })

    it('should create AuthenticationError with custom code', () => {
      const error = new AuthenticationError('Custom auth error', 'CUSTOM_CODE')

      expect(error.code).toBe('CUSTOM_CODE')
    })

    it('should create InvalidCredentialsError', () => {
      const error = new InvalidCredentialsError()

      expect(error.message).toBe('Invalid credentials provided')
      expect(error.code).toBe('INVALID_CREDENTIALS')
    })

    it('should create InvalidCredentialsError with custom message', () => {
      const error = new InvalidCredentialsError('Wrong password')

      expect(error.message).toBe('Wrong password')
    })

    it('should create UserNotFoundError', () => {
      const error = new UserNotFoundError()

      expect(error.message).toBe('User not found')
      expect(error.code).toBe('USER_NOT_FOUND')
    })

    it('should create UserNotFoundError with custom message', () => {
      const error = new UserNotFoundError('User user-123 not found')

      expect(error.message).toBe('User user-123 not found')
    })

    it('should create AccountLockedError', () => {
      const unlockAt = new Date()
      const error = new AccountLockedError('Account locked', unlockAt)

      expect(error.code).toBe('ACCOUNT_LOCKED')
      expect(error.lockedUntil).toEqual(unlockAt)
    })

    it('should create SessionExpiredError', () => {
      const error = new SessionExpiredError()

      expect(error.message).toBe('Session has expired')
      expect(error.code).toBe('SESSION_EXPIRED')
    })
  })

  describe('Token Errors', () => {
    it('should create TokenError', () => {
      const error = new TokenError('Token error', 'TOKEN_ERROR')

      expect(error.message).toBe('Token error')
      expect(error.code).toBe('TOKEN_ERROR')
      expect(error.statusCode).toBe(401)
    })

    it('should create TokenExpiredError', () => {
      const expiredAt = new Date()
      const error = new TokenExpiredError('Token expired', expiredAt)

      expect(error.code).toBe('TOKEN_EXPIRED')
      expect(error.expiredAt).toEqual(expiredAt)
    })

    it('should create TokenExpiredError with default expiredAt', () => {
      const error = new TokenExpiredError()

      expect(error.message).toBe('Token has expired')
      expect(error.expiredAt).toBeDefined()
    })

    it('should create TokenInvalidError', () => {
      const error = new TokenInvalidError()

      expect(error.message).toBe('Token is invalid')
      expect(error.code).toBe('TOKEN_INVALID')
    })

    it('should create TokenMalformedError', () => {
      const error = new TokenMalformedError()

      expect(error.message).toBe('Token is malformed')
      expect(error.code).toBe('TOKEN_MALFORMED')
    })

    it('should create TokenSignatureError', () => {
      const error = new TokenSignatureError()

      expect(error.message).toBe('Token signature verification failed')
      expect(error.code).toBe('TOKEN_SIGNATURE_INVALID')
    })

    it('should create TokenNotBeforeError', () => {
      const notBefore = new Date()
      const error = new TokenNotBeforeError('Too early', notBefore)

      expect(error.code).toBe('TOKEN_NOT_BEFORE')
      expect(error.notBefore).toEqual(notBefore)
    })

    it('should create TokenRevokedError', () => {
      const error = new TokenRevokedError()

      expect(error.message).toBe('Token has been revoked')
      expect(error.code).toBe('TOKEN_REVOKED')
    })
  })

  describe('OAuth Errors', () => {
    it('should create OAuthError', () => {
      const error = new OAuthError('OAuth failed', 'google')

      expect(error.message).toBe('OAuth failed')
      expect(error.provider).toBe('google')
      expect(error.code).toBe('OAUTH_ERROR')
      expect(error.statusCode).toBe(400)
    })

    it('should create OAuthStateError', () => {
      const error = new OAuthStateError('google')

      expect(error.message).toBe('OAuth state validation failed')
      expect(error.provider).toBe('google')
      expect(error.code).toBe('OAUTH_STATE_INVALID')
    })

    it('should create OAuthTokenError', () => {
      const error = new OAuthTokenError('github')

      expect(error.message).toBe('Failed to obtain OAuth token')
      expect(error.provider).toBe('github')
      expect(error.code).toBe('OAUTH_TOKEN_ERROR')
    })

    it('should create OAuthTokenError with custom message', () => {
      const error = new OAuthTokenError('github', 'Token exchange failed')

      expect(error.message).toBe('Token exchange failed')
    })

    it('should create OAuthUserInfoError', () => {
      const error = new OAuthUserInfoError('facebook')

      expect(error.code).toBe('OAUTH_USER_INFO_ERROR')
      expect(error.provider).toBe('facebook')
    })

    it('should create OAuthProviderNotFoundError', () => {
      const error = new OAuthProviderNotFoundError('myspace')

      expect(error.message).toBe("OAuth provider 'myspace' is not registered")
      expect(error.code).toBe('OAUTH_PROVIDER_NOT_FOUND')
      expect(error.provider).toBe('myspace')
    })
  })

  describe('WebAuthn Errors', () => {
    it('should create WebAuthnError', () => {
      const error = new WebAuthnError('WebAuthn failed', 'WEBAUTHN_ERROR')

      expect(error.message).toBe('WebAuthn failed')
      expect(error.code).toBe('WEBAUTHN_ERROR')
      expect(error.statusCode).toBe(400)
    })

    it('should create WebAuthnRegistrationError', () => {
      const error = new WebAuthnRegistrationError('Registration failed')

      expect(error.code).toBe('WEBAUTHN_REGISTRATION_FAILED')
    })

    it('should create WebAuthnAuthenticationError', () => {
      const error = new WebAuthnAuthenticationError('Auth failed')

      expect(error.code).toBe('WEBAUTHN_AUTHENTICATION_FAILED')
    })

    it('should create WebAuthnChallengeError', () => {
      const error = new WebAuthnChallengeError()

      expect(error.message).toBe('WebAuthn challenge verification failed')
      expect(error.code).toBe('WEBAUTHN_CHALLENGE_INVALID')
    })

    it('should create WebAuthnOriginError', () => {
      const error = new WebAuthnOriginError('https://example.com', 'https://evil.com')

      expect(error.message).toBe('Origin mismatch: expected https://example.com, got https://evil.com')
      expect(error.expectedOrigin).toBe('https://example.com')
      expect(error.actualOrigin).toBe('https://evil.com')
    })

    it('should create WebAuthnRpIdError', () => {
      const error = new WebAuthnRpIdError('example.com', 'evil.com')

      expect(error.message).toBe('RP ID mismatch: expected example.com, got evil.com')
      expect(error.expectedRpId).toBe('example.com')
      expect(error.actualRpId).toBe('evil.com')
    })

    it('should create WebAuthnCounterError', () => {
      const error = new WebAuthnCounterError(10, 5)

      expect(error.code).toBe('WEBAUTHN_COUNTER_INVALID')
      expect(error.expectedCounter).toBe(10)
      expect(error.actualCounter).toBe(5)
    })
  })

  describe('TOTP Errors', () => {
    it('should create TOTPError', () => {
      const error = new TOTPError('TOTP failed', 'TOTP_ERROR')

      expect(error.message).toBe('TOTP failed')
      expect(error.code).toBe('TOTP_ERROR')
      expect(error.statusCode).toBe(400)
    })

    it('should create TOTPInvalidCodeError', () => {
      const error = new TOTPInvalidCodeError()

      expect(error.message).toBe('Invalid TOTP code')
      expect(error.code).toBe('TOTP_CODE_INVALID')
    })

    it('should create TOTPSecretError', () => {
      const error = new TOTPSecretError()

      expect(error.message).toBe('Invalid TOTP secret')
      expect(error.code).toBe('TOTP_SECRET_INVALID')
    })
  })

  describe('Session Errors', () => {
    it('should create SessionError', () => {
      const error = new SessionError('Session error', 'SESSION_ERROR')

      expect(error.message).toBe('Session error')
      expect(error.code).toBe('SESSION_ERROR')
    })

    it('should create SessionNotStartedError', () => {
      const error = new SessionNotStartedError()

      expect(error.message).toBe('Session has not been started')
      expect(error.code).toBe('SESSION_NOT_STARTED')
    })

    it('should create SessionStorageError', () => {
      const error = new SessionStorageError('Storage failed')

      expect(error.message).toBe('Storage failed')
      expect(error.code).toBe('SESSION_STORAGE_ERROR')
    })
  })

  describe('CSRF Errors', () => {
    it('should create CSRFError', () => {
      const error = new CSRFError('CSRF error', 'CSRF_ERROR')

      expect(error.message).toBe('CSRF error')
      expect(error.code).toBe('CSRF_ERROR')
      expect(error.statusCode).toBe(419)
    })

    it('should create CSRFTokenMissingError', () => {
      const error = new CSRFTokenMissingError()

      expect(error.message).toBe('CSRF token is missing')
      expect(error.code).toBe('CSRF_TOKEN_MISSING')
    })

    it('should create CSRFTokenMismatchError', () => {
      const error = new CSRFTokenMismatchError()

      expect(error.message).toBe('CSRF token mismatch')
      expect(error.code).toBe('CSRF_TOKEN_MISMATCH')
    })
  })

  describe('Validation Errors', () => {
    it('should create ValidationError', () => {
      const error = new ValidationError('Invalid input', 'field', 'bad-value')

      expect(error.message).toBe('Invalid input')
      expect(error.field).toBe('field')
      expect(error.value).toBe('bad-value')
      expect(error.code).toBe('VALIDATION_ERROR')
    })

    it('should create InvalidEmailError', () => {
      const error = new InvalidEmailError('bad@')

      expect(error.message).toBe('Invalid email format: bad@')
      expect(error.field).toBe('email')
      expect(error.value).toBe('bad@')
    })

    it('should create InvalidUrlError', () => {
      const error = new InvalidUrlError('not-a-url')

      expect(error.message).toBe('Invalid URL format: not-a-url')
      expect(error.field).toBe('url')
    })
  })

  describe('Guard/Provider Errors', () => {
    it('should create GuardError', () => {
      const error = new GuardError('Guard failed', 'session')

      expect(error.message).toBe('Guard failed')
      expect(error.code).toBe('GUARD_ERROR')
      expect(error.guard).toBe('session')
    })

    it('should create GuardNotFoundError', () => {
      const error = new GuardNotFoundError('custom-guard')

      expect(error.message).toBe("Guard 'custom-guard' is not defined")
      expect(error.guard).toBe('custom-guard')
      expect(error.code).toBe('GUARD_NOT_FOUND')
    })

    it('should create ProviderError', () => {
      const error = new ProviderError('Provider failed', 'database')

      expect(error.message).toBe('Provider failed')
      expect(error.code).toBe('PROVIDER_ERROR')
    })

    it('should create ProviderNotFoundError', () => {
      const error = new ProviderNotFoundError('custom-provider')

      expect(error.message).toBe("Provider 'custom-provider' is not defined")
      expect(error.code).toBe('PROVIDER_NOT_FOUND')
    })
  })

  describe('Configuration Errors', () => {
    it('should create ConfigurationError', () => {
      const error = new ConfigurationError('Config error', 'CONFIG_ERROR')

      expect(error.message).toBe('Config error')
    })

    it('should create MissingSecretError', () => {
      const error = new MissingSecretError()

      expect(error.message).toBe('Secret key is not configured')
      expect(error.code).toBe('SECRET_MISSING')
    })

    it('should create MissingSecretError with custom message', () => {
      const error = new MissingSecretError('JWT secret not found')

      expect(error.message).toBe('JWT secret not found')
    })

    it('should create InvalidConfigurationError', () => {
      const error = new InvalidConfigurationError('sessionLifetime')

      expect(error.message).toBe("Invalid configuration for 'sessionLifetime'")
      expect(error.configKey).toBe('sessionLifetime')
      expect(error.code).toBe('CONFIG_INVALID')
    })

    it('should create InvalidConfigurationError with custom message', () => {
      const error = new InvalidConfigurationError('timeout', 'Timeout must be positive')

      expect(error.message).toBe('Timeout must be positive')
      expect(error.configKey).toBe('timeout')
    })
  })
})
