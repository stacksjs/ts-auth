/**
 * Input validation utilities for ts-auth
 * Validates user input before processing to prevent security issues
 */

import { InvalidEmailError, InvalidUrlError, ValidationError } from './errors'

/**
 * Validate an email address format
 */
export function validateEmail(email: string): void {
  // RFC 5322 compliant email regex (simplified)
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

  if (!email || typeof email !== 'string') {
    throw new InvalidEmailError(String(email))
  }

  if (email.length > 254) {
    throw new InvalidEmailError(email)
  }

  if (!emailRegex.test(email)) {
    throw new InvalidEmailError(email)
  }
}

/**
 * Validate a URL format
 */
export function validateUrl(url: string, field: string = 'url'): void {
  if (!url || typeof url !== 'string') {
    throw new InvalidUrlError(String(url), field)
  }

  try {
    const parsed = new URL(url)
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new InvalidUrlError(url, field)
    }
  }
  catch {
    throw new InvalidUrlError(url, field)
  }
}

/**
 * Validate a redirect URI for OAuth
 */
export function validateRedirectUri(uri: string): void {
  validateUrl(uri, 'redirectUri')

  // Additional OAuth-specific validation
  const parsed = new URL(uri)

  // Disallow fragments in redirect URIs (OAuth spec)
  if (parsed.hash) {
    throw new ValidationError('Redirect URI must not contain a fragment', 'redirectUri', uri)
  }
}

/**
 * Validate an RP ID (Relying Party ID) for WebAuthn
 */
export function validateRpId(rpId: string): void {
  if (!rpId || typeof rpId !== 'string') {
    throw new ValidationError('RP ID is required', 'rpId', rpId)
  }

  // RP ID must be a valid domain
  const domainRegex = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$|^localhost$/i

  if (!domainRegex.test(rpId)) {
    throw new ValidationError(`Invalid RP ID format: ${rpId}`, 'rpId', rpId)
  }
}

/**
 * Validate a Base32-encoded string (for TOTP secrets)
 */
export function validateBase32(secret: string): void {
  if (!secret || typeof secret !== 'string') {
    throw new ValidationError('Secret is required', 'secret', secret)
  }

  // Remove padding and check characters
  const normalized = secret.replace(/=+$/, '').toUpperCase()
  const base32Regex = /^[A-Z2-7]+$/

  if (!base32Regex.test(normalized)) {
    throw new ValidationError('Invalid Base32 format', 'secret', '[REDACTED]')
  }

  // Minimum length for security (10 bytes = 16 base32 chars)
  if (normalized.length < 16) {
    throw new ValidationError('Secret is too short (minimum 16 characters)', 'secret', '[REDACTED]')
  }
}

/**
 * Validate a JWT algorithm
 */
export function validateJwtAlgorithm(algorithm: string): void {
  const validAlgorithms = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']

  if (!validAlgorithms.includes(algorithm)) {
    throw new ValidationError(`Invalid JWT algorithm: ${algorithm}`, 'algorithm', algorithm)
  }
}

/**
 * Validate a duration string (e.g., '1h', '7d', '30m')
 */
export function validateDuration(duration: string): void {
  if (!duration || typeof duration !== 'string') {
    throw new ValidationError('Duration is required', 'duration', duration)
  }

  const durationRegex = /^(\d+)([smhdw])$/
  if (!durationRegex.test(duration)) {
    throw new ValidationError(
      `Invalid duration format: ${duration}. Use format like '1h', '7d', '30m'`,
      'duration',
      duration,
    )
  }
}

/**
 * Validate string length
 */
export function validateLength(
  value: string,
  field: string,
  options: { min?: number, max?: number },
): void {
  if (!value || typeof value !== 'string') {
    throw new ValidationError(`${field} is required`, field, value)
  }

  if (options.min !== undefined && value.length < options.min) {
    throw new ValidationError(
      `${field} must be at least ${options.min} characters`,
      field,
      value,
    )
  }

  if (options.max !== undefined && value.length > options.max) {
    throw new ValidationError(
      `${field} must be at most ${options.max} characters`,
      field,
      '[TRUNCATED]',
    )
  }
}

/**
 * Validate required field
 */
export function validateRequired(value: unknown, field: string): void {
  if (value === undefined || value === null || value === '') {
    throw new ValidationError(`${field} is required`, field, value)
  }
}

/**
 * Validate positive number
 */
export function validatePositiveNumber(value: number, field: string): void {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    throw new ValidationError(`${field} must be a number`, field, value)
  }

  if (value <= 0) {
    throw new ValidationError(`${field} must be positive`, field, value)
  }
}

/**
 * Validate OAuth provider name
 */
export function validateProviderName(name: string): void {
  if (!name || typeof name !== 'string') {
    throw new ValidationError('Provider name is required', 'provider', name)
  }

  // Allow alphanumeric and hyphens
  const nameRegex = /^[a-z0-9-]+$/i
  if (!nameRegex.test(name)) {
    throw new ValidationError('Invalid provider name format', 'provider', name)
  }

  if (name.length > 50) {
    throw new ValidationError('Provider name is too long', 'provider', name)
  }
}

/**
 * Validate OAuth client credentials
 */
export function validateOAuthCredentials(clientId: string, clientSecret: string): void {
  validateRequired(clientId, 'clientId')
  validateRequired(clientSecret, 'clientSecret')

  validateLength(clientId, 'clientId', { min: 1, max: 500 })
  validateLength(clientSecret, 'clientSecret', { min: 1, max: 500 })
}

/**
 * Sanitize a string for safe use (removes control characters)
 */
export function sanitizeString(value: string): string {
  if (typeof value !== 'string') {
    return ''
  }

  // Remove control characters and null bytes
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
}

/**
 * Validate and sanitize username
 */
export function validateUsername(username: string): string {
  validateRequired(username, 'username')
  validateLength(username, 'username', { min: 1, max: 255 })

  return sanitizeString(username)
}

/**
 * Validate scope string or array
 */
export function validateScopes(scopes: string | string[]): string[] {
  if (typeof scopes === 'string') {
    scopes = scopes.split(/[\s,]+/).filter(Boolean)
  }

  if (!Array.isArray(scopes)) {
    throw new ValidationError('Scopes must be a string or array', 'scopes', scopes)
  }

  // Validate each scope
  for (const scope of scopes) {
    if (typeof scope !== 'string' || !scope) {
      throw new ValidationError('Invalid scope format', 'scopes', scopes)
    }

    // Scopes should be alphanumeric with colons, dots, or underscores
    const scopeRegex = /^[a-z0-9:._-]+$/i
    if (!scopeRegex.test(scope)) {
      throw new ValidationError(`Invalid scope: ${scope}`, 'scopes', scopes)
    }

    if (scope.length > 100) {
      throw new ValidationError(`Scope too long: ${scope}`, 'scopes', scopes)
    }
  }

  return scopes
}
