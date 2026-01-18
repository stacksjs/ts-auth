/**
 * Password hashing utilities using Web Crypto API
 * Provides secure password hashing without external dependencies
 */

import type { Hasher } from '../types'

export interface HashOptions {
  /** Number of iterations (default: 100000) */
  iterations?: number
  /** Salt length in bytes (default: 16) */
  saltLength?: number
  /** Hash length in bytes (default: 32) */
  hashLength?: number
  /** Algorithm (default: 'SHA-256') */
  algorithm?: 'SHA-256' | 'SHA-384' | 'SHA-512'
}

const DEFAULT_OPTIONS: Required<HashOptions> = {
  iterations: 100000,
  saltLength: 16,
  hashLength: 32,
  algorithm: 'SHA-256',
}

/**
 * Hash a password using PBKDF2
 */
export async function hash(password: string, options?: HashOptions): Promise<string> {
  const opts = { ...DEFAULT_OPTIONS, ...options }

  // Generate random salt
  const salt = crypto.getRandomValues(new Uint8Array(opts.saltLength))

  // Import password as key
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits'],
  )

  // Derive hash
  const hashBuffer = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations: opts.iterations,
      hash: opts.algorithm,
    },
    passwordKey,
    opts.hashLength * 8,
  )

  const hashArray = new Uint8Array(hashBuffer)

  // Encode as: $pbkdf2$algorithm$iterations$salt$hash
  const saltBase64 = btoa(String.fromCharCode(...salt))
  const hashBase64 = btoa(String.fromCharCode(...hashArray))

  return `$pbkdf2$${opts.algorithm}$${opts.iterations}$${saltBase64}$${hashBase64}`
}

/**
 * Verify a password against a hash
 */
export async function verify(password: string, hashedPassword: string): Promise<boolean> {
  try {
    // Parse hash format: $pbkdf2$algorithm$iterations$salt$hash
    const parts = hashedPassword.split('$')

    if (parts.length !== 6 || parts[1] !== 'pbkdf2') {
      return false
    }

    const algorithm = parts[2] as 'SHA-256' | 'SHA-384' | 'SHA-512'
    const iterations = Number.parseInt(parts[3], 10)
    const salt = Uint8Array.from(atob(parts[4]), c => c.charCodeAt(0))
    const expectedHash = Uint8Array.from(atob(parts[5]), c => c.charCodeAt(0))

    // Import password as key
    const passwordKey = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      'PBKDF2',
      false,
      ['deriveBits'],
    )

    // Derive hash
    const hashBuffer = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations,
        hash: algorithm,
      },
      passwordKey,
      expectedHash.length * 8,
    )

    const actualHash = new Uint8Array(hashBuffer)

    // Timing-safe comparison
    return timingSafeEqual(actualHash, expectedHash)
  }
  catch {
    return false
  }
}

/**
 * Check if a hash needs to be rehashed (e.g., algorithm/iterations changed)
 */
export function needsRehash(hashedPassword: string, options?: HashOptions): boolean {
  try {
    const opts = { ...DEFAULT_OPTIONS, ...options }
    const parts = hashedPassword.split('$')

    if (parts.length !== 6 || parts[1] !== 'pbkdf2') {
      return true
    }

    const algorithm = parts[2]
    const iterations = Number.parseInt(parts[3], 10)

    return algorithm !== opts.algorithm || iterations < opts.iterations
  }
  catch {
    return true
  }
}

/**
 * Create a Hasher instance (implements the Hasher interface from types)
 */
export function createHasher(options?: HashOptions): Hasher {
  const opts = { ...DEFAULT_OPTIONS, ...options }

  return {
    make: (value: string) => hash(value, opts),
    check: (value: string, hashedValue: string) => verify(value, hashedValue),
    needsRehash: (hashedValue: string) => needsRehash(hashedValue, opts),
  }
}

/**
 * Timing-safe comparison of two byte arrays
 */
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false
  }

  let result = 0
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i]
  }

  return result === 0
}

/**
 * Generate a random string for use as passwords, tokens, etc.
 */
export function generateRandomString(length: number = 32): string {
  const bytes = crypto.getRandomValues(new Uint8Array(length))
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Generate a secure random token (URL-safe)
 */
export function generateToken(length: number = 32): string {
  const bytes = crypto.getRandomValues(new Uint8Array(length))
  // URL-safe base64 encoding
  const base64 = btoa(String.fromCharCode(...bytes))
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
