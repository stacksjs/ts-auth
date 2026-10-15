/* eslint-disable regexp/no-unused-capturing-group */
/**
 * WebAuthn Server Implementation
 * Native implementation to replace @simplewebauthn/server
 */

import { Buffer } from 'node:buffer'
import { createPublicKey, verify as verifyCryptoSignature } from 'node:crypto'
import { decodeCBOR } from './cbor'
import type {
  AuthenticationCredential,
  AuthenticatorAssertionResponse,
  AuthenticatorAttestationResponse,
  PublicKeyCredentialCreationOptions,
  PublicKeyCredentialRequestOptions,
  RegistrationCredential,
} from './types'

export interface RegistrationOptions {
  rpName: string
  rpID: string
  userID: string
  userName: string
  userDisplayName?: string
  challenge?: Uint8Array
  attestationType?: 'none' | 'indirect' | 'direct'
  authenticatorSelection?: {
    authenticatorAttachment?: 'platform' | 'cross-platform'
    requireResidentKey?: boolean
    residentKey?: 'discouraged' | 'preferred' | 'required'
    userVerification?: 'required' | 'preferred' | 'discouraged'
  }
  /**
   * Credentials to exclude. `id` accepts a base64url STRING as well as an
   * ArrayBuffer: a server generating these options has to send them to the
   * browser as JSON, where an ArrayBuffer serializes to `{}`, so the stored
   * base64url id is what actually travels. The client decodes it before
   * calling `navigator.credentials`.
   */
  excludeCredentials?: Array<{
    id: ArrayBuffer | string
    type: 'public-key'
    transports?: ('usb' | 'nfc' | 'ble' | 'internal' | 'hybrid')[]
  }>
  timeout?: number
}

export interface AuthenticationOptions {
  rpID: string
  challenge?: Uint8Array
  /** See `RegistrationOptions.excludeCredentials` on the string form. */
  allowCredentials?: Array<{
    id: ArrayBuffer | string
    type: 'public-key'
    transports?: ('usb' | 'nfc' | 'ble' | 'internal' | 'hybrid')[]
  }>
  userVerification?: 'required' | 'preferred' | 'discouraged'
  timeout?: number
}

/**
 * Generate registration options for creating a new credential
 */
export function generateRegistrationOptions(
  options: RegistrationOptions,
): PublicKeyCredentialCreationOptions {
  const challenge = options.challenge || crypto.getRandomValues(new Uint8Array(32))

  return {
    challenge,
    rp: {
      name: options.rpName,
      id: options.rpID,
    },
    user: {
      id: new TextEncoder().encode(options.userID),
      name: options.userName,
      displayName: options.userDisplayName || options.userName,
    },
    pubKeyCredParams: [
      { alg: -7, type: 'public-key' }, // ES256
      { alg: -257, type: 'public-key' }, // RS256
    ],
    timeout: options.timeout || 60000,
    attestation: options.attestationType || 'none',
    authenticatorSelection: options.authenticatorSelection || {
      authenticatorAttachment: 'platform',
      requireResidentKey: false,
      userVerification: 'preferred',
    },
    excludeCredentials: options.excludeCredentials || [],
  }
}

/**
 * Generate authentication options for verifying an existing credential
 */
export function generateAuthenticationOptions(
  options: AuthenticationOptions,
): PublicKeyCredentialRequestOptions {
  const challenge = options.challenge || crypto.getRandomValues(new Uint8Array(32))

  return {
    challenge,
    rpId: options.rpID,
    allowCredentials: options.allowCredentials || [],
    userVerification: options.userVerification || 'preferred',
    timeout: options.timeout || 60000,
  }
}

/**
 * Verify registration response from the client
 */
// eslint-disable-next-line no-unused-vars
export async function verifyRegistrationResponse(
  credential: RegistrationCredential,
  expectedChallenge: Uint8Array,
  expectedOrigin: string,
  expectedRPID: string,
  options: { requireUserVerification?: boolean } = {},
): Promise<{
  verified: boolean
  registrationInfo?: {
    credential: {
      id: string
      publicKey: ArrayBuffer
      counter: number
    }
    credentialType: string
    credentialDeviceType: string
    credentialBackedUp: boolean
  }
}> {
  try {
    const response = credential.response as AuthenticatorAttestationResponse

    // Decode client data JSON
    const clientDataJSON = JSON.parse(new TextDecoder().decode(response.clientDataJSON))

    // Verify challenge
    if (!challengeMatches(clientDataJSON.challenge, expectedChallenge)) {
      return { verified: false }
    }

    // Verify origin
    if (clientDataJSON.origin !== expectedOrigin || clientDataJSON.crossOrigin === true) {
      return { verified: false }
    }

    // Verify type
    if (clientDataJSON.type !== 'webauthn.create') {
      return { verified: false }
    }

    if (credential.type !== 'public-key' || credential.id !== Buffer.from(credential.rawId).toString('base64url')) return { verified: false }

    // Parse attestation object
    const attestationObject = parseAttestationObject(response.attestationObject)

    if (!attestationObject.authData.flags.userPresent || (options.requireUserVerification && !attestationObject.authData.flags.userVerified)) return { verified: false }
    if (attestationObject.authData.flags.backupState && !attestationObject.authData.flags.backupEligible) return { verified: false }
    if (!arraysEqual(new Uint8Array(credential.rawId), attestationObject.authData.credentialId)) return { verified: false }
    // Reject unsupported algorithms and malformed COSE keys at enrollment.
    importCredentialKey(attestationObject.authData.credentialPublicKey)

    // Verify RP ID hash
    const rpIdHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(expectedRPID))
    if (!arraysEqual(new Uint8Array(rpIdHash), attestationObject.authData.rpIdHash)) {
      return { verified: false }
    }

    return {
      verified: true,
      registrationInfo: {
        credential: {
          id: credential.id,
          publicKey: attestationObject.authData.credentialPublicKey,
          counter: attestationObject.authData.signCount,
        },
        credentialType: 'public-key',
        credentialDeviceType: attestationObject.authData.flags.backupEligible ? 'multiDevice' : 'singleDevice',
        credentialBackedUp: attestationObject.authData.flags.backupState,
      },
    }
  }
  catch (error) {
    return { verified: false }
  }
}

/**
 * Verify authentication response from the client
 */
// eslint-disable-next-line no-unused-vars
export async function verifyAuthenticationResponse(
  credential: AuthenticationCredential,
  expectedChallenge: Uint8Array,
  expectedOrigin: string,
  expectedRPID: string,
  credentialPublicKey: ArrayBuffer,
  currentCounter: number,
  options: { requireUserVerification?: boolean } = {},
): Promise<{
  verified: boolean
  authenticationInfo?: {
    newCounter: number
  }
}> {
  try {
    const response = credential.response as AuthenticatorAssertionResponse

    // Decode client data JSON
    const clientDataJSON = JSON.parse(new TextDecoder().decode(response.clientDataJSON))

    // Verify challenge
    if (!challengeMatches(clientDataJSON.challenge, expectedChallenge)) {
      return { verified: false }
    }

    // Verify origin
    if (clientDataJSON.origin !== expectedOrigin || clientDataJSON.crossOrigin === true) {
      return { verified: false }
    }

    // Verify type
    if (clientDataJSON.type !== 'webauthn.get') {
      return { verified: false }
    }

    // Parse authenticator data
    const authData = parseAuthenticatorData(response.authenticatorData)
    if (credential.type !== 'public-key' || credential.id !== Buffer.from(credential.rawId).toString('base64url')) return { verified: false }
    if (!authData.flags.userPresent || (options.requireUserVerification && !authData.flags.userVerified)) return { verified: false }
    if (authData.flags.backupState && !authData.flags.backupEligible) return { verified: false }

    // Verify RP ID hash
    const rpIdHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(expectedRPID))
    if (!arraysEqual(new Uint8Array(rpIdHash), authData.rpIdHash)) {
      return { verified: false }
    }

    // Verify counter
    if ((authData.signCount !== 0 || currentCounter !== 0) && authData.signCount <= currentCounter) {
      return { verified: false }
    }

    // Verify signature
    const clientDataHash = await crypto.subtle.digest('SHA-256', response.clientDataJSON)
    const signatureBase = new Uint8Array([
      ...new Uint8Array(response.authenticatorData),
      ...new Uint8Array(clientDataHash),
    ])

    const verified = await verifySignature(
      credentialPublicKey,
      signatureBase,
      response.signature,
    )

    if (!verified) {
      return { verified: false }
    }

    return {
      verified: true,
      authenticationInfo: {
        newCounter: authData.signCount,
      },
    }
  }
  catch (error) {
    return { verified: false }
  }
}

// Helper functions

function parseAttestationObject(attestationObject: ArrayBuffer) {
  const bytes = new Uint8Array(attestationObject)
  const decoded = decodeCBOR(bytes)
  const object = decoded.value
  // This RP requests attestation:none. Never silently accept unverified attestation.
  if (decoded.end !== bytes.length || !(object instanceof Map) || object.get('fmt') !== 'none'
    || !(object.get('attStmt') instanceof Map) || object.get('attStmt').size !== 0
    || !(object.get('authData') instanceof Uint8Array)) throw new Error('Invalid attestation')
  const authData = parseAuthenticatorData(object.get('authData').buffer)
  if (!authData.flags.attestedCredentialData) throw new Error('Missing credential data')
  return { authData }
}

function parseAuthenticatorData(authData: ArrayBuffer) {
  if (authData.byteLength < 37) throw new Error('Truncated authenticator data')
  const view = new DataView(authData)
  let offset = 0

  // RP ID Hash (32 bytes)
  const rpIdHash = new Uint8Array(authData.slice(offset, offset + 32))
  offset += 32

  // Flags (1 byte)
  const flagsByte = view.getUint8(offset)
  offset += 1

  const flags = {
    userPresent: (flagsByte & 0x01) !== 0,
    userVerified: (flagsByte & 0x04) !== 0,
    backupEligible: (flagsByte & 0x08) !== 0,
    backupState: (flagsByte & 0x10) !== 0,
    attestedCredentialData: (flagsByte & 0x40) !== 0,
    extensionData: (flagsByte & 0x80) !== 0,
  }

  // Sign count (4 bytes)
  const signCount = view.getUint32(offset, false)
  offset += 4

  let credentialPublicKey: ArrayBuffer = new ArrayBuffer(0)
  let credentialId = new Uint8Array(0)

  if (flags.attestedCredentialData) {
    // AAGUID (16 bytes)
    offset += 16

    // Credential ID length (2 bytes)
    const credIdLength = view.getUint16(offset, false)
    offset += 2

    if (!credIdLength || offset + credIdLength > authData.byteLength) throw new Error('Invalid credential id')
    credentialId = new Uint8Array(authData.slice(offset, offset + credIdLength))
    offset += credIdLength
    const key = decodeCBOR(new Uint8Array(authData), offset)
    credentialPublicKey = authData.slice(offset, key.end)
    offset = key.end
  }

  if (flags.extensionData) offset = decodeCBOR(new Uint8Array(authData), offset).end
  if (offset !== authData.byteLength) throw new Error('Trailing authenticator data')
  return {
    credentialId,
    rpIdHash,
    flags,
    signCount,
    credentialPublicKey,
  }
}

/**
 * Whether the challenge in `clientDataJSON` is the one the server issued.
 *
 * The browser writes it as **base64url of the raw challenge bytes**, per the
 * WebAuthn specification. This previously read `base64Decode(challenge)` -
 * which interprets those bytes as UTF-8 text - and compared the result to
 * `base64Encode(expected)`, a base64 string. For a random 32-byte challenge
 * those two are never equal, so the check failed on every well-formed
 * assertion and `verifyAuthenticationResponse` always returned
 * `{ verified: false }`. Passkeys could not be used at all.
 *
 * Compared as bytes, and in constant time: a challenge is a secret for the
 * length of a ceremony.
 */
function challengeMatches(received: unknown, expected: Uint8Array): boolean {
  if (typeof received !== 'string')
    return false

  const normalized = received.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4)
  const bytes = new Uint8Array(Buffer.from(padded, 'base64'))

  if (bytes.length !== expected.length)
    return false

  let difference = 0

  for (let i = 0; i < bytes.length; i++)
    difference |= bytes[i]! ^ expected[i]!

  return difference === 0
}

/**
 * Import a credential public key, whether it is COSE or SPKI.
 *
 * An authenticator reports its public key as a **COSE key** - a small CBOR map
 * carrying the curve and the two coordinates - and that is what a relying party
 * stores. This function previously called `importKey('spki', ...)` only, which
 * throws on COSE bytes and was caught and reported as a bad signature, so a
 * genuine assertion from a genuine authenticator was rejected as forged.
 *
 * SPKI is still accepted, because callers that stored a converted key should
 * not break.
 */
function importCredentialKey(publicKey: ArrayBuffer): ReturnType<typeof createPublicKey> {
  const bytes = new Uint8Array(publicKey)
  if ((bytes[0]! & 0xE0) !== 0xA0)
    return createPublicKey({ key: Buffer.from(publicKey), format: 'der', type: 'spki' })
  const decoded = decodeCBOR(bytes)
  const key = decoded.value
  if (!(key instanceof Map) || decoded.end !== bytes.length) throw new Error('Invalid COSE key')
  function part(label: number, length?: number): string {
    const value = key.get(label)
    if (!(value instanceof Uint8Array) || !value.length || (length && value.length !== length)) throw new Error('Invalid key component')
    return Buffer.from(value).toString('base64url')
  }
  if (key.get(1) === 2 && key.get(3) === -7 && key.get(-1) === 1)
    return createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256', x: part(-2, 32), y: part(-3, 32) } })
  if (key.get(1) === 3 && key.get(3) === -257) {
    const modulus = key.get(-1)
    if (!(modulus instanceof Uint8Array) || modulus.length < 256) throw new Error('Weak RSA key')
    return createPublicKey({ format: 'jwk', key: { kty: 'RSA', n: part(-1), e: part(-2) } })
  }
  throw new Error('Unsupported credential algorithm')
}

async function verifySignature(publicKey: ArrayBuffer, data: Uint8Array, signature: ArrayBuffer): Promise<boolean> {
  try {
    const key = importCredentialKey(publicKey)
    if (key.asymmetricKeyType !== 'ec' && key.asymmetricKeyType !== 'rsa') return false
    // Authenticators encode ES256 signatures as ASN.1 DER, not WebCrypto's P1363.
    return verifyCryptoSignature('sha256', data, key, Buffer.from(signature))
  }
  catch {
    return false
  }
}

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length)
    return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i])
      return false
  }
  return true
}
