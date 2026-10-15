/**
 * WebAuthn Browser Implementation
 * Native implementation to replace @simplewebauthn/browser
 */

import { decodeBase64URL } from './json'
import type { RegistrationOptionsJSON, AuthenticationOptionsJSON } from './json'
import type {
  AuthenticationCredential,
  PublicKeyCredentialCreationOptions,
  PublicKeyCredentialRequestOptions,
  RegistrationCredential,
} from './types'

/**
 * Start registration (credential creation) process
 */
export async function startRegistration(
  options: PublicKeyCredentialCreationOptions | RegistrationOptionsJSON,
  control: { signal?: AbortSignal } = {},
): Promise<RegistrationCredential> {
  // Check if WebAuthn is supported
  if (!browserSupportsWebAuthn()) {
    throw new Error('WebAuthn is not supported in this browser')
  }

  // Convert options to browser-compatible format
  const publicKeyOptions: PublicKeyCredentialCreationOptions = {
    ...options,
    challenge: typeof options.challenge === 'string' ? new Uint8Array(decodeBase64URL(options.challenge)) : options.challenge,
    user: {
      ...options.user,
      id: typeof options.user.id === 'string' ? new Uint8Array(decodeBase64URL(options.user.id)) : options.user.id,
    },
  }

  publicKeyOptions.excludeCredentials = options.excludeCredentials?.map(item => ({ ...item, id: typeof item.id === 'string' ? decodeBase64URL(item.id) : item.id }))

  // Create credential
  const credential = await navigator.credentials.create({
    publicKey: publicKeyOptions as any,
    signal: control.signal,
  }) as any

  if (!credential) {
    throw new Error('Failed to create credential')
  }

  // Convert to serializable format
  return {
    id: credential.id,
    rawId: credential.rawId,
    response: {
      clientDataJSON: credential.response.clientDataJSON,
      attestationObject: credential.response.attestationObject,
      transports: credential.response.getTransports?.() || [],
    },
    type: credential.type,
  }
}

/**
 * Start authentication (credential verification) process
 */
export async function startAuthentication(
  options: PublicKeyCredentialRequestOptions | AuthenticationOptionsJSON,
  control: { signal?: AbortSignal, mediation?: 'conditional' | 'optional' | 'required' } = {},
): Promise<AuthenticationCredential> {
  // Check if WebAuthn is supported
  if (!browserSupportsWebAuthn()) {
    throw new Error('WebAuthn is not supported in this browser')
  }

  // Get credential
  const credential = await navigator.credentials.get({
    publicKey: { ...options, challenge: typeof options.challenge === 'string' ? decodeBase64URL(options.challenge) : options.challenge,
      allowCredentials: options.allowCredentials?.map(item => ({ ...item, id: typeof item.id === 'string' ? decodeBase64URL(item.id) : item.id })) } as any,
    signal: control.signal,
    mediation: control.mediation,
  }) as any

  if (!credential) {
    throw new Error('Failed to get credential')
  }

  // Convert to serializable format
  return {
    id: credential.id,
    rawId: credential.rawId,
    response: {
      clientDataJSON: credential.response.clientDataJSON,
      authenticatorData: credential.response.authenticatorData,
      signature: credential.response.signature,
      userHandle: credential.response.userHandle,
    },
    type: credential.type,
  }
}

/**
 * Check if platform authenticator is available
 */
export async function platformAuthenticatorIsAvailable(): Promise<boolean> {
  if (!browserSupportsWebAuthn()) {
    return false
  }

  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
  }
  catch {
    return false
  }
}

/**
 * Check if browser supports WebAuthn
 */
export function browserSupportsWebAuthn(): boolean {
  return typeof globalThis.PublicKeyCredential !== 'undefined' && typeof navigator !== 'undefined' && !!navigator.credentials
}

/**
 * Check if browser supports conditional UI
 */
export async function browserSupportsWebAuthnAutofill(): Promise<boolean> {
  if (!browserSupportsWebAuthn()) {
    return false
  }

  try {
    return !!(await (PublicKeyCredential as any).isConditionalMediationAvailable?.())
  }
  catch {
    return false
  }
}
