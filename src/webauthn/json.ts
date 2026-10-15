import type { AuthenticationCredential, RegistrationCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions } from './types'

/** JSON-safe WebAuthn binary fields, encoded as unpadded base64url. */
export function encodeBase64URL(value: ArrayBuffer | Uint8Array): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value)
  return btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function decodeBase64URL(value: unknown): ArrayBuffer {
  if (typeof value !== 'string' || !value || value.length > 131072 || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1)
    throw new Error('Invalid base64url')
  const raw = atob(value.replace(/-/g, '+').replace(/_/g, '/'))
  const bytes = Uint8Array.from(raw, char => char.charCodeAt(0))
  if (encodeBase64URL(bytes) !== value) throw new Error('Noncanonical base64url')
  return bytes.buffer
}

export interface RegistrationCredentialJSON {
  id: string
  rawId: string
  type: string
  response: { clientDataJSON: string, attestationObject: string, transports?: string[] }
}
export interface AuthenticationCredentialJSON {
  id: string
  rawId: string
  type: string
  response: { clientDataJSON: string, authenticatorData: string, signature: string, userHandle: string | null }
}
export type RegistrationOptionsJSON = Omit<PublicKeyCredentialCreationOptions, 'challenge' | 'user' | 'excludeCredentials'> & {
  challenge: string
  user: { id: string, name: string, displayName: string }
  excludeCredentials?: { id: string, type: string, transports?: string[] }[]
}
export type AuthenticationOptionsJSON = Omit<PublicKeyCredentialRequestOptions, 'challenge' | 'allowCredentials'> & {
  challenge: string
  allowCredentials?: { id: string, type: string, transports?: string[] }[]
}

export function registrationOptionsToJSON(options: PublicKeyCredentialCreationOptions): RegistrationOptionsJSON {
  return { ...options, challenge: encodeBase64URL(options.challenge), user: { ...options.user, id: encodeBase64URL(options.user.id) },
    excludeCredentials: options.excludeCredentials?.map(item => ({ ...item, id: typeof item.id === 'string' ? item.id : encodeBase64URL(item.id) })) }
}
export function authenticationOptionsToJSON(options: PublicKeyCredentialRequestOptions): AuthenticationOptionsJSON {
  return { ...options, challenge: encodeBase64URL(options.challenge),
    allowCredentials: options.allowCredentials?.map(item => ({ ...item, id: typeof item.id === 'string' ? item.id : encodeBase64URL(item.id) })) }
}
export function registrationCredentialFromJSON(value: RegistrationCredentialJSON): RegistrationCredential {
  return { id: value.id, type: value.type, rawId: decodeBase64URL(value.rawId), response: {
    clientDataJSON: decodeBase64URL(value.response.clientDataJSON), attestationObject: decodeBase64URL(value.response.attestationObject) } }
}
export function authenticationCredentialFromJSON(value: AuthenticationCredentialJSON): AuthenticationCredential {
  return { id: value.id, type: value.type, rawId: decodeBase64URL(value.rawId), response: {
    clientDataJSON: decodeBase64URL(value.response.clientDataJSON), authenticatorData: decodeBase64URL(value.response.authenticatorData),
    signature: decodeBase64URL(value.response.signature), userHandle: value.response.userHandle == null ? null : decodeBase64URL(value.response.userHandle) } }
}
export function registrationCredentialToJSON(value: RegistrationCredential): RegistrationCredentialJSON {
  return { id: value.id, type: value.type, rawId: encodeBase64URL(value.rawId), response: {
    clientDataJSON: encodeBase64URL(value.response.clientDataJSON), attestationObject: encodeBase64URL(value.response.attestationObject), transports: value.response.transports } }
}
export function authenticationCredentialToJSON(value: AuthenticationCredential): AuthenticationCredentialJSON {
  return { id: value.id, type: value.type, rawId: encodeBase64URL(value.rawId), response: {
    clientDataJSON: encodeBase64URL(value.response.clientDataJSON), authenticatorData: encodeBase64URL(value.response.authenticatorData),
    signature: encodeBase64URL(value.response.signature), userHandle: value.response.userHandle == null ? null : encodeBase64URL(value.response.userHandle) } }
}
