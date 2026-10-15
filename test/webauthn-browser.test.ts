import { expect, test } from 'bun:test'
import { startAuthentication, startRegistration, browserSupportsWebAuthn } from '../src/webauthn/browser'
import { encodeBase64URL, registrationCredentialToJSON } from '../src/webauthn/json'

test('browser JSON options become BufferSources and cancellation/conditional mediation reach WebAuthn', async () => {
  const originalNavigator = Object.getOwnPropertyDescriptor(globalThis, 'navigator')
  const originalCredential = Object.getOwnPropertyDescriptor(globalThis, 'PublicKeyCredential')
  const bytes = new Uint8Array([1, 2, 3])
  const encoded = encodeBase64URL(bytes)
  const abort = new AbortController()
  let call: any
  Object.defineProperty(globalThis, 'PublicKeyCredential', { configurable: true, value: class {} })
  Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { credentials: {
    create: async (options: any) => {
      call = options
      return { id: encoded, rawId: bytes.buffer, type: 'public-key', response: {
        clientDataJSON: bytes.buffer, attestationObject: bytes.buffer, getTransports: () => ['usb'] } }
    },
    get: async (options: any) => {
      call = options
      return { id: encoded, rawId: bytes.buffer, type: 'public-key', response: {
        clientDataJSON: bytes.buffer, authenticatorData: bytes.buffer, signature: bytes.buffer, userHandle: null } }
    },
  } } })
  try {
    expect(browserSupportsWebAuthn()).toBe(true)
    const registered = await startRegistration({ challenge: encoded, rp: { id: 'localhost', name: 'Example' },
      user: { id: encoded, name: 'user', displayName: 'User' }, pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
      excludeCredentials: [{ id: encoded, type: 'public-key' }] }, { signal: abort.signal })
    expect(new Uint8Array(call.publicKey.challenge)).toEqual(bytes)
    expect(new Uint8Array(call.publicKey.user.id)).toEqual(bytes)
    expect(new Uint8Array(call.publicKey.excludeCredentials[0].id)).toEqual(bytes)
    expect(registrationCredentialToJSON(registered).response.transports).toEqual(['usb'])
    await startAuthentication({ challenge: encoded, allowCredentials: [{ id: encoded, type: 'public-key' }] }, { signal: abort.signal, mediation: 'conditional' })
    expect(call.mediation).toBe('conditional')
    expect(call.signal).toBe(abort.signal)
    expect(new Uint8Array(call.publicKey.allowCredentials[0].id)).toEqual(bytes)
  }
  finally {
    if (originalNavigator) Object.defineProperty(globalThis, 'navigator', originalNavigator)
    else Reflect.deleteProperty(globalThis, 'navigator')
    if (originalCredential) Object.defineProperty(globalThis, 'PublicKeyCredential', originalCredential)
    else Reflect.deleteProperty(globalThis, 'PublicKeyCredential')
  }
})
