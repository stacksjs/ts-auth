---
title: WebAuthn Server-side Registration
description: Implement WebAuthn credential registration on the server
---
    await storeCredential(userId, {
      credentialId: credentialData.id,
      publicKey: credentialData.publicKey,
      counter: credentialData.counter,
      deviceType: verification.registrationInfo.credentialDeviceType,
      backedUp: verification.registrationInfo.credentialBackedUp,
      createdAt: new Date(),
    })

    // Clean up the challenge
    challenges.delete(userId)

    return {
      success: true,
      credentialId: credentialData.id,
    }
  }

  return {
    success: false,
    error: 'Verification failed',
  }
}

```

## Verification Response

The `verifyRegistrationResponse` function returns:

```typescript

{
  verified: boolean
  registrationInfo?: {
    credential: {
      id: string           // Base64URL-encoded credential ID
      publicKey: ArrayBuffer  // COSE public key
      counter: number        // Signature counter
    }
    credentialType: string      // Always 'public-key'
    credentialDeviceType: string // 'singleDevice' or 'multiDevice'
    credentialBackedUp: boolean  // Whether synced to cloud
  }
}

```

## Complete Example

```typescript

// registration-handler.ts
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from 'ts-auth'
import type { RegistrationCredential } from 'ts-auth'

const challenges = new Map<string, Uint8Array>()
const credentials = new Map<string, any[]>()

export async function startRegistration(
  userId: string,
  userName: string,
  userDisplayName?: string
) {
  // Get existing credentials for this user
  const existingCreds = credentials.get(userId) || []

  const options = generateRegistrationOptions({
    rpName: 'My Application',
    rpID: 'example.com',
    userID: userId,
    userName: userName,
    userDisplayName: userDisplayName || userName,
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'preferred',
      residentKey: 'preferred',
    },
    excludeCredentials: existingCreds.map(c => ({
      id: c.credentialId,
      type: 'public-key',
    })),
  })

  // Store challenge
  challenges.set(userId, options.challenge)

  return options
}

export async function finishRegistration(
  userId: string,
  credential: RegistrationCredential
) {
  const expectedChallenge = challenges.get(userId)

  if (!expectedChallenge) {
    return { success: false, error: 'Challenge not found' }
  }

  const verification = await verifyRegistrationResponse(
    credential,
    expectedChallenge,
    'https://example.com',
    'example.com'
  )

  if (!verification.verified || !verification.registrationInfo) {
    return { success: false, error: 'Verification failed' }
  }

  // Store credential
  const userCreds = credentials.get(userId) || []
  userCreds.push({
    credentialId: verification.registrationInfo.credential.id,
    publicKey: verification.registrationInfo.credential.publicKey,
    counter: verification.registrationInfo.credential.counter,
    deviceType: verification.registrationInfo.credentialDeviceType,
    backedUp: verification.registrationInfo.credentialBackedUp,
    createdAt: new Date(),
  })
  credentials.set(userId, userCreds)

  // Clean up
  challenges.delete(userId)

  return {
    success: true,
    credentialId: verification.registrationInfo.credential.id,
  }
}

```

## Express/Bun Integration

```typescript

// Using Bun.serve
Bun.serve({
  port: 3000,
  async fetch(req) {
    const url = new URL(req.url)

    if (url.pathname === '/api/register/start' && req.method === 'POST') {
      const { userId, userName } = await req.json()
      const options = await startRegistration(userId, userName)
      return Response.json(options)
    }

    if (url.pathname === '/api/register/finish' && req.method === 'POST') {
      const { userId, credential } = await req.json()
      const result = await finishRegistration(userId, credential)
      return Response.json(result)
    }

    return new Response('Not Found', { status: 404 })
  },
})

```

## Next Steps

- [Server-side Authentication](/webauthn/authentication)
- [Browser Integration](/webauthn/browser)
- [Security Best Practices](/security/best-practices)

## JSON and verification profile

Use `registrationOptionsToJSON` to send creation options over HTTP and
`registrationCredentialFromJSON` to decode the returned credential before
verification. For the browser import `@stacksjs/ts-auth/passkeys-browser`:
it contains no server or Node dependencies. `startRegistration` accepts either
binary options or base64url JSON; send its result with
`registrationCredentialToJSON`, which also preserves authenticator transports.
Authentication has the corresponding option and credential codecs, and
`startAuthentication(options, { signal, mediation: 'conditional' })` supports
abortable autofill. Place `webauthn` last in the username autocomplete attribute.

The verifier supports attestation `none`, ES256/P-256 and RS256 credentials.
It decodes definite-length CBOR and COSE, checks the credential ID against
attested data, and verifies authenticator signatures (including DER ES256).
Other attestation formats fail closed. Pass `{ requireUserVerification: true }`
as the last argument to both verifiers for passwordless sign-in. User presence
is always required. The relying party must persist short-lived challenges,
consume them once and atomically advance the verified credential's counter.
See the [WebAuthn registration and assertion algorithms](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential).
