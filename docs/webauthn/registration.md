---
title: WebAuthn Server-side Registration
description: Implement WebAuthn credential registration on the server
---
  const options = generateRegistrationOptions({
    // Relying Party information
    rpName: 'My Application',
    rpID: 'example.com',

    // User information
    userID: userId,
    userName: userName,
    userDisplayName: 'John Doe', // Optional, defaults to userName

    // Authenticator selection
    authenticatorSelection: {
      authenticatorAttachment: 'platform', // or 'cross-platform'
      requireResidentKey: false,
      residentKey: 'preferred',
      userVerification: 'preferred',
    },

    // Attestation type
    attestationType: 'none', // 'none', 'indirect', or 'direct'

    // Timeout in milliseconds
    timeout: 60000,

    // Exclude existing credentials
    excludeCredentials: existingCredentials.map(cred => ({
      id: cred.id,
      type: 'public-key',
      transports: ['internal'],
    })),
  })

  // Store the challenge for verification
  challenges.set(userId, options.challenge)

  return options
}

```

## Registration Options Reference

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `rpName` | `string` | Human-readable name of the relying party |
| `rpID` | `string` | Domain of the relying party (e.g., 'example.com') |
| `userID` | `string` | Unique identifier for the user |
| `userName` | `string` | Username (typically email) |

### Optional Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `userDisplayName` | `string` | `userName` | Human-readable display name |
| `challenge` | `Uint8Array` | Random 32 bytes | Challenge for the request |
| `attestationType` | `string` | `'none'` | Attestation conveyance preference |
| `timeout` | `number` | `60000` | Timeout in milliseconds |
| `authenticatorSelection` | `object` | See below | Authenticator criteria |
| `excludeCredentials` | `array` | `[]` | Credentials to exclude |

### Authenticator Selection

```typescript

authenticatorSelection: {
  // Require platform (built-in) or cross-platform (roaming) authenticator
  authenticatorAttachment: 'platform' | 'cross-platform',

  // Require a resident key (discoverable credential)
  requireResidentKey: false,

  // Resident key preference
  residentKey: 'discouraged' | 'preferred' | 'required',

  // User verification requirement
  userVerification: 'required' | 'preferred' | 'discouraged',
}

```

## Verify Registration Response

After receiving the credential from the browser, verify it:

```typescript

import { verifyRegistrationResponse } from 'ts-auth'

async function handleRegistrationFinish(
  userId: string,
  credential: RegistrationCredential
) {
  // Retrieve the stored challenge
  const expectedChallenge = challenges.get(userId)

  if (!expectedChallenge) {
    throw new Error('No challenge found for user')
  }

  // Verify the registration response
  const verification = await verifyRegistrationResponse(
    credential,
    expectedChallenge,
    'https://example.com', // Expected origin
    'example.com'          // Expected RP ID
  )

  if (verification.verified && verification.registrationInfo) {
    // Store the credential
    const { credential: credentialData } = verification.registrationInfo

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
