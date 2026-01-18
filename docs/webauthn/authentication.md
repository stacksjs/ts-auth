---
title: WebAuthn Server-side Authentication
description: Implement WebAuthn credential authentication on the server
---

# Server-side Authentication

This guide covers implementing WebAuthn authentication verification on your server.

## Authentication Flow

1. Generate authentication options
2. Send options to the browser
3. Receive assertion from browser
4. Verify the assertion

## Generate Authentication Options

```typescript
import { generateAuthenticationOptions } from 'ts-auth'

function handleAuthenticationStart(userId: string) {
  // Get user's stored credentials
  const storedCredentials = getCredentialsForUser(userId)

  const options = generateAuthenticationOptions({
    // Relying Party ID
    rpID: 'example.com',

    // Allow these credentials
    allowCredentials: storedCredentials.map(cred => ({
      id: cred.credentialId,
      type: 'public-key',
      transports: ['internal', 'usb', 'ble', 'nfc'],
    })),

    // User verification requirement
    userVerification: 'preferred',

    // Timeout in milliseconds
    timeout: 60000,
  })

  // Store the challenge for verification
  challenges.set(userId, options.challenge)

  return options
}
```

## Authentication Options Reference

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `rpID` | `string` | Domain of the relying party |

### Optional Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `challenge` | `Uint8Array` | Random 32 bytes | Challenge for the request |
| `allowCredentials` | `array` | `[]` | Allowed credentials |
| `userVerification` | `string` | `'preferred'` | User verification requirement |
| `timeout` | `number` | `60000` | Timeout in milliseconds |

### Allow Credentials

```typescript
allowCredentials: [
  {
    id: credentialId,        // ArrayBuffer or Uint8Array
    type: 'public-key',      // Always 'public-key'
    transports: [            // Optional transport hints
      'internal',            // Platform authenticator
      'usb',                 // USB security key
      'ble',                 // Bluetooth
      'nfc',                 // NFC
    ],
  },
]
```

## Verify Authentication Response

```typescript
import { verifyAuthenticationResponse } from 'ts-auth'

async function handleAuthenticationFinish(
  userId: string,
  credential: AuthenticationCredential
) {
  // Retrieve the stored challenge
  const expectedChallenge = challenges.get(userId)

  if (!expectedChallenge) {
    throw new Error('No challenge found')
  }

  // Get the stored credential
  const storedCredential = getCredential(userId, credential.id)

  if (!storedCredential) {
    throw new Error('Credential not found')
  }

  // Verify the authentication response
  const verification = await verifyAuthenticationResponse(
    credential,
    expectedChallenge,
    'https://example.com',     // Expected origin
    'example.com',             // Expected RP ID
    storedCredential.publicKey, // Stored public key
    storedCredential.counter    // Stored counter
  )

  if (verification.verified) {
    // Update the counter to prevent replay attacks
    await updateCredentialCounter(
      userId,
      credential.id,
      verification.authenticationInfo!.newCounter
    )

    // Clean up the challenge
    challenges.delete(userId)

    return {
      success: true,
      userId: userId,
    }
  }

  return {
    success: false,
    error: 'Authentication failed',
  }
}
```

## Verification Response

The `verifyAuthenticationResponse` function returns:

```typescript
{
  verified: boolean
  authenticationInfo?: {
    newCounter: number  // Updated signature counter
  }
}
```

## Counter Verification

The signature counter prevents replay attacks and detects cloned authenticators:

```typescript
// In verifyAuthenticationResponse, the counter is checked:
// - If newCounter > storedCounter: Valid, authenticator is genuine
// - If newCounter <= storedCounter && newCounter > 0: Potential clone!

// Always update the counter after successful authentication
await db.credentials.update({
  where: { id: credential.id },
  data: { counter: verification.authenticationInfo.newCounter },
})
```

## Complete Example

```typescript
// authentication-handler.ts
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from 'ts-auth'
import type { AuthenticationCredential } from 'ts-auth'

const challenges = new Map<string, Uint8Array>()

// In-memory credential storage (use a database in production)
const credentials = new Map<string, any[]>()

export async function startAuthentication(userId?: string) {
  let allowCredentials: any[] = []

  if (userId) {
    // If userId provided, only allow that user's credentials
    const userCreds = credentials.get(userId) || []
    allowCredentials = userCreds.map(c => ({
      id: c.credentialId,
      type: 'public-key',
    }))
  }

  const options = generateAuthenticationOptions({
    rpID: 'example.com',
    allowCredentials,
    userVerification: 'preferred',
  })

  // Store challenge (use session ID if no userId)
  const challengeKey = userId || 'anonymous'
  challenges.set(challengeKey, options.challenge)

  return { options, challengeKey }
}

export async function finishAuthentication(
  challengeKey: string,
  credential: AuthenticationCredential
) {
  const expectedChallenge = challenges.get(challengeKey)

  if (!expectedChallenge) {
    return { success: false, error: 'Challenge not found' }
  }

  // Find the credential across all users
  let storedCredential = null
  let userId = null

  for (const [uid, userCreds] of credentials) {
    const found = userCreds.find(c => c.credentialId === credential.id)
    if (found) {
      storedCredential = found
      userId = uid
      break
    }
  }

  if (!storedCredential || !userId) {
    return { success: false, error: 'Credential not found' }
  }

  const verification = await verifyAuthenticationResponse(
    credential,
    expectedChallenge,
    'https://example.com',
    'example.com',
    storedCredential.publicKey,
    storedCredential.counter
  )

  if (!verification.verified || !verification.authenticationInfo) {
    return { success: false, error: 'Verification failed' }
  }

  // Update counter
  storedCredential.counter = verification.authenticationInfo.newCounter

  // Clean up
  challenges.delete(challengeKey)

  return {
    success: true,
    userId,
  }
}
```

## Passwordless Authentication

For true passwordless authentication without specifying a user:

```typescript
// Start authentication without userId
const options = generateAuthenticationOptions({
  rpID: 'example.com',
  allowCredentials: [], // Empty = discoverable credentials
  userVerification: 'required',
})

// The authenticator will show all available credentials
// User selects one, and the response includes the credential ID
// Server looks up the user from the credential ID
```

## Error Handling

```typescript
async function authenticate(credential: AuthenticationCredential) {
  try {
    const result = await finishAuthentication(challengeKey, credential)

    if (!result.success) {
      switch (result.error) {
        case 'Challenge not found':
          // Session expired, restart authentication
          break
        case 'Credential not found':
          // Unknown credential
          break
        case 'Verification failed':
          // Signature invalid or counter mismatch
          break
      }
    }

    return result
  } catch (error) {
    console.error('Authentication error:', error)
    return { success: false, error: 'Internal error' }
  }
}
```

## Next Steps

- [Browser Integration](/webauthn/browser)
- [Credential Management](/webauthn/credentials)
- [Security Best Practices](/security/best-practices)
