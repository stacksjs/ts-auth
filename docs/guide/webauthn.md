---
title: WebAuthn/Passkeys Implementation
description: Complete guide to implementing WebAuthn and Passkeys authentication with ts-auth
---
// Check basic WebAuthn support
if (!browserSupportsWebAuthn()) {
  console.log('WebAuthn is not supported in this browser')
  // Fall back to password authentication
}

// Check for platform authenticator (Face ID, Touch ID, Windows Hello)
if (await platformAuthenticatorIsAvailable()) {
  console.log('Platform authenticator available - can use biometrics')
}

```

## Registration Flow

Registration creates a new credential (passkey) for the user.

### Server-Side: Generate Registration Options

```typescript

import { generateRegistrationOptions } from 'ts-auth'

function handleRegistrationStart(userId: string, userName: string) {
  const options = generateRegistrationOptions({
    // Relying Party (your application)
    rpName: 'My Application',
    rpID: 'example.com', // Your domain

    // User information
    userID: userId,
    userName: userName, // Usually email
    userDisplayName: 'John Doe',

    // Authenticator preferences
    authenticatorSelection: {
      // 'platform' = built-in (Face ID, Touch ID, Windows Hello)
      // 'cross-platform' = external (YubiKey, etc.)
      authenticatorAttachment: 'platform',

      // Resident key (discoverable credential) settings
      residentKey: 'preferred',
      requireResidentKey: false,

      // User verification level
      userVerification: 'preferred', // 'required', 'preferred', 'discouraged'
    },

    // Attestation type
    attestationType: 'none', // 'none', 'indirect', 'direct'

    // Prevent duplicate registrations
    excludeCredentials: existingCredentials.map(cred => ({
      id: cred.id,
      type: 'public-key',
      transports: ['internal', 'usb', 'ble', 'nfc'],
    })),

    // Timeout in milliseconds
    timeout: 60000,
  })

  // Store the challenge for verification
  // IMPORTANT: Use server-side storage (session, cache, database)
  challengeStore.set(userId, options.challenge)

  return options
}

```

### Client-Side: Create Credential

```typescript

import { startRegistration, browserSupportsWebAuthn } from 'ts-auth'

async function register() {
  // Check support first
  if (!browserSupportsWebAuthn()) {
    throw new Error('WebAuthn not supported')
  }

  // Get options from your server
  const options = await fetch('/api/auth/register/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId, userName }),
  }).then(r => r.json())

  try {
    // Create the credential (this prompts the user)
    const credential = await startRegistration(options)

    // Send credential to server for verification
    const result = await fetch('/api/auth/register/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credential),
    }).then(r => r.json())

    if (result.success) {
      console.log('Registration successful!')
    }
  } catch (error) {
    if (error.name === 'NotAllowedError') {
      console.log('User cancelled the registration')
    } else {
      console.error('Registration failed:', error)
    }
  }
}

```

### Server-Side: Verify Registration

```typescript

import { verifyRegistrationResponse } from 'ts-auth'

async function handleRegistrationFinish(userId: string, credential: any) {
  // Retrieve the challenge from storage
  const expectedChallenge = challengeStore.get(userId)

  if (!expectedChallenge) {
    throw new Error('Challenge not found or expired')
  }

  const verification = await verifyRegistrationResponse(
    credential,
    expectedChallenge,
    'https://example.com', // Expected origin
    'example.com' // Expected RP ID
  )

  if (verification.verified && verification.registrationInfo) {
    // Store the credential in your database
    await db.userCredentials.create({
      userId,
      credentialId: verification.registrationInfo.credential.id,
      publicKey: verification.registrationInfo.credential.publicKey,
      counter: verification.registrationInfo.credential.counter,
      deviceType: verification.registrationInfo.credentialDeviceType,
      backedUp: verification.registrationInfo.credentialBackedUp,
      createdAt: new Date(),
    })

    // Clean up the challenge
    challengeStore.delete(userId)

    return { success: true }
  }

  return { success: false, error: 'Verification failed' }
}

```

## Authentication Flow

Authentication verifies the user owns a previously registered credential.

### Server-Side: Generate Authentication Options

```typescript

import { generateAuthenticationOptions } from 'ts-auth'

async function handleAuthenticationStart(userId?: string) {
  // If userId is provided, allow only their credentials
  // If not provided, allow any credential (discoverable credentials)
  let allowCredentials = []

  if (userId) {
    const userCreds = await db.userCredentials.findByUserId(userId)
    allowCredentials = userCreds.map(cred => ({
      id: cred.credentialId,
      type: 'public-key' as const,
      transports: ['internal', 'usb', 'ble', 'nfc'],
    }))
  }

  const options = generateAuthenticationOptions({
    rpID: 'example.com',
    allowCredentials,
    userVerification: 'preferred',
    timeout: 60000,
  })

  // Store challenge for verification
  const sessionId = generateSessionId()
  challengeStore.set(sessionId, {
    challenge: options.challenge,
    userId,
  })

  return { options, sessionId }
}

```

### Client-Side: Authenticate

```typescript

import { startAuthentication, browserSupportsWebAuthnAutofill } from 'ts-auth'

async function login() {
  // Get options from server
  const { options, sessionId } = await fetch('/api/auth/login/start', {
    method: 'POST',
  }).then(r => r.json())

  try {
    // Get the credential (prompts user)
    const credential = await startAuthentication(options)

    // Verify with server
    const result = await fetch('/api/auth/login/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ credential, sessionId }),
    }).then(r => r.json())

    if (result.success) {
      // User is authenticated
      window.location.href = '/dashboard'
    }
  } catch (error) {
    if (error.name === 'NotAllowedError') {
      console.log('User cancelled authentication')
    } else {
      console.error('Authentication failed:', error)
    }
  }
}

// Conditional UI (autofill) support
async function setupAutofill() {
  if (await browserSupportsWebAuthnAutofill()) {
    // Enable passkey autofill on username input
    const { options } = await fetch('/api/auth/login/start').then(r => r.json())
    const credential = await startAuthentication(options, true) // true = conditional UI
    // Auto-login when user selects a passkey from autofill
  }
}

```

### Server-Side: Verify Authentication

```typescript

import { verifyAuthenticationResponse } from 'ts-auth'

async function handleAuthenticationFinish(sessionId: string, credential: any) {
  // Get stored challenge
  const session = challengeStore.get(sessionId)
  if (!session) {
    throw new Error('Session not found or expired')
  }

  // Find the credential in your database
  const storedCred = await db.userCredentials.findByCredentialId(credential.id)
  if (!storedCred) {
    throw new Error('Credential not found')
  }

  const verification = await verifyAuthenticationResponse(
    credential,
    session.challenge,
    'https://example.com',
    'example.com',
    storedCred.publicKey,
    storedCred.counter
  )

  if (verification.verified && verification.authenticationInfo) {
    // Update the counter to prevent replay attacks
    await db.userCredentials.updateCounter(
      credential.id,
      verification.authenticationInfo.newCounter
    )

    // Clean up
    challengeStore.delete(sessionId)

    // Create user session
    return {
      success: true,
      userId: storedCred.userId,
    }
  }

  return { success: false, error: 'Authentication failed' }
}

```

## Security Best Practices

### Challenge Management

```typescript

// Always generate challenges server-side
const challenge = crypto.getRandomValues(new Uint8Array(32))

// Use short expiration times
challengeStore.set(userId, {
  challenge,
  expiresAt: Date.now() + 60000, // 1 minute
})

// Clean up expired challenges regularly
setInterval(() => {
  for (const [key, value] of challengeStore) {
    if (Date.now() > value.expiresAt) {
      challengeStore.delete(key)
    }
  }
}, 60000)

```

### Counter Verification

```typescript

// Always verify and update counters
if (authData.signCount > 0 && authData.signCount <= storedCounter) {
  // Possible cloned authenticator!
  console.warn('Counter did not increase - possible clone detected')
  // Consider requiring re-registration or additional verification
}

```

### Origin and RP ID Validation

```typescript

// Verify these match exactly
const expectedOrigin = 'https://example.com'
const expectedRpId = 'example.com'

// For subdomains, the RP ID must be the registrable domain
// e.g., for app.example.com, RP ID can be 'example.com' or 'app.example.com'

```

## Error Handling

```typescript

import {
  WebAuthnError,
  WebAuthnRegistrationError,
  WebAuthnAuthenticationError,
  WebAuthnChallengeError,
  WebAuthnOriginError,
  WebAuthnRpIdError,
  WebAuthnCounterError,
} from 'ts-auth'

try {
  await verifyRegistrationResponse(credential, challenge, origin, rpId)
} catch (error) {
  if (error instanceof WebAuthnChallengeError) {
    console.error('Challenge mismatch - possible replay attack')
  } else if (error instanceof WebAuthnOriginError) {
    console.error('Origin mismatch - request from unexpected domain')
  } else if (error instanceof WebAuthnRpIdError) {
    console.error('RP ID mismatch')
  } else if (error instanceof WebAuthnCounterError) {
    console.error('Counter error - possible cloned authenticator')
  }
}

```

## Complete Example

See the [Complete Authentication Flow](/guide/getting-started#complete-authentication-flow) for a full implementation example combining WebAuthn with other authentication methods.

## Next Steps

- Learn about [TOTP/2FA](/guide/totp) for additional security
- Configure [Session Management](/session/overview)
- Review [Security Best Practices](/security/best-practices)
