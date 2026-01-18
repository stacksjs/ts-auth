---
title: Getting Started with ts-auth
description: Learn how to implement authentication in your application using ts-auth
---

# Getting Started

This guide will walk you through setting up authentication in your application using ts-auth.

## Installation

Install ts-auth using your preferred package manager:

```bash
# Using bun
bun add ts-auth

# Using npm
npm install ts-auth

# Using yarn
yarn add ts-auth

# Using pnpm
pnpm add ts-auth
```

## Basic Setup

### 1. WebAuthn (Passkeys) Authentication

WebAuthn enables passwordless authentication using biometrics, security keys, or device PINs.

```typescript
// Server-side: Generate registration options
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from 'ts-auth'

// Generate options for creating a new credential
const options = generateRegistrationOptions({
  rpName: 'My Application',
  rpID: 'example.com',
  userID: 'user-unique-id',
  userName: 'john@example.com',
  userDisplayName: 'John Doe',
  authenticatorSelection: {
    authenticatorAttachment: 'platform',
    userVerification: 'preferred',
  },
})

// Send options to the browser...
```

```typescript
// Browser-side: Create credential
import { startRegistration, browserSupportsWebAuthn } from 'ts-auth'

if (browserSupportsWebAuthn()) {
  const credential = await startRegistration(optionsFromServer)
  // Send credential to server for verification
}
```

### 2. TOTP Two-Factor Authentication

Add an extra layer of security with time-based one-time passwords.

```typescript
import {
  generateTOTPSecret,
  generateTOTP,
  verifyTOTP,
  totpKeyUri,
} from 'ts-auth'

// Generate a secret for the user
const secret = generateTOTPSecret()

// Generate the otpauth:// URI for QR codes
const uri = totpKeyUri('user@example.com', 'MyApp', secret)

// Verify a code submitted by the user
const isValid = verifyTOTP(userSubmittedCode, {
  secret,
  window: 1, // Allow 1 step before/after for clock drift
})
```

### 3. Session Management

Manage user sessions with built-in session handling.

```typescript
import { createSession, sessionMiddleware } from 'ts-auth'

// Create a session
const session = createSession({
  driver: 'memory',
  lifetime: 120, // minutes
  cookie: 'app_session',
  secure: true,
  httpOnly: true,
})

// Start the session
await session.start()

// Store user data
session.put('user_id', 123)
session.put('role', 'admin')

// Retrieve data
const userId = session.get('user_id')

// Save the session
await session.save()
```

### 4. JWT Authentication

Generate and verify JSON Web Tokens for API authentication.

```typescript
import { signJwt, verifyJwt, createTokenPair } from 'ts-auth'

// Sign a JWT token
const token = await signJwt(
  { sub: 'user-123', role: 'admin' },
  'your-secret-key',
  {
    algorithm: 'HS256',
    expiresIn: '7d',
    issuer: 'my-app',
  }
)

// Verify and decode a token
const payload = await verifyJwt(token, 'your-secret-key', {
  algorithms: ['HS256'],
  issuer: 'my-app',
})

// Create access + refresh token pair
const tokens = await createTokenPair('user-123', 'your-secret-key', {
  expiry: '15m',
  refresh: true,
  refreshExpiry: '7d',
})
```

## Complete Authentication Flow

Here is a complete example showing how to implement a full authentication system:

```typescript
// auth-service.ts
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  signJwt,
  verifyJwt,
  generateTOTPSecret,
  verifyTOTP,
  createSession,
} from 'ts-auth'

export class AuthService {
  private userCredentials = new Map()
  private challenges = new Map()
  private totpSecrets = new Map()

  // WebAuthn Registration
  async startRegistration(userId: string, userName: string) {
    const options = generateRegistrationOptions({
      rpName: 'My Application',
      rpID: 'example.com',
      userID: userId,
      userName: userName,
    })

    this.challenges.set(userId, options.challenge)
    return options
  }

  async finishRegistration(userId: string, credential: any) {
    const challenge = this.challenges.get(userId)

    const verification = await verifyRegistrationResponse(
      credential,
      challenge,
      'https://example.com',
      'example.com'
    )

    if (verification.verified && verification.registrationInfo) {
      this.userCredentials.set(userId, verification.registrationInfo.credential)
      return { success: true }
    }

    return { success: false }
  }

  // TOTP Setup
  async setupTOTP(userId: string) {
    const secret = generateTOTPSecret()
    this.totpSecrets.set(userId, secret)

    return {
      secret,
      uri: totpKeyUri(`user-${userId}`, 'MyApp', secret),
    }
  }

  verifyTOTPCode(userId: string, code: string) {
    const secret = this.totpSecrets.get(userId)
    return verifyTOTP(code, { secret, window: 1 })
  }

  // JWT Token Management
  async createToken(userId: string) {
    return signJwt(
      { sub: userId },
      process.env.JWT_SECRET!,
      { expiresIn: '1h' }
    )
  }
}
```

## Next Steps

- Learn more about [WebAuthn/Passkeys](/webauthn/overview)
- Set up [Two-Factor Authentication](/totp/overview)
- Configure [Session Management](/session/overview)
- Implement [JWT Authentication](/jwt/overview)
- Follow [Security Best Practices](/security/best-practices)
