---
title: Getting Started with ts-auth
description: Learn how to implement authentication in your application using ts-auth
---
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
