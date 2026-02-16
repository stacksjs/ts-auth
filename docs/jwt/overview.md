---
title: JWT Overview
description: JSON Web Tokens for stateless authentication
---
- **Payload**: Claims (user data)
- **Signature**: Verification signature

## Quick Start

```typescript

import { signJwt, verifyJwt } from 'ts-auth'

// Create a token
const token = await signJwt(
  { sub: 'user-123', role: 'admin' },
  'your-secret-key',
  { expiresIn: '7d' }
)

// Verify and decode
const payload = await verifyJwt(token, 'your-secret-key')
console.log(payload.sub) // 'user-123'

```

## Supported Algorithms

ts-auth supports these signing algorithms:

| Algorithm | Type | Key Size | Use Case |
|-----------|------|----------|----------|
| HS256 | HMAC | 256-bit | Shared secret |
| HS384 | HMAC | 384-bit | Shared secret |
| HS512 | HMAC | 512-bit | Shared secret |
| RS256 | RSA | 2048-bit+ | Public/private key |
| RS384 | RSA | 2048-bit+ | Public/private key |
| RS512 | RSA | 2048-bit+ | Public/private key |
| ES256 | ECDSA | P-256 | Public/private key |
| ES384 | ECDSA | P-384 | Public/private key |
| ES512 | ECDSA | P-521 | Public/private key |

### Symmetric (HMAC)

Use the same secret for signing and verification:

```typescript

const secret = 'your-256-bit-secret'
const token = await signJwt(payload, secret, { algorithm: 'HS256' })
const verified = await verifyJwt(token, secret)

```

### Asymmetric (RSA/ECDSA)

Use private key for signing, public key for verification:

```typescript

// Sign with private key
const token = await signJwt(payload, privateKey, { algorithm: 'RS256' })

// Verify with public key
const verified = await verifyJwt(token, publicKey, { algorithms: ['RS256'] })

```

## Standard Claims

JWTs support standard registered claims:

```typescript

const token = await signJwt(
  {
    // Standard claims
    sub: 'user-123',        // Subject (user ID)
    iss: 'my-app',          // Issuer
    aud: 'api.example.com', // Audience
    exp: Date.now() + 3600, // Expiration time
    nbf: Date.now(),        // Not before
    iat: Date.now(),        // Issued at
    jti: 'unique-token-id', // JWT ID

    // Custom claims
    role: 'admin',
    permissions: ['read', 'write'],
  },
  secret
)

```

## Token Expiration

Always set expiration for security:

```typescript

// Using expiresIn option (recommended)
const token = await signJwt(payload, secret, {
  expiresIn: '15m', // 15 minutes
  // expiresIn: '1h', // 1 hour
  // expiresIn: '7d', // 7 days
})

// Using exp claim directly
const token = await signJwt(
  {
    ...payload,
    exp: Math.floor(Date.now() / 1000) + (60 * 15), // 15 minutes
  },
  secret
)

```

## When to Use JWT

**Good for:**

- Stateless API authentication
- Microservices communication
- Single Sign-On (SSO)
- Mobile app authentication
- Short-lived access tokens

**Consider alternatives when:**

- You need immediate token revocation
- Tokens contain sensitive data
- Token size is a concern
- Long-lived sessions are required

## JWT vs Sessions

| Feature | JWT | Sessions |
|---------|-----|----------|
| Storage | Client-side | Server-side |
| Scalability | Stateless, scales easily | Requires shared storage |
| Revocation | Difficult (blacklist needed) | Easy (delete from store) |
| Size | Can be large | Cookie is small |
| Security | Token theft risk | Session fixation risk |
| Mobile | Works well | Cookie handling issues |

## Access and Refresh Tokens

A common pattern uses two tokens:

```typescript

import { createTokenPair } from 'ts-auth'

// Create token pair
const { accessToken, refreshToken } = await createTokenPair(
  'user-123',
  secret,
  {
    expiry: '15m',        // Access token: short-lived
    refresh: true,
    refreshExpiry: '7d',  // Refresh token: long-lived
  }
)

// Use access token for API requests
// Use refresh token to get new access tokens

```

## Security Considerations

1. **Use HTTPS only** - Prevent token interception
2. **Keep tokens short-lived** - Limit exposure window
3. **Use appropriate algorithm** - RS256 for public clients
4. **Validate all claims** - issuer, audience, expiration
5. **Store securely** - HttpOnly cookies or secure storage
6. **Implement refresh tokens** - For longer sessions

## Next Steps

- [Signing Tokens](/jwt/signing)
- [Verifying Tokens](/jwt/verification)
- [Token Pairs](/jwt/token-pairs)
