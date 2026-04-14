---
title: JWT Overview
description: JSON Web Tokens for stateless authentication
---

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

### Good for

- Stateless API authentication
- Microservices communication
- Single Sign-On (SSO)
- Mobile app authentication
- Short-lived access tokens

### Consider alternatives when

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
