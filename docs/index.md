---
title: ts-auth - Native WebAuthn and OTP Authentication
description: A native WebAuthn and OTP authentication library built with Bun. Zero external authentication dependencies.
---

```typescript
import { generateRegistrationOptions, verifyTOTP, signJwt } from 'ts-auth'

// WebAuthn Registration
const options = generateRegistrationOptions({
  rpName: 'My App',
  rpID: 'example.com',
  userID: 'user-123',
  userName: 'john@example.com',
})

// TOTP Verification
const isValid = verifyTOTP(userCode, { secret: userSecret })

// JWT Token
const token = await signJwt({ sub: 'user-123' }, secret, { expiresIn: '7d' })
```

## Why ts-auth

| Feature | ts-auth | @simplewebauthn | otplib |
|---------|---------|-----------------|--------|
| WebAuthn Support | Yes | Yes | No |
| TOTP Support | Yes | No | Yes |
| QR Code Generation | Yes | No | No |
| Zero Auth Dependencies | Yes | No | No |
| Native Bun Crypto | Yes | No | No |
| Bundle Size | Minimal | ~50KB | ~25KB |
| Single Package | Yes | 2 packages | Yes |

## Requirements

- **Bun** >= 1.0.0
- **HTTPS** - WebAuthn requires a secure context (HTTPS or localhost)
- **Browser Support** (for WebAuthn): Chrome/Edge 67+, Firefox 60+, Safari 13+, iOS 14.5+, Android Chrome 67+

## Getting Started

```bash
bun add ts-auth
```

Continue to the [Getting Started Guide](/guide/getting-started) to learn how to implement authentication in your application.
