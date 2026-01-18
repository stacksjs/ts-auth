---
title: ts-auth - Native WebAuthn and OTP Authentication
description: A native WebAuthn and OTP authentication library built with Bun. Zero external authentication dependencies.
---

# ts-auth

A native WebAuthn and OTP authentication library built with Bun. Zero external authentication dependencies - everything is implemented using native Web Crypto APIs.

## Features

- **WebAuthn/Passkeys** - Full WebAuthn support for passwordless authentication
- **TOTP (Two-Factor Authentication)** - Time-based One-Time Password implementation
- **QR Code Generation** - Built-in QR code generation for 2FA setup
- **Session Management** - Laravel-style session handling with multiple drivers
- **JWT Support** - Full JWT signing and verification with multiple algorithms
- **OAuth Integration** - Support for 11+ OAuth providers
- **Fully Typed** - Complete TypeScript support with comprehensive type definitions
- **Native Implementation** - No dependency on external auth libraries; uses Bun's native crypto

## Quick Example

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

## Why ts-auth?

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
