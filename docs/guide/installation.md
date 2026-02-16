---
title: Installation
description: Install ts-auth in your project
---

# Using pnpm

pnpm add ts-auth

```

## Requirements

### Runtime Requirements

- **Bun** >= 1.0.0 (for server-side TOTP and WebAuthn verification)
- **Node.js** >= 18.0.0 (if using Node.js instead of Bun)

### WebAuthn Requirements

WebAuthn requires a secure context to function:

- **HTTPS** - Production environments must use HTTPS
- **localhost** - Local development works without HTTPS

### Browser Support

For WebAuthn (Passkeys) functionality in the browser:

| Browser | Minimum Version |
|---------|----------------|
| Chrome/Edge | 67+ |
| Firefox | 60+ |
| Safari | 13+ |
| iOS Safari | 14.5+ |
| Android Chrome | 67+ |

## Configuration

You can optionally create an `auth.config.ts` file in your project root:

```typescript

import type { AuthOptions } from 'ts-auth'

const config: AuthOptions = {
  verbose: true, // Enable verbose logging for debugging
}

export default config

```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `verbose` | `boolean` | `false` | Enable verbose logging for debugging |

## TypeScript Configuration

ts-auth is written in TypeScript and includes comprehensive type definitions. No additional `@types` packages are required.

Ensure your `tsconfig.json` includes:

```json

{
  "compilerOptions": {
    "moduleResolution": "bundler",
    "esModuleInterop": true,
    "strict": true
  }
}

```

## Importing

### Named Imports

Import specific functions as needed:

```typescript

import {
  // WebAuthn
  generateRegistrationOptions,
  verifyRegistrationResponse,
  startRegistration,
  browserSupportsWebAuthn,

  // TOTP
  generateTOTPSecret,
  generateTOTP,
  verifyTOTP,
  totpKeyUri,

  // JWT
  signJwt,
  verifyJwt,
  createTokenPair,

  // Session
  createSession,
  SessionManager,

  // OAuth
  createGoogleProvider,
  createGitHubProvider,
} from 'ts-auth'

```

### Type Imports

Import types for TypeScript:

```typescript

import type {
  AuthConfig,
  TOTPOptions,
  RegistrationOptions,
  AuthenticationOptions,
  JWTPayload,
  SessionConfig,
  OAuthProviderConfig,
} from 'ts-auth'

```

## Verifying Installation

Create a simple test file to verify the installation:

```typescript

// test-auth.ts
import { generateTOTPSecret, generateTOTP } from 'ts-auth'

const secret = generateTOTPSecret()
const code = await generateTOTP({ secret })

console.log('Secret:', secret)
console.log('TOTP Code:', code)
console.log('ts-auth is working!')

```

Run with:

```bash

bun run test-auth.ts

```

You should see output similar to:

```

Secret: JBSWY3DPEHPK3PXP
TOTP Code: 123456
ts-auth is working!

```

## Next Steps

Now that ts-auth is installed, continue to the [Getting Started Guide](/guide/getting-started) to implement authentication in your application.
