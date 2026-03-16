---
title: Installation
description: Install ts-auth in your project
---
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
