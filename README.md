<p align="center"><img src=".github/art/cover.jpg" alt="Social Card of this repo"></p>

[![npm version][npm-version-src]][npm-version-href]
[![GitHub Actions][github-actions-src]][github-actions-href]
[![Commitizen friendly](https://img.shields.io/badge/commitizen-friendly-brightgreen.svg)](http://commitizen.github.io/cz-cli/)
<!-- [![npm downloads][npm-downloads-src]][npm-downloads-href] -->
<!-- [![Codecov][codecov-src]][codecov-href] -->

# ts-auth

A native WebAuthn and OTP authentication library built with Bun. Zero external authentication dependencies—everything is implemented using native Web Crypto APIs.

## Features

- **WebAuthn/Passkeys** - Full WebAuthn support for passwordless authentication
  - Server-side registration and authentication verification
  - Browser-side credential creation and assertion
  - Platform authenticator detection
  - Conditional UI (autofill) support
- **TOTP (Two-Factor Authentication)** - Time-based One-Time Password implementation
  - Generate and verify TOTP codes
  - Configurable time steps, digits, and algorithms (SHA-1, SHA-256, SHA-512)
  - Generate otpauth:// URIs for authenticator apps
- **QR Code Generation** - Built-in QR code generation for 2FA setup
  - SVG and Data URL output formats
  - Configurable error correction levels
- **Fully Typed** - Complete TypeScript support with comprehensive type definitions
- **Native Implementation** - No dependency on external auth libraries; uses Bun's native crypto

## Why ts-auth?

| Feature | ts-auth | @simplewebauthn | otplib |
|---------|---------|-----------------|--------|
| WebAuthn Support | Yes | Yes | No |
| TOTP Support | Yes | No | Yes |
| QR Code Generation | Yes | No | No |
| Zero Auth Dependencies | Yes | No | No |
| Native Bun Crypto | Yes | No | No |
| Bundle Size | Minimal | ~50KB | ~25KB |
| Single Package | Yes | 2 packages (server + browser) | Yes |

**Key advantages:**

- **All-in-one solution** - WebAuthn, TOTP, and QR codes in a single package
- **Zero external auth dependencies** - Uses native Web Crypto APIs and Bun's built-in crypto
- **Bun-optimized** - Built specifically for Bun's runtime for optimal performance
- **Simpler API** - Streamlined functions that are easy to understand and use
- **Fully typed** - Complete TypeScript definitions with no `any` types in the public API

## Requirements

- **Bun** >= 1.0.0 (for server-side TOTP and WebAuthn verification)
- **HTTPS** - WebAuthn requires a secure context (HTTPS or localhost)
- **Browser Support** (for WebAuthn):
  - Chrome/Edge 67+
  - Firefox 60+
  - Safari 13+
  - Mobile: iOS 14.5+, Android Chrome 67+

## Installation

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

## Usage

### WebAuthn (Passkeys)

#### Server-side Registration

```ts
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from 'ts-auth'

// Generate registration options
const options = generateRegistrationOptions({
  rpName: 'My App',
  rpID: 'example.com',
  userID: 'user-123',
  userName: 'john@example.com',
  userDisplayName: 'John Doe',
  authenticatorSelection: {
    authenticatorAttachment: 'platform',
    userVerification: 'preferred',
  },
})

// Send `options` to the browser...

// After receiving the response from the browser:
const verification = await verifyRegistrationResponse(
  credential,
  expectedChallenge,
  'https://example.com',
  'example.com',
)

if (verification.verified) {
  // Store verification.registrationInfo.credential in your database
}
```

#### Browser-side Registration

```ts
import {
  startRegistration,
  browserSupportsWebAuthn,
  platformAuthenticatorIsAvailable,
} from 'ts-auth'

// Check for WebAuthn support
if (!browserSupportsWebAuthn()) {
  console.log('WebAuthn is not supported')
}

// Check for platform authenticator (Face ID, Touch ID, Windows Hello)
if (await platformAuthenticatorIsAvailable()) {
  console.log('Platform authenticator available')
}

// Start registration with options from your server
const credential = await startRegistration(optionsFromServer)

// Send credential to your server for verification
```

#### Server-side Authentication

```ts
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from 'ts-auth'

// Generate authentication options
const options = generateAuthenticationOptions({
  rpID: 'example.com',
  allowCredentials: [{
    id: storedCredentialId,
    type: 'public-key',
  }],
})

// After receiving the response from the browser:
const verification = await verifyAuthenticationResponse(
  credential,
  expectedChallenge,
  'https://example.com',
  'example.com',
  storedPublicKey,
  storedCounter,
)

if (verification.verified) {
  // Update the stored counter with verification.authenticationInfo.newCounter
}
```

### TOTP (Two-Factor Authentication)

```ts
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

// Generate a TOTP code (for testing/display)
const code = generateTOTP({ secret })

// Verify a code submitted by the user
const isValid = verifyTOTP(userSubmittedCode, {
  secret,
  window: 1, // Allow 1 step before/after for clock drift
})
```

### QR Code Generation

```ts
import {
  generateQRCodeSVG,
  generateQRCodeDataURL,
  QRErrorCorrection,
  totpKeyUri,
} from 'ts-auth'

// Generate a QR code for TOTP setup
const uri = totpKeyUri('user@example.com', 'MyApp', secret)

// Generate as SVG (browser environment)
const svg = generateQRCodeSVG({
  text: uri,
  width: 256,
  height: 256,
  correctLevel: QRErrorCorrection.H,
})

// Generate as data URL for <img> tags
const dataUrl = await generateQRCodeDataURL({
  text: uri,
  width: 256,
  height: 256,
})
```

### Complete Authentication Flow Example

Here's a complete example showing WebAuthn registration and authentication:

```ts
// === SERVER SIDE ===
import {
  generateRegistrationOptions,
  generateAuthenticationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} from 'ts-auth'

// Store for demo purposes (use a real database in production)
const userCredentials = new Map()
const challenges = new Map()

// 1. Registration: Generate options
function handleRegistrationStart(userId: string, userName: string) {
  const options = generateRegistrationOptions({
    rpName: 'My Application',
    rpID: 'example.com',
    userID: userId,
    userName: userName,
  })

  // Store challenge for verification
  challenges.set(userId, options.challenge)

  return options
}

// 2. Registration: Verify response
async function handleRegistrationFinish(userId: string, credential: any) {
  const expectedChallenge = challenges.get(userId)

  const verification = await verifyRegistrationResponse(
    credential,
    expectedChallenge,
    'https://example.com',
    'example.com',
  )

  if (verification.verified && verification.registrationInfo) {
    // Store credential for future authentication
    userCredentials.set(userId, {
      credentialId: verification.registrationInfo.credential.id,
      publicKey: verification.registrationInfo.credential.publicKey,
      counter: verification.registrationInfo.credential.counter,
    })

    return { success: true }
  }

  return { success: false }
}

// 3. Authentication: Generate options
function handleAuthenticationStart(userId: string) {
  const stored = userCredentials.get(userId)

  const options = generateAuthenticationOptions({
    rpID: 'example.com',
    allowCredentials: stored ? [{
      id: stored.credentialId,
      type: 'public-key',
    }] : [],
  })

  challenges.set(userId, options.challenge)

  return options
}

// 4. Authentication: Verify response
async function handleAuthenticationFinish(userId: string, credential: any) {
  const stored = userCredentials.get(userId)
  const expectedChallenge = challenges.get(userId)

  const verification = await verifyAuthenticationResponse(
    credential,
    expectedChallenge,
    'https://example.com',
    'example.com',
    stored.publicKey,
    stored.counter,
  )

  if (verification.verified) {
    // Update counter
    stored.counter = verification.authenticationInfo!.newCounter
    userCredentials.set(userId, stored)

    return { success: true }
  }

  return { success: false }
}
```

```ts
// === BROWSER SIDE ===
import { startRegistration, startAuthentication } from 'ts-auth'

// Registration
async function register() {
  // Get options from server
  const options = await fetch('/api/register/start').then(r => r.json())

  // Create credential
  const credential = await startRegistration(options)

  // Send to server for verification
  await fetch('/api/register/finish', {
    method: 'POST',
    body: JSON.stringify(credential),
  })
}

// Authentication
async function login() {
  // Get options from server
  const options = await fetch('/api/auth/start').then(r => r.json())

  // Get credential
  const credential = await startAuthentication(options)

  // Send to server for verification
  await fetch('/api/auth/finish', {
    method: 'POST',
    body: JSON.stringify(credential),
  })
}
```

## API Reference

### WebAuthn

| Function | Description |
|----------|-------------|
| `generateRegistrationOptions()` | Generate options for creating a new credential |
| `generateAuthenticationOptions()` | Generate options for authenticating with an existing credential |
| `verifyRegistrationResponse()` | Verify the registration response from the browser |
| `verifyAuthenticationResponse()` | Verify the authentication response from the browser |
| `startRegistration()` | Start the registration process in the browser |
| `startAuthentication()` | Start the authentication process in the browser |
| `browserSupportsWebAuthn()` | Check if the browser supports WebAuthn |
| `platformAuthenticatorIsAvailable()` | Check if a platform authenticator is available |
| `browserSupportsWebAuthnAutofill()` | Check if conditional UI is supported |

### TOTP

| Function | Description |
|----------|-------------|
| `generateTOTPSecret()` | Generate a random base32-encoded secret |
| `generateTOTP()` | Generate a TOTP code |
| `verifyTOTP()` | Verify a TOTP code |
| `totpKeyUri()` | Generate an otpauth:// URI for authenticator apps |

### QR Code

| Function | Description |
|----------|-------------|
| `generateQRCodeSVG()` | Generate a QR code as an SVG string |
| `generateQRCodeDataURL()` | Generate a QR code as a data URL |
| `createQRCode()` | Create a QR code instance attached to a DOM element |

## TypeScript Types

All types are exported and available for use in your TypeScript projects:

```ts
import type {
  // Configuration
  AuthConfig,
  AuthOptions,

  // TOTP
  TOTPOptions,

  // WebAuthn
  RegistrationOptions,
  AuthenticationOptions,
  RegistrationCredential,
  AuthenticationCredential,
  PublicKeyCredentialCreationOptions,
  PublicKeyCredentialRequestOptions,

  // QR Code
  QRCodeOptions,
} from 'ts-auth'
```

### Key Types

| Type | Description |
|------|-------------|
| `TOTPOptions` | Options for TOTP generation/verification (secret, step, digits, algorithm, window) |
| `RegistrationOptions` | Server-side options for WebAuthn registration |
| `AuthenticationOptions` | Server-side options for WebAuthn authentication |
| `QRCodeOptions` | Options for QR code generation (text, dimensions, colors, error correction) |

## Security Considerations

When implementing authentication, keep these security practices in mind:

### WebAuthn

- **Always use HTTPS** - WebAuthn only works in secure contexts
- **Store challenges server-side** - Generate challenges on the server and validate them; never trust client-provided challenges
- **Validate the origin** - Always verify the origin matches your expected domain
- **Track credential counters** - Store and validate the signature counter to detect cloned authenticators
- **Use appropriate user verification** - Set `userVerification: 'required'` for sensitive operations

### TOTP

- **Secure secret storage** - Store TOTP secrets encrypted at rest
- **Use timing-safe comparison** - This library uses timing-safe comparison internally to prevent timing attacks
- **Implement rate limiting** - Protect against brute-force attacks on TOTP codes
- **Consider backup codes** - Provide users with backup codes in case they lose their authenticator
- **Clock synchronization** - The `window` parameter helps account for clock drift (default: 1 step = ±30 seconds)

### General

- **Transport security** - Always use HTTPS/TLS for all authentication-related requests
- **Session management** - Implement secure session handling after successful authentication
- **Audit logging** - Log authentication attempts for security monitoring

## Configuration

You can configure ts-auth by creating an `auth.config.ts` file in your project root:

```ts
import type { AuthOptions } from 'ts-auth'

const config: AuthOptions = {
  verbose: true, // Enable verbose logging
}

export default config
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `verbose` | `boolean` | `false` | Enable verbose logging for debugging |

## Testing

```bash
bun test
```

## Changelog

Please see our [releases](https://github.com/stackjs/ts-auth/releases) page for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING](.github/CONTRIBUTING.md) for details.

## Community

For help, discussion about best practices, or any other conversation that would benefit from being searchable:

[Discussions on GitHub](https://github.com/stacksjs/ts-starter/discussions)

For casual chit-chat with others using this package:

[Join the Stacks Discord Server](https://discord.gg/stacksjs)

## Postcardware

"Software that is free, but hopes for a postcard." We love receiving postcards from around the world showing where Stacks is being used! We showcase them on our website too.

Our address: Stacks.js, 12665 Village Ln #2306, Playa Vista, CA 90094, United States 🌎

## Sponsors

We would like to extend our thanks to the following sponsors for funding Stacks development. If you are interested in becoming a sponsor, please reach out to us.

- [JetBrains](https://www.jetbrains.com/)
- [The Solana Foundation](https://solana.com/)

## License

The MIT License (MIT). Please see [LICENSE](LICENSE.md) for more information.

Made with 💙

<!-- Badges -->
[npm-version-src]: https://img.shields.io/npm/v/ts-auth?style=flat-square
[npm-version-href]: https://npmjs.com/package/ts-auth
[github-actions-src]: https://img.shields.io/github/actions/workflow/status/stacksjs/ts-starter/ci.yml?style=flat-square&branch=main
[github-actions-href]: https://github.com/stacksjs/ts-starter/actions?query=workflow%3Aci

<!-- [codecov-src]: https://img.shields.io/codecov/c/gh/stacksjs/ts-starter/main?style=flat-square
[codecov-href]: https://codecov.io/gh/stacksjs/ts-starter -->
