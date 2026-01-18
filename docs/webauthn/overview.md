---
title: WebAuthn Overview
description: Implement passwordless authentication with WebAuthn and Passkeys
---

# WebAuthn / Passkeys

WebAuthn (Web Authentication) is a W3C standard for passwordless authentication. It enables users to authenticate using biometrics (Face ID, Touch ID, Windows Hello), security keys, or device PINs.

## What are Passkeys?

Passkeys are a user-friendly name for WebAuthn credentials. They provide:

- **Passwordless Authentication** - No passwords to remember or steal
- **Phishing Resistance** - Credentials are bound to specific domains
- **Biometric Security** - Uses device biometrics for verification
- **Cross-Device Support** - Sync across devices via cloud providers

## How It Works

```
┌─────────────┐     ┌─────────────┐     ┌─────────────────────┐
│   Browser   │────>│   Server    │────>│  Authenticator      │
│             │<────│             │<────│  (Face ID, etc.)    │
└─────────────┘     └─────────────┘     └─────────────────────┘
     1. Request          2. Generate          3. User
        options             challenge            verification
     4. Create           5. Verify
        credential          response
```

### Registration Flow

1. **Server generates options** - Creates challenge and user info
2. **Browser creates credential** - Prompts user for biometric/PIN
3. **Server verifies response** - Validates and stores credential

### Authentication Flow

1. **Server generates options** - Creates challenge and allowed credentials
2. **Browser gets assertion** - User authenticates with biometric/PIN
3. **Server verifies response** - Validates signature and counter

## Basic Example

### Server-side (Bun)

```typescript
import {
  generateRegistrationOptions,
  generateAuthenticationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} from 'ts-auth'

// Registration
const registrationOptions = generateRegistrationOptions({
  rpName: 'My App',
  rpID: 'example.com',
  userID: 'user-123',
  userName: 'john@example.com',
})

// Authentication
const authOptions = generateAuthenticationOptions({
  rpID: 'example.com',
  allowCredentials: [{
    id: storedCredentialId,
    type: 'public-key',
  }],
})
```

### Browser-side

```typescript
import {
  startRegistration,
  startAuthentication,
  browserSupportsWebAuthn,
  platformAuthenticatorIsAvailable,
} from 'ts-auth'

// Check support
if (!browserSupportsWebAuthn()) {
  console.log('WebAuthn not supported')
  return
}

// Check for platform authenticator (Face ID, Touch ID, etc.)
if (await platformAuthenticatorIsAvailable()) {
  console.log('Platform authenticator available')
}

// Register
const credential = await startRegistration(optionsFromServer)

// Authenticate
const assertion = await startAuthentication(optionsFromServer)
```

## Authenticator Types

### Platform Authenticators

Built into the device:

- **Face ID** (iOS/macOS)
- **Touch ID** (iOS/macOS)
- **Windows Hello** (Windows)
- **Android Biometrics** (Android)

```typescript
const options = generateRegistrationOptions({
  // ... other options
  authenticatorSelection: {
    authenticatorAttachment: 'platform',
    userVerification: 'required',
  },
})
```

### Roaming Authenticators

External security keys:

- **YubiKey**
- **Google Titan**
- **Feitian**

```typescript
const options = generateRegistrationOptions({
  // ... other options
  authenticatorSelection: {
    authenticatorAttachment: 'cross-platform',
  },
})
```

## Security Considerations

1. **Always use HTTPS** - WebAuthn only works in secure contexts
2. **Validate origin** - Verify the origin matches your domain
3. **Store credentials securely** - Protect public keys and credential IDs
4. **Track counters** - Detect cloned authenticators
5. **Handle multiple credentials** - Users may register multiple devices

## Browser Support

| Browser | Platform Auth | Roaming Auth | Conditional UI |
|---------|--------------|--------------|----------------|
| Chrome | Yes | Yes | Yes |
| Firefox | Yes | Yes | No |
| Safari | Yes | Yes | Yes |
| Edge | Yes | Yes | Yes |

## Next Steps

- [Server-side Registration](/webauthn/registration)
- [Server-side Authentication](/webauthn/authentication)
- [Browser Integration](/webauthn/browser)
- [Credential Management](/webauthn/credentials)
