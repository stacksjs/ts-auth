---
title: TOTP Overview
description: Time-based One-Time Password (TOTP) two-factor authentication
---

# TOTP / Two-Factor Authentication

TOTP (Time-based One-Time Password) is a widely-used two-factor authentication method that generates temporary codes using a shared secret and the current time.

## How TOTP Works

```
┌─────────────────────┐     ┌─────────────────────┐
│    Authenticator    │     │       Server        │
│    (App/Device)     │     │                     │
│                     │     │                     │
│  Shared Secret ─────┼─────┼── Shared Secret     │
│        +            │     │        +            │
│  Current Time ──────┼─────┼── Current Time      │
│        =            │     │        =            │
│   TOTP Code         │     │   TOTP Code         │
│   (123456)          │     │   (123456)          │
│                     │     │                     │
│   Matches? ─────────┼─────┼─── Yes, verified!   │
└─────────────────────┘     └─────────────────────┘
```

The same code is generated on both sides because:
1. They share the same secret
2. They use the same time (within a window)
3. They use the same algorithm

## Basic Usage

```typescript
import {
  generateTOTPSecret,
  generateTOTP,
  verifyTOTP,
  totpKeyUri,
} from 'ts-auth'

// 1. Generate a secret for the user
const secret = generateTOTPSecret()
// Example: "JBSWY3DPEHPK3PXP"

// 2. Create a URI for authenticator apps
const uri = totpKeyUri('user@example.com', 'MyApp', secret)
// Example: "otpauth://totp/MyApp:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp"

// 3. Generate a code (for testing)
const code = await generateTOTP({ secret })
// Example: "123456"

// 4. Verify a user-submitted code
const isValid = await verifyTOTP(userCode, {
  secret,
  window: 1, // Allow 1 step before/after
})
```

## Supported Authenticator Apps

TOTP codes work with any standard authenticator app:

- **Google Authenticator**
- **Microsoft Authenticator**
- **Authy**
- **1Password**
- **Bitwarden**
- **Apple Passwords** (iOS 15+)

## Configuration Options

```typescript
interface TOTPOptions {
  // The base32-encoded secret
  secret: string

  // Time step in seconds (default: 30)
  step?: number

  // Number of digits in the code (default: 6)
  digits?: number

  // HMAC algorithm (default: 'SHA-1')
  algorithm?: 'SHA-1' | 'SHA-256' | 'SHA-512'

  // Window for verification (default: 1)
  // Allows codes from +-window time steps
  window?: number
}
```

### Default Values

| Option | Default | Description |
|--------|---------|-------------|
| `step` | 30 | Seconds per time period |
| `digits` | 6 | Length of generated code |
| `algorithm` | 'SHA-1' | HMAC algorithm |
| `window` | 1 | Verification tolerance |

## Security Considerations

### Secret Storage

- **Never** store secrets in plain text in production
- Use encryption at rest
- Consider using a hardware security module (HSM)

```typescript
// Example: Encrypt secret before storage
import { encrypt, decrypt } from './encryption'

// Store
const encryptedSecret = encrypt(secret, process.env.ENCRYPTION_KEY)
await db.user.update({
  where: { id: userId },
  data: { totpSecret: encryptedSecret },
})

// Retrieve
const encryptedSecret = user.totpSecret
const secret = decrypt(encryptedSecret, process.env.ENCRYPTION_KEY)
```

### Rate Limiting

Implement rate limiting to prevent brute-force attacks:

```typescript
import { createAuthRateLimiter } from 'ts-auth'

const limiter = createAuthRateLimiter({
  maxAttempts: 5,
  windowMs: 15 * 60 * 1000, // 15 minutes
})

async function verifyTOTPWithRateLimit(userId: string, code: string) {
  if (await limiter.isLimited(userId)) {
    throw new Error('Too many attempts. Try again later.')
  }

  const secret = await getSecretForUser(userId)
  const isValid = await verifyTOTP(code, { secret })

  if (!isValid) {
    await limiter.recordFailure(userId)
  } else {
    await limiter.reset(userId)
  }

  return isValid
}
```

### Backup Codes

Always provide backup codes when setting up TOTP:

```typescript
import { generateToken } from 'ts-auth'

function generateBackupCodes(count = 10): string[] {
  return Array.from({ length: count }, () =>
    generateToken(8) // 8-character random codes
  )
}

// Store hashed backup codes
const codes = generateBackupCodes()
const hashedCodes = await Promise.all(
  codes.map(code => hash(code))
)

// Show codes to user (only once!)
// Store only the hashed versions
```

## When to Use TOTP

**Good for:**
- Second factor authentication
- Account recovery verification
- Sensitive operation confirmation
- Applications requiring offline code generation

**Consider alternatives when:**
- WebAuthn/Passkeys are available (more secure, better UX)
- Push notifications are feasible
- SMS is acceptable (less secure but more convenient)

## Integration with WebAuthn

TOTP and WebAuthn can complement each other:

```typescript
// Check if user has WebAuthn or TOTP enabled
async function requireSecondFactor(userId: string) {
  const hasWebAuthn = await credentialService.hasCredentials(userId)
  const hasTOTP = await hasTOTPEnabled(userId)

  if (hasWebAuthn) {
    // Prefer WebAuthn
    return { method: 'webauthn' }
  } else if (hasTOTP) {
    // Fall back to TOTP
    return { method: 'totp' }
  }

  return { method: 'none' }
}
```

## Next Steps

- [Generating Secrets](/totp/secrets)
- [Code Verification](/totp/verification)
- [QR Code Generation](/totp/qr-codes)
