---
title: TOTP Overview
description: Time-based One-Time Password (TOTP) two-factor authentication
---
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
  windowMs: 15 _ 60 _ 1000, // 15 minutes
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

### Good for

- Second factor authentication
- Account recovery verification
- Sensitive operation confirmation
- Applications requiring offline code generation

### Consider alternatives when

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
