---
title: Generating TOTP Secrets
description: Generate and manage TOTP secrets for two-factor authentication
---

# Generating TOTP Secrets

TOTP secrets are the shared key between your server and the user's authenticator app.

## Generating a Secret

```typescript
import { generateTOTPSecret } from 'ts-auth'

// Generate a 20-byte (160-bit) secret (default)
const secret = generateTOTPSecret()
// Example: "JBSWY3DPEHPK3PXP"

// Generate a longer secret for higher security
const strongSecret = generateTOTPSecret(32) // 32 bytes = 256 bits
```

## Secret Format

Secrets are encoded in Base32 format, which:

- Uses characters A-Z and 2-7
- Is case-insensitive
- Avoids ambiguous characters (0, 1, 8, 9)
- Is URL-safe

```typescript
// Valid base32 characters
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

// The generated secret length depends on the input bytes:
// 20 bytes -> 32 base32 characters
// 32 bytes -> 52 base32 characters
```

## Security Requirements

### Minimum Length

RFC 4226 recommends at least 128 bits (16 bytes) of entropy. The default 160-bit (20-byte) secret exceeds this requirement.

```typescript
// Recommended: Use at least 20 bytes (default)
const secret = generateTOTPSecret(20)

// For high-security applications: 32 bytes
const strongSecret = generateTOTPSecret(32)
```

### Secure Random Generation

ts-auth uses the Web Crypto API for cryptographically secure random generation:

```typescript
// Internally uses:
const bytes = crypto.getRandomValues(new Uint8Array(length))
```

## Storing Secrets

### Encryption at Rest

Always encrypt secrets before storing:

```typescript
import { hash } from 'ts-auth'

// Using AES-256-GCM encryption
async function encryptSecret(secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    Buffer.from(process.env.ENCRYPTION_KEY!, 'hex'),
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  )

  const iv = crypto.getRandomValues(new Uint8Array(12))
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(secret)
  )

  // Return IV + ciphertext as base64
  const combined = new Uint8Array(iv.length + encrypted.byteLength)
  combined.set(iv)
  combined.set(new Uint8Array(encrypted), iv.length)

  return Buffer.from(combined).toString('base64')
}

async function decryptSecret(encrypted: string): Promise<string> {
  const data = Buffer.from(encrypted, 'base64')
  const iv = data.subarray(0, 12)
  const ciphertext = data.subarray(12)

  const key = await crypto.subtle.importKey(
    'raw',
    Buffer.from(process.env.ENCRYPTION_KEY!, 'hex'),
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  )

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  )

  return new TextDecoder().decode(decrypted)
}
```

### Database Storage

```typescript
// Store encrypted secret
const secret = generateTOTPSecret()
const encryptedSecret = await encryptSecret(secret)

await db.user.update({
  where: { id: userId },
  data: {
    totpSecret: encryptedSecret,
    totpEnabled: false, // Don't enable until verified
    totpEnabledAt: null,
  },
})

// Retrieve and decrypt
const user = await db.user.findUnique({ where: { id: userId } })
const secret = await decryptSecret(user.totpSecret)
```

## TOTP Setup Flow

A secure TOTP setup flow:

```typescript
// 1. Generate secret (not stored yet)
async function initiateTOTPSetup(userId: string) {
  const secret = generateTOTPSecret()

  // Store in session or temporary storage
  await session.put(`totp_setup_${userId}`, {
    secret,
    createdAt: Date.now(),
    expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
  })

  return {
    secret,
    uri: totpKeyUri(user.email, 'MyApp', secret),
  }
}

// 2. Verify setup with a code
async function confirmTOTPSetup(userId: string, code: string) {
  const setup = await session.get(`totp_setup_${userId}`)

  if (!setup || setup.expiresAt < Date.now()) {
    throw new Error('Setup expired, please start over')
  }

  // Verify the code
  const isValid = await verifyTOTP(code, { secret: setup.secret })

  if (!isValid) {
    throw new Error('Invalid code')
  }

  // Now store the secret permanently
  const encryptedSecret = await encryptSecret(setup.secret)

  // Generate backup codes
  const backupCodes = generateBackupCodes(10)
  const hashedBackupCodes = await Promise.all(
    backupCodes.map(c => hash(c))
  )

  await db.user.update({
    where: { id: userId },
    data: {
      totpSecret: encryptedSecret,
      totpEnabled: true,
      totpEnabledAt: new Date(),
      backupCodes: hashedBackupCodes,
    },
  })

  // Clean up session
  await session.forget(`totp_setup_${userId}`)

  // Return backup codes (show only once!)
  return { backupCodes }
}
```

## Backup Codes

Generate backup codes for account recovery:

```typescript
import { generateToken, hash, verifyHash } from 'ts-auth'

// Generate 10 backup codes
function generateBackupCodes(count = 10): string[] {
  return Array.from({ length: count }, () => {
    // Generate 8-character alphanumeric code
    return generateToken(8)
  })
}

// Verify a backup code
async function verifyBackupCode(
  userId: string,
  code: string
): Promise<boolean> {
  const user = await db.user.findUnique({ where: { id: userId } })

  for (let i = 0; i < user.backupCodes.length; i++) {
    if (await verifyHash(code, user.backupCodes[i])) {
      // Remove used code
      const updatedCodes = [...user.backupCodes]
      updatedCodes.splice(i, 1)

      await db.user.update({
        where: { id: userId },
        data: { backupCodes: updatedCodes },
      })

      return true
    }
  }

  return false
}
```

## Secret Rotation

Consider allowing users to regenerate their secret:

```typescript
async function rotateTOTPSecret(userId: string, currentCode: string) {
  // Verify current TOTP first
  const user = await db.user.findUnique({ where: { id: userId } })
  const currentSecret = await decryptSecret(user.totpSecret)

  if (!await verifyTOTP(currentCode, { secret: currentSecret })) {
    throw new Error('Invalid current code')
  }

  // Generate new secret
  const newSecret = generateTOTPSecret()

  return {
    secret: newSecret,
    uri: totpKeyUri(user.email, 'MyApp', newSecret),
    // User must verify new secret before it's saved
  }
}
```

## Next Steps

- [Code Verification](/totp/verification)
- [QR Code Generation](/totp/qr-codes)
