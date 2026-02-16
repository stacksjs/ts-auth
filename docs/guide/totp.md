---
title: TOTP/2FA Setup
description: Implement Time-based One-Time Password (TOTP) two-factor authentication with ts-auth
---

```typescript
import { generateTOTPSecret, totpKeyUri } from 'ts-auth'

// Generate a random base32-encoded secret
const secret = generateTOTPSecret()
// Returns something like: "JBSWY3DPEHPK3PXP"

// Generate the otpauth:// URI for QR codes
const uri = totpKeyUri('user@example.com', 'MyApp', secret)
// Returns: "otpauth://totp/MyApp:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp"
```

### Generate a Code

```typescript
import { generateTOTP } from 'ts-auth'

// Generate the current TOTP code
const code = await generateTOTP({
  secret: 'JBSWY3DPEHPK3PXP',
})
// Returns: "123456"

// With custom options
const codeCustom = await generateTOTP({
  secret: 'JBSWY3DPEHPK3PXP',
  step: 30, // Time step in seconds (default: 30)
  digits: 6, // Number of digits (default: 6)
  algorithm: 'SHA-1', // 'SHA-1', 'SHA-256', 'SHA-512' (default: 'SHA-1')
})
```

### Verify a Code

```typescript
import { verifyTOTP } from 'ts-auth'

// Verify a code submitted by the user
const isValid = await verifyTOTP(userSubmittedCode, {
  secret: userSecret,
  window: 1, // Allow 1 step before/after for clock drift
})

if (isValid) {
  console.log('Code is valid!')
} else {
  console.log('Invalid code')
}
```

## Complete 2FA Setup Flow

### Step 1: Enable 2FA for User

```typescript
import { generateTOTPSecret, totpKeyUri } from 'ts-auth'

async function enable2FA(userId: string) {
  // Generate a new secret
  const secret = generateTOTPSecret()

  // Get user email for the URI
  const user = await db.users.findById(userId)

  // Generate the URI for QR code
  const uri = totpKeyUri(user.email, 'MyApp', secret, {
    algorithm: 'SHA-1',
    digits: 6,
    period: 30,
  })

  // Store the secret temporarily (not yet verified)
  await db.pending2FA.create({
    userId,
    secret,
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
  })

  return {
    secret, // Display this as backup
    uri, // Use this to generate QR code
  }
}
```

### Step 2: Generate QR Code

ts-auth includes QR code generation for easy setup:

```typescript
import { generateQRCodeSVG, generateQRCodeDataURL, totpKeyUri } from 'ts-auth'

// Generate as SVG string
const svg = generateQRCodeSVG({
  text: uri,
  width: 256,
  height: 256,
  correctLevel: 'H', // Error correction: L, M, Q, H
})

// Generate as data URL for img tags
const dataUrl = await generateQRCodeDataURL({
  text: uri,
  width: 256,
  height: 256,
})

// Use in HTML
// <img src="${dataUrl}" alt="Scan with authenticator app" />
```

### Step 3: Verify Setup Code

```typescript
import { verifyTOTP } from 'ts-auth'

async function verify2FASetup(userId: string, code: string) {
  // Get the pending 2FA secret
  const pending = await db.pending2FA.findByUserId(userId)

  if (!pending || pending.expiresAt < new Date()) {
    throw new Error('2FA setup expired. Please start again.')
  }

  // Verify the code
  const isValid = await verifyTOTP(code, {
    secret: pending.secret,
    window: 1,
  })

  if (isValid) {
    // Activate 2FA for the user
    await db.users.update(userId, {
      totpSecret: pending.secret,
      totpEnabled: true,
      totpEnabledAt: new Date(),
    })

    // Generate backup codes
    const backupCodes = await generateBackupCodes(userId)

    // Clean up pending record
    await db.pending2FA.delete(userId)

    return {
      success: true,
      backupCodes, // Show these to the user ONCE
    }
  }

  return {
    success: false,
    error: 'Invalid verification code',
  }
}
```

### Step 4: Generate Backup Codes

```typescript
import { generateRandomString } from 'ts-auth'

async function generateBackupCodes(userId: string, count = 10) {
  const codes = []

  for (let i = 0; i < count; i++) {
    // Generate 8-character codes
    const code = generateRandomString(8).toUpperCase()
    codes.push(code)
  }

  // Hash the codes before storing
  const hashedCodes = await Promise.all(
    codes.map(async code => ({
      code: await hash(code),
      used: false,
      createdAt: new Date(),
    }))
  )

  await db.backupCodes.createMany(userId, hashedCodes)

  // Return plain codes to show user (only time they'll see them)
  return codes.map((code, i) =>
    `${code.slice(0, 4)}-${code.slice(4)}`
  )
}
```

## Login with 2FA

### Step 1: Check if 2FA is Enabled

```typescript
async function login(email: string, password: string) {
  // Verify password first
  const user = await db.users.findByEmail(email)
  if (!user || !await verifyHash(password, user.passwordHash)) {
    throw new Error('Invalid credentials')
  }

  // Check if 2FA is enabled
  if (user.totpEnabled) {
    // Create a temporary token for the 2FA step
    const tempToken = await signJwt(
      { sub: user.id, purpose: '2fa-pending' },
      process.env.JWT*SECRET!,
      { expiresIn: '5m' }
    )

    return {
      requires2FA: true,
      tempToken,
    }
  }

  // No 2FA, create session directly
  return createUserSession(user)
}
```

### Step 2: Verify 2FA Code

```typescript
import { verifyTOTP } from 'ts-auth'

async function verify2FA(tempToken: string, code: string) {
  // Verify the temp token
  const payload = await verifyJwt(tempToken, process.env.JWT*SECRET!, {
    issuer: 'my-app',
  })

  if (payload.purpose !== '2fa-pending') {
    throw new Error('Invalid token')
  }

  const user = await db.users.findById(payload.sub)

  // Try TOTP code first
  const isValidTOTP = await verifyTOTP(code, {
    secret: user.totpSecret,
    window: 1,
  })

  if (isValidTOTP) {
    return createUserSession(user)
  }

  // Try backup code
  const backupCode = code.replace('-', '').toUpperCase()
  const usedBackup = await tryBackupCode(user.id, backupCode)

  if (usedBackup) {
    return createUserSession(user)
  }

  throw new Error('Invalid verification code')
}

async function tryBackupCode(userId: string, code: string) {
  const codes = await db.backupCodes.findUnused(userId)

  for (const stored of codes) {
    if (await verifyHash(code, stored.code)) {
      // Mark as used
      await db.backupCodes.markUsed(stored.id)
      return true
    }
  }

  return false
}
```

## Configuration Options

### TOTPOptions

```typescript
interface TOTPOptions {
  /** Secret key (base32 encoded) */
  secret: string

  /** Time step in seconds (default: 30) */
  step?: number

  /** Number of digits (default: 6) */
  digits?: number

  /** HMAC algorithm (default: 'SHA-1') */
  algorithm?: 'SHA-1' | 'SHA-256' | 'SHA-512'

  /** Window for validation (default: 1) */
  window?: number
}
```

### Algorithm Compatibility

Most authenticator apps support all algorithms, but SHA-1 is the most widely supported:

| Algorithm | Google Auth | Microsoft Auth | Authy | 1Password |
|-----------|-------------|----------------|-------|-----------|
| SHA-1     | Yes         | Yes            | Yes   | Yes       |
| SHA-256   | Yes         | Yes            | Yes   | Yes       |
| SHA-512   | Yes         | Yes            | Yes   | Yes       |

## Security Best Practices

### Secret Storage

```typescript
// NEVER store TOTP secrets in plain text
// Use encryption at rest

import { encrypt, decrypt } from './crypto'

async function storeTOTPSecret(userId: string, secret: string) {
  const encryptedSecret = await encrypt(secret, process.env.ENCRYPTION*KEY!)
  await db.users.update(userId, { totpSecret: encryptedSecret })
}

async function getTOTPSecret(userId: string) {
  const user = await db.users.findById(userId)
  return decrypt(user.totpSecret, process.env.ENCRYPTION*KEY!)
}
```

### Rate Limiting

```typescript
import { createAuthRateLimiter } from 'ts-auth'

const rateLimiter = createAuthRateLimiter({
  maxAttempts: 5,
  windowMs: 15 * 60 * 1000, // 15 minutes
})

async function verify2FAWithRateLimit(userId: string, code: string) {
  const key = `2fa:${userId}`

  if (await rateLimiter.isBlocked(key)) {
    throw new Error('Too many attempts. Please try again later.')
  }

  const isValid = await verifyTOTP(code, { secret: userSecret })

  if (!isValid) {
    await rateLimiter.recordFailure(key)
    throw new Error('Invalid code')
  }

  await rateLimiter.reset(key)
  return true
}
```

### Timing-Safe Comparison

ts-auth uses timing-safe comparison internally to prevent timing attacks:

```typescript
// Internally implemented as:
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false
  }

  let result = 0
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }

  return result === 0
}
```

## Error Handling

```typescript
import {
  TOTPError,
  TOTPInvalidCodeError,
  TOTPSecretError,
} from 'ts-auth'

try {
  await verifyTOTP(code, { secret })
} catch (error) {
  if (error instanceof TOTPSecretError) {
    console.error('Invalid secret format')
  } else if (error instanceof TOTPInvalidCodeError) {
    console.error('Invalid code')
  } else if (error instanceof TOTPError) {
    console.error('TOTP error:', error.message)
  }
}
```

## Disabling 2FA

```typescript
async function disable2FA(userId: string, password: string, code: string) {
  const user = await db.users.findById(userId)

  // Require password verification
  if (!await verifyHash(password, user.passwordHash)) {
    throw new Error('Invalid password')
  }

  // Require valid TOTP code
  const isValid = await verifyTOTP(code, {
    secret: user.totpSecret,
    window: 1,
  })

  if (!isValid) {
    throw new Error('Invalid verification code')
  }

  // Disable 2FA
  await db.users.update(userId, {
    totpSecret: null,
    totpEnabled: false,
  })

  // Delete backup codes
  await db.backupCodes.deleteAll(userId)

  // Log the action
  await auditLog.create({
    userId,
    action: '2fa_disabled',
    timestamp: new Date(),
  })

  return { success: true }
}
```

## Next Steps

- Implement [WebAuthn/Passkeys](/guide/webauthn) for passwordless authentication
- Set up [Session Management](/session/overview)
- Review [Security Best Practices](/security/best-practices)
