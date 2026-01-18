---
title: TOTP Code Verification
description: Verify time-based one-time passwords
---

# Code Verification

Verify TOTP codes submitted by users against their stored secret.

## Basic Verification

```typescript
import { verifyTOTP } from 'ts-auth'

const isValid = await verifyTOTP(userSubmittedCode, {
  secret: userSecret,
})

if (isValid) {
  console.log('Authentication successful')
} else {
  console.log('Invalid code')
}
```

## Verification Options

```typescript
const isValid = await verifyTOTP(code, {
  // Required: The user's secret
  secret: 'JBSWY3DPEHPK3PXP',

  // Time step in seconds (default: 30)
  step: 30,

  // Number of digits (default: 6)
  digits: 6,

  // Algorithm (default: 'SHA-1')
  algorithm: 'SHA-1', // 'SHA-1' | 'SHA-256' | 'SHA-512'

  // Window for drift tolerance (default: 1)
  window: 1,
})
```

## Time Window

The `window` parameter allows for clock drift between the server and the user's device:

```typescript
// window: 0 - Only current time period (strict)
// window: 1 - Current + 1 before + 1 after (default, recommended)
// window: 2 - Current + 2 before + 2 after (more lenient)

// With 30-second steps and window: 1
// Accepts codes from -30 to +30 seconds around the current time
```

### How Window Works

```
Time:     |-----|-----|-----|-----|-----|
          T-2   T-1   T     T+1   T+2

window=0:              [T]
window=1:        [T-1, T, T+1]
window=2: [T-2, T-1, T, T+1, T+2]
```

## Timing-Safe Comparison

ts-auth uses timing-safe comparison internally to prevent timing attacks:

```typescript
// The verification function compares codes safely
// regardless of where they differ
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false

  let result = 0
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }

  return result === 0
}
```

## Complete Verification Flow

```typescript
import { verifyTOTP, hash, verifyHash } from 'ts-auth'

interface VerificationResult {
  success: boolean
  method?: 'totp' | 'backup'
  error?: string
}

async function verify2FA(
  userId: string,
  code: string
): Promise<VerificationResult> {
  const user = await db.user.findUnique({ where: { id: userId } })

  if (!user || !user.totpEnabled) {
    return { success: false, error: '2FA not enabled' }
  }

  // Check rate limiting
  const attempts = await getAttempts(userId)
  if (attempts >= 5) {
    return { success: false, error: 'Too many attempts' }
  }

  // Try TOTP verification first
  const secret = await decryptSecret(user.totpSecret)
  const totpValid = await verifyTOTP(code, { secret, window: 1 })

  if (totpValid) {
    await resetAttempts(userId)
    await logVerification(userId, 'totp', true)
    return { success: true, method: 'totp' }
  }

  // Try backup codes
  for (let i = 0; i < user.backupCodes.length; i++) {
    if (await verifyHash(code, user.backupCodes[i])) {
      // Remove used backup code
      const codes = [...user.backupCodes]
      codes.splice(i, 1)
      await db.user.update({
        where: { id: userId },
        data: { backupCodes: codes },
      })

      await resetAttempts(userId)
      await logVerification(userId, 'backup', true)

      // Warn if running low on backup codes
      if (codes.length <= 3) {
        await notifyLowBackupCodes(userId)
      }

      return { success: true, method: 'backup' }
    }
  }

  // Verification failed
  await incrementAttempts(userId)
  await logVerification(userId, 'failed', false)

  return { success: false, error: 'Invalid code' }
}
```

## Rate Limiting

Implement rate limiting to prevent brute-force attacks:

```typescript
import { createAuthRateLimiter } from 'ts-auth'

const totpLimiter = createAuthRateLimiter({
  maxAttempts: 5,
  windowMs: 15 * 60 * 1000, // 15 minutes
  lockoutMs: 30 * 60 * 1000, // 30 minute lockout
})

async function verifyWithRateLimit(userId: string, code: string) {
  // Check if locked out
  if (await totpLimiter.isLocked(userId)) {
    const remaining = await totpLimiter.getRemainingLockout(userId)
    throw new Error(`Account locked. Try again in ${remaining} seconds`)
  }

  const result = await verify2FA(userId, code)

  if (!result.success) {
    await totpLimiter.recordFailure(userId)

    const remaining = await totpLimiter.getRemainingAttempts(userId)
    if (remaining > 0) {
      throw new Error(`Invalid code. ${remaining} attempts remaining`)
    } else {
      throw new Error('Account locked due to too many failed attempts')
    }
  }

  // Reset on success
  await totpLimiter.reset(userId)
  return result
}
```

## Code Reuse Prevention

Prevent the same code from being used twice:

```typescript
const usedCodes = new Map<string, Set<string>>()

async function verifyWithReusePrevention(
  userId: string,
  code: string,
  secret: string
): Promise<boolean> {
  // Get or create used codes set for this user
  if (!usedCodes.has(userId)) {
    usedCodes.set(userId, new Set())
  }
  const userUsedCodes = usedCodes.get(userId)!

  // Check if code was already used
  if (userUsedCodes.has(code)) {
    return false
  }

  // Verify the code
  const isValid = await verifyTOTP(code, { secret })

  if (isValid) {
    // Mark code as used
    userUsedCodes.add(code)

    // Clean up old codes (keep last 10)
    if (userUsedCodes.size > 10) {
      const oldest = userUsedCodes.values().next().value
      userUsedCodes.delete(oldest)
    }
  }

  return isValid
}
```

## Generating Codes (Testing)

Generate a TOTP code for testing or debugging:

```typescript
import { generateTOTP } from 'ts-auth'

// Generate current code
const code = await generateTOTP({ secret })
console.log('Current code:', code)

// Generate code for specific time (testing)
const futureCode = await generateTOTP({
  secret,
  // Note: This is internal - use for testing only
})
```

## Error Handling

```typescript
async function handleVerification(userId: string, code: string) {
  try {
    // Validate code format first
    if (!/^\d{6}$/.test(code)) {
      return { error: 'Code must be 6 digits' }
    }

    const result = await verifyWithRateLimit(userId, code)
    return { success: true, ...result }
  } catch (error) {
    if (error.message.includes('locked')) {
      return { error: error.message, locked: true }
    }
    if (error.message.includes('attempts remaining')) {
      return { error: error.message, attemptsExceeded: false }
    }
    return { error: 'Verification failed' }
  }
}
```

## Next Steps

- [QR Code Generation](/totp/qr-codes)
- [Security Best Practices](/security/best-practices)
