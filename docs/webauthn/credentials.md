---
title: WebAuthn Credential Management
description: Store and manage WebAuthn credentials
---
  counter: number

  // Device type: 'singleDevice' or 'multiDevice'
  deviceType: string

  // Whether the credential is backed up (synced to cloud)
  backedUp: boolean

  // Transports the credential supports
  transports?: string[]

  // Metadata
  userId: string
  name?: string  // User-provided name like "MacBook Pro"
  createdAt: Date
  lastUsedAt?: Date
}

```

## Database Schema Example

### PostgreSQL / SQLite

```sql

CREATE TABLE webauthn_credentials (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL UNIQUE,
  public_key BYTEA NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  device_type TEXT NOT NULL,
  backed_up BOOLEAN NOT NULL DEFAULT FALSE,
  transports TEXT[],
  name TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMP
);

CREATE INDEX idx_credentials_user_id ON webauthn_credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON webauthn_credentials(credential_id);

```

### Prisma Schema

```prisma

model WebAuthnCredential {
  id           String   @id @default(uuid())
  userId       String
  user         User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  credentialId String   @unique
  publicKey    Bytes
  counter      Int      @default(0)
  deviceType   String
  backedUp     Boolean  @default(false)
  transports   String[]
  name         String?
  createdAt    DateTime @default(now())
  lastUsedAt   DateTime?

  @@index([userId])
}

```

## Credential Service

```typescript

import { db } from './database'

export class CredentialService {
  // Store a new credential
  async create(
    userId: string,
    credentialData: {
      credentialId: string
      publicKey: ArrayBuffer
      counter: number
      deviceType: string
      backedUp: boolean
      transports?: string[]
    }
  ) {
    return db.webAuthnCredential.create({
      data: {
        userId,
        credentialId: credentialData.credentialId,
        publicKey: Buffer.from(credentialData.publicKey),
        counter: credentialData.counter,
        deviceType: credentialData.deviceType,
        backedUp: credentialData.backedUp,
        transports: credentialData.transports || [],
      },
    })
  }

  // Get all credentials for a user
  async getByUserId(userId: string) {
    return db.webAuthnCredential.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    })
  }

  // Get a specific credential
  async getByCredentialId(credentialId: string) {
    return db.webAuthnCredential.findUnique({
      where: { credentialId },
    })
  }

  // Update counter after authentication
  async updateCounter(credentialId: string, newCounter: number) {
    return db.webAuthnCredential.update({
      where: { credentialId },
      data: {
        counter: newCounter,
        lastUsedAt: new Date(),
      },
    })
  }

  // Rename a credential
  async rename(credentialId: string, name: string) {
    return db.webAuthnCredential.update({
      where: { credentialId },
      data: { name },
    })
  }

  // Delete a credential
  async delete(credentialId: string, userId: string) {
    // Ensure user owns the credential
    const credential = await this.getByCredentialId(credentialId)
    if (!credential || credential.userId !== userId) {
      throw new Error('Credential not found')
    }

    return db.webAuthnCredential.delete({
      where: { credentialId },
    })
  }

  // Check if user has any credentials
  async hasCredentials(userId: string) {
    const count = await db.webAuthnCredential.count({
      where: { userId },
    })
    return count > 0
  }
}

```

## Converting Public Key

The public key is stored as an ArrayBuffer. Here is how to handle conversion:

```typescript

// ArrayBuffer to Base64 for storage
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString('base64')
}

// Base64 to ArrayBuffer for verification
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const buffer = Buffer.from(base64, 'base64')
  return buffer.buffer.slice(
    buffer.byteOffset,
    buffer.byteOffset + buffer.byteLength
  )
}

// Store credential
const publicKeyBase64 = arrayBufferToBase64(
  registrationInfo.credential.publicKey
)

// Retrieve for verification
const publicKeyBuffer = base64ToArrayBuffer(storedCredential.publicKey)

```

## Managing Multiple Credentials

Users may register multiple credentials (different devices):

```typescript

// Registration: exclude existing credentials
const existingCredentials = await credentialService.getByUserId(userId)

const options = generateRegistrationOptions({
  // ... other options
  excludeCredentials: existingCredentials.map(c => ({
    id: base64ToArrayBuffer(c.credentialId),
    type: 'public-key',
  })),
})

// Authentication: allow all user's credentials
const options = generateAuthenticationOptions({
  rpID: 'example.com',
  allowCredentials: existingCredentials.map(c => ({
    id: base64ToArrayBuffer(c.credentialId),
    type: 'public-key',
    transports: c.transports,
  })),
})

```

## User Interface for Credential Management

```typescript

// API endpoint to list credentials
app.get('/api/credentials', async (req, res) => {
  const credentials = await credentialService.getByUserId(req.user.id)

  res.json(credentials.map(c => ({
    id: c.id,
    credentialId: c.credentialId,
    name: c.name || getDefaultName(c),
    deviceType: c.deviceType,
    backedUp: c.backedUp,
    createdAt: c.createdAt,
    lastUsedAt: c.lastUsedAt,
  })))
})

// API endpoint to rename
app.patch('/api/credentials/:id', async (req, res) => {
  const { name } = req.body
  await credentialService.rename(req.params.id, name)
  res.json({ success: true })
})

// API endpoint to delete
app.delete('/api/credentials/:id', async (req, res) => {
  await credentialService.delete(req.params.id, req.user.id)
  res.json({ success: true })
})

// Generate a default name based on device type
function getDefaultName(credential: StoredCredential): string {
  if (credential.backedUp) {
    return 'iCloud Keychain / Google Password Manager'
  }
  return credential.deviceType === 'singleDevice'
    ? 'Security Key'
    : 'Passkey'
}

```

## Security Considerations

### Counter Validation

Always check the counter to detect cloned authenticators:

```typescript

if (newCounter <= storedCounter && newCounter !== 0) {
  // Potential cloned authenticator!
  await logSecurityEvent('counter_regression', {
    credentialId,
    storedCounter,
    newCounter,
  })

  // Options:
  // 1. Deny authentication
  // 2. Require additional verification
  // 3. Revoke all credentials and force re-registration
}

```

### Credential Backup Status

Track whether credentials are synced to cloud providers:

```typescript

// Synced credentials (backedUp: true)
// - Available across devices
// - May be more convenient for users
// - Subject to cloud provider security

// Single-device credentials (backedUp: false)
// - More secure (physically bound to device)
// - Lost if device is lost
// - Better for high-security scenarios

// You might require non-backed-up credentials for sensitive operations
if (operation === 'withdraw_funds' && credential.backedUp) {
  requireSecurityKeyVerification()
}

```

### Revocation

Implement credential revocation for security events:

```typescript

// Revoke a specific credential
async function revokeCredential(credentialId: string, reason: string) {
  await credentialService.delete(credentialId)
  await logSecurityEvent('credential_revoked', { credentialId, reason })
}

// Revoke all credentials for a user (account compromise)
async function revokeAllCredentials(userId: string, reason: string) {
  const credentials = await credentialService.getByUserId(userId)
  await Promise.all(
    credentials.map(c => credentialService.delete(c.credentialId, userId))
  )
  await logSecurityEvent('all_credentials_revoked', { userId, reason })
}

```

## Next Steps

- [Security Best Practices](/security/best-practices)
- [TOTP Two-Factor Authentication](/totp/overview)
