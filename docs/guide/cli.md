---
title: Auth CLI Usage
description: Command-line interface for ts-auth authentication utilities
---
auth

```

## Available Commands

### Version

Display the current version of ts-auth:

```bash

auth version

# Output: 0.4.0

```

### Help

Display help information:

```bash

auth help
auth --help
auth -h

```

## TOTP Commands

### Generate TOTP Secret

Generate a new TOTP secret for testing:

```bash

auth totp:secret

# Output: JBSWY3DPEHPK3PXP

auth totp:secret --length 32

# Output: JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP

```

### Generate TOTP Code

Generate a TOTP code from a secret:

```bash

auth totp:generate --secret JBSWY3DPEHPK3PXP

# Output: 123456

# With custom options

auth totp:generate --secret JBSWY3DPEHPK3PXP --digits 8 --algorithm SHA-256

# Output: 12345678

```

### Verify TOTP Code

Verify a TOTP code against a secret:

```bash

auth totp:verify --secret JBSWY3DPEHPK3PXP --code 123456

# Output: Valid

auth totp:verify --secret JBSWY3DPEHPK3PXP --code 000000

# Output: Invalid

```

### Generate TOTP URI

Generate an otpauth:// URI for QR codes:

```bash

auth totp:uri --account user@example.com --issuer MyApp --secret JBSWY3DPEHPK3PXP

# Output: otpauth://totp/MyApp:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp

```

## JWT Commands

### Sign JWT Token

Create a signed JWT token:

```bash

auth jwt:sign --payload '{"sub":"user-123","role":"admin"}' --secret your-secret-key

# Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9

# With options

auth jwt:sign \
  --payload '{"sub":"user-123"}' \
  --secret your-secret-key \
  --algorithm HS512 \
  --expires-in 7d \
  --issuer my-app

```

### Verify JWT Token

Verify and decode a JWT token:

```bash

auth jwt:verify --token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... --secret your-secret-key

# Output: { "sub": "user-123", "role": "admin", "iat": 1234567890, "exp": 1234567890 }

```

### Decode JWT Token

Decode a JWT token without verification (for debugging):

```bash

auth jwt:decode --token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Output: { header: {...}, payload: {...} }

```

## Hash Commands

### Hash Password

Hash a password using Argon2:

```bash

auth hash --password "my-secure-password"

# Output: $argon2id$v=19$m=65536,t=3,p=4$

# With custom options

auth hash --password "my-secure-password" --memory 131072 --iterations 4

```

### Verify Password

Verify a password against a hash:

```bash

auth hash:verify --password "my-secure-password" --hash '$argon2id$v=19$m=65536,t=3,p=4$...'

# Output: Match

auth hash:verify --password "wrong-password" --hash '$argon2id$v=19$m=65536,t=3,p=4$...'

# Output: No match

```

## Random Generation Commands

### Generate Random String

Generate a cryptographically secure random string:

```bash

auth random

# Output: a1b2c3d4e5f6g7h8

auth random --length 32

# Output: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6

auth random --length 16 --charset alphanumeric

# Output: A1b2C3d4E5f6G7h8

```

### Generate Random Token

Generate a secure token for API keys, reset tokens, etc.:

```bash

auth token

# Output: 8f14e45f-ceea-367a-a714-80fa5d12e2b4

auth token --format hex --bytes 32

# Output: 8f14e45fceea367aa71480fa5d12e2b4

auth token --format base64 --bytes 32

# Output: jxTkX87qNnqnFID6XRLitA==

```

## Configuration Commands

### Initialize Config

Create a configuration file:

```bash

auth init

# Creates auth.config.ts in current directory

auth init --format json

# Creates auth.config.json

```

Example generated config:

```typescript

// auth.config.ts
import type { AuthOptions } from 'ts-auth'

const config: AuthOptions = {
  verbose: true,

  defaults: {
    guard: 'session',
  },

  guards: {
    session: {
      driver: 'session',
      provider: 'users',
    },
    api: {
      driver: 'jwt',
      provider: 'users',
    },
  },

  providers: {
    users: {
      driver: 'database',
      model: 'User',
    },
  },

  tokens: {
    expiry: '7d',
    refresh: true,
    refreshExpiry: '30d',
    algorithm: 'HS256',
  },

  session: {
    driver: 'memory',
    lifetime: 120,
    cookie: 'app_session',
    secure: true,
    httpOnly: true,
    sameSite: 'lax',
  },
}

export default config

```

### Validate Config

Validate an existing configuration file:

```bash

auth config:validate

# Output: Configuration is valid

auth config:validate --config ./custom-auth.config.ts

```

## Development Commands

### Start Development Server

Start a development server for testing authentication flows:

```bash

auth dev

# Starts server on <http://localhost:3000>

auth dev --port 8080

# Starts server on <http://localhost:8080>

```

The dev server provides:

- WebAuthn registration/authentication endpoints
- TOTP setup and verification
- JWT token generation
- Session management

### Generate Test Data

Generate test users and credentials:

```bash

auth generate:users --count 10

# Generates 10 test users with passwords

auth generate:credentials --user-id user-123

# Generates WebAuthn credentials for a user

```

## Environment Variables

The CLI respects the following environment variables:

```bash

# JWT secret for token operations

AUTH_JWT_SECRET=your-secret-key

# Default issuer for tokens

AUTH_JWT_ISSUER=my-app

# Verbose output

AUTH_VERBOSE=true

# Configuration file path

AUTH_CONFIG_PATH=./auth.config.ts

```

## Command Options Reference

### Global Options

| Option | Description |
|--------|-------------|
| `--help, -h` | Show help for command |
| `--version, -v` | Show version number |
| `--verbose` | Enable verbose output |
| `--config <path>` | Path to config file |

### TOTP Options

| Option | Description | Default |
|--------|-------------|---------|
| `--secret` | TOTP secret (base32) | - |
| `--digits` | Number of digits | 6 |
| `--algorithm` | Hash algorithm | SHA-1 |
| `--period` | Time period (seconds) | 30 |
| `--window` | Verification window | 1 |

### JWT Options

| Option | Description | Default |
|--------|-------------|---------|
| `--secret` | Signing secret | - |
| `--algorithm` | Algorithm (HS256, RS256, etc.) | HS256 |
| `--expires-in` | Expiration time | 1h |
| `--issuer` | Token issuer | - |
| `--audience` | Token audience | - |

## Examples

### Complete 2FA Setup Test

```bash

# Generate a secret

SECRET=$(auth totp:secret)
echo "Secret: $SECRET"

# Generate the URI

URI=$(auth totp:uri --account test@example.com --issuer TestApp --secret $SECRET)
echo "URI: $URI"

# Generate a code

CODE=$(auth totp:generate --secret $SECRET)
echo "Current code: $CODE"

# Verify the code

auth totp:verify --secret $SECRET --code $CODE

```

### JWT Token Workflow

```bash

# Create a token

TOKEN=$(auth jwt:sign --payload '{"sub":"user-123"}' --secret my-secret --expires-in 1h)
echo "Token: $TOKEN"

# Decode without verification

auth jwt:decode --token $TOKEN

# Verify the token

auth jwt:verify --token $TOKEN --secret my-secret

```

### Password Hashing Workflow

```bash

# Hash a password

HASH=$(auth hash --password "my-password")
echo "Hash: $HASH"

# Verify correct password

auth hash:verify --password "my-password" --hash "$HASH"

# Verify wrong password

auth hash:verify --password "wrong-password" --hash "$HASH"

```

## Scripting Integration

The CLI is designed for scripting and automation:

```bash

# !/bin/bash

# Generate tokens for multiple users

for user in user-1 user-2 user-3; do
  TOKEN=$(auth jwt:sign --payload "{\"sub\":\"$user\"}" --secret $JWT_SECRET)
  echo "$user: $TOKEN"
done

```

```bash

# !/bin/bash

# Bulk verify TOTP codes

while IFS=, read -r secret code; do
  result=$(auth totp:verify --secret "$secret" --code "$code")
  echo "$secret: $result"
done < codes.csv

```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Configuration error |
| 4 | Authentication failed |
| 5 | Verification failed |

## Next Steps

- Learn about [WebAuthn/Passkeys](/guide/webauthn)
- Set up [TOTP/2FA](/guide/totp)
- Review the [API Reference](/api/webauthn)
