---
title: WebAuthn Browser Integration
description: Implement WebAuthn in the browser with ts-auth
---
  return
}

// Platform authenticator (Face ID, Touch ID, Windows Hello)
if (await platformAuthenticatorIsAvailable()) {
  showOption('Sign in with Face ID / Touch ID')
}

// Conditional UI (autofill) support
if (await browserSupportsWebAuthnAutofill()) {
  enablePasskeyAutofill()
}

```

## Registration

Use `startRegistration` to create a new credential:

```typescript

import { startRegistration } from 'ts-auth'

async function registerPasskey() {
  try {
    // Get options from your server
    const response = await fetch('/api/register/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: currentUser.id }),
    })
    const options = await response.json()

    // Create the credential
    const credential = await startRegistration(options)

    // Send to server for verification
    const verifyResponse = await fetch('/api/register/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        userId: currentUser.id,
        credential,
      }),
    })

    const result = await verifyResponse.json()

    if (result.success) {
      showSuccess('Passkey registered successfully!')
    } else {
      showError('Registration failed: ' + result.error)
    }
  } catch (error) {
    if (error.name === 'NotAllowedError') {
      showError('Registration was cancelled')
    } else if (error.name === 'InvalidStateError') {
      showError('This device is already registered')
    } else {
      showError('Registration failed: ' + error.message)
    }
  }
}

```

## Authentication

Use `startAuthentication` to authenticate with an existing credential:

```typescript

import { startAuthentication } from 'ts-auth'

async function authenticateWithPasskey() {
  try {
    // Get options from your server
    const response = await fetch('/api/auth/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    })
    const options = await response.json()

    // Get the assertion
    const credential = await startAuthentication(options)

    // Send to server for verification
    const verifyResponse = await fetch('/api/auth/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ credential }),
    })

    const result = await verifyResponse.json()

    if (result.success) {
      // Redirect to dashboard or update UI
      window.location.href = '/dashboard'
    } else {
      showError('Authentication failed: ' + result.error)
    }
  } catch (error) {
    if (error.name === 'NotAllowedError') {
      showError('Authentication was cancelled')
    } else {
      showError('Authentication failed: ' + error.message)
    }
  }
}

```

## Conditional UI (Autofill)

Enable passkey autofill for a seamless login experience:

```typescript

import {
  startAuthentication,
  browserSupportsWebAuthnAutofill,
} from 'ts-auth'

async function setupPasskeyAutofill() {
  // Check support
  if (!await browserSupportsWebAuthnAutofill()) {
    return
  }

  // Get options with no allowCredentials (discoverable)
  const response = await fetch('/api/auth/start?autofill=true')
  const options = await response.json()

  try {
    // Start conditional authentication
    // This will show passkey option in the autofill dropdown
    const credential = await startAuthentication(options, {
      mediation: 'conditional',
    })

    // Verify with server
    await verifyCredential(credential)
  } catch (error) {
    // User didn't select a passkey - this is expected
    if (error.name !== 'AbortError') {
      console.error('Autofill error:', error)
    }
  }
}

// Call on page load for login pages
if (document.querySelector('input[autocomplete*="webauthn"]')) {
  setupPasskeyAutofill()
}

```

HTML for conditional UI:

```html

<input
  type="text"
  name="username"
  autocomplete="username webauthn"
  placeholder="Email or username"
/>

```

## Error Handling

Handle common WebAuthn errors:

```typescript

async function handleWebAuthnError(error: Error) {
  switch (error.name) {
    case 'NotAllowedError':
      // User cancelled or denied permission
      return 'Authentication was cancelled or denied'

    case 'InvalidStateError':
      // Credential already registered (for registration)
      return 'This authenticator is already registered'

    case 'NotSupportedError':
      // Algorithm not supported
      return 'Your device does not support this authentication method'

    case 'SecurityError':
      // Origin mismatch or insecure context
      return 'Security error - please ensure you are using HTTPS'

    case 'AbortError':
      // Request was aborted
      return 'Request was aborted'

    case 'ConstraintError':
      // Authenticator doesn't meet requirements
      return 'Your authenticator does not meet the requirements'

    default:
      return 'An unexpected error occurred: ' + error.message
  }
}

```

## React Example

```tsx

import { useState } from 'react'
import {
  startRegistration,
  startAuthentication,
  browserSupportsWebAuthn,
} from 'ts-auth'

function PasskeyAuth() {
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const isSupported = browserSupportsWebAuthn()

  async function handleRegister() {
    if (!isSupported) return

    setLoading(true)
    setError(null)

    try {
      const options = await fetch('/api/register/start').then(r => r.json())
      const credential = await startRegistration(options)
      const result = await fetch('/api/register/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential }),
      }).then(r => r.json())

      if (!result.success) {
        setError(result.error)
      }
    } catch (err) {
      setError(handleWebAuthnError(err as Error))
    } finally {
      setLoading(false)
    }
  }

  async function handleLogin() {
    if (!isSupported) return

    setLoading(true)
    setError(null)

    try {
      const options = await fetch('/api/auth/start').then(r => r.json())
      const credential = await startAuthentication(options)
      const result = await fetch('/api/auth/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential }),
      }).then(r => r.json())

      if (result.success) {
        window.location.href = '/dashboard'
      } else {
        setError(result.error)
      }
    } catch (err) {
      setError(handleWebAuthnError(err as Error))
    } finally {
      setLoading(false)
    }
  }

  if (!isSupported) {
    return <p>Your browser does not support passkeys</p>
  }

  return (
    <div>
      {error && <div className="error">{error}</div>}

      <button onClick={handleLogin} disabled={loading}>
        {loading ? 'Authenticating...' : 'Sign in with Passkey'}
      </button>

      <button onClick={handleRegister} disabled={loading}>
        {loading ? 'Registering...' : 'Register Passkey'}
      </button>
    </div>
  )
}

```

## API Reference

### browserSupportsWebAuthn()

Check if the browser supports WebAuthn.

```typescript

function browserSupportsWebAuthn(): boolean

```

### platformAuthenticatorIsAvailable()

Check if a platform authenticator (Face ID, Touch ID, etc.) is available.

```typescript

async function platformAuthenticatorIsAvailable(): Promise<boolean>

```

### browserSupportsWebAuthnAutofill()

Check if the browser supports WebAuthn conditional UI (autofill).

```typescript

async function browserSupportsWebAuthnAutofill(): Promise<boolean>

```

### startRegistration()

Create a new WebAuthn credential.

```typescript

async function startRegistration(
  options: PublicKeyCredentialCreationOptions
): Promise<RegistrationCredential>

```

### startAuthentication()

Authenticate with an existing credential.

```typescript

async function startAuthentication(
  options: PublicKeyCredentialRequestOptions,
  opts?: { mediation?: 'conditional' | 'optional' | 'required' | 'silent' }
): Promise<AuthenticationCredential>

```

## Next Steps

- [Credential Management](/webauthn/credentials)
- [Security Best Practices](/security/best-practices)
