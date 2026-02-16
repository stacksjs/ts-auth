---
title: CSRF Protection
description: Protect your application from Cross-Site Request Forgery attacks
---

5. Form auto-submits with user's session cookie
6. Your app processes the request as legitimate

```

## CSRF Token Protection

Generate and validate CSRF tokens to prevent these attacks:

```typescript

import { generateCSRFToken, validateCSRFToken } from 'ts-auth'

// Generate token and store in session
async function getCSRFToken(session: Session): Promise<string> {
  let token = session.get('_csrf_token')

  if (!token) {
    token = generateCSRFToken()
    session.put('_csrf_token', token)
    await session.save()
  }

  return token
}

// Validate token from request
async function validateCSRF(req: Request, session: Session): Promise<boolean> {
  const sessionToken = session.get('_csrf_token')
  if (!sessionToken) return false

  // Check header first (for AJAX)
  const headerToken = req.headers.get('X-CSRF-Token')
  if (headerToken) {
    return validateCSRFToken(headerToken, sessionToken)
  }

  // Check form body
  if (req.method === 'POST') {
    const formData = await req.formData()
    const formToken = formData.get('_token')
    if (formToken && typeof formToken === 'string') {
      return validateCSRFToken(formToken, sessionToken)
    }
  }

  return false
}

```

## CSRF Middleware

```typescript

import { generateCSRFToken, validateCSRFToken } from 'ts-auth'

// Methods that require CSRF validation
const UNSAFE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE']

function csrfMiddleware(config?: { exclude?: string[] }) {
  return async (req: Request, session: Session) => {
    // Ensure token exists
    if (!session.get('_csrf_token')) {
      session.put('_csrf_token', generateCSRFToken())
    }

    // Skip safe methods
    if (!UNSAFE_METHODS.includes(req.method)) {
      return null // Continue
    }

    // Skip excluded paths
    const url = new URL(req.url)
    if (config?.exclude?.some(path => url.pathname.startsWith(path))) {
      return null
    }

    // Validate token
    const isValid = await validateCSRF(req, session)

    if (!isValid) {
      return new Response('CSRF token mismatch', { status: 419 })
    }

    return null // Continue
  }
}

// Usage
Bun.serve({
  async fetch(req) {
    const session = await sessionMiddleware(req, sessionConfig)

    // Apply CSRF middleware
    const csrfResult = await csrfMiddleware({
      exclude: ['/api/webhooks'], // Exclude webhook endpoints
    })(req, session)

    if (csrfResult) return csrfResult

    // Continue with request handling...
  },
})

```

## HTML Form Integration

Include the CSRF token in forms:

```typescript

// Server-side: Render form with token
function renderForm(session: Session) {
  const token = session.get('_csrf_token')

  return `
    <form method="POST" action="/transfer">
      <input type="hidden" name="_token" value="${token}">
      <input type="text" name="amount" placeholder="Amount">
      <button type="submit">Transfer</button>
    </form>
  `
}

```

## JavaScript/AJAX Requests

For AJAX requests, include the token in headers:

```typescript

// Get token from meta tag or cookie
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content

// Include in fetch requests
fetch('/api/transfer', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrfToken,
  },
  body: JSON.stringify({ amount: 100 }),
})

// Or set up axios defaults
axios.defaults.headers.common['X-CSRF-Token'] = csrfToken

```

## React Integration

```tsx

// Create CSRF context
import { createContext, useContext } from 'react'

const CSRFContext = createContext<string>('')

export function CSRFProvider({ token, children }) {
  return (
    <CSRFContext.Provider value={token}>
      {children}
    </CSRFContext.Provider>
  )
}

export function useCSRF() {
  return useContext(CSRFContext)
}

// Usage in components
function TransferForm() {
  const csrfToken = useCSRF()

  return (
    <form method="POST" action="/transfer">
      <input type="hidden" name="_token" value={csrfToken} />
      {/_ form fields _/}
    </form>
  )
}

// For API calls
function useSecureFetch() {
  const csrfToken = useCSRF()

  return async (url: string, options: RequestInit = {}) => {
    return fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        'X-CSRF-Token': csrfToken,
      },
    })
  }
}

```

## Token Rotation

Regenerate tokens periodically for additional security:

```typescript

// Regenerate token after sensitive actions
async function regenerateCSRFToken(session: Session): Promise<string> {
  const newToken = generateCSRFToken()
  session.put('_csrf_token', newToken)
  await session.save()
  return newToken
}

// Example: Regenerate after login
async function handleLogin(req: Request, session: Session) {
  // ... authenticate user ...

  // Regenerate both session ID and CSRF token
  await session.regenerate()
  await regenerateCSRFToken(session)

  return new Response('Logged in')
}

```

## Double Submit Cookie Pattern

An alternative approach using cookies:

```typescript

import { generateCSRFToken, validateCSRFToken } from 'ts-auth'

// Generate and set as cookie
function setCSRFCookie(): string {
  const token = generateCSRFToken()

  // Set as a non-HttpOnly cookie so JavaScript can read it
  return `csrf_token=${token}; Path=/; SameSite=Strict`
}

// Validate: cookie value must match header/body value
async function validateDoubleSubmit(req: Request): Promise<boolean> {
  // Get from cookie
  const cookies = req.headers.get('Cookie') || ''
  const cookieMatch = cookies.match(/csrf_token=([^;]+)/)
  const cookieToken = cookieMatch?.[1]

  // Get from header or body
  const headerToken = req.headers.get('X-CSRF-Token')

  if (!cookieToken || !headerToken) return false

  return validateCSRFToken(headerToken, cookieToken)
}

```

## SameSite Cookie Protection

Modern browsers support SameSite cookies which provide CSRF protection:

```typescript

const sessionConfig = {
  // ...
  sameSite: 'strict', // or 'lax'
}

// SameSite=Strict: Cookie only sent for same-site requests
// SameSite=Lax: Cookie sent for same-site + top-level navigations

```

**Note:** SameSite is not supported in all browsers and scenarios. Always use CSRF tokens as the primary defense.

## Best Practices

1. **Always use CSRF tokens** - Don't rely solely on SameSite cookies
2. **Use cryptographically secure tokens** - ts-auth uses Web Crypto API
3. **Validate on all state-changing requests** - POST, PUT, PATCH, DELETE
4. **Include token in both forms and AJAX** - Cover all request types
5. **Regenerate tokens** - After authentication and sensitive operations
6. **Use HTTPS** - Prevent token interception

## Next Steps

- [JWT Authentication](/jwt/overview)
- [Security Best Practices](/security/best-practices)
