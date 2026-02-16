---
title: Session Middleware
description: Integrate sessions with your web framework
---
}

Bun.serve({
  port: 3000,

  async fetch(req) {
    // Create session middleware
    const session = await sessionMiddleware(req, sessionConfig)

    // Session is now available
    const userId = session.get('user_id')

    // Your route handling
    const url = new URL(req.url)

    if (url.pathname === '/login' && req.method === 'POST') {
      // Login logic
      session.put('user_id', 123)
      await session.regenerate() // Prevent session fixation
      await session.save()

      return new Response('Logged in', {
        headers: session.getCookieHeader(),
      })
    }

    if (url.pathname === '/dashboard') {
      if (!userId) {
        return new Response('Unauthorized', { status: 401 })
      }
      return new Response(`Welcome, user ${userId}`)
    }

    // Save session at the end
    await session.save()

    return new Response('Hello World', {
      headers: session.getCookieHeader(),
    })
  },
})

```

## Express/Hono-style Middleware

```typescript

import type { Context, Next } from 'hono'
import { createSession } from 'ts-auth'

export function session(config: SessionConfig) {
  return async (c: Context, next: Next) => {
    // Get session ID from cookie
    const sessionId = c.req.cookie(config.cookie)

    // Create session instance
    const sess = createSession({
      ...config,
      id: sessionId,
    })

    await sess.start()

    // Attach to context
    c.set('session', sess)

    // Process request
    await next()

    // Save session
    await sess.save()

    // Set cookie
    c.header('Set-Cookie', sess.getCookieString())
  }
}

// Usage with Hono
import { Hono } from 'hono'

const app = new Hono()

app.use('_', session({
  driver: 'redis',
  lifetime: 120,
  cookie: 'app_session',
}))

app.get('/', (c) => {
  const session = c.get('session')
  session.put('visits', (session.get('visits') || 0) + 1)
  return c.json({ visits: session.get('visits') })
})

```

## Type-Safe Session Data

Define session data types for TypeScript:

```typescript

// Define your session data structure
interface SessionData {
  user_id?: number
  role?: 'admin' | 'user' | 'guest'
  cart?: CartItem[]
  flash_message?: string
}

// Create a typed session wrapper
import { Session, createSession } from 'ts-auth'

class TypedSession {
  constructor(private session: Session) {}

  get userId(): number | undefined {
    return this.session.get('user_id')
  }

  set userId(value: number | undefined) {
    if (value === undefined) {
      this.session.forget('user_id')
    } else {
      this.session.put('user_id', value)
    }
  }

  get role(): SessionData['role'] {
    return this.session.get('role') || 'guest'
  }

  set role(value: SessionData['role']) {
    this.session.put('role', value)
  }

  get cart(): CartItem[] {
    return this.session.get('cart') || []
  }

  addToCart(item: CartItem) {
    const cart = this.cart
    cart.push(item)
    this.session.put('cart', cart)
  }

  async save() {
    await this.session.save()
  }
}

// Usage
const session = new TypedSession(await createSession(config))
session.userId = 123
session.role = 'admin'
await session.save()

```

## Request/Response Helpers

```typescript

// Parse session ID from request
function getSessionIdFromRequest(req: Request, cookieName: string): string | null {
  const cookies = req.headers.get('Cookie')
  if (!cookies) return null

  const match = cookies.match(new RegExp(`${cookieName}=([^;]+)`))
  return match ? match[1] : null
}

// Create Set-Cookie header
function createSetCookieHeader(
  name: string,
  value: string,
  options: CookieOptions
): string {
  const parts = [`${name}=${value}`]

  if (options.maxAge) {
    parts.push(`Max-Age=${options.maxAge}`)
  }
  if (options.path) {
    parts.push(`Path=${options.path}`)
  }
  if (options.domain) {
    parts.push(`Domain=${options.domain}`)
  }
  if (options.secure) {
    parts.push('Secure')
  }
  if (options.httpOnly) {
    parts.push('HttpOnly')
  }
  if (options.sameSite) {
    parts.push(`SameSite=${options.sameSite}`)
  }

  return parts.join('; ')
}

// Complete middleware helper
async function withSession<T>(
  req: Request,
  config: SessionConfig,
  handler: (session: Session) => Promise<T>
): Promise<{ result: T; headers: Headers }> {
  const sessionId = getSessionIdFromRequest(req, config.cookie)
  const session = createSession({ ...config, id: sessionId })

  await session.start()

  const result = await handler(session)

  await session.save()

  const headers = new Headers()
  headers.set('Set-Cookie', createSetCookieHeader(
    config.cookie,
    session.getId(),
    {
      maxAge: config.lifetime _ 60,
      path: config.path || '/',
      secure: config.secure,
      httpOnly: config.httpOnly,
      sameSite: config.sameSite,
    }
  ))

  return { result, headers }
}

// Usage
Bun.serve({
  async fetch(req) {
    const { result, headers } = await withSession(req, sessionConfig, async (session) => {
      session.put('visited', true)
      return { message: 'Hello' }
    })

    return Response.json(result, { headers })
  },
})

```

## Session Validation Middleware

Add authentication checks:

```typescript

function requireAuth(session: Session) {
  if (!session.get('user_id')) {
    throw new UnauthorizedError('Authentication required')
  }
}

function requireRole(session: Session, ...roles: string[]) {
  requireAuth(session)

  const userRole = session.get('role')
  if (!roles.includes(userRole)) {
    throw new ForbiddenError('Insufficient permissions')
  }
}

// Usage
Bun.serve({
  async fetch(req) {
    const session = await sessionMiddleware(req, config)
    const url = new URL(req.url)

    try {
      if (url.pathname.startsWith('/admin')) {
        requireRole(session, 'admin')
      } else if (url.pathname.startsWith('/dashboard')) {
        requireAuth(session)
      }

      // Handle route...

    } catch (error) {
      if (error instanceof UnauthorizedError) {
        return new Response('Unauthorized', { status: 401 })
      }
      if (error instanceof ForbiddenError) {
        return new Response('Forbidden', { status: 403 })
      }
      throw error
    }
  },
})

```

## Flash Messages

Handle one-time flash messages:

```typescript

// Set flash message
session.flash('success', 'Profile updated successfully')
session.flash('errors', { email: 'Email already taken' })

// In next request, get flash data
const success = session.get('_flash.success')
const errors = session.get('_flash.errors')

// Flash data is automatically cleared after being read

// Keep flash data for another request
session.reflash()

// Keep only specific keys
session.keep(['success'])

```

## Next Steps

- [CSRF Protection](/session/csrf)
- [Security Best Practices](/security/best-practices)
