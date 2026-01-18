---
title: Session Management Overview
description: Manage user sessions with ts-auth
---

# Session Management

ts-auth provides Laravel-inspired session management with multiple storage drivers.

## Features

- Multiple storage drivers (memory, file, Redis)
- Automatic session ID generation
- Cookie-based session tracking
- CSRF protection
- Session regeneration
- Flash data support

## Quick Start

```typescript
import { createSession, SessionManager } from 'ts-auth'

// Create a session with default settings
const session = createSession({
  driver: 'memory',
  lifetime: 120, // minutes
  cookie: 'app_session',
})

// Start the session
await session.start()

// Store data
session.put('user_id', 123)
session.put('role', 'admin')

// Retrieve data
const userId = session.get('user_id')
const role = session.get('role', 'guest') // With default

// Save the session
await session.save()
```

## Session Drivers

### Memory Driver

Stores sessions in memory. Best for development or single-server deployments.

```typescript
const session = createSession({
  driver: 'memory',
  lifetime: 120,
})
```

**Pros:**
- Very fast
- No external dependencies
- Simple setup

**Cons:**
- Lost on server restart
- Not suitable for multi-server deployments

### File Driver

Stores sessions in the filesystem.

```typescript
const session = createSession({
  driver: 'file',
  lifetime: 120,
  path: '/tmp/sessions', // Session file directory
})
```

**Pros:**
- Persistent across restarts
- No external dependencies

**Cons:**
- Slower than memory
- Not suitable for multi-server without shared filesystem

### Redis Driver

Stores sessions in Redis. Recommended for production.

```typescript
const session = createSession({
  driver: 'redis',
  lifetime: 120,
  connection: {
    host: 'localhost',
    port: 6379,
    password: process.env.REDIS_PASSWORD,
    db: 0,
  },
})
```

**Pros:**
- Fast and persistent
- Works with multiple servers
- Built-in expiration

**Cons:**
- Requires Redis server

## Configuration Options

```typescript
interface SessionConfig {
  // Storage driver
  driver: 'memory' | 'file' | 'redis'

  // Session lifetime in minutes
  lifetime: number

  // Cookie name
  cookie: string

  // Cookie path
  path?: string

  // Cookie domain
  domain?: string

  // HTTPS only
  secure?: boolean

  // Prevent JavaScript access
  httpOnly?: boolean

  // Same-site policy
  sameSite?: 'strict' | 'lax' | 'none'

  // Driver-specific options
  connection?: RedisOptions
}
```

## Session Methods

### Reading Data

```typescript
// Get a value
const value = session.get('key')

// Get with default
const value = session.get('key', 'default')

// Check if key exists
if (session.has('key')) {
  // ...
}

// Get all data
const all = session.all()

// Get only specific keys
const subset = session.only(['user_id', 'role'])

// Get all except specific keys
const filtered = session.except(['password'])
```

### Writing Data

```typescript
// Set a value
session.put('key', 'value')

// Set multiple values
session.put({
  user_id: 123,
  name: 'John',
  role: 'admin',
})

// Push to array
session.push('visited_pages', '/dashboard')

// Increment
session.increment('page_views')
session.increment('page_views', 5) // By 5

// Decrement
session.decrement('credits')
session.decrement('credits', 10) // By 10
```

### Removing Data

```typescript
// Remove a specific key
session.forget('key')

// Remove multiple keys
session.forget(['key1', 'key2'])

// Remove and get value
const value = session.pull('key')

// Clear all data
session.flush()
```

### Flash Data

Flash data is available only for the next request:

```typescript
// Set flash data
session.flash('message', 'Welcome back!')
session.flash('errors', { email: 'Invalid email' })

// Reflash to keep for another request
session.reflash()

// Keep only specific keys
session.keep(['message'])
```

## Session Lifecycle

```typescript
// 1. Start the session
await session.start()

// 2. Use the session
session.put('key', 'value')

// 3. Regenerate ID (after login)
await session.regenerate()

// 4. Save changes
await session.save()

// 5. Optionally invalidate
await session.invalidate() // Clear and regenerate
```

## Security Considerations

1. **Regenerate after authentication** - Prevent session fixation attacks
2. **Use secure cookies** - Always enable in production
3. **Set HttpOnly** - Prevent XSS attacks
4. **Configure SameSite** - Prevent CSRF attacks
5. **Set appropriate lifetime** - Balance security and UX

## Next Steps

- [Session Manager](/session/manager)
- [Middleware Integration](/session/middleware)
- [CSRF Protection](/session/csrf)
