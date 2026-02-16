---
title: Session Manager
description: Use the SessionManager class for advanced session handling
---
    },
    file: {
      driver: 'file',
      lifetime: 120,
      path: '/tmp/sessions',
    },
    redis: {
      driver: 'redis',
      lifetime: 120,
      connection: {
        host: process.env.REDIS_HOST,
        port: 6379,
      },
    },
  },

  cookie: {
    name: 'app_session',
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax',
  },
})

```

## Using Multiple Drivers

```typescript

// Get default driver session
const session = await manager.driver()

// Get specific driver session
const redisSession = await manager.driver('redis')
const memorySession = await manager.driver('memory')

// Use different drivers for different purposes
const userSession = await manager.driver('redis') // Persistent
const flashSession = await manager.driver('memory') // Temporary

```

## Extending with Custom Drivers

```typescript

import { SessionDriver } from 'ts-auth'

// Create a custom driver
class DatabaseDriver implements SessionDriver {
  private db: Database

  constructor(config: any) {
    this.db = new Database(config.connection)
  }

  async read(sessionId: string): Promise<Record<string, any> | null> {
    const row = await this.db.query(
      'SELECT data FROM sessions WHERE id = ?',
      [sessionId]
    )
    return row ? JSON.parse(row.data) : null
  }

  async write(
    sessionId: string,
    data: Record<string, any>,
    lifetime: number
  ): Promise<void> {
    await this.db.query(
      `INSERT INTO sessions (id, data, expires_at)
       VALUES (?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET data = ?, expires_at = ?`,
      [
        sessionId,
        JSON.stringify(data),
        new Date(Date.now() + lifetime _ 60 _ 1000),
        JSON.stringify(data),
        new Date(Date.now() + lifetime _ 60 _ 1000),
      ]
    )
  }

  async destroy(sessionId: string): Promise<void> {
    await this.db.query('DELETE FROM sessions WHERE id = ?', [sessionId])
  }

  async gc(maxLifetime: number): Promise<void> {
    await this.db.query('DELETE FROM sessions WHERE expires_at < NOW()')
  }
}

// Register the custom driver
manager.extend('database', (config) => new DatabaseDriver(config))

// Use it
const session = await manager.driver('database')

```

## Session Store Implementation

```typescript

import { SessionStore } from 'ts-auth'

class CustomStore extends SessionStore {
  private data: Record<string, any> = {}
  private id: string = ''
  private started = false

  constructor(
    private driver: SessionDriver,
    private config: SessionConfig
  ) {
    super()
  }

  async start(): Promise<void> {
    if (this.started) return

    this.id = this.generateSessionId()
    const stored = await this.driver.read(this.id)
    this.data = stored || {}
    this.started = true
  }

  getId(): string {
    return this.id
  }

  get<T>(key: string, defaultValue?: T): T | undefined {
    return this.data[key] ?? defaultValue
  }

  put(key: string | Record<string, any>, value?: any): void {
    if (typeof key === 'object') {
      Object.assign(this.data, key)
    } else {
      this.data[key] = value
    }
  }

  async save(): Promise<void> {
    await this.driver.write(this.id, this.data, this.config.lifetime)
  }

  async regenerate(): Promise<void> {
    await this.driver.destroy(this.id)
    this.id = this.generateSessionId()
    await this.save()
  }

  private generateSessionId(): string {
    return crypto.randomUUID()
  }
}

```

## Garbage Collection

Clean up expired sessions periodically:

```typescript

// Manual garbage collection
await manager.gc()

// Automatic garbage collection (run every hour)
setInterval(() => {
  manager.gc().catch(console.error)
}, 60 _ 60 _ 1000)

// Or use probability-based GC
// 2% chance to run GC on each request
if (Math.random() < 0.02) {
  manager.gc().catch(console.error)
}

```

## Session Events

```typescript

import { SessionManager, SessionEvents } from 'ts-auth'

const manager = new SessionManager(config)

// Listen for session events
manager.on(SessionEvents.STARTED, (session) => {
  console.log('Session started:', session.getId())
})

manager.on(SessionEvents.REGENERATED, (session, oldId, newId) => {
  console.log(`Session regenerated: ${oldId} -> ${newId}`)
})

manager.on(SessionEvents.INVALIDATED, (session) => {
  console.log('Session invalidated:', session.getId())
})

manager.on(SessionEvents.DESTROYED, (sessionId) => {
  console.log('Session destroyed:', sessionId)
})

```

## Session Data Encryption

For sensitive data, enable encryption:

```typescript

const manager = new SessionManager({
  default: 'redis',

  encryption: {
    enabled: true,
    key: process.env.SESSION_ENCRYPTION_KEY!, // 32 bytes for AES-256
    algorithm: 'aes-256-gcm',
  },

  drivers: {
    redis: {
      driver: 'redis',
      lifetime: 120,
    },
  },
})

// Data is automatically encrypted/decrypted
const session = await manager.driver()
session.put('credit_card', '4111111111111111') // Stored encrypted

```

## Session Serialization

Customize how session data is serialized:

```typescript

const manager = new SessionManager({
  serializer: {
    serialize: (data) => JSON.stringify(data),
    deserialize: (data) => JSON.parse(data),
  },
})

// Or use MessagePack for better performance
import { encode, decode } from '@msgpack/msgpack'

const manager = new SessionManager({
  serializer: {
    serialize: (data) => encode(data),
    deserialize: (data) => decode(data),
  },
})

```

## Multiple Session Contexts

Handle multiple sessions (e.g., web and API):

```typescript

const webManager = new SessionManager({
  default: 'redis',
  cookie: { name: 'web_session' },
  // ...
})

const apiManager = new SessionManager({
  default: 'redis',
  cookie: { name: 'api_session' },
  // ...
})

// In your routes
async function webRoute(req: Request) {
  const session = await webManager.driver()
  // ...
}

async function apiRoute(req: Request) {
  const session = await apiManager.driver()
  // ...
}

```

## Next Steps

- [Middleware Integration](/session/middleware)
- [CSRF Protection](/session/csrf)
