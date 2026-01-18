import type { SessionHandler } from '../types'

// Re-export specialized handlers
export * from './handlers/database'
export * from './handlers/redis'

/**
 * In-memory session handler for testing and development
 * WARNING: Sessions are lost on server restart. Do not use in production!
 */
export class MemorySessionHandler implements SessionHandler {
  private sessions: Map<string, { data: string, lastAccess: number }> = new Map()

  async open(_savePath: string, _sessionName: string): Promise<boolean> {
    return true
  }

  async close(): Promise<boolean> {
    return true
  }

  async read(sessionId: string): Promise<string> {
    const session = this.sessions.get(sessionId)
    if (session) {
      session.lastAccess = Date.now()
      return session.data
    }
    return ''
  }

  async write(sessionId: string, data: string): Promise<boolean> {
    this.sessions.set(sessionId, {
      data,
      lastAccess: Date.now(),
    })
    return true
  }

  async destroy(sessionId: string): Promise<boolean> {
    this.sessions.delete(sessionId)
    return true
  }

  async gc(maxLifetime: number): Promise<number> {
    const now = Date.now()
    const maxAge = maxLifetime * 1000
    let count = 0

    for (const [id, session] of this.sessions) {
      if (now - session.lastAccess > maxAge) {
        this.sessions.delete(id)
        count++
      }
    }

    return count
  }

  /**
   * Get session count (useful for monitoring)
   */
  getSessionCount(): number {
    return this.sessions.size
  }

  /**
   * Clear all sessions
   */
  clear(): void {
    this.sessions.clear()
  }
}

/**
 * File-based session handler
 */
export class FileSessionHandler implements SessionHandler {
  private savePath: string = ''

  async open(savePath: string, _sessionName: string): Promise<boolean> {
    this.savePath = savePath
    return true
  }

  async close(): Promise<boolean> {
    return true
  }

  async read(sessionId: string): Promise<string> {
    try {
      const path = `${this.savePath}/${sessionId}`
      const file = Bun.file(path)
      if (await file.exists()) {
        return await file.text()
      }
    }
    catch {
      // File doesn't exist or can't be read
    }
    return ''
  }

  async write(sessionId: string, data: string): Promise<boolean> {
    try {
      const path = `${this.savePath}/${sessionId}`
      await Bun.write(path, data)
      return true
    }
    catch {
      return false
    }
  }

  async destroy(sessionId: string): Promise<boolean> {
    try {
      const path = `${this.savePath}/${sessionId}`
      const file = Bun.file(path)
      if (await file.exists()) {
        // Use unlink to delete the file
        const { unlink } = await import('node:fs/promises')
        await unlink(path)
      }
      return true
    }
    catch {
      return false
    }
  }

  async gc(maxLifetime: number): Promise<number> {
    let count = 0
    try {
      const { readdir, stat, unlink } = await import('node:fs/promises')
      const now = Date.now()
      const files = await readdir(this.savePath)

      for (const file of files) {
        const path = `${this.savePath}/${file}`
        const stats = await stat(path)
        const age = now - stats.mtimeMs

        if (age > maxLifetime * 1000) {
          await unlink(path)
          count++
        }
      }
    }
    catch {
      // Directory doesn't exist or can't be read
    }
    return count
  }
}

/**
 * Cookie-based session handler (stores data in encrypted cookie)
 */
export class CookieSessionHandler implements SessionHandler {
  private data: string = ''

  async open(_savePath: string, _sessionName: string): Promise<boolean> {
    return true
  }

  async close(): Promise<boolean> {
    return true
  }

  async read(_sessionId: string): Promise<string> {
    // Cookie data would be passed in from middleware
    return this.data
  }

  async write(_sessionId: string, data: string): Promise<boolean> {
    this.data = data
    return true
  }

  async destroy(_sessionId: string): Promise<boolean> {
    this.data = ''
    return true
  }

  async gc(_maxLifetime: number): Promise<number> {
    // Cookies handle their own expiration
    return 0
  }

  /**
   * Set the cookie data (called from middleware)
   */
  setCookieData(data: string): void {
    this.data = data
  }

  /**
   * Get the cookie data (called from middleware)
   */
  getCookieData(): string {
    return this.data
  }
}
