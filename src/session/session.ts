import type { Session, SessionConfig, SessionHandler } from '../types'
import { MemorySessionHandler } from './handlers'

/**
 * Session Manager - Laravel-style session management
 */
export class SessionManager implements Session {
  private id: string = ''
  private data: Record<string, unknown> = {}
  private flashData: Record<string, unknown> = {}
  private started = false
  private handler: SessionHandler
  private config: SessionConfig
  private csrfToken: string = ''

  constructor(config: SessionConfig, handler?: SessionHandler) {
    this.config = config
    this.handler = handler ?? this.createHandler(config)
  }

  private createHandler(config: SessionConfig): SessionHandler {
    switch (config.driver) {
      case 'memory':
      case 'array':
        return new MemorySessionHandler()
      case 'file':
        // File handler would be implemented separately
        return new MemorySessionHandler()
      case 'database':
        // Database handler would be implemented separately
        return new MemorySessionHandler()
      case 'redis':
        // Redis handler would be implemented separately
        return new MemorySessionHandler()
      case 'cookie':
        // Cookie handler would be implemented separately
        return new MemorySessionHandler()
      default:
        return new MemorySessionHandler()
    }
  }

  getId(): string {
    return this.id
  }

  setId(id: string): void {
    this.id = id
  }

  async start(): Promise<boolean> {
    if (this.started) {
      return true
    }

    if (!this.id) {
      this.id = this.generateSessionId()
    }

    await this.handler.open(this.config.files ?? '', this.config.cookie)

    const data = await this.handler.read(this.id)
    if (data) {
      try {
        const parsed = JSON.parse(data)
        this.data = parsed.data ?? {}
        this.flashData = parsed.flash ?? {}
        this.csrfToken = parsed.csrfToken ?? this.generateToken()
      }
      catch {
        this.data = {}
        this.flashData = {}
        this.csrfToken = this.generateToken()
      }
    }
    else {
      this.csrfToken = this.generateToken()
    }

    this.started = true
    return true
  }

  async save(): Promise<void> {
    if (!this.started) {
      return
    }

    const serialized = JSON.stringify({
      data: this.data,
      flash: {}, // Flash data is cleared after save
      csrfToken: this.csrfToken,
    })

    await this.handler.write(this.id, serialized)

    // Clear flash data after save
    this.flashData = {}
  }

  all(): Record<string, unknown> {
    return { ...this.data, ...this.flashData }
  }

  has(key: string): boolean {
    return key in this.data || key in this.flashData
  }

  get<T = unknown>(key: string, defaultValue?: T): T | null {
    if (key in this.flashData) {
      return this.flashData[key] as T
    }
    if (key in this.data) {
      return this.data[key] as T
    }
    return defaultValue ?? null
  }

  put(key: string, value: unknown): void {
    this.data[key] = value
  }

  pull<T = unknown>(key: string, defaultValue?: T): T | null {
    const value = this.get<T>(key, defaultValue)
    this.forget(key)
    return value
  }

  forget(key: string): void {
    delete this.data[key]
    delete this.flashData[key]
  }

  flush(): void {
    this.data = {}
    this.flashData = {}
  }

  async regenerate(destroy = false): Promise<boolean> {
    if (destroy) {
      await this.handler.destroy(this.id)
    }

    this.id = this.generateSessionId()
    return true
  }

  async invalidate(): Promise<boolean> {
    await this.handler.destroy(this.id)
    this.flush()
    this.id = this.generateSessionId()
    this.csrfToken = this.generateToken()
    return true
  }

  flash(key: string, value: unknown): void {
    this.flashData[key] = value
  }

  token(): string {
    return this.csrfToken
  }

  regenerateToken(): string {
    this.csrfToken = this.generateToken()
    return this.csrfToken
  }

  private generateSessionId(): string {
    const bytes = new Uint8Array(32)
    crypto.getRandomValues(bytes)
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
  }

  private generateToken(): string {
    const bytes = new Uint8Array(32)
    crypto.getRandomValues(bytes)
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
  }

  /**
   * Get session cookie options
   */
  getCookieOptions(): {
    name: string
    path: string
    domain: string | null
    secure: boolean
    httpOnly: boolean
    sameSite: 'lax' | 'strict' | 'none'
    maxAge: number | undefined
  } {
    return {
      name: this.config.cookie,
      path: this.config.path,
      domain: this.config.domain,
      secure: this.config.secure,
      httpOnly: this.config.httpOnly,
      sameSite: this.config.sameSite,
      maxAge: this.config.expireOnClose ? undefined : this.config.lifetime * 60,
    }
  }
}

/**
 * Create a new session instance with default configuration
 */
export function createSession(config?: Partial<SessionConfig>): SessionManager {
  const defaultConfig: SessionConfig = {
    driver: 'memory',
    lifetime: 120,
    expireOnClose: false,
    encrypt: false,
    cookie: 'session',
    path: '/',
    domain: null,
    secure: true,
    httpOnly: true,
    sameSite: 'lax',
  }

  return new SessionManager({ ...defaultConfig, ...config })
}
