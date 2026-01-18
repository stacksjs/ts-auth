/**
 * Audit Logging System for Authentication Events
 * Tracks all authentication-related activities for security monitoring
 */

/**
 * Authentication event types
 */
export type AuthEventType =
  // Authentication events
  | 'login.attempt'
  | 'login.success'
  | 'login.failure'
  | 'logout'
  | 'logout.all_devices'

  // Registration events
  | 'registration.attempt'
  | 'registration.success'
  | 'registration.failure'

  // Password events
  | 'password.reset_request'
  | 'password.reset_success'
  | 'password.reset_failure'
  | 'password.change'

  // Token events
  | 'token.issued'
  | 'token.refreshed'
  | 'token.revoked'
  | 'token.expired'
  | 'token.invalid'

  // Session events
  | 'session.created'
  | 'session.destroyed'
  | 'session.regenerated'
  | 'session.expired'

  // 2FA events
  | 'twoFactor.enabled'
  | 'twoFactor.disabled'
  | 'twoFactor.challenge'
  | 'twoFactor.success'
  | 'twoFactor.failure'

  // OAuth events
  | 'oauth.redirect'
  | 'oauth.callback'
  | 'oauth.success'
  | 'oauth.failure'
  | 'oauth.link'
  | 'oauth.unlink'

  // WebAuthn events
  | 'webauthn.registration_start'
  | 'webauthn.registration_success'
  | 'webauthn.registration_failure'
  | 'webauthn.authentication_start'
  | 'webauthn.authentication_success'
  | 'webauthn.authentication_failure'
  | 'webauthn.credential_removed'

  // Security events
  | 'security.rate_limited'
  | 'security.account_locked'
  | 'security.account_unlocked'
  | 'security.suspicious_activity'
  | 'security.csrf_failure'

  // Admin events
  | 'admin.user_created'
  | 'admin.user_deleted'
  | 'admin.user_updated'
  | 'admin.permissions_changed'

  // Custom events
  | `custom.${string}`

/**
 * Audit log entry
 */
export interface AuditLogEntry {
  /**
   * Unique identifier for the log entry
   */
  id: string

  /**
   * Event type
   */
  event: AuthEventType

  /**
   * Timestamp of the event
   */
  timestamp: Date

  /**
   * User identifier (if available)
   */
  userId?: string | number

  /**
   * IP address of the request
   */
  ipAddress?: string

  /**
   * User agent string
   */
  userAgent?: string

  /**
   * Additional metadata
   */
  metadata?: Record<string, unknown>

  /**
   * Whether the action was successful
   */
  success: boolean

  /**
   * Error message if the action failed
   */
  error?: string

  /**
   * Request ID for correlation
   */
  requestId?: string

  /**
   * Session ID if applicable
   */
  sessionId?: string

  /**
   * Guard name used for authentication
   */
  guard?: string

  /**
   * Provider name (for OAuth)
   */
  provider?: string
}

/**
 * Audit log storage interface
 */
export interface AuditLogStorage {
  /**
   * Store a log entry
   */
  store(entry: AuditLogEntry): Promise<void>

  /**
   * Query log entries
   */
  query(options: AuditLogQueryOptions): Promise<AuditLogEntry[]>

  /**
   * Get a specific log entry by ID
   */
  get(id: string): Promise<AuditLogEntry | null>

  /**
   * Delete old entries (retention policy)
   */
  deleteOlderThan(date: Date): Promise<number>

  /**
   * Count entries matching criteria
   */
  count(options?: Partial<AuditLogQueryOptions>): Promise<number>

  /**
   * Close the storage connection
   */
  close(): Promise<void>
}

/**
 * Query options for audit logs
 */
export interface AuditLogQueryOptions {
  /**
   * Filter by user ID
   */
  userId?: string | number

  /**
   * Filter by event types
   */
  events?: AuthEventType[]

  /**
   * Filter by date range
   */
  from?: Date
  to?: Date

  /**
   * Filter by success/failure
   */
  success?: boolean

  /**
   * Filter by IP address
   */
  ipAddress?: string

  /**
   * Filter by session ID
   */
  sessionId?: string

  /**
   * Pagination
   */
  limit?: number
  offset?: number

  /**
   * Sort order
   */
  order?: 'asc' | 'desc'
}

/**
 * In-memory audit log storage (for development/testing)
 */
export class MemoryAuditLogStorage implements AuditLogStorage {
  private entries: AuditLogEntry[] = []
  private maxEntries: number

  constructor(options: { maxEntries?: number } = {}) {
    this.maxEntries = options.maxEntries ?? 10000
  }

  async store(entry: AuditLogEntry): Promise<void> {
    this.entries.unshift(entry)

    // Trim to max entries
    if (this.entries.length > this.maxEntries) {
      this.entries = this.entries.slice(0, this.maxEntries)
    }
  }

  async query(options: AuditLogQueryOptions): Promise<AuditLogEntry[]> {
    let results = this.entries.filter((entry) => {
      if (options.userId !== undefined && entry.userId !== options.userId) {
        return false
      }
      if (options.events && !options.events.includes(entry.event)) {
        return false
      }
      if (options.from && entry.timestamp < options.from) {
        return false
      }
      if (options.to && entry.timestamp > options.to) {
        return false
      }
      if (options.success !== undefined && entry.success !== options.success) {
        return false
      }
      if (options.ipAddress && entry.ipAddress !== options.ipAddress) {
        return false
      }
      if (options.sessionId && entry.sessionId !== options.sessionId) {
        return false
      }
      return true
    })

    // Sort
    if (options.order === 'asc') {
      results = results.reverse()
    }

    // Pagination
    const offset = options.offset ?? 0
    const limit = options.limit ?? 100
    return results.slice(offset, offset + limit)
  }

  async get(id: string): Promise<AuditLogEntry | null> {
    return this.entries.find(e => e.id === id) ?? null
  }

  async deleteOlderThan(date: Date): Promise<number> {
    const before = this.entries.length
    this.entries = this.entries.filter(e => e.timestamp >= date)
    return before - this.entries.length
  }

  async count(options?: Partial<AuditLogQueryOptions>): Promise<number> {
    if (!options) {
      return this.entries.length
    }

    return (await this.query({ ...options, limit: Number.MAX_SAFE_INTEGER })).length
  }

  async close(): Promise<void> {
    this.entries = []
  }
}

/**
 * Console audit log storage (for debugging)
 */
export class ConsoleAuditLogStorage implements AuditLogStorage {
  private baseStorage: AuditLogStorage

  constructor(baseStorage?: AuditLogStorage) {
    this.baseStorage = baseStorage ?? new MemoryAuditLogStorage()
  }

  async store(entry: AuditLogEntry): Promise<void> {
    const color = entry.success ? '\x1b[32m' : '\x1b[31m'
    const reset = '\x1b[0m'

    console.log(
      `${color}[AUTH]${reset} ${entry.timestamp.toISOString()} ` +
      `${entry.event} | User: ${entry.userId ?? 'anonymous'} | ` +
      `IP: ${entry.ipAddress ?? 'unknown'} | ` +
      `Success: ${entry.success}` +
      (entry.error ? ` | Error: ${entry.error}` : ''),
    )

    await this.baseStorage.store(entry)
  }

  async query(options: AuditLogQueryOptions): Promise<AuditLogEntry[]> {
    return this.baseStorage.query(options)
  }

  async get(id: string): Promise<AuditLogEntry | null> {
    return this.baseStorage.get(id)
  }

  async deleteOlderThan(date: Date): Promise<number> {
    return this.baseStorage.deleteOlderThan(date)
  }

  async count(options?: Partial<AuditLogQueryOptions>): Promise<number> {
    return this.baseStorage.count(options)
  }

  async close(): Promise<void> {
    return this.baseStorage.close()
  }
}

/**
 * Callback-based audit log storage (for external integrations)
 */
export class CallbackAuditLogStorage implements AuditLogStorage {
  private callback: (entry: AuditLogEntry) => Promise<void>
  private baseStorage: AuditLogStorage

  constructor(
    callback: (entry: AuditLogEntry) => Promise<void>,
    baseStorage?: AuditLogStorage,
  ) {
    this.callback = callback
    this.baseStorage = baseStorage ?? new MemoryAuditLogStorage()
  }

  async store(entry: AuditLogEntry): Promise<void> {
    await this.callback(entry)
    await this.baseStorage.store(entry)
  }

  async query(options: AuditLogQueryOptions): Promise<AuditLogEntry[]> {
    return this.baseStorage.query(options)
  }

  async get(id: string): Promise<AuditLogEntry | null> {
    return this.baseStorage.get(id)
  }

  async deleteOlderThan(date: Date): Promise<number> {
    return this.baseStorage.deleteOlderThan(date)
  }

  async count(options?: Partial<AuditLogQueryOptions>): Promise<number> {
    return this.baseStorage.count(options)
  }

  async close(): Promise<void> {
    return this.baseStorage.close()
  }
}

/**
 * Audit Logger
 * Main class for logging authentication events
 */
export class AuditLogger {
  private storage: AuditLogStorage
  private defaultMetadata: Record<string, unknown>

  constructor(storage?: AuditLogStorage, defaultMetadata?: Record<string, unknown>) {
    this.storage = storage ?? new MemoryAuditLogStorage()
    this.defaultMetadata = defaultMetadata ?? {}
  }

  /**
   * Log an authentication event
   */
  async log(
    event: AuthEventType,
    options: {
      userId?: string | number
      success: boolean
      error?: string
      ipAddress?: string
      userAgent?: string
      sessionId?: string
      requestId?: string
      guard?: string
      provider?: string
      metadata?: Record<string, unknown>
    },
  ): Promise<AuditLogEntry> {
    const entry: AuditLogEntry = {
      id: this.generateId(),
      event,
      timestamp: new Date(),
      userId: options.userId,
      success: options.success,
      error: options.error,
      ipAddress: options.ipAddress,
      userAgent: options.userAgent,
      sessionId: options.sessionId,
      requestId: options.requestId,
      guard: options.guard,
      provider: options.provider,
      metadata: { ...this.defaultMetadata, ...options.metadata },
    }

    await this.storage.store(entry)
    return entry
  }

  /**
   * Log from a Request object
   */
  async logFromRequest(
    event: AuthEventType,
    request: Request,
    options: {
      userId?: string | number
      success: boolean
      error?: string
      sessionId?: string
      guard?: string
      provider?: string
      metadata?: Record<string, unknown>
    },
  ): Promise<AuditLogEntry> {
    return this.log(event, {
      ...options,
      ipAddress: this.extractIpAddress(request),
      userAgent: request.headers.get('user-agent') ?? undefined,
      requestId: request.headers.get('x-request-id') ?? undefined,
    })
  }

  // Convenience methods for common events

  async logLoginAttempt(userId: string | number, request?: Request): Promise<AuditLogEntry> {
    if (request) {
      return this.logFromRequest('login.attempt', request, { userId, success: true })
    }
    return this.log('login.attempt', { userId, success: true })
  }

  async logLoginSuccess(userId: string | number, request?: Request, guard?: string): Promise<AuditLogEntry> {
    if (request) {
      return this.logFromRequest('login.success', request, { userId, success: true, guard })
    }
    return this.log('login.success', { userId, success: true, guard })
  }

  async logLoginFailure(userId: string | number | undefined, error: string, request?: Request): Promise<AuditLogEntry> {
    if (request) {
      return this.logFromRequest('login.failure', request, { userId, success: false, error })
    }
    return this.log('login.failure', { userId, success: false, error })
  }

  async logLogout(userId: string | number, request?: Request): Promise<AuditLogEntry> {
    if (request) {
      return this.logFromRequest('logout', request, { userId, success: true })
    }
    return this.log('logout', { userId, success: true })
  }

  async logTokenIssued(userId: string | number, tokenType?: string): Promise<AuditLogEntry> {
    return this.log('token.issued', {
      userId,
      success: true,
      metadata: { tokenType },
    })
  }

  async logTokenRevoked(userId: string | number, tokenId?: string): Promise<AuditLogEntry> {
    return this.log('token.revoked', {
      userId,
      success: true,
      metadata: { tokenId },
    })
  }

  async logRateLimited(identifier: string, endpoint: string, request?: Request): Promise<AuditLogEntry> {
    if (request) {
      return this.logFromRequest('security.rate_limited', request, {
        success: false,
        metadata: { identifier, endpoint },
      })
    }
    return this.log('security.rate_limited', {
      success: false,
      metadata: { identifier, endpoint },
    })
  }

  async logAccountLocked(userId: string | number, request?: Request): Promise<AuditLogEntry> {
    if (request) {
      return this.logFromRequest('security.account_locked', request, { userId, success: false })
    }
    return this.log('security.account_locked', { userId, success: false })
  }

  async logTwoFactorSuccess(userId: string | number, method: string, request?: Request): Promise<AuditLogEntry> {
    if (request) {
      return this.logFromRequest('twoFactor.success', request, {
        userId,
        success: true,
        metadata: { method },
      })
    }
    return this.log('twoFactor.success', { userId, success: true, metadata: { method } })
  }

  async logTwoFactorFailure(userId: string | number, method: string, request?: Request): Promise<AuditLogEntry> {
    if (request) {
      return this.logFromRequest('twoFactor.failure', request, {
        userId,
        success: false,
        metadata: { method },
      })
    }
    return this.log('twoFactor.failure', { userId, success: false, metadata: { method } })
  }

  async logOAuthSuccess(userId: string | number, provider: string, request?: Request): Promise<AuditLogEntry> {
    if (request) {
      return this.logFromRequest('oauth.success', request, { userId, success: true, provider })
    }
    return this.log('oauth.success', { userId, success: true, provider })
  }

  async logOAuthFailure(provider: string, error: string, request?: Request): Promise<AuditLogEntry> {
    if (request) {
      return this.logFromRequest('oauth.failure', request, { success: false, error, provider })
    }
    return this.log('oauth.failure', { success: false, error, provider })
  }

  async logWebAuthnSuccess(userId: string | number, operation: 'registration' | 'authentication', request?: Request): Promise<AuditLogEntry> {
    const event: AuthEventType = operation === 'registration'
      ? 'webauthn.registration_success'
      : 'webauthn.authentication_success'

    if (request) {
      return this.logFromRequest(event, request, { userId, success: true })
    }
    return this.log(event, { userId, success: true })
  }

  async logWebAuthnFailure(userId: string | number | undefined, operation: 'registration' | 'authentication', error: string, request?: Request): Promise<AuditLogEntry> {
    const event: AuthEventType = operation === 'registration'
      ? 'webauthn.registration_failure'
      : 'webauthn.authentication_failure'

    if (request) {
      return this.logFromRequest(event, request, { userId, success: false, error })
    }
    return this.log(event, { userId, success: false, error })
  }

  /**
   * Query audit logs
   */
  async query(options: AuditLogQueryOptions): Promise<AuditLogEntry[]> {
    return this.storage.query(options)
  }

  /**
   * Get user's recent activity
   */
  async getUserActivity(userId: string | number, limit: number = 50): Promise<AuditLogEntry[]> {
    return this.storage.query({ userId, limit, order: 'desc' })
  }

  /**
   * Get failed login attempts for a user
   */
  async getFailedLogins(userId: string | number, since?: Date): Promise<AuditLogEntry[]> {
    return this.storage.query({
      userId,
      events: ['login.failure'],
      from: since,
      order: 'desc',
    })
  }

  /**
   * Get security events
   */
  async getSecurityEvents(since?: Date, limit: number = 100): Promise<AuditLogEntry[]> {
    return this.storage.query({
      events: [
        'security.rate_limited',
        'security.account_locked',
        'security.account_unlocked',
        'security.suspicious_activity',
        'security.csrf_failure',
      ],
      from: since,
      limit,
      order: 'desc',
    })
  }

  /**
   * Delete old entries (for compliance/retention)
   */
  async deleteOlderThan(date: Date): Promise<number> {
    return this.storage.deleteOlderThan(date)
  }

  /**
   * Close the logger
   */
  async close(): Promise<void> {
    return this.storage.close()
  }

  private generateId(): string {
    const bytes = new Uint8Array(16)
    crypto.getRandomValues(bytes)
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
  }

  private extractIpAddress(request: Request): string | undefined {
    // Check various headers for the real IP
    const forwarded = request.headers.get('x-forwarded-for')
    if (forwarded) {
      return forwarded.split(',')[0].trim()
    }

    const realIp = request.headers.get('x-real-ip')
    if (realIp) {
      return realIp
    }

    const cfIp = request.headers.get('cf-connecting-ip')
    if (cfIp) {
      return cfIp
    }

    return undefined
  }
}

/**
 * Create an audit logger instance
 */
export function createAuditLogger(
  storage?: AuditLogStorage,
  defaultMetadata?: Record<string, unknown>,
): AuditLogger {
  return new AuditLogger(storage, defaultMetadata)
}

/**
 * Create an audit logger with console output
 */
export function createConsoleAuditLogger(
  baseStorage?: AuditLogStorage,
  defaultMetadata?: Record<string, unknown>,
): AuditLogger {
  return new AuditLogger(new ConsoleAuditLogStorage(baseStorage), defaultMetadata)
}

/**
 * Create an audit logger with callback
 */
export function createCallbackAuditLogger(
  callback: (entry: AuditLogEntry) => Promise<void>,
  baseStorage?: AuditLogStorage,
  defaultMetadata?: Record<string, unknown>,
): AuditLogger {
  return new AuditLogger(new CallbackAuditLogStorage(callback, baseStorage), defaultMetadata)
}
