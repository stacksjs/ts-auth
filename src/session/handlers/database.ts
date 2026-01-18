import type { SessionHandler } from '../../types'
import { SessionStorageError } from '../../errors'

/**
 * Database adapter interface for session storage
 * Implement this interface to support different database drivers
 */
export interface DatabaseAdapter {
  /**
   * Get a session by ID
   */
  get(sessionId: string): Promise<{ data: string, lastActivity: number } | null>

  /**
   * Set a session
   */
  set(sessionId: string, data: string, lastActivity: number): Promise<void>

  /**
   * Delete a session
   */
  delete(sessionId: string): Promise<boolean>

  /**
   * Delete expired sessions
   */
  deleteExpired(maxLifetime: number): Promise<number>

  /**
   * Close the database connection
   */
  close(): Promise<void>
}

/**
 * Database session handler
 * Works with any database by implementing the DatabaseAdapter interface
 */
export class DatabaseSessionHandler implements SessionHandler {
  private adapter: DatabaseAdapter
  private tableName: string

  constructor(adapter: DatabaseAdapter, tableName: string = 'sessions') {
    this.adapter = adapter
    this.tableName = tableName
  }

  async open(_savePath: string, _sessionName: string): Promise<boolean> {
    return true
  }

  async close(): Promise<boolean> {
    try {
      await this.adapter.close()
      return true
    }
    catch {
      return false
    }
  }

  async read(sessionId: string): Promise<string> {
    try {
      const result = await this.adapter.get(sessionId)
      return result?.data ?? ''
    }
    catch (error) {
      throw new SessionStorageError(`Failed to read session: ${error}`)
    }
  }

  async write(sessionId: string, data: string): Promise<boolean> {
    try {
      await this.adapter.set(sessionId, data, Date.now())
      return true
    }
    catch (error) {
      throw new SessionStorageError(`Failed to write session: ${error}`)
    }
  }

  async destroy(sessionId: string): Promise<boolean> {
    try {
      return await this.adapter.delete(sessionId)
    }
    catch (error) {
      throw new SessionStorageError(`Failed to destroy session: ${error}`)
    }
  }

  async gc(maxLifetime: number): Promise<number> {
    try {
      return await this.adapter.deleteExpired(maxLifetime)
    }
    catch (error) {
      throw new SessionStorageError(`Failed to garbage collect sessions: ${error}`)
    }
  }
}

/**
 * SQLite adapter for session storage (works with Bun's built-in SQLite)
 */
export class SQLiteSessionAdapter implements DatabaseAdapter {
  private db: { query: (sql: string) => { all: () => unknown[], run: (...args: unknown[]) => { changes: number }, get: (...args: unknown[]) => unknown } }
  private tableName: string

  constructor(
    database: { query: (sql: string) => { all: () => unknown[], run: (...args: unknown[]) => { changes: number }, get: (...args: unknown[]) => unknown } },
    tableName: string = 'sessions',
  ) {
    this.db = database
    this.tableName = tableName
    this.createTable()
  }

  private createTable(): void {
    this.db.query(`
      CREATE TABLE IF NOT EXISTS ${this.tableName} (
        id TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        last_activity INTEGER NOT NULL
      )
    `).run()

    // Create index for garbage collection
    this.db.query(`
      CREATE INDEX IF NOT EXISTS idx_${this.tableName}_last_activity
      ON ${this.tableName} (last_activity)
    `).run()
  }

  async get(sessionId: string): Promise<{ data: string, lastActivity: number } | null> {
    const result = this.db.query(`
      SELECT data, last_activity FROM ${this.tableName} WHERE id = ?
    `).get(sessionId) as { data: string, last_activity: number } | undefined

    if (!result) {
      return null
    }

    return {
      data: result.data,
      lastActivity: result.last_activity,
    }
  }

  async set(sessionId: string, data: string, lastActivity: number): Promise<void> {
    this.db.query(`
      INSERT INTO ${this.tableName} (id, data, last_activity)
      VALUES (?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET data = ?, last_activity = ?
    `).run(sessionId, data, lastActivity, data, lastActivity)
  }

  async delete(sessionId: string): Promise<boolean> {
    const result = this.db.query(`
      DELETE FROM ${this.tableName} WHERE id = ?
    `).run(sessionId)
    return result.changes > 0
  }

  async deleteExpired(maxLifetime: number): Promise<number> {
    const cutoff = Date.now() - (maxLifetime * 1000)
    const result = this.db.query(`
      DELETE FROM ${this.tableName} WHERE last_activity < ?
    `).run(cutoff)
    return result.changes
  }

  async close(): Promise<void> {
    // SQLite doesn't need explicit close in most cases
  }
}

/**
 * Generic SQL adapter for session storage
 * Works with any database that supports standard SQL
 */
export interface SqlConnection {
  execute(sql: string, params?: unknown[]): Promise<{ rowCount?: number, rows?: unknown[] }>
  query(sql: string, params?: unknown[]): Promise<unknown[]>
}

export class GenericSqlSessionAdapter implements DatabaseAdapter {
  private connection: SqlConnection
  private tableName: string

  constructor(connection: SqlConnection, tableName: string = 'sessions') {
    this.connection = connection
    this.tableName = tableName
  }

  /**
   * Create the sessions table (call this during setup)
   */
  async createTable(): Promise<void> {
    await this.connection.execute(`
      CREATE TABLE IF NOT EXISTS ${this.tableName} (
        id VARCHAR(255) PRIMARY KEY,
        data TEXT NOT NULL,
        last_activity BIGINT NOT NULL
      )
    `)
  }

  async get(sessionId: string): Promise<{ data: string, lastActivity: number } | null> {
    const rows = await this.connection.query(
      `SELECT data, last_activity FROM ${this.tableName} WHERE id = ?`,
      [sessionId],
    )

    if (!rows || rows.length === 0) {
      return null
    }

    const row = rows[0] as { data: string, last_activity: number }
    return {
      data: row.data,
      lastActivity: row.last_activity,
    }
  }

  async set(sessionId: string, data: string, lastActivity: number): Promise<void> {
    // Use upsert pattern (varies by database)
    await this.connection.execute(
      `INSERT INTO ${this.tableName} (id, data, last_activity)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE data = ?, last_activity = ?`,
      [sessionId, data, lastActivity, data, lastActivity],
    )
  }

  async delete(sessionId: string): Promise<boolean> {
    const result = await this.connection.execute(
      `DELETE FROM ${this.tableName} WHERE id = ?`,
      [sessionId],
    )
    return (result.rowCount ?? 0) > 0
  }

  async deleteExpired(maxLifetime: number): Promise<number> {
    const cutoff = Date.now() - (maxLifetime * 1000)
    const result = await this.connection.execute(
      `DELETE FROM ${this.tableName} WHERE last_activity < ?`,
      [cutoff],
    )
    return result.rowCount ?? 0
  }

  async close(): Promise<void> {
    // Connection management is handled externally
  }
}

/**
 * Create a database session handler with SQLite
 */
export function createSQLiteSessionHandler(
  database: { query: (sql: string) => { all: () => unknown[], run: (...args: unknown[]) => { changes: number }, get: (...args: unknown[]) => unknown } },
  tableName: string = 'sessions',
): DatabaseSessionHandler {
  const adapter = new SQLiteSessionAdapter(database, tableName)
  return new DatabaseSessionHandler(adapter, tableName)
}

/**
 * Create a database session handler with a generic SQL connection
 */
export function createDatabaseSessionHandler(
  connection: SqlConnection,
  tableName: string = 'sessions',
): DatabaseSessionHandler {
  const adapter = new GenericSqlSessionAdapter(connection, tableName)
  return new DatabaseSessionHandler(adapter, tableName)
}
