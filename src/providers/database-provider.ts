import type { Authenticatable, Credentials, ProviderConfig, UserProvider } from '../types'

/**
 * Generic user model that implements Authenticatable
 * Can be extended or replaced with your own model
 */
export class GenericUser implements Authenticatable {
  private data: Record<string, unknown>
  private identifierName: string
  private passwordField: string
  private rememberTokenField: string
  private rememberToken: string | null = null

  constructor(
    data: Record<string, unknown>,
    options: {
      identifierName?: string
      passwordField?: string
      rememberTokenField?: string
    } = {},
  ) {
    this.data = data
    this.identifierName = options.identifierName ?? 'id'
    this.passwordField = options.passwordField ?? 'password'
    this.rememberTokenField = options.rememberTokenField ?? 'remember_token'
    this.rememberToken = (data[this.rememberTokenField] as string) ?? null
  }

  getAuthIdentifier(): string | number {
    return this.data[this.identifierName] as string | number
  }

  getAuthIdentifierName(): string {
    return this.identifierName
  }

  getAuthPassword(): string {
    return this.data[this.passwordField] as string
  }

  getRememberToken(): string | null {
    return this.rememberToken
  }

  setRememberToken(value: string): void {
    this.rememberToken = value
    this.data[this.rememberTokenField] = value
  }

  getRememberTokenName(): string {
    return this.rememberTokenField
  }

  /**
   * Get any attribute from the user data
   */
  getAttribute(key: string): unknown {
    return this.data[key]
  }

  /**
   * Get all user data
   */
  toObject(): Record<string, unknown> {
    return { ...this.data }
  }
}

/**
 * Database user provider
 * Retrieves users from a database using a provided query function
 */
export class DatabaseUserProvider implements UserProvider {
  private config: ProviderConfig
  private hashPassword: (password: string) => Promise<string>
  private verifyPassword: (password: string, hash: string) => Promise<boolean>
  private queryUser: (table: string, query: Record<string, unknown>) => Promise<Record<string, unknown> | null>
  private updateUser: (table: string, id: string | number, data: Record<string, unknown>) => Promise<void>

  constructor(
    config: ProviderConfig,
    options: {
      hashPassword: (password: string) => Promise<string>
      verifyPassword: (password: string, hash: string) => Promise<boolean>
      queryUser: (table: string, query: Record<string, unknown>) => Promise<Record<string, unknown> | null>
      updateUser: (table: string, id: string | number, data: Record<string, unknown>) => Promise<void>
    },
  ) {
    this.config = config
    this.hashPassword = options.hashPassword
    this.verifyPassword = options.verifyPassword
    this.queryUser = options.queryUser
    this.updateUser = options.updateUser
  }

  /**
   * Retrieve a user by their unique identifier
   */
  async retrieveById(identifier: string | number): Promise<Authenticatable | null> {
    const table = this.config.table ?? 'users'
    const user = await this.queryUser(table, { id: identifier })

    if (!user) {
      return null
    }

    return new GenericUser(user)
  }

  /**
   * Retrieve a user by their unique identifier and "remember me" token
   */
  async retrieveByToken(identifier: string | number, token: string): Promise<Authenticatable | null> {
    const table = this.config.table ?? 'users'
    const user = await this.queryUser(table, {
      id: identifier,
      remember_token: token,
    })

    if (!user) {
      return null
    }

    return new GenericUser(user)
  }

  /**
   * Update the "remember me" token for the given user
   */
  async updateRememberToken(user: Authenticatable, token: string): Promise<void> {
    const table = this.config.table ?? 'users'
    await this.updateUser(table, user.getAuthIdentifier(), {
      [user.getRememberTokenName()]: token,
    })
  }

  /**
   * Retrieve a user by the given credentials
   */
  async retrieveByCredentials(credentials: Credentials): Promise<Authenticatable | null> {
    const table = this.config.table ?? 'users'

    // Build query from credentials, excluding password
    const query: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(credentials)) {
      if (key !== 'password') {
        query[key] = value
      }
    }

    if (Object.keys(query).length === 0) {
      return null
    }

    const user = await this.queryUser(table, query)

    if (!user) {
      return null
    }

    return new GenericUser(user)
  }

  /**
   * Validate a user against the given credentials
   */
  async validateCredentials(user: Authenticatable, credentials: Credentials): Promise<boolean> {
    const password = credentials.password
    if (!password) {
      return false
    }

    const hashedPassword = user.getAuthPassword()
    return this.verifyPassword(password, hashedPassword)
  }
}

/**
 * In-memory user provider for testing
 */
export class InMemoryUserProvider implements UserProvider {
  private users: Map<string | number, Record<string, unknown>> = new Map()
  private verifyPassword: (password: string, hash: string) => Promise<boolean>

  constructor(
    users: Record<string, unknown>[] = [],
    verifyPassword?: (password: string, hash: string) => Promise<boolean>,
  ) {
    for (const user of users) {
      const id = user.id as string | number
      this.users.set(id, user)
    }

    this.verifyPassword = verifyPassword ?? (async (password, hash) => password === hash)
  }

  /**
   * Add a user to the provider
   */
  addUser(user: Record<string, unknown>): void {
    const id = user.id as string | number
    this.users.set(id, user)
  }

  async retrieveById(identifier: string | number): Promise<Authenticatable | null> {
    const user = this.users.get(identifier)
    if (!user) {
      return null
    }
    return new GenericUser(user)
  }

  async retrieveByToken(identifier: string | number, token: string): Promise<Authenticatable | null> {
    const user = this.users.get(identifier)
    if (!user || user.remember_token !== token) {
      return null
    }
    return new GenericUser(user)
  }

  async updateRememberToken(user: Authenticatable, token: string): Promise<void> {
    const id = user.getAuthIdentifier()
    const userData = this.users.get(id)
    if (userData) {
      userData.remember_token = token
    }
  }

  async retrieveByCredentials(credentials: Credentials): Promise<Authenticatable | null> {
    for (const user of this.users.values()) {
      let match = true

      for (const [key, value] of Object.entries(credentials)) {
        if (key !== 'password' && user[key] !== value) {
          match = false
          break
        }
      }

      if (match) {
        return new GenericUser(user)
      }
    }

    return null
  }

  async validateCredentials(user: Authenticatable, credentials: Credentials): Promise<boolean> {
    const password = credentials.password
    if (!password) {
      return false
    }

    return this.verifyPassword(password, user.getAuthPassword())
  }
}
