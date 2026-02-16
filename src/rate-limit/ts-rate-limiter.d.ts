declare module 'ts-rate-limiter' {
  export interface RateLimiterOptions {
    windowMs?: number
    maxRequests?: number
    storage?: StorageProvider
    keyGenerator?: (request: Request) => string
    handler?: (request: Request, result: RateLimitResult) => Response
  }

  export interface RateLimitResult {
    allowed: boolean
    limit: number
    remaining: number
    resetTime: number
  }

  export interface StorageProvider {
    get(key: string): Promise<unknown>
    set(key: string, value: unknown, ttl?: number): Promise<void>
    increment(key: string): Promise<number>
    reset(key: string): Promise<void>
    clear(): Promise<void>
  }

  export class RateLimiter {
    constructor(options: RateLimiterOptions)
    check(request: Request): Promise<RateLimitResult>
    consume(key: string): Promise<RateLimitResult>
    middleware(): (request: Request, next: (request: Request) => Promise<Response> | Response) => Promise<Response>
    reset(key: string): Promise<void>
    resetAll(): Promise<void>
    dispose(): void
  }

  export class MemoryStorage implements StorageProvider {
    constructor(options?: { enableAutoCleanup?: boolean })
    get(key: string): Promise<unknown>
    set(key: string, value: unknown, ttl?: number): Promise<void>
    increment(key: string): Promise<number>
    reset(key: string): Promise<void>
    clear(): Promise<void>
  }
}
