import type { SessionConfig } from '../types'
import { SessionManager } from './session'

/**
 * Session middleware options
 */
export interface SessionMiddlewareOptions {
  config?: Partial<SessionConfig>
}

/**
 * Create session middleware for HTTP servers
 * Works with Bun.serve and similar HTTP server patterns
 */
export function sessionMiddleware(options: SessionMiddlewareOptions = {}) {
  const config: SessionConfig = {
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
    ...options.config,
  }

  return async (
    request: Request,
    next: (request: Request & { session: SessionManager }) => Promise<Response> | Response,
  ): Promise<Response> => {
    // Create session instance
    const session = new SessionManager(config)

    // Get session ID from cookie
    const cookieHeader = request.headers.get('cookie')
    if (cookieHeader) {
      const cookies = parseCookies(cookieHeader)
      const sessionId = cookies[config.cookie]
      if (sessionId) {
        session.setId(sessionId)
      }
    }

    // Start session
    await session.start()

    // Add session to request
    const requestWithSession = Object.assign(request, { session })

    // Call next handler
    const response = await next(requestWithSession)

    // Save session
    await session.save()

    // Set session cookie on response
    const cookieOptions = session.getCookieOptions()
    const cookieValue = buildCookie(cookieOptions.name, session.getId(), cookieOptions)

    // Clone response to add cookie header
    const headers = new Headers(response.headers)
    headers.append('Set-Cookie', cookieValue)

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    })
  }
}

/**
 * CSRF protection middleware
 */
export function csrfMiddleware(options: { except?: string[] } = {}) {
  const except = options.except ?? []

  return async (
    request: Request & { session: SessionManager },
    next: (request: Request & { session: SessionManager }) => Promise<Response> | Response,
  ): Promise<Response> => {
    const method = request.method.toUpperCase()
    const url = new URL(request.url)

    // Skip CSRF check for safe methods and excepted paths
    if (['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      return next(request)
    }

    // Check if path is excepted
    for (const pattern of except) {
      if (matchPath(url.pathname, pattern)) {
        return next(request)
      }
    }

    // Get CSRF token from request
    const token = await getCsrfToken(request)
    const sessionToken = request.session.token()

    // Verify token
    if (!token || !timingSafeEqual(token, sessionToken)) {
      return new Response('CSRF token mismatch', { status: 419 })
    }

    return next(request)
  }
}

/**
 * Get CSRF token from request (header or body)
 */
async function getCsrfToken(request: Request): Promise<string | null> {
  // Check header first
  const headerToken = request.headers.get('X-CSRF-TOKEN') || request.headers.get('X-XSRF-TOKEN')
  if (headerToken) {
    return headerToken
  }

  // Check form data
  const contentType = request.headers.get('content-type') ?? ''
  if (contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data')) {
    try {
      const formData = await request.clone().formData()
      const token = formData.get('_token')
      if (typeof token === 'string') {
        return token
      }
    }
    catch {
      // Not form data
    }
  }

  // Check JSON body
  if (contentType.includes('application/json')) {
    try {
      const body = await request.clone().json()
      if (body && typeof body._token === 'string') {
        return body._token
      }
    }
    catch {
      // Not JSON
    }
  }

  return null
}

/**
 * Parse cookies from header
 */
function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {}
  const pairs = cookieHeader.split(';')

  for (const pair of pairs) {
    const [name, ...rest] = pair.trim().split('=')
    if (name) {
      cookies[name] = rest.join('=')
    }
  }

  return cookies
}

/**
 * Build cookie string
 */
function buildCookie(
  name: string,
  value: string,
  options: {
    path?: string
    domain?: string | null
    secure?: boolean
    httpOnly?: boolean
    sameSite?: 'lax' | 'strict' | 'none'
    maxAge?: number
  },
): string {
  let cookie = `${name}=${value}`

  if (options.path) {
    cookie += `; Path=${options.path}`
  }
  if (options.domain) {
    cookie += `; Domain=${options.domain}`
  }
  if (options.secure) {
    cookie += '; Secure'
  }
  if (options.httpOnly) {
    cookie += '; HttpOnly'
  }
  if (options.sameSite) {
    cookie += `; SameSite=${options.sameSite.charAt(0).toUpperCase() + options.sameSite.slice(1)}`
  }
  if (options.maxAge !== undefined) {
    cookie += `; Max-Age=${options.maxAge}`
  }

  return cookie
}

/**
 * Match path against pattern (supports wildcards)
 */
function matchPath(path: string, pattern: string): boolean {
  if (pattern.endsWith('*')) {
    return path.startsWith(pattern.slice(0, -1))
  }
  return path === pattern
}

/**
 * Timing-safe string comparison
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false
  }

  let result = 0
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }

  return result === 0
}
