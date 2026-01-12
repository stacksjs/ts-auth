import type { JWTAlgorithm, JWTPayload, TokenConfig, TokenResult } from '../types'

/**
 * JWT implementation using Web Crypto API
 * Zero dependencies, works in Bun, Node.js, and browsers
 */

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

/**
 * Base64URL encode
 */
function base64UrlEncode(data: Uint8Array | string): string {
  const bytes = typeof data === 'string' ? textEncoder.encode(data) : data
  const base64 = btoa(String.fromCharCode(...bytes))
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Base64URL decode
 */
function base64UrlDecode(str: string): Uint8Array {
  // Add padding if needed
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4)
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

/**
 * Get crypto algorithm config from JWT algorithm
 */
function getAlgorithmConfig(alg: JWTAlgorithm): {
  name: string
  hash?: string
  namedCurve?: string
} {
  switch (alg) {
    case 'HS256':
      return { name: 'HMAC', hash: 'SHA-256' }
    case 'HS384':
      return { name: 'HMAC', hash: 'SHA-384' }
    case 'HS512':
      return { name: 'HMAC', hash: 'SHA-512' }
    case 'RS256':
      return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
    case 'RS384':
      return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' }
    case 'RS512':
      return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' }
    case 'ES256':
      return { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' }
    case 'ES384':
      return { name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384' }
    case 'ES512':
      return { name: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-521' }
    default:
      throw new Error(`Unsupported algorithm: ${alg}`)
  }
}

/**
 * Import key for signing/verification
 */
async function importKey(
  secret: string | CryptoKey,
  alg: JWTAlgorithm,
  usage: 'sign' | 'verify',
): Promise<CryptoKey> {
  if (secret instanceof CryptoKey) {
    return secret
  }

  const config = getAlgorithmConfig(alg)
  const keyData = textEncoder.encode(secret)

  if (config.name === 'HMAC') {
    return crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: config.hash! },
      false,
      [usage],
    )
  }

  // For RSA/ECDSA, assume secret is PEM-encoded key
  const pemContent = secret.replace(/-----[A-Z ]+-----/g, '').replace(/\s/g, '')
  const keyBytes = base64UrlDecode(pemContent)

  const keyUsage: KeyUsage[] = usage === 'sign' ? ['sign'] : ['verify']
  const format = usage === 'sign' ? 'pkcs8' : 'spki'

  if (config.name === 'RSASSA-PKCS1-v1_5') {
    return crypto.subtle.importKey(
      format,
      keyBytes,
      { name: 'RSASSA-PKCS1-v1_5', hash: config.hash! },
      false,
      keyUsage,
    )
  }

  // ECDSA
  return crypto.subtle.importKey(
    format,
    keyBytes,
    { name: 'ECDSA', namedCurve: config.namedCurve! },
    false,
    keyUsage,
  )
}

/**
 * Sign data with key
 */
async function signData(data: Uint8Array, key: CryptoKey, alg: JWTAlgorithm): Promise<Uint8Array> {
  const config = getAlgorithmConfig(alg)

  let algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams
  if (config.name === 'HMAC' || config.name === 'RSASSA-PKCS1-v1_5') {
    algorithm = config.name
  }
  else {
    algorithm = { name: 'ECDSA', hash: config.hash! }
  }

  const signature = await crypto.subtle.sign(algorithm, key, data)
  return new Uint8Array(signature)
}

/**
 * Verify signature
 */
async function verifySignature(
  data: Uint8Array,
  signature: Uint8Array,
  key: CryptoKey,
  alg: JWTAlgorithm,
): Promise<boolean> {
  const config = getAlgorithmConfig(alg)

  let algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams
  if (config.name === 'HMAC' || config.name === 'RSASSA-PKCS1-v1_5') {
    algorithm = config.name
  }
  else {
    algorithm = { name: 'ECDSA', hash: config.hash! }
  }

  return crypto.subtle.verify(algorithm, key, signature, data)
}

/**
 * Parse duration string to seconds
 */
export function parseDuration(duration: string): number {
  const match = duration.match(/^(\d+)([smhdw])$/)
  if (!match) {
    throw new Error(`Invalid duration format: ${duration}`)
  }

  const value = Number.parseInt(match[1], 10)
  const unit = match[2]

  switch (unit) {
    case 's':
      return value
    case 'm':
      return value * 60
    case 'h':
      return value * 60 * 60
    case 'd':
      return value * 60 * 60 * 24
    case 'w':
      return value * 60 * 60 * 24 * 7
    default:
      throw new Error(`Invalid duration unit: ${unit}`)
  }
}

/**
 * Sign a JWT token
 */
export async function sign(
  payload: Omit<JWTPayload, 'iat' | 'exp'> & { iat?: number, exp?: number },
  secret: string | CryptoKey,
  options: {
    algorithm?: JWTAlgorithm
    expiresIn?: string | number
    issuer?: string
    audience?: string
    jwtId?: string
    notBefore?: number
  } = {},
): Promise<string> {
  const alg = options.algorithm ?? 'HS256'
  const now = Math.floor(Date.now() / 1000)

  // Build payload
  const fullPayload: JWTPayload = {
    ...payload,
    iat: payload.iat ?? now,
    exp: payload.exp ?? now + (
      typeof options.expiresIn === 'string'
        ? parseDuration(options.expiresIn)
        : (options.expiresIn ?? 3600)
    ),
  }

  if (options.issuer) {
    fullPayload.iss = options.issuer
  }
  if (options.audience) {
    fullPayload.aud = options.audience
  }
  if (options.jwtId) {
    fullPayload.jti = options.jwtId
  }
  if (options.notBefore !== undefined) {
    fullPayload.nbf = options.notBefore
  }

  // Create header
  const header = { alg, typ: 'JWT' }

  // Encode header and payload
  const encodedHeader = base64UrlEncode(JSON.stringify(header))
  const encodedPayload = base64UrlEncode(JSON.stringify(fullPayload))

  // Sign
  const signingInput = `${encodedHeader}.${encodedPayload}`
  const key = await importKey(secret, alg, 'sign')
  const signature = await signData(textEncoder.encode(signingInput), key, alg)

  return `${signingInput}.${base64UrlEncode(signature)}`
}

/**
 * Verify and decode a JWT token
 */
export async function verify<T extends JWTPayload = JWTPayload>(
  token: string,
  secret: string | CryptoKey,
  options: {
    algorithms?: JWTAlgorithm[]
    issuer?: string
    audience?: string
    clockTolerance?: number
  } = {},
): Promise<T> {
  const parts = token.split('.')
  if (parts.length !== 3) {
    throw new Error('Invalid token format')
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts

  // Decode header
  let header: { alg: JWTAlgorithm, typ?: string }
  try {
    header = JSON.parse(textDecoder.decode(base64UrlDecode(encodedHeader)))
  }
  catch {
    throw new Error('Invalid token header')
  }

  // Verify algorithm
  const allowedAlgs = options.algorithms ?? ['HS256']
  if (!allowedAlgs.includes(header.alg)) {
    throw new Error(`Algorithm ${header.alg} not allowed`)
  }

  // Verify signature
  const signingInput = `${encodedHeader}.${encodedPayload}`
  const signature = base64UrlDecode(encodedSignature)
  const key = await importKey(secret, header.alg, 'verify')

  const isValid = await verifySignature(
    textEncoder.encode(signingInput),
    signature,
    key,
    header.alg,
  )

  if (!isValid) {
    throw new Error('Invalid signature')
  }

  // Decode payload
  let payload: T
  try {
    payload = JSON.parse(textDecoder.decode(base64UrlDecode(encodedPayload)))
  }
  catch {
    throw new Error('Invalid token payload')
  }

  // Verify claims
  const now = Math.floor(Date.now() / 1000)
  const clockTolerance = options.clockTolerance ?? 0

  // Check expiration
  if (payload.exp !== undefined && now > payload.exp + clockTolerance) {
    throw new Error('Token expired')
  }

  // Check not before
  if (payload.nbf !== undefined && now < payload.nbf - clockTolerance) {
    throw new Error('Token not yet valid')
  }

  // Check issuer
  if (options.issuer && payload.iss !== options.issuer) {
    throw new Error('Invalid issuer')
  }

  // Check audience
  if (options.audience && payload.aud !== options.audience) {
    throw new Error('Invalid audience')
  }

  return payload
}

/**
 * Decode a JWT token without verification (unsafe!)
 */
export function decode<T extends JWTPayload = JWTPayload>(token: string): {
  header: { alg: JWTAlgorithm, typ?: string }
  payload: T
} | null {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) {
      return null
    }

    const header = JSON.parse(textDecoder.decode(base64UrlDecode(parts[0])))
    const payload = JSON.parse(textDecoder.decode(base64UrlDecode(parts[1])))

    return { header, payload }
  }
  catch {
    return null
  }
}

/**
 * Generate a random JWT ID
 */
export function generateJwtId(): string {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Create a token pair (access + refresh)
 */
export async function createTokenPair(
  subject: string | number,
  secret: string | CryptoKey,
  config: TokenConfig,
  claims: Record<string, unknown> = {},
): Promise<TokenResult> {
  const accessExpiresIn = parseDuration(config.expiry)

  const accessToken = await sign(
    {
      sub: subject,
      ...claims,
    },
    secret,
    {
      algorithm: config.algorithm,
      expiresIn: accessExpiresIn,
      issuer: config.issuer,
      audience: config.audience,
      jwtId: generateJwtId(),
    },
  )

  const result: TokenResult = {
    accessToken,
    tokenType: 'Bearer',
    expiresIn: accessExpiresIn,
  }

  if (config.refresh && config.refreshExpiry) {
    const refreshExpiresIn = parseDuration(config.refreshExpiry)
    result.refreshToken = await sign(
      {
        sub: subject,
        type: 'refresh',
      },
      secret,
      {
        algorithm: config.algorithm,
        expiresIn: refreshExpiresIn,
        issuer: config.issuer,
        jwtId: generateJwtId(),
      },
    )
  }

  return result
}
