import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

/**
 * Self-authenticating SIWE nonces.
 *
 * A nonce carries its own timestamped expiry and a truncated HMAC-SHA256 MAC over the
 * random material and expiry time. Any stateless node possessing SESSION_SECRET
 * can validate that the nonce was issued locally within the permissible TTL.
 */

/** Validity window for issued nonces (10 minutes). */
const NONCE_TTL_SECONDS = 10 * 60

const RANDOM_HEX_LENGTH = 32 // 16 bytes random hex
const EXPIRY_HEX_LENGTH = 8  // 4 bytes uint32 epoch seconds in hex
const MAC_HEX_LENGTH = 32    // 16 bytes truncated HMAC hex

export const NONCE_LENGTH = RANDOM_HEX_LENGTH + EXPIRY_HEX_LENGTH + MAC_HEX_LENGTH

/** Local cache of redeemed nonces to prevent in-flight replays. */
const usedNonces = new Map<string, number>()
const MAX_REMEMBERED_NONCES = 10_000

function getKey(): Buffer | null {
  const secret = process.env.SESSION_SECRET
  if (!secret || secret.length < 16) {
    return null
  }
  // Domain-separated key to avoid collision with session token HMAC
  return createHmac('sha256', secret).update('siwe-nonce-v1').digest()
}

function macFor(body: string, key: Buffer): string {
  return createHmac('sha256', key).update(body).digest('hex').slice(0, MAC_HEX_LENGTH)
}

function macsMatch(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8')
  const right = Buffer.from(b, 'utf8')
  if (left.length !== right.length) {
    return false
  }
  return timingSafeEqual(left, right)
}

/**
 * Issues a self-authenticating SIWE nonce.
 * Returns null if SESSION_SECRET is not configured.
 */
export function issueNonce(): string | null {
  const key = getKey()
  if (!key) {
    return null
  }

  const random = randomBytes(RANDOM_HEX_LENGTH / 2).toString('hex')
  const expiry = Math.floor(Date.now() / 1000) + NONCE_TTL_SECONDS
  const expiryHex = expiry.toString(16).padStart(EXPIRY_HEX_LENGTH, '0')
  const body = `${random}${expiryHex}`

  return `${body}${macFor(body, key)}`
}

/** Prunes expired entries and caps the map capacity. */
function rememberUsed(nonce: string, expiry: number): void {
  const now = Math.floor(Date.now() / 1000)
  
  // Evict stale nonces
  for (const [entry, entryExpiry] of usedNonces.entries()) {
    if (entryExpiry <= now) {
      usedNonces.delete(entry)
    }
  }

  // Bound memory footprint to MAX_REMEMBERED_NONCES
  if (usedNonces.size >= MAX_REMEMBERED_NONCES) {
    const oldestKey = usedNonces.keys().next().value
    if (oldestKey !== undefined) {
      usedNonces.delete(oldestKey)
    }
  }

  usedNonces.set(nonce, expiry)
}

export type NonceCheck = 'ok' | 'malformed' | 'expired' | 'reused' | 'unavailable'

/**
 * Verifies the validity of an incoming SIWE nonce and marks it as spent.
 */
export function consumeNonce(nonce: unknown): NonceCheck {
  const key = getKey()
  if (!key) {
    return 'unavailable'
  }
  if (typeof nonce !== 'string' || nonce.length !== NONCE_LENGTH || !/^[0-9a-f]+$/.test(nonce)) {
    return 'malformed'
  }

  const body = nonce.slice(0, RANDOM_HEX_LENGTH + EXPIRY_HEX_LENGTH)
  const mac = nonce.slice(RANDOM_HEX_LENGTH + EXPIRY_HEX_LENGTH)
  if (!macsMatch(mac, macFor(body, key))) {
    return 'malformed'
  }

  const expiry = parseInt(nonce.slice(RANDOM_HEX_LENGTH, RANDOM_HEX_LENGTH + EXPIRY_HEX_LENGTH), 16)
  if (!Number.isFinite(expiry) || expiry <= Math.floor(Date.now() / 1000)) {
    return 'expired'
  }

  if (usedNonces.has(nonce)) {
    return 'reused'
  }
  rememberUsed(nonce, expiry)

  return 'ok'
}
