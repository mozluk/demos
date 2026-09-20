import { NextRequest, NextResponse } from 'next/server'
import { createPublicClient, http, isAddress, getAddress } from 'viem'
import { base } from 'viem/chains'
// SIWE helpers live behind the `viem/siwe` entrypoint
import { parseSiweMessage } from 'viem/siwe'

import { SESSION_COOKIE_NAME, SESSION_TTL_SECONDS, createSessionToken } from '@/lib/session'
import { consumeNonce, issueNonce } from '@/lib/siwe-nonce'

/**
 * Sign-In with Ethereum (SIWE) Endpoint.
 *
 * Enforces cryptographic domain binding, single-use self-authenticating nonces,
 * and ERC-6492 / ERC-1271 smart wallet signature validation.
 */

const client = createPublicClient({
  chain: base,
  transport: http(process.env.NEXT_PUBLIC_BASE_RPC_URL || 'https://mainnet.base.org'),
})

/**
 * Resolves the expected domain for the SIWE assertion.
 * Prefer explicit SIWE_DOMAIN configuration to prevent host header poisoning behind proxies.
 */
function expectedDomain(request: NextRequest): string | null {
  const configured = process.env.SIWE_DOMAIN
  if (configured) {
    return configured
  }
  const host = request.headers.get('host')
  if (!host) {
    return null
  }
  // Strip optional port if present in the Host header
  return host.split(':')[0]
}

export async function POST(request: NextRequest) {
  try {
    const body: unknown = await request.json().catch(() => null)
    if (typeof body !== 'object' || body === null) {
      return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 })
    }

    const { address, message, signature } = body as Record<string, unknown>

    if (typeof address !== 'string' || typeof message !== 'string' || typeof signature !== 'string') {
      return NextResponse.json({
        error: 'Missing required fields: address, message, signature'
      }, { status: 400 })
    }
    if (!isAddress(address)) {
      return NextResponse.json({ error: 'Invalid address' }, { status: 400 })
    }
    // Bound processing length before performing cryptographic operations
    if (message.length > 4096 || signature.length > 8192) {
      return NextResponse.json({ error: 'Message or signature too large' }, { status: 400 })
    }

    const domain = expectedDomain(request)
    if (!domain) {
      console.error('Cannot determine the expected SIWE domain; set SIWE_DOMAIN')
      return NextResponse.json({ error: 'Authentication is not configured' }, { status: 503 })
    }

    // Parse SIWE message structure
    let siwe
    try {
      siwe = parseSiweMessage(message)
    } catch {
      return NextResponse.json({ error: 'Invalid message format' }, { status: 400 })
    }

    if (!siwe?.nonce || !siwe?.address) {
      return NextResponse.json({ error: 'Invalid message format' }, { status: 400 })
    }

    // Consume self-authenticating nonce (enforcing MAC, TTL, and replay tracking)
    const nonceCheck = consumeNonce(siwe.nonce)
    if (nonceCheck === 'unavailable') {
      console.error('SESSION_SECRET is not set; sign-in cannot be completed')
      return NextResponse.json({ error: 'Authentication is not configured' }, { status: 503 })
    }
    if (nonceCheck !== 'ok') {
      return NextResponse.json({ error: 'Invalid or expired nonce' }, { status: 401 })
    }

    // Strict caller-address matching (checksum normalized)
    const normalizedBodyAddress = getAddress(address)
    const normalizedSiweAddress = getAddress(siwe.address)
    if (normalizedBodyAddress !== normalizedSiweAddress) {
      return NextResponse.json({ error: 'Message address does not match' }, { status: 401 })
    }

    // Verify SIWE signature: supports EOA (ecrecover) as well as Smart Wallets (ERC-1271 / ERC-6492)
    const isValid = await client.verifySiweMessage({
      message,
      signature: signature as `0x${string}`,
      address: normalizedBodyAddress,
      domain,
      nonce: siwe.nonce,
      time: new Date(),
    })

    if (!isValid) {
      return NextResponse.json({ error: 'Invalid signature' }, { status: 401 })
    }

    const sessionToken = createSessionToken(normalizedBodyAddress)
    if (!sessionToken) {
      console.error('SESSION_SECRET is not set; refusing to issue an unsigned session')
      return NextResponse.json({ error: 'Authentication is not configured' }, { status: 503 })
    }

    // Return authenticated response; session cookie is strictly HttpOnly and SameSite: strict
    const response = NextResponse.json({ ok: true, address: normalizedBodyAddress })

    response.cookies.set(SESSION_COOKIE_NAME, sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
      maxAge: SESSION_TTL_SECONDS
    })

    return response
  } catch (error) {
    console.error('Auth verification error:', error)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}

export async function GET() {
  const nonce = issueNonce()
  if (!nonce) {
    console.error('SESSION_SECRET is not set; cannot issue a nonce')
    return NextResponse.json({ error: 'Authentication is not configured' }, { status: 503 })
  }

  return NextResponse.json({ nonce })
}
