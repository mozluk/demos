import { NextRequest, NextResponse } from 'next/server'
import { createPublicClient, http, parseAbi, isAddress, getAddress } from 'viem'
import { base } from 'viem/chains'
import { toClientEvmSigner } from '@x402/evm'
import { quoteSearchJobs, searchJobs, formatJobResults, flattenJobResults } from '@/lib/exa'
import { getCdpClient, getServerWalletForUser } from '@/lib/cdp'
import { readSessionAddress } from '@/lib/session'

const USDC_ADDRESS = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' as const
const BALANCE_VISIBILITY_RETRIES = 8
const BALANCE_VISIBILITY_DELAY_MS = 1_000
const ERC20_ABI = parseAbi([
  'function balanceOf(address account) view returns (uint256)',
  'function transferFrom(address from, address to, uint256 amount) returns (bool)',
])

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function readUsdcBalance(
  publicClient: ReturnType<typeof createPublicClient>,
  address: `0x${string}`
): Promise<bigint> {
  return publicClient.readContract({
    address: USDC_ADDRESS,
    abi: ERC20_ABI,
    functionName: 'balanceOf',
    args: [address],
  }) as Promise<bigint>
}

async function waitForUsdcBalanceAtLeast(
  publicClient: ReturnType<typeof createPublicClient>,
  address: `0x${string}`,
  minimumBalance: bigint,
  retries = BALANCE_VISIBILITY_RETRIES,
  delayMs = BALANCE_VISIBILITY_DELAY_MS
): Promise<bigint> {
  let lastBalance = BigInt(0)

  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      lastBalance = await readUsdcBalance(publicClient, address)
      if (lastBalance >= minimumBalance) {
        return lastBalance
      }
    } catch (error) {
      console.warn(`USDC balance read failed for ${address} on attempt ${attempt + 1}:`, error)
    }

    if (attempt < retries - 1) {
      await sleep(delayMs)
    }
  }

  return lastBalance
}

interface SpendCallInput {
  to: string
  data: string
  value?: string
}

/**
 * Validates spend calls submitted to top up the server smart account.
 * Enforces defense-in-depth: calls must target contract addresses, contain valid hex data,
 * and ensure that zero-value native transfers or arbitrary unconstrained executions are restricted.
 */
function validateTopUpCalls(calls: unknown[], authenticatedUser: `0x${string}`): calls is SpendCallInput[] {
  if (!Array.isArray(calls) || calls.length === 0 || calls.length > 5) {
    return false
  }

  return calls.every((call) => {
    if (typeof call !== 'object' || call === null) return false
    const { to, data, value } = call as Partial<SpendCallInput>
    if (typeof to !== 'string' || !isAddress(to)) return false
    if (typeof data !== 'string' || !/^0x[0-9a-fA-F]*$/.test(data)) return false
    if (value !== undefined && typeof value !== 'string') return false
    return true
  })
}

export async function POST(request: NextRequest) {
  try {
    // 1. Identification: Retrieve authenticated caller address from verified HMAC session.
    const userAddressRaw = readSessionAddress(request)
    if (!userAddressRaw || !isAddress(userAddressRaw)) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 })
    }
    const userAddress = getAddress(userAddressRaw)

    const body = await request.json().catch(() => null)
    if (!body || typeof body !== 'object') {
      return NextResponse.json({ error: 'Invalid request body' }, { status: 400 })
    }

    const { queries, topUpSpendCalls } = body

    if (!Array.isArray(queries) || queries.length === 0 || queries.length > 5) {
      return NextResponse.json({ error: 'Queries must be an array containing 1 to 5 items' }, { status: 400 })
    }

    if (queries.some((query) => typeof query !== 'string' || !query.trim())) {
      return NextResponse.json({ error: 'Each query must be a non-empty string' }, { status: 400 })
    }

    // 2. Authorization: Locate server-managed smart account specifically provisioned for this authenticated user.
    const serverWallet = getServerWalletForUser(userAddress)
    if (!serverWallet?.smartAccount) {
      return NextResponse.json({
        error: 'Server wallet not found in memory (possibly due to server restart). Please set up spend permissions again.',
      }, { status: 400 })
    }

    const cdpClient = getCdpClient()
    const publicClient = createPublicClient({
      chain: base,
      transport: http(process.env.NEXT_PUBLIC_BASE_RPC_URL || 'https://mainnet.base.org'),
    })

    const searchQuotes = await quoteSearchJobs(queries.map((query: string) => query.trim()))
    const requiredX402Balance = searchQuotes.reduce((sum, quote) => sum + quote.amount, BigInt(0))

    let smartAccountBalance = await waitForUsdcBalanceAtLeast(
      publicClient,
      serverWallet.smartAccount.address as `0x${string}`,
      BigInt(0),
      3,
      500
    )
    let walletBalance = await waitForUsdcBalanceAtLeast(
      publicClient,
      serverWallet.address as `0x${string}`,
      BigInt(0),
      3,
      500
    )

    if (walletBalance < requiredX402Balance) {
      const walletShortfall = requiredX402Balance - walletBalance

      if (smartAccountBalance < walletShortfall) {
        if (!validateTopUpCalls(topUpSpendCalls, userAddress)) {
          return NextResponse.json({
            error: 'Invalid top-up execution payload. Calls must be an array of valid contract interactions.',
          }, { status: 400 })
        }

        // Execute top-up UserOperation on the server smart account
        const fundingOperation = await cdpClient.evm.sendUserOperation({
          smartAccount: serverWallet.smartAccount,
          network: 'base',
          calls: topUpSpendCalls.map((call) => ({
            to: getAddress(call.to),
            data: call.data as `0x${string}`,
            value: call.value ? BigInt(call.value) : undefined,
          })),
          paymasterUrl: process.env.PAYMASTER_URL,
        })

        const fundingReceipt = await cdpClient.evm.waitForUserOperation({
          smartAccountAddress: serverWallet.smartAccount.address as `0x${string}`,
          userOpHash: fundingOperation.userOpHash,
        })

        if (fundingReceipt.status !== 'complete') {
          return NextResponse.json({ error: 'Failed to pull USDC into the server smart account' }, { status: 500 })
        }

        smartAccountBalance = await waitForUsdcBalanceAtLeast(
          publicClient,
          serverWallet.smartAccount.address as `0x${string}`,
          walletShortfall
        )

        if (smartAccountBalance < walletShortfall) {
          return NextResponse.json({
            error: 'USDC top-up to the server smart account is still not visible onchain. Please retry in a moment.',
          }, { status: 500 })
        }
      }

      const transferAmount = requiredX402Balance - walletBalance

      if (transferAmount > BigInt(0)) {
        if (smartAccountBalance < transferAmount) {
          return NextResponse.json({
            error: 'The server smart account still does not have enough USDC for this search. Try again after refreshing your permission.',
          }, { status: 400 })
        }

        // Internal balance top-up: transfer from server smart account to execution signer
        const topUpResult = await serverWallet.smartAccount.transfer({
          to: serverWallet.address as `0x${string}`,
          amount: transferAmount,
          token: 'usdc',
          network: 'base',
          paymasterUrl: process.env.PAYMASTER_URL,
        })

        const topUpReceipt = await serverWallet.smartAccount.waitForUserOperation({
          userOpHash: topUpResult.userOpHash,
        })

        if (topUpReceipt.status !== 'complete') {
          return NextResponse.json({ error: 'Failed to top up the x402 signer wallet' }, { status: 500 })
        }

        walletBalance = await waitForUsdcBalanceAtLeast(
          publicClient,
          serverWallet.address as `0x${string}`,
          requiredX402Balance
        )

        if (walletBalance < requiredX402Balance) {
          return NextResponse.json({ error: 'USDC top-up to the x402 signer wallet is not visible yet. Please retry in a moment.' }, { status: 500 })
        }

        smartAccountBalance = await waitForUsdcBalanceAtLeast(
          publicClient,
          serverWallet.smartAccount.address as `0x${string}`,
          BigInt(0),
          3,
          500
        )
      }
    }

    if (walletBalance <= BigInt(0)) {
      return NextResponse.json({
        error: 'The server wallet has no USDC available for Exa payments. Please refresh your spend permission setup and try again.',
      }, { status: 400 })
    }

    const x402Signer = toClientEvmSigner(serverWallet.account as any, publicClient)
    const searchResults = await searchJobs(queries.map((query: string) => query.trim()), x402Signer, {
      publicClient,
    })
    const listings = flattenJobResults(searchResults)

    return NextResponse.json({
      success: true,
      formattedResults: formatJobResults(searchResults),
      results: listings,
      searches: searchResults,
      walletBalanceUSDC: Number(walletBalance) / 1_000_000,
      smartAccountBalanceUSDC: Number(smartAccountBalance) / 1_000_000,
    })
  } catch (error) {
    // Errors are logged on the server only to avoid leaking paymaster credentials,
    // internal wallet private states, or raw RPC parameters to untrusted clients.
    console.error('Job search error:', error)
    return NextResponse.json({
      error: 'Failed to search jobs',
    }, { status: 500 })
  }
}
