import { getSolanaConnection } from './solana';
// dynamic import of node-fetch to avoid missing types in workspace
// @ts-ignore
const nodeFetch: any = typeof fetch !== 'undefined' ? (globalThis as any).fetch : null;
async function fetchWrapper(url: string, opts?: any) {
  if (nodeFetch) return (nodeFetch as any)(url, opts);
  // @ts-ignore dynamic import
  const f: any = (await import('node-fetch')).default;
  return f(url, opts);
}
import { PublicKey } from '@solana/web3.js';

function getEnv(name: string, fallback = '') { return process.env[name] ?? fallback; }

// COINGECKO_TOKEN_MAP env should be JSON object mapping tokenMint => coingeckoId
// e.g. { "Es9vMFr...USDC...": "usd-coin" }
const COINGECKO_MAP = (() => {
  try { return JSON.parse(getEnv('COINGECKO_TOKEN_MAP', '{}')); } catch { return {}; }
})();

export async function getTokenDecimals(mint: string): Promise<number> {
  const connection = getSolanaConnection();
  const pk = new PublicKey(mint);
  const mintInfo = await connection.getParsedAccountInfo(pk, 'confirmed');
  try {
    const data: any = (mintInfo.value && (mintInfo.value.data as any)?.parsed?.info) || (mintInfo.value && mintInfo.value.data);
    const decimals = data?.decimals ?? 6; // default fallback
    return Number(decimals);
  } catch (e) {
    return 6;
  }
}

export async function getTokenPriceUsd(mintOrCoingeckoId: string): Promise<number | null> {
  try {
    const cgId = COINGECKO_MAP[mintOrCoingeckoId] || mintOrCoingeckoId;
    const url = `https://api.coingecko.com/api/v3/simple/price?ids=${encodeURIComponent(cgId)}&vs_currencies=usd`;
  const res = await fetchWrapper(url, { timeout: 5000 });
    if (!res.ok) return null;
    const js = await res.json();
    if (js && js[cgId] && typeof js[cgId].usd === 'number') return js[cgId].usd;
    return null;
  } catch (e) {
    return null;
  }
}

export async function convertUsdToTokenBaseUnits(mint: string, usdAmount: number): Promise<string> {
  // Fetch decimals
  const decimals = await getTokenDecimals(mint);
  // Fetch price from coingecko using mapping
  const price = await getTokenPriceUsd(mint);
  if (!price || price <= 0) {
    throw new Error('price_unavailable');
  }
  // tokens = usdAmount / price
  const tokens = usdAmount / price;
  const baseUnits = BigInt(Math.round(tokens * Math.pow(10, decimals))).toString();
  return baseUnits;
}
