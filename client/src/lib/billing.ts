/*
  Client-side Billing API helper
  - Uses API key auth header (Authorization: ApiKey <key>) as supported by the server
  - Provides functions to create a Solana subscription checkout and poll subscription status
*/

export interface CreateSubscriptionResponse {
  subscriptionId: string;
  orderId: string;
  phantomUrl: string;
  qrDataUrl: string;
  unsignedTxB64: string;
  expiresAt: string;
}

export interface SubscriptionStatusResponse {
  subscriptionId: string;
  status: 'pending' | 'active' | 'expired' | 'canceled';
  activeUntil: string | null;
  plan: 'basic' | 'pro';
  chain: 'solana' | 'ethereum' | 'bitcoin' | 'xrp' | 'other';
  asset: 'SOL' | 'SPL' | 'ETH' | 'BTC' | 'XRP' | 'OTHER';
  orderId: string | null;
  issuedApiKey?: { id: string; key?: string };
}

export async function createSolanaSubscription(opts: { apiKey: string; userPubkey: string; plan?: 'basic' | 'pro' }): Promise<CreateSubscriptionResponse> {
  const res = await fetch('/api/billing/solana/subscribe', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `ApiKey ${opts.apiKey}`,
    },
    body: JSON.stringify({ userPubkey: opts.userPubkey, plan: opts.plan ?? 'pro' }),
    credentials: 'include',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

export async function getSubscriptionStatus(opts: { apiKey: string; subscriptionId: string }): Promise<SubscriptionStatusResponse> {
  const res = await fetch(`/api/billing/subscriptions/${opts.subscriptionId}`, {
    method: 'GET',
    headers: {
      'Authorization': `ApiKey ${opts.apiKey}`,
    },
    credentials: 'include',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

export async function pollSubscriptionStatus(opts: { apiKey: string; subscriptionId: string; intervalMs?: number; maxAttempts?: number; onTick?: (s: SubscriptionStatusResponse) => void; }): Promise<SubscriptionStatusResponse> {
  const interval = opts.intervalMs ?? 3000;
  const max = opts.maxAttempts ?? 60; // ~3 minutes
  let last: SubscriptionStatusResponse | null = null;

  for (let i = 0; i < max; i++) {
    // eslint-disable-next-line no-await-in-loop
    const status = await getSubscriptionStatus({ apiKey: opts.apiKey, subscriptionId: opts.subscriptionId });
    last = status;
    opts.onTick?.(status);
    if (status.status === 'active' || status.status === 'canceled' || status.status === 'expired') {
      return status;
    }
    // eslint-disable-next-line no-await-in-loop
    await new Promise((r) => setTimeout(r, interval));
  }
  if (last) return last;
  throw new Error('Polling timeout');
}