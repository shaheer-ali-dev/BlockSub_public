import React, { useEffect, useMemo, useState } from 'react';
import { Navigation } from '@/components/Navigation';
import { Footer } from '@/components/Footer';
import { createSolanaSubscription, pollSubscriptionStatus, CreateSubscriptionResponse, SubscriptionStatusResponse } from '@/lib/billing';

function useLocalStorage(key: string, initial: string = '') {
  const [value, setValue] = useState<string>(() => {
    try {
      const v = localStorage.getItem(key);
      return v ?? initial;
    } catch {
      return initial;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem(key, value);
    } catch {}
  }, [key, value]);
  return [value, setValue] as const;
}

export default function SubscribePage() {
  const [apiKey, setApiKey] = useLocalStorage('blocksub_api_key');
  const [userPubkey, setUserPubkey] = useLocalStorage('blocksub_user_pubkey');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>('');

  const [checkout, setCheckout] = useState<CreateSubscriptionResponse | null>(null);
  const [status, setStatus] = useState<SubscriptionStatusResponse | null>(null);

  const canStart = useMemo(() => !!apiKey && !!userPubkey && userPubkey.length >= 32, [apiKey, userPubkey]);

  const startSubscription = async () => {
    setError('');
    setLoading(true);
    setCheckout(null);
    setStatus(null);
    try {
      const sub = await createSolanaSubscription({ apiKey, userPubkey, plan: 'pro' });
      setCheckout(sub);
      pollSubscriptionStatus({ apiKey, subscriptionId: sub.subscriptionId, onTick: setStatus }).catch(() => {});
    } catch (e: any) {
      setError(e?.message || 'Failed to start subscription');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col relative overflow-hidden">
      <Navigation />
      <main className="flex-1 relative">
        {/* The entire UI blurred */}
        <div className="max-w-4xl mx-auto px-4 py-10 filter blur-md pointer-events-none select-none opacity-60">
          <h1 className="text-3xl font-bold mb-2">Subscribe to BlockSub Pro</h1>
          <p className="text-muted-foreground mb-8">
            Pay $30/month in USDC on Solana using Phantom. Scan the QR or tap the Phantom link. Your subscription activates automatically when the transaction confirms.
          </p>

          <div className="grid md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">API Key</label>
                <input
                  className="w-full border rounded-md px-3 py-2"
                  placeholder="Paste your BlockSub API Key"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                />
                <p className="text-xs text-muted-foreground mt-1">
                  This is used to authorize the checkout call. You can generate one in Dashboard → API Keys.
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">Your Solana Public Key</label>
                <input
                  className="w-full border rounded-md px-3 py-2"
                  placeholder="9WzDXw..."
                  value={userPubkey}
                  onChange={(e) => setUserPubkey(e.target.value)}
                />
                <p className="text-xs text-muted-foreground mt-1">
                  This wallet signs the USDC transfer in Phantom.
                </p>
              </div>

              <button
                className="px-4 py-2 rounded-md bg-primary text-primary-foreground disabled:opacity-50"
                disabled={!canStart || loading}
                onClick={startSubscription}
              >
                {loading ? 'Creating checkout…' : 'Start $1/month Subscription'}
              </button>

              {error && <div className="text-sm text-red-600">{error}</div>}

              {status && (
                <div className="text-sm text-muted-foreground">
                  Status: <span className="font-medium">{status.status}</span>
                  {status.activeUntil && (
                    <>
                      {' '}• Active until {new Date(status.activeUntil).toLocaleString()}
                    </>
                  )}
                </div>
              )}
            </div>

            <div>
              {!checkout ? (
                <div className="border border-dashed rounded-md p-6 text-muted-foreground">
                  After you start, the Phantom QR will appear here.
                </div>
              ) : (
                <div className="space-y-4">
                  <div>
                    <img src={checkout.qrDataUrl} alt="Phantom QR" className="w-60 h-60 border rounded-md" />
                  </div>
                  <div>
                    <a href={checkout.phantomUrl} target="_blank" rel="noreferrer" className="underline text-primary">
                      Open in Phantom
                    </a>
                  </div>
                  <div className="text-xs text-muted-foreground">Order: {checkout.orderId}</div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Overlay Message */}
        <div className="absolute inset-0 flex flex-col items-center justify-center z-10 text-center bg-black/60 backdrop-blur-sm">
          <h1 className="text-5xl font-bold text-white mb-4">
            🎉 Grand Opening — API Access is <span className="text-purple-400">100% Free!</span>
          </h1>
          <p className="text-lg text-gray-200 max-w-2xl">
            No payments, no USDC transfers — our platform is <strong>completely free</strong> for early adopters.
            Build and test your subscription products seamlessly on Solana 🔥
          </p>
        </div>
      </main>
      <Footer />
    </div>
  );
}
