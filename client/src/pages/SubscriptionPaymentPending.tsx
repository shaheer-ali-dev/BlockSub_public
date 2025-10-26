import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

type Intent = {
  payment_id?: string;
  phantom_url?: string | null;
  qr_data_url?: string | null;
  unsigned_tx?: string | null;
  expires_at?: string | null;
};

export default function SubscriptionPaymentPending() {
  const [params] = useSearchParams();
  const subscriptionId = params.get('subscription_id') || '';
  const paymentId = params.get('payment_id') || '';
  const [intent, setIntent] = useState<Intent | null>(null);
  const [status, setStatus] = useState<string>('loading');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!subscriptionId) { setError('Missing subscription_id'); setStatus('error'); return; }

    let mounted = true;

    async function fetchIntent() {
      try {
        // 1) Try to get subscription detail which may include initial payment intent in some flows
        const subRes = await fetch(`/api/recurring-subscriptions/${encodeURIComponent(subscriptionId)}`, { headers: { 'Content-Type': 'application/json' } });
        if (!subRes.ok) throw new Error(`Subscription fetch failed: ${subRes.status}`);
        const sub = await subRes.json();

        // 2) Optionally, your backend might return the initial created intent in the create / connect redirect.
        // If not, you might need to call another endpoint to fetch the last PaymentOrder; for now try a best-effort fetch:
        const poRes = await fetch(`/api/payment-orders?subscriptionId=${encodeURIComponent(subscriptionId)}`); // implement or adapt on server if needed
        let found: any = null;
        if (poRes.ok) {
          const list = await poRes.json();
          // look for pending order
          found = list?.orders?.find((o: any) => o.subscriptionId === subscriptionId && (o.status === 'pending' || o.status === 'created'));
        }

        // fallback: use query param payment_id for the redirect case
        if (!found && paymentId) {
          // call endpoint that returns PaymentOrder by id if available
          const r = await fetch(`/api/payment-order/${encodeURIComponent(paymentId)}`);
          if (r.ok) found = await r.json();
        }

        let newIntent: Intent | null = null;
        if (found) {
          newIntent = {
            payment_id: found.orderId || found.paymentId || paymentId,
            phantom_url: found.phantomUrl || found.phantom_url || found.phantom_url,
            qr_data_url: found.phantomQrDataUrl || found.qr_data_url || found.qrDataUrl,
            unsigned_tx: found.unsignedTxB64 || found.unsigned_tx,
            expires_at: found.expiresAt || found.expires_at,
          };
        }

        if (mounted) {
          setIntent(newIntent);
          setStatus('ready');
        }
      } catch (e: any) {
        if (mounted) { setError(String(e)); setStatus('error'); }
      }
    }

    fetchIntent();
    const t = setInterval(fetchIntent, 4000);
    return () => { mounted = false; clearInterval(t); };
  }, [subscriptionId, paymentId]);

  if (status === 'loading') return <div>Loading payment intent…</div>;
  if (status === 'error') return <div>Error: {error}</div>;

  return (
    <div style={{padding:20}}>
      <h2>Complete your initial payment</h2>
      <p>Subscription: <strong>{subscriptionId}</strong></p>
      {intent ? (
        <>
          <p>Payment id: <strong>{intent.payment_id}</strong></p>

          {intent.phantom_url ? (
            <div>
              <p>Open in Phantom:</p>
              <a href={intent.phantom_url} onClick={() => { window.location.href = intent.phantom_url || '#'; }} style={{display:'inline-block', padding:'10px 14px', background:'#5123ff', color:'#fff', borderRadius:8, textDecoration:'none'}}>Open Phantom</a>
            </div>
          ) : null}

          {intent.qr_data_url ? (
            <div style={{marginTop: 16}}>
              <p>Or scan QR with your Phantom mobile:</p>
              <img alt="payment qr" src={intent.qr_data_url} style={{maxWidth:320, border:'1px solid #eee', borderRadius:8}} />
            </div>
          ) : (<p>No deeplink or QR available; check the payment order record.</p>)}

          <p style={{marginTop:16}}>If the transaction is signed in Phantom, it will redirect you back and the server will verify on-chain. Refresh for status.</p>
        </>
      ) : (
        <div>
          <p>No payment intent found yet. Wait a few seconds for the server to create the initial payment or contact support.</p>
        </div>
      )}
    </div>
  );
}
