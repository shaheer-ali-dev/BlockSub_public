import React, { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';

type SubResp = {
  subscription_id: string;
  status: string;
  plan?: string;
  price_usd?: number;
  wallet_address?: string | null;
  next_billing_date?: string | null;
  trial_active?: boolean;
};

export default function SubscriptionConnectSuccess() {
  const [params] = useSearchParams();
  const subscriptionId = params.get('subscription_id') || '';
  const navigate = useNavigate();
  const [sub, setSub] = useState<SubResp | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!subscriptionId) { setError('Missing subscription_id'); setLoading(false); return; }
    let mounted = true;

    async function fetchSub() {
      try {
        const res = await fetch(`/api/recurring-subscriptions/${encodeURIComponent(subscriptionId)}`, {
          headers: { 'Content-Type': 'application/json' /* add Authorization if needed */ },
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        if (!mounted) return;
        setSub(json);
        setLoading(false);

        // If the subscription immediately requires payment (pending_payment), go to the payment page
        if (json.status === 'pending_payment') {
          navigate(`/subscription/payment-pending?subscription_id=${encodeURIComponent(subscriptionId)}`);
        }
      } catch (e: any) {
        setError(e.message || String(e));
        setLoading(false);
      }
    }

    fetchSub();
    const t = setInterval(fetchSub, 5000); // poll until state changes
    return () => { mounted = false; clearInterval(t); };
  }, [subscriptionId, navigate]);

  if (loading) return <div>Loading subscription…</div>;
  if (error) return <div>Error: {error}</div>;
  if (!sub) return <div>No subscription data</div>;

  return (
    <div style={{padding:20}}>
      <h2>Wallet connected</h2>
      <p>Subscription: <strong>{sub.subscription_id}</strong></p>
      <p>Status: <strong>{sub.status}</strong></p>
      <p>Plan: {sub.plan} — ${sub.price_usd}</p>
      {sub.trial_active ? (
        <p>Your trial is active and ends: {sub.next_billing_date}</p>
      ) : (
        <p>Next billing: {sub.next_billing_date ?? 'pending'}</p>
      )}
      <p>
        To complete setup open the app or check payments page:
        <br/>
        <a href={`/subscription/details?subscription_id=${encodeURIComponent(sub.subscription_id)}`}>View subscription details</a>
      </p>
    </div>
  );
}
