import React, { useEffect, useState } from "react";
import { Key, BookOpen, BarChart3 } from "lucide-react";
import { useLocation } from "wouter";

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
  // useLocation gives the path+search; parse query params from location[0]
  const [location] = useLocation();
  const qs = React.useMemo(() => new URLSearchParams(location.split("?")[1] || ""), [location]);
  const subscriptionId = qs.get("subscription_id") || "";

  const [sub, setSub] = useState<SubResp | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    if (!subscriptionId) {
      setError("Missing subscription_id in URL");
      setLoading(false);
      return;
    }

    async function fetchSub() {
      try {
        const res = await fetch(`/api/recurring-subscriptions/${encodeURIComponent(subscriptionId)}`, {
          headers: { "Content-Type": "application/json" },
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        if (!mounted) return;
        setSub(json);
        setLoading(false);
      } catch (e: any) {
        if (!mounted) return;
        setError(String(e?.message || e));
        setLoading(false);
      }
    }

    fetchSub();
    const timer = window.setInterval(fetchSub, 5000);
    return () => {
      mounted = false;
      clearInterval(timer);
    };
  }, [subscriptionId]);

  if (loading) return <div style={{ padding: 20 }}>Loading subscription…</div>;
  if (error) return <div style={{ padding: 20, color: "crimson" }}>Error: {error}</div>;
  if (!sub) return <div style={{ padding: 20 }}>No subscription data</div>;

  return (
    <div style={{ padding: 20, maxWidth: 820, margin: "0 auto" }}>
      <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 16 }}>
        <Key size={28} />
        <h2 style={{ margin: 0 }}>Wallet connected</h2>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <div style={{ padding: 12, borderRadius: 8, background: "#fff", boxShadow: "0 6px 18px rgba(0,0,0,0.06)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <BookOpen size={18} />
            <strong>Subscription</strong>
          </div>
          <div style={{ marginTop: 8 }}>{sub.subscription_id}</div>
          <div style={{ marginTop: 8 }}>Plan: {sub.plan} — ${sub.price_usd}</div>
        </div>

        <div style={{ padding: 12, borderRadius: 8, background: "#fff", boxShadow: "0 6px 18px rgba(0,0,0,0.06)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <BarChart3 size={18} />
            <strong>Billing</strong>
          </div>
          <div style={{ marginTop: 8 }}>
            Status: <strong>{sub.status}</strong>
          </div>
          <div style={{ marginTop: 8 }}>
            {sub.trial_active ? (
              <>Trial active — next billing: {sub.next_billing_date}</>
            ) : (
              <>Next billing: {sub.next_billing_date ?? "pending"}</>
            )}
          </div>
        </div>
      </div>

      <div style={{ marginTop: 18 }}>
        {sub.status === "pending_payment" ? (
          <a
            href={`/subscription/payment-pending?subscription_id=${encodeURIComponent(sub.subscription_id)}`}
            style={{
              display: "inline-block",
              padding: "10px 14px",
              background: "#4f46e5",
              color: "white",
              borderRadius: 8,
              textDecoration: "none",
            }}
          >
            Complete payment
          </a>
        ) : (
          <div>
            <p style={{ marginTop: 12 }}>
              If your subscription is active you’re all set. You can view details or wait for the first billing cycle.
            </p>
            <a href={`/subscription/details?subscription_id=${encodeURIComponent(sub.subscription_id)}`}>View subscription details</a>
          </div>
        )}
      </div>
    </div>
  );
}
