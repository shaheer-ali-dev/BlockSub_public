import React, { useEffect, useState } from "react";
import { useLocation } from "wouter";
import { BookOpen, Key } from "lucide-react";

type Intent = {
  payment_id?: string;
  phantom_url?: string | null;
  qr_data_url?: string | null;
  unsigned_tx?: string | null;
  expires_at?: string | null;
};

export default function SubscriptionPaymentPending() {
  const [location] = useLocation();
  const qs = React.useMemo(() => new URLSearchParams(location.split("?")[1] || ""), [location]);
  const subscriptionId = qs.get("subscription_id") || "";
  const paymentIdFromQuery = qs.get("payment_id") || "";

  const [intent, setIntent] = useState<Intent | null>(null);
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!subscriptionId) {
      setError("Missing subscription_id");
      setStatus("error");
      return;
    }
    let mounted = true;

    async function fetchIntent() {
      try {
        // Try to list payment orders for this subscription
        const poRes = await fetch(`/api/payment-orders?subscriptionId=${encodeURIComponent(subscriptionId)}`);
        let found: any = null;
        if (poRes.ok) {
          const list = await poRes.json();
          found = (list?.orders || []).find((o: any) => o.subscriptionId === subscriptionId && (o.status === "pending" || o.status === "created"));
        }

        // fallback to server-provided payment id in query
        if (!found && paymentIdFromQuery) {
          const r = await fetch(`/api/payment-order/${encodeURIComponent(paymentIdFromQuery)}`);
          if (r.ok) found = await r.json();
        }

        // Another fallback: the subscription endpoint might include a recent payment intent
        if (!found) {
          const s = await fetch(`/api/recurring-subscriptions/${encodeURIComponent(subscriptionId)}`);
          if (s.ok) {
            const sub = await s.json();
            // server might include payment intent fields on the subscription; try to use known props
            // (adjust here if your server returns createdIntent on subscription)
          }
        }

        if (!mounted) return;
        if (found) {
          setIntent({
            payment_id: found.orderId || found.paymentId,
            phantom_url: found.phantomUrl || found.phantom_url,
            qr_data_url: found.phantomQrDataUrl || found.qr_data_url || found.qrDataUrl,
            unsigned_tx: found.unsignedTxB64 || found.unsigned_tx,
            expires_at: found.expiresAt || found.expires_at,
          });
        } else {
          setIntent(null);
        }
        setStatus("ready");
      } catch (e: any) {
        if (!mounted) return;
        setError(String(e?.message || e));
        setStatus("error");
      }
    }

    fetchIntent();
    const t = setInterval(fetchIntent, 4000);
    return () => {
      mounted = false;
      clearInterval(t);
    };
  }, [subscriptionId, paymentIdFromQuery]);

  if (status === "loading") return <div style={{ padding: 20 }}>Loading payment intent…</div>;
  if (status === "error") return <div style={{ padding: 20, color: "crimson" }}>Error: {error}</div>;

  return (
    <div style={{ padding: 20, maxWidth: 820, margin: "0 auto" }}>
      <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 12 }}>
        <Key size={26} />
        <h2 style={{ margin: 0 }}>Complete initial payment</h2>
      </div>

      <div style={{ padding: 12, borderRadius: 8, background: "#fff", boxShadow: "0 6px 18px rgba(0,0,0,0.06)" }}>
        <div>
          <strong>Subscription:</strong> {subscriptionId}
        </div>

        {intent ? (
          <>
            <div style={{ marginTop: 12 }}>
              <strong>Payment ID:</strong> {intent.payment_id}
            </div>

            {intent.phantom_url ? (
              <div style={{ marginTop: 12 }}>
                <a
                  href={intent.phantom_url}
                  onClick={() => (window.location.href = intent.phantom_url || "#")}
                  style={{ display: "inline-block", padding: "10px 14px", background: "#4f46e5", color: "#fff", borderRadius: 8, textDecoration: "none" }}
                >
                  Open Phantom
                </a>
              </div>
            ) : null}

            {intent.qr_data_url ? (
              <div style={{ marginTop: 12 }}>
                <div style={{ marginBottom: 8 }}>Or scan QR with Phantom mobile:</div>
                <img src={intent.qr_data_url} alt="payment qr" style={{ maxWidth: 320, borderRadius: 8, border: "1px solid #eee" }} />
              </div>
            ) : (
              <p style={{ marginTop: 12 }}>No deeplink or QR available yet; wait a few seconds and refresh.</p>
            )}

            <p style={{ marginTop: 16 }}>After signing in Phantom the server will verify the tx and update the subscription.</p>
          </>
        ) : (
          <div>
            <p>No payment intent found yet. Wait a few seconds for the server to create the initial payment or check the subscription details.</p>
          </div>
        )}
      </div>
    </div>
  );
}
