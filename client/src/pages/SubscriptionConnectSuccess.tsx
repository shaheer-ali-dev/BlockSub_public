import React, { useEffect, useState } from "react";
import { Key } from "lucide-react";
import { useLocation } from "wouter";

/**
 * Subscription Connect Success page
 * - Fetches subscription details (including initialize_tx_url / initialize_tx_qr returned by server)
 * - Shows the initialize QR and an "Open in Phantom" link (initialize_tx_url)
 * - Explains the locked amount and monthly billing schedule to the customer/merchant
 */

type SubResp = {
  subscription_id: string;
  status: string;
  plan?: string;
  price_usd?: number;
  wallet_address?: string | null;
  next_billing_date?: string | null;
  trial_active?: boolean;
  // explicit initialize fields (added on server)
  initialize_tx_url?: string | null;
  initialize_tx_qr?: string | null;
  initialize_serialized_tx?: string | null;
  amount_per_month_lamports?: number | null;
  total_months?: number | null;
  locked_amount_lamports?: number | null;
  metadata?: Record<string, any>;
};

function lamportsToSolString(lamports?: number | null) {
  if (!lamports && lamports !== 0) return "—";
  return (Number(lamports) / 1e9).toFixed(6) + " SOL";
}

export default function SubscriptionConnectSuccess() {
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
        const apiKey = "sk_test_6d2c2be52a83263537b5fe3e0650f5e5fa93347b7ec154a0e115934f4fb8621f";
        const res = await fetch(`/api/recurring-subscriptions/${encodeURIComponent(subscriptionId)}`, {
          method: "GET",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${apiKey}`,
          },
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

  const {
    initialize_tx_qr,
    initialize_tx_url,
    amount_per_month_lamports,
    total_months,
    locked_amount_lamports,
    price_usd,
  } = sub;

  // readable explanation (client side)
  const perMonthSOL = amount_per_month_lamports ? (amount_per_month_lamports / 1e9).toFixed(6) : "—";
  const lockedSOL = locked_amount_lamports ? (locked_amount_lamports / 1e9).toFixed(6) : "—";
  const months = total_months ?? "—";

  return (
    <div style={{ padding: 20, maxWidth: 900, margin: "0 auto" }}>
      <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 16 }}>
        <Key size={28} />
        <h2 style={{ margin: 0 }}>Wallet connected — complete initialization</h2>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 380px", gap: 16 }}>
        <div style={{ padding: 16, borderRadius: 8, background: "#fff", boxShadow: "0 6px 18px rgba(0,0,0,0.06)" }}>
          <h3 style={{ marginTop: 0 }}>What we need from you</h3>

          <p>
            We will ask you to sign an initialize transaction that transfers a one‑time locked amount into an on‑chain escrow.
            The locked amount covers the subscription for the configured term and will be released to the merchant monthly.
          </p>

          <div style={{ marginTop: 12 }}>
            <strong>Summary</strong>
            <table style={{ width: "100%", marginTop: 8 }}>
              <tbody>
                <tr>
                  <td style={{ padding: 6 }}>Price (USD):</td>
                  <td style={{ padding: 6, textAlign: "right" }}>{price_usd ? `$${price_usd.toFixed(2)}` : "—"}</td>
                </tr>
                <tr>
                  <td style={{ padding: 6 }}>Amount per month (SOL):</td>
                  <td style={{ padding: 6, textAlign: "right" }}>{perMonthSOL} SOL</td>
                </tr>
                <tr>
                  <td style={{ padding: 6 }}>Total months:</td>
                  <td style={{ padding: 6, textAlign: "right" }}>{months}</td>
                </tr>
                <tr>
                  <td style={{ padding: 6 }}>Locked amount (SOL):</td>
                  <td style={{ padding: 6, textAlign: "right" }}>{lockedSOL} SOL</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div style={{ marginTop: 14 }}>
            <strong>How this works</strong>
            <ol style={{ marginTop: 8 }}>
              <li>By signing the initialize transaction you fund the escrow with the locked amount.</li>
              <li>Every month a worker/relayer will call a release operation that transfers the monthly amount from escrow to the merchant.</li>
              <li>If the escrow lacks funds for a scheduled release the release will fail and the subscription records a failed attempt.</li>
            </ol>
          </div>

          <div style={{ marginTop: 14 }}>
            <strong>Complete initialization</strong>
            <p style={{ marginTop: 8 }}>
              Scan the QR with Phantom mobile or click "Open in Phantom" from a mobile device to open Phantom and sign the initialize transaction.
            </p>
            <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 8 }}>
              {initialize_tx_url ? (
                <a
                  href={initialize_tx_url}
                  target="_blank"
                  rel="noreferrer"
                  style={{
                    display: "inline-block",
                    padding: "10px 14px",
                    background: "#512bd4",
                    color: "#fff",
                    borderRadius: 8,
                    textDecoration: "none",
                  }}
                >
                  Open in Phantom
                </a>
              ) : (
                <div style={{ color: "#666" }}>Initialize URL not available</div>
              )}
            </div>
          </div>
        </div>

        <div style={{ padding: 12 }}>
          <div style={{ textAlign: "center" }}>
            <div style={{ marginBottom: 8, color: "#666" }}>Scan to open in Phantom</div>
            {initialize_tx_qr ? (
              <img
                alt="Initialize transaction QR"
                src={initialize_tx_qr}
                style={{ width: 320, height: 320, borderRadius: 12, border: "1px solid #eee" }}
              />
            ) : (
              <div style={{ width: 320, height: 320, display: "flex", alignItems: "center", justifyContent: "center", border: "1px dashed #ddd", borderRadius: 12 }}>
                <div style={{ color: "#999" }}>QR not available</div>
              </div>
            )}

            <div style={{ marginTop: 12, fontSize: 13, color: "#555" }}>
              By signing the initialize transaction you authorize the transfer of the locked amount into escrow.
              The worker will then release the configured monthly amount to the merchant automatically.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
