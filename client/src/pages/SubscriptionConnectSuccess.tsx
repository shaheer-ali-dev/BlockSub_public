import React, { useEffect, useState } from "react";
import { Key } from "lucide-react";
import { useLocation } from "wouter";

/**
 * Subscription Connect Success page
 * - Prefer query params provided by server redirect (initialize_tx_url, amounts, brief)
 * - If query params missing, fallback to public GET endpoint: /api/recurring-subscriptions/public/:subscriptionId
 * - Avoid calling authenticated endpoints here to prevent 401/token-refresh loops
 */

type QuickInit = {
  initialize_tx_url?: string | null;
  amount_per_month_lamports?: number | null;
  total_months?: number | null;
  locked_amount_lamports?: number | null;
  init_brief?: string | null;
};

function lamportsToSolString(lamports?: number | null) {
  if (lamports === null || lamports === undefined) return "—";
  return (Number(lamports) / 1e9).toFixed(6) + " SOL";
}

export default function SubscriptionConnectSuccess() {
  const [location] = useLocation();
  const qs = React.useMemo(() => new URLSearchParams(location.split("?")[1] || ""), [location]);
  const subscriptionId = qs.get("subscription_id") || "";

  const [initData, setInitData] = useState<QuickInit | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    if (!subscriptionId) {
      setError("Missing subscription_id in URL");
      setLoading(false);
      return;
    }

    // 1) Prefer redirect-provided data
    const initUrl = qs.get("initialize_tx_url");
    const amountPerMonth = qs.get("amount_per_month_lamports");
    const totalMonths = qs.get("total_months");
    const lockedAmount = qs.get("locked_amount_lamports");
    const brief = qs.get("init_brief");

    if (initUrl) {
      const parsed: QuickInit = {
        initialize_tx_url: decodeURIComponent(initUrl),
        amount_per_month_lamports: amountPerMonth ? Number(amountPerMonth) : null,
        total_months: totalMonths ? Number(totalMonths) : null,
        locked_amount_lamports: lockedAmount ? Number(lockedAmount) : null,
        init_brief: brief ? decodeURIComponent(brief) : null,
      };
      setInitData(parsed);
      setLoading(false);
      return;
    }

    // 2) Fallback: call the public read-only endpoint (no auth required)
    async function fetchPublic() {
      try {
        const res = await fetch(`/api/recurring-subscriptions/public/${encodeURIComponent(subscriptionId)}`, {
          method: "GET",
          headers: { "Content-Type": "application/json" },
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        if (!mounted) return;
        setInitData({
          initialize_tx_url: json.initialize_tx_url || null,
          amount_per_month_lamports: json.amount_per_month_lamports ?? null,
          total_months: json.total_months ?? null,
          locked_amount_lamports: json.locked_amount_lamports ?? null,
          init_brief: null,
        });
        setLoading(false);
      } catch (e: any) {
        if (!mounted) return;
        setError(String(e?.message || e));
        setLoading(false);
      }
    }

    fetchPublic();
    return () => {
      mounted = false;
    };
  }, [qs, subscriptionId]);

  if (loading) return <div style={{ padding: 20 }}>Loading…</div>;
  if (error) return <div style={{ padding: 20, color: "crimson" }}>Error: {error}</div>;
  if (!initData) return <div style={{ padding: 20 }}>No initialize data</div>;

  const {
    initialize_tx_url,
    amount_per_month_lamports,
    total_months,
    locked_amount_lamports,
    init_brief,
  } = initData;

  // Create a QR that opens initialize_tx_url (we use a public QR generator to avoid shipping base64)
  const qrImageSrc = initialize_tx_url
    ? `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(initialize_tx_url)}&size=320x320`
    : null;

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
                  <td style={{ padding: 6 }}>Amount per month:</td>
                  <td style={{ padding: 6, textAlign: "right" }}>{lamportsToSolString(amount_per_month_lamports)}</td>
                </tr>
                <tr>
                  <td style={{ padding: 6 }}>Total months:</td>
                  <td style={{ padding: 6, textAlign: "right" }}>{total_months ?? "—"}</td>
                </tr>
                <tr>
                  <td style={{ padding: 6 }}>Locked amount:</td>
                  <td style={{ padding: 6, textAlign: "right" }}>{lamportsToSolString(locked_amount_lamports)}</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div style={{ marginTop: 14 }}>
            <strong>How this works</strong>
            <ol style={{ marginTop: 8 }}>
              <li>Sign the initialize transaction to fund the escrow with the locked amount.</li>
              <li>Each month the worker/relayer will release the monthly amount from escrow to the merchant.</li>
              <li>If the escrow lacks funds for a release, the attempt will fail and be recorded.</li>
            </ol>
          </div>

          {init_brief ? (
            <div style={{ marginTop: 12, color: "#333", fontWeight: 500 }}>{init_brief}</div>
          ) : null}

          <div style={{ marginTop: 14 }}>
            <strong>Complete initialization</strong>
            <p style={{ marginTop: 8 }}>
              Scan with Phantom mobile or click the link on a mobile device to open Phantom and sign the initialize transaction.
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
            {qrImageSrc ? (
              <img alt="Initialize transaction QR" src={qrImageSrc} style={{ width: 320, height: 320, borderRadius: 12, border: "1px solid #eee" }} />
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
