import { Express, Request, Response } from "express";
import { v4 as uuidv4 } from "uuid";
import crypto from "crypto";
import bs58 from "bs58";
import { ApiKeyAuthenticatedRequest, authenticateApiKey } from "../shared/auth";
import {
  RecurringSubscription,
  createRecurringSubscriptionSchema,
} from "../shared/recurring-subscription-schema";

import { generateWalletConnectionQR, decryptPhantomCallbackData, buildInitializeUrlAndQr } from "./phantom-wallet-utils";
import { buildInitializeSubscriptionTx, cancelOnChainSubscription } from "./solana-anchor";
import { enqueueWebhookDelivery } from "./webhook-delivery";

function getEnv(key: string, fallback?: string) {
  const v = process.env[key];
  if (typeof v === "string" && v.length > 0) return v;
  return fallback;
}
async function fetchSolPriceUsd(): Promise<number> {
  // Allow manual override for deterministic testing / staging
  const envPrice = process.env.SOL_USD_PRICE;
  if (envPrice) {
    const v = Number(envPrice);
    if (Number.isFinite(v) && v > 0) return v;
  }

  // Try fetch from CoinGecko
  try {
    // Node18+ has global fetch; fall back to node-fetch dynamic import if not available
    let fetchFn: any = (global as any).fetch;
    if (typeof fetchFn !== "function") {
      const mod = await import("node-fetch");
      fetchFn = mod.default || mod;
    }
    const url = "https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd";
    const resp = await fetchFn(url, { method: "GET" });
    if (!resp.ok) throw new Error(`CoinGecko ${resp.status}`);
    const json = await resp.json();
    const p = Number(json?.solana?.usd ?? 0);
    if (Number.isFinite(p) && p > 0) return p;
  } catch (e) {
    console.warn("fetchSolPriceUsd: coinGecko fetch failed, falling back to default", e instanceof Error ? e.message : String(e));
  }

  // Fallback default (reasonable devnet testing value) — you should set SOL_USD_PRICE in prod
  const fallback = 20; // USD per SOL fallback
  return fallback;
}
export function registerRecurringSubscriptionRoutes(app: Express) {
  // Create subscription and return wallet connection QR + deeplink
  app.post("/api/recurring-subscriptions", authenticateApiKey(0.0), async (req: ApiKeyAuthenticatedRequest, res: Response) => {
    try {
      const parse = createRecurringSubscriptionSchema.safeParse(req.body);
      if (!parse.success) {
        return res.status(400).json({ error: "invalid_request", details: parse.error.flatten() });
      }

      const data = parse.data;

      // Ensure apiKey info from middleware
      const apiKey = req.apiKey;
      if (!apiKey || !apiKey._id) {
        return res.status(401).json({ error: "api_key_required" });
      }

      const subscriptionId = `rsub_${uuidv4().replace(/-/g, "")}`;

      // Calculate trial end date (if provided)
      let trialEndDate: Date | undefined = undefined;
      if (typeof data.trialDays === "number" && data.trialDays > 0) {
        trialEndDate = new Date(Date.now() + data.trialDays * 24 * 60 * 60 * 1000);
      }

      // Create subscription and include required apiKeyId and userId fields
      const subDoc = await RecurringSubscription.create({
        subscriptionId,
        userId: apiKey.userId,
        apiKeyId: apiKey._id,
        merchantAddress: data.merchant,
        plan: data.plan,
        priceUsd: data.priceUsd,
        billingInterval: data.billingInterval || "monthly",
        asset: data.asset || "SPL",
        tokenMint: data.tokenMint || undefined,
        webhookUrl: data.webhookUrl || undefined,
        metadata: data.metadata || {},
        trialEndDate: trialEndDate,
        status: "pending_wallet_connection",
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      // Build a connection message + nonce for the wallet connection.
      const timestamp = Date.now();
      const message = `Connect subscription ${subscriptionId} at ${timestamp}`;
      const nonceRaw = crypto.randomBytes(24);
      const nonceB58 = bs58.encode(nonceRaw);

      const dappUrl = process.env.PHANTOM_DAPP_URL || "";
      const dappEncryptionPublicKey = process.env.PHANTOM_DAPP_ENCRYPTION_PUBLIC_KEY;

      const connectionRequest = {
        subscriptionId,
        message,
        nonce: nonceB58,
        timestamp,
        dappUrl,
        dappEncryptionPublicKey,
      };

      // Persist the connection message/nonce in subscription metadata for later verification
      subDoc.metadata = { ...(subDoc.metadata || {}), walletConnectionMessage: message, walletConnectionNonce: nonceB58 };
      await subDoc.save();

      // Generate QR + deeplink using existing helper
      const qr = await generateWalletConnectionQR(connectionRequest);

      return res.json({
        subscription_id: subscriptionId,
        status: subDoc.status,
        wallet_connection: {
          qr_data_url: qr.qrCodeDataUrl,
          deeplink: qr.deeplink,
          connection_url: qr.connectionUrl,
          message,
          nonce: nonceB58,
          expires_at: qr.expiresAt,
        }
      });
    } catch (err) {
      console.log("POST /api/subscription failed", { error: err instanceof Error ? err.message : String(err) });
      return res.status(500).json({ error: "internal_error" });
    }
  });

  // Public Phantom connect callback (minimal). For debugging: decrypt and log payload + public key.
  app.get("/api/recurring-subscriptions/phantom/connect-callback/:subscriptionId?", async (req: Request, res: Response) => {
    // Outer handler try/catch to catch unexpected errors and redirect to error page
    try {
      const subscriptionId = (req.params && (req.params as any).subscriptionId) || (req.query && req.query.subscription_id);
      const phantom_encryption_public_key = (req.query.phantom_encryption_public_key || req.query.phantom_pub_key || req.query.phantom_public_key) as string | undefined;
      const data = req.query.data as string | undefined;
      const nonce = req.query.nonce as string | undefined;

      if (!subscriptionId || typeof subscriptionId !== "string") {
        console.log("Phantom callback missing subscription id", { params: req.params, query: req.query });
        return res.status(400).json({ error: "missing_subscription_id" });
      }

      console.log('[routes] query params:', {
        subscriptionId,
        phantom_encryption_public_key: phantom_encryption_public_key ? `${phantom_encryption_public_key.slice(0, 12)}...` : null,
        nonce: nonce ? `${nonce.slice(0, 12)}...` : null,
        data: data ? `${data.slice(0, 12)}...` : null,
      });

      // Load subscription early
      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      if (!subscription) {
        console.log(`[phantom-callback] subscription not found: ${subscriptionId}`);
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "");
        return res.redirect(`${frontendUrl}/subscription/connect-error?error=subscription_not_found`);
      }

      // If no encrypted payload, fallback to success redirect (use previously stored anchor details if available)
      if (!phantom_encryption_public_key || !data || !nonce) {
        console.log(`[phantom-callback] no encrypted payload received for subscription ${subscriptionId}`);

        const anchorMeta = (subscription.metadata && (subscription.metadata as any).anchor) || {};
        const redirectInitUrl = anchorMeta.initializeTxUrl || null;
        const amountPerMonthLamports = anchorMeta.amountPerMonthLamports;
        const totalMonths = anchorMeta.totalMonths;
        const lockedAmountLamports = anchorMeta.lockedAmountLamports;

        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "") || "";
        const q: string[] = [
          `subscription_id=${encodeURIComponent(subscriptionId)}`
        ];
        if (redirectInitUrl) q.push(`initialize_tx_url=${encodeURIComponent(String(redirectInitUrl))}`);
        if (typeof amountPerMonthLamports !== "undefined" && amountPerMonthLamports !== null) q.push(`amount_per_month_lamports=${encodeURIComponent(String(amountPerMonthLamports))}`);
        if (typeof totalMonths !== "undefined" && totalMonths !== null) q.push(`total_months=${encodeURIComponent(String(totalMonths))}`);
        if (typeof lockedAmountLamports !== "undefined" && lockedAmountLamports !== null) q.push(`locked_amount_lamports=${encodeURIComponent(String(lockedAmountLamports))}`);
        const brief = lockedAmountLamports ? `The subscriber will fund escrow with ${lockedAmountLamports} lamports which covers ${totalMonths} month(s).` : "";
        if (brief) q.push(`init_brief=${encodeURIComponent(brief)}`);

        const redirectUrl = `${frontendUrl.replace(/\/$/, "")}/subscription/connect-success?${q.join("&")}`;
        return res.redirect(redirectUrl);
      }

      // Attempt decryption & parse
      let decryptedPayload: string | null = null;
      try {
        decryptedPayload = decryptPhantomCallbackData(String(phantom_encryption_public_key), String(data), String(nonce));
      } catch (e) {
        console.log(`[phantom-callback] decrypt failed for subscription ${subscriptionId}`, { error: e instanceof Error ? e.message : String(e) });
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "");
        return res.redirect(`${frontendUrl}/subscription/connect-error?error=callback_decrypt_failed`);
      }

      let parsed: any = {};
      try {
        parsed = JSON.parse(decryptedPayload as string);
      } catch (e) {
        console.log(`[phantom-callback] decrypted payload not JSON for subscription ${subscriptionId}`, { decrypted: decryptedPayload });
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "");
        return res.redirect(`${frontendUrl}/subscription/connect-error?error=payload_not_json`);
      }

      const walletAddress = parsed.publicKey || parsed.public_key || parsed.pubkey || parsed.wallet;
      if (!walletAddress) {
        console.log(`[phantom-callback] decrypted payload missing publicKey for subscription ${subscriptionId}`, { parsed });
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "");
        return res.redirect(`${frontendUrl}/subscription/connect-error?error=missing_public_key`);
      }

      // Attach wallet and set pending_onchain_initialize
      console.log(`[phantom-callback] attaching walletAddress ${walletAddress} to subscription ${subscriptionId}`);
      subscription.walletAddress = walletAddress;

      // Build initialize tx for the subscriber (so they can sign/fund escrow)
      try {
        const merchant = subscription.merchantAddress || getEnv('MERCHANT_SOL_ADDRESS', '');
        if (!merchant) {
          console.log('MERCHANT_SOL_ADDRESS is not configured and subscription missing merchantAddress; skipping initialize tx build');
          // Persist wallet and pending_payment status instead
          subscription.status = 'pending_payment';
          await subscription.save();

          const frontendUrl = getEnv("PHANTOM_DAPP_URL", "");
          return res.redirect(`${frontendUrl}/subscription/connect-success?subscription_id=${encodeURIComponent(subscriptionId)}`);
        }

        // convert priceUsd -> lamports (simple example; replace with real price oracle/conversion)
const solPriceUsd = await fetchSolPriceUsd(); // USD per SOL
// subscription.priceUsd is the USD amount per month (e.g. 5.00)
// Compute SOL amount = priceUsd / solPriceUsd
// Convert to lamports (1 SOL = 1e9 lamports) and round to integer lamports.
const priceUsd = Number(subscription.priceUsd || 0) || 0;
if (!(priceUsd > 0)) {
  // Ensure a minimum non-zero value to avoid locking zero lamports
  // You can override via subscription.metadata if needed
}
const solAmount = priceUsd / solPriceUsd;
const amountPerMonthLamports = Math.max(
  1,
  Math.round(solAmount * 1e9) // lamports
);
        const totalMonths = (subscription.metadata && (subscription.metadata as any).totalMonths) || 12;
        const lockedAmountLamports = (subscription.metadata && (subscription.metadata as any).lockedAmountLamports) || (amountPerMonthLamports * totalMonths);

        const txInfo = await buildInitializeSubscriptionTx({
          merchantPubkey: merchant,
          subscriberPubkey: walletAddress,
          amountPerMonthLamports,
          totalMonths,
          lockedAmountLamports
        });

        // Build initialize URL/QR (pass serialized tx so helper can create Phantom deeplink QR for devnet)
        const { initializeTxUrl, initializeTxQr, phantomDeeplink } = await buildInitializeUrlAndQr(subscriptionId, txInfo.serializedTxBase64);
console.log('[phantom-callback] txInfo.serializedTxBase64 present:', !!txInfo.serializedTxBase64);
console.log('[phantom-callback] buildInitializeUrlAndQr returned phantomDeeplink:', typeof phantomDeeplink === 'string' ? (phantomDeeplink.length > 200 ? phantomDeeplink.slice(0,200) + '...' : phantomDeeplink) : null);
console.log('[phantom-callback] initializeTxUrl (site fallback):', initializeTxUrl);
console.log('[phantom-callback] initializeTxQr present:', !!initializeTxQr);

// If we have a phantomDeeplink but the QR does not look like it encodes it (or is missing), regenerate the QR for phantomDeeplink.
let finalInitializeTxQr = initializeTxQr;
if (phantomDeeplink && (!finalInitializeTxQr || !finalInitializeTxQr.startsWith('data:image'))) {
  try {
    const QRCode = (await import('qrcode')).default;
    finalInitializeTxQr = String(await QRCode.toDataURL(phantomDeeplink, { errorCorrectionLevel: 'M', width: 320 }));
    console.log('[phantom-callback] regenerated initializeTxQr from phantomDeeplink (len):', finalInitializeTxQr.length);
  } catch (qrErr) {
    console.error('[phantom-callback] failed to regenerate QR for phantomDeeplink', qrErr);
  }
}

// Persist the phantom deeplink and the QR that encodes it (guarantees DB has the correct QR)
subscription.metadata = {
  ...(subscription.metadata || {}),
  anchor: {
    ...(subscription.metadata && subscription.metadata.anchor ? subscription.metadata.anchor : {}),
    subscriptionPda: txInfo.subscriptionPda,
    escrowPda: txInfo.escrowPda,
    subscriptionBump: txInfo.subscriptionBump,
    escrowBump: txInfo.escrowBump,
    amountPerMonthLamports,
    totalMonths,
    lockedAmountLamports,
    serializedTxBase64: txInfo.serializedTxBase64,
    initializeTxUrl,                     // site fallback page
    initializeTxQr: finalInitializeTxQr, // QR that should encode phantomDeeplink
    phantomDeeplink: phantomDeeplink || null,
  }
};
await subscription.save();

// Use finalInitializeTxQr and phantomDeeplink in webhook payload (merchant gets direct phantom link + QR)
const webhookPayload = {
  subscription_id: subscriptionId,
  initialize_tx_url: phantomDeeplink || initializeTxUrl, // prefer direct phantom link
  initialize_tx_qr: finalInitializeTxQr,
  phantom_deeplink: phantomDeeplink || null,
  serializedTxBase64: txInfo.serializedTxBase64,
  subscription_pda: txInfo.subscriptionPda,
  escrow_pda: txInfo.escrowPda,
  status: subscription.status,
  amount_per_month_lamports: amountPerMonthLamports,
  amount_per_month_sol: Number((amountPerMonthLamports / 1e9).toFixed(6)),
  total_months: totalMonths,
  locked_amount_lamports: lockedAmountLamports,
  locked_amount_sol: Number((lockedAmountLamports / 1e9).toFixed(6)),
};
        // Try direct POST, otherwise enqueue
        if (subscription.webhookUrl) {
          try {
            if (typeof (global as any).fetch === 'function') {
              const resp = await (global as any).fetch(subscription.webhookUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(webhookPayload),
              });
              if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
              console.log(`[phantom-callback] posted initialize tx to webhook ${subscription.webhookUrl}`);
            } else {
              const fetchModule = await import('node-fetch');
              const fetchFn = fetchModule.default || fetchModule;
              const resp = await fetchFn(subscription.webhookUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(webhookPayload),
              });
              if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
              console.log(`[phantom-callback] posted initialize tx to webhook ${subscription.webhookUrl}`);
            }
          } catch (postErr) {
            console.log(`[phantom-callback] direct POST to webhook failed, will enqueue delivery`, { error: postErr instanceof Error ? postErr.message : String(postErr) });
            try {
              const enqueueId = await enqueueWebhookDelivery({
                subscriptionId,
                url: subscription.webhookUrl,
                event: 'initialize_tx_ready',
                payload: webhookPayload,
                initialDelaySeconds: 30,
                maxAttempts: 6,
              });
              console.log(`[phantom-callback] enqueued webhook delivery for initialize_tx_ready (id=${String(enqueueId)})`);
            } catch (enqErr) {
              console.log('[phantom-callback] enqueueWebhookDelivery failed', { error: enqErr instanceof Error ? enqErr.message : String(enqErr) });
            }
          }
        }

        // Prepare redirect so the subscriber sees QR and amounts immediately without auth
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "").replace(/\/$/, "");
        const q: string[] = [
          `subscription_id=${encodeURIComponent(subscriptionId)}`,
        ];
        if (initializeTxUrl) q.push(`initialize_tx_url=${encodeURIComponent(initializeTxUrl)}`);
        if (amountPerMonthLamports !== undefined) q.push(`amount_per_month_lamports=${encodeURIComponent(String(amountPerMonthLamports))}`);
        if (totalMonths !== undefined) q.push(`total_months=${encodeURIComponent(String(totalMonths))}`);
        if (lockedAmountLamports !== undefined) q.push(`locked_amount_lamports=${encodeURIComponent(String(lockedAmountLamports))}`);
        const brief = `Subscriber will fund escrow with ${(lockedAmountLamports / 1e9).toFixed(6)} SOL (${lockedAmountLamports} lamports) covering ${totalMonths} month(s).`;
        q.push(`init_brief=${encodeURIComponent(brief)}`);

        const redirectUrl = `${frontendUrl}/subscription/connect-success?${q.join("&")}`;
        return res.redirect(redirectUrl);
      } catch (buildErr) {
        console.log('Failed to build initialize tx for subscription', { subscriptionId, error: buildErr instanceof Error ? buildErr.message : String(buildErr) });
        // keep subscription saved (walletAddress persisted), set to pending_payment so merchant can retry
        subscription.status = 'pending_payment';
        await subscription.save();
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "");
        return res.redirect(`${frontendUrl}/subscription/connect-success?subscription_id=${encodeURIComponent(subscriptionId)}`);
      }
    } catch (error) {
      console.log("Phantom connect callback failed (unexpected)", { error: error instanceof Error ? error.message : String(error) });
      const frontendUrl = getEnv("PHANTOM_DAPP_URL", "");
      return res.redirect(`${frontendUrl}/subscription/connect-error?error=callback_failed`);
    }
  });

  /**
   * GET subscription status/details
   * Requires API key auth (authenticateApiKey attaches req.apiKey)
   */
  app.get("/api/recurring-subscriptions/:subscriptionId", async (req: ApiKeyAuthenticatedRequest, res: Response) => {
    try {
      const { subscriptionId } = req.params;
      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      if (!subscription) return res.status(404).json({ error: "subscription_not_found" });

      const now = new Date();
      const trialActive = !!(subscription.trialEndDate && subscription.trialEndDate > now);

      // Provide initialize tx fields explicitly for frontend convenience
      const anchorMeta = (subscription.metadata && subscription.metadata.anchor) || {};

      return res.json({
        subscription_id: subscription.subscriptionId,
        status: subscription.status,
        plan: subscription.plan,
        price_usd: subscription.priceUsd,
        billing_interval: subscription.billingInterval,
        wallet_address: subscription.walletAddress || null,
        next_billing_date: subscription.nextBillingDate ? subscription.nextBillingDate.toISOString() : null,
        current_period_start: subscription.currentPeriodStart ? subscription.currentPeriodStart.toISOString() : null,
        current_period_end: subscription.currentPeriodEnd ? subscription.currentPeriodEnd.toISOString() : null,
        last_payment_date: subscription.lastPaymentDate ? subscription.lastPaymentDate.toISOString() : null,
        last_payment_signature: subscription.lastPaymentSignature || null,
        failed_payment_attempts: subscription.failedPaymentAttempts || 0,
        auto_renew: subscription.autoRenew,
        cancel_at_period_end: subscription.cancelAtPeriodEnd,
        trial_active: trialActive,
        trial_end_date: subscription.trialEndDate ? subscription.trialEndDate.toISOString() : null,
        canceled_at: subscription.canceledAt ? subscription.canceledAt.toISOString() : null,
        cancellation_reason: subscription.cancellationReason || null,
        created_at: subscription.createdAt ? subscription.createdAt.toISOString() : null,
        updated_at: subscription.updatedAt ? subscription.updatedAt.toISOString() : null,

        // --- Explicit initialize / anchor fields for frontend convenience ---
        initialize_tx_url: anchorMeta.initializeTxUrl || null,
        initialize_tx_qr: anchorMeta.initializeTxQr || null,
        initialize_serialized_tx: anchorMeta.serializedTxBase64 || null,

        // amounts & schedule (from saved anchor metadata when available)
        amount_per_month_lamports: anchorMeta.amountPerMonthLamports || null,
        total_months: anchorMeta.totalMonths || null,
        locked_amount_lamports: anchorMeta.lockedAmountLamports || null,

        // fallback: include the whole metadata (unchanged)
        metadata: subscription.metadata || {},
      });
    } catch (e) {
      console.log("Get subscription failed", e);
      return res.status(500).json({ error: "internal_error" });
    }
  });

  app.delete(
    "/api/recurring-subscriptions/:subscriptionId",
    authenticateApiKey(0.0),
    async (req: ApiKeyAuthenticatedRequest, res: Response) => {
      try {
        const { subscriptionId } = req.params;
        const reason = (req.body && (req.body as any).reason) || "user_requested";

        const subscription = await RecurringSubscription.findOne({ subscriptionId });
        if (!subscription) return res.status(404).json({ error: "subscription_not_found" });

        // Verify ownership
        if (req.apiKey && subscription.apiKeyId !== req.apiKey._id) {
          return res.status(403).json({ error: "forbidden" });
        }

        if (["canceled", "completed"].includes(subscription.status)) {
          return res.status(400).json({ error: "already_canceled_or_completed" });
        }

        // Call the separate cancel function
        const tx = await cancelOnChainSubscription(subscription);

        // Update DB after success
        subscription.status = "canceled";
        subscription.canceledAt = new Date();
        subscription.cancellationReason = reason;
        subscription.autoRenew = false;
        subscription.cancelTx = tx;
        await subscription.save();

        return res.json({
          subscription_id: subscriptionId,
          status: subscription.status,
          canceled_at: subscription.canceledAt?.toISOString(),
          cancellation_reason: subscription.cancellationReason,
          cancel_tx: tx,
        });
      } catch (e) {
        console.error("Cancel subscription failed:", e);
        return res.status(500).json({ error: "internal_error" });
      }
    }
  );

  // Public, minimal read-only endpoint for connect-success page (no auth)
  app.get("/api/recurring-subscriptions/public/:subscriptionId", async (req: Request, res: Response) => {
    try {
      const { subscriptionId } = req.params;
      if (!subscriptionId || typeof subscriptionId !== "string") return res.status(400).json({ error: "missing_subscription_id" });
      const subscription = await RecurringSubscription.findOne({ subscriptionId }).lean();
      if (!subscription) return res.status(404).json({ error: "subscription_not_found" });

      const anchorMeta = (subscription.metadata && (subscription.metadata as any).anchor) || {};

      // Only expose minimal fields required for the connect-success UI
      return res.json({
        subscription_id: subscription.subscriptionId,
        status: subscription.status,
        price_usd: subscription.priceUsd,
        initialize_tx_url: anchorMeta.initializeTxUrl || null,
        initialize_tx_qr: anchorMeta.initializeTxQr || null,
        amount_per_month_lamports: anchorMeta.amountPerMonthLamports || null,
        total_months: anchorMeta.totalMonths || null,
        locked_amount_lamports: anchorMeta.lockedAmountLamports || null,
      });
    } catch (e) {
      console.error("Public GET subscription failed", e);
      return res.status(500).json({ error: "internal_error" });
    }
  });
  // Public minimal page that shows the initialize QR + quick summary.
// This is intentionally server-rendered HTML (no auth) so the user sees something immediately
// after the Phantom callback redirect (query params).
app.get("/subscription/connect-success", async (req: Request, res: Response) => {
  try {
    const subscriptionId = String(req.query.subscription_id || "");
    const initializeTxUrl = String(req.query.initialize_tx_url || "");
    const amountPerMonthLamports = req.query.amount_per_month_lamports ? Number(req.query.amount_per_month_lamports) : null;
    const totalMonths = req.query.total_months ? Number(req.query.total_months) : null;
    const lockedAmountLamports = req.query.locked_amount_lamports ? Number(req.query.locked_amount_lamports) : null;
    const initBrief = String(req.query.init_brief || "");

    const amountPerMonthSol = amountPerMonthLamports ? (amountPerMonthLamports / 1e9).toFixed(6) + " SOL" : "—";
    const lockedAmountSol = lockedAmountLamports ? (lockedAmountLamports / 1e9).toFixed(6) + " SOL" : "—";

    // Build a small QR image using a public QR service so we don't need to embed base64 here
    const qrImage = initializeTxUrl
      ? `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(initializeTxUrl)}&size=320x320`
      : null;

    const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Subscription: Connect Success</title>
  <style>
    body { font-family: system-ui, -apple-system, Arial, sans-serif; background:#f7f8fb; color:#111; margin:0; padding:24px; }
    .card { background:#fff; padding:20px; border-radius:8px; box-shadow:0 6px 20px rgba(0,0,0,0.06); max-width:900px; margin:18px auto; }
    .grid { display:grid; grid-template-columns: 1fr 360px; gap:18px; align-items:start; }
    table { width:100%; border-collapse:collapse; }
    td { padding:6px 8px; }
    .muted { color:#666; font-size:13px; }
    .qr { text-align:center; }
    a.button { display:inline-block; padding:10px 14px; background:#512bd4; color:#fff; border-radius:8px; text-decoration:none; }
  </style>
</head>
<body>
  <div class="card">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px;">
      <h2 style="margin:0">Wallet connected — complete initialization</h2>
    </div>
    <div class="grid">
      <div>
        <p class="muted">Thank you. Please sign the initialize transaction to fund the subscription escrow. This page is public and minimal so you can complete setup immediately.</p>

        <h3>Summary</h3>
        <table>
          <tbody>
            <tr><td>Subscription</td><td style="text-align:right">${subscriptionId || "—"}</td></tr>
            <tr><td>Amount per month</td><td style="text-align:right">${amountPerMonthSol}</td></tr>
            <tr><td>Total months</td><td style="text-align:right">${totalMonths ?? "—"}</td></tr>
            <tr><td>Locked amount</td><td style="text-align:right">${lockedAmountSol}</td></tr>
          </tbody>
        </table>

        ${initBrief ? `<p style="margin-top:12px"><strong>Note:</strong> ${initBrief}</p>` : ""}

        <div style="margin-top:16px">
          ${initializeTxUrl ? `<a class="button" href="${initializeTxUrl}" target="_blank" rel="noreferrer">Open in Phantom / Initialize</a>` : `<div class="muted">Initialize URL not provided</div>`}
        </div>
      </div>

      <div class="qr">
        <div class="muted">Scan with Phantom (mobile)</div>
        ${
          qrImage
            ? `<img src="${qrImage}" alt="initialize qr" style="width:320px;height:320px;border-radius:12px;margin-top:12px;border:1px solid #eee" />`
            : `<div style="width:320px;height:320px;display:flex;align-items:center;justify-content:center;border-radius:12px;border:1px dashed #ddd;margin-top:12px;color:#999">QR not available</div>`
        }
        <p class="muted" style="margin-top:12px">After signing in Phantom you should be redirected back to the app.</p>
      </div>
    </div>
  </div>
</body>
</html>`;

    res.setHeader("content-type", "text/html; charset=utf-8");
    return res.status(200).send(html);
  } catch (e) {
    console.error("connect-success page render failed", e);
    return res.status(500).send("internal_error");
  }
});
app.get("/subscription/initialize-complete", async (req: Request, res: Response) => {
  try {
    const subscriptionId = String(req.query.subscription_id || "").trim();
    if (!subscriptionId) {
      return res.status(400).send("missing subscription_id");
    }

    // Load subscription from DB
    const subscription = await RecurringSubscription.findOne({ subscriptionId });
    if (!subscription) {
      return res.status(404).send("subscription not found");
    }

    // Read anchor metadata (must exist if we built tx earlier)
    const anchorMeta = (subscription.metadata && (subscription.metadata as any).anchor) || {};
    const escrowPdaStr = anchorMeta.escrowPda || null;
    const lockedAmountLamports = Number(anchorMeta.lockedAmountLamports || 0);

    // If we don't have anchor info, render a helpful page and let merchant/user know
    if (!escrowPdaStr || !lockedAmountLamports) {
      const html = `<!doctype html><html><body>
        <h2>Initialization pending</h2>
        <p>No on-chain initialize data found for subscription ${subscriptionId}. If you just signed, wait a moment and click "Re-check".</p>
        <form><input type="hidden" name="subscription_id" value="${subscriptionId}" /><button formaction="/subscription/initialize-complete" formmethod="get">Re-check</button></form>
        </body></html>`;
      res.setHeader("content-type", "text/html; charset=utf-8");
      return res.status(200).send(html);
    }

    // Use RPC to check escrow PDA balance. Hard-code or read RPC_URL from env.
    const rpcUrl = process.env.SOLANA_RPC_URL || "https://api.devnet.solana.com";
    const connection = new Connection(rpcUrl, "confirmed");
    const escrowPda = new PublicKey(escrowPdaStr);

    // Polling loop: attempt a few times to allow transaction finality propagation
    const maxAttempts = 8;
    const delayMs = 1500;
    let funded = false;
    let lastBalance = 0;
    for (let i = 0; i < maxAttempts; i++) {
      try {
        lastBalance = await connection.getBalance(escrowPda, "confirmed");
        if (lastBalance >= lockedAmountLamports) {
          funded = true;
          break;
        }
      } catch (e) {
        // ignore RPC transient
      }
      // small backoff
      // eslint-disable-next-line no-await-in-loop
      await new Promise((r) => setTimeout(r, delayMs));
    }

    if (funded) {
      // mark subscription as active/initialized and set next billing date
      const now = new Date();
      // set nextBillingDate to ~1 month from now (preserve timezone as ISO)
      const nextBillingMs = now.getTime() + 30 * 24 * 60 * 60 * 1000; // 30 days
      subscription.status = "active";
      subscription.currentPeriodStart = now;
      subscription.currentPeriodEnd = new Date(nextBillingMs);
      subscription.nextBillingDate = new Date(nextBillingMs);
      subscription.lastPaymentDate = now;
      // persist any useful onchain confirmation info
      subscription.onchain = subscription.onchain || {};
      subscription.onchain.initializedAt = now;
      subscription.onchain.escrowBalanceVerified = lastBalance;
      await subscription.save();

      // Optionally: enqueue or POST merchant webhook to notify initialization complete
      try {
        if (subscription.webhookUrl) {
          const payload = {
            event: "subscription_initialized",
            subscription_id: subscriptionId,
            escrow_pda: escrowPdaStr,
            locked_amount_lamports: lockedAmountLamports,
            locked_amount_sol: Number((lockedAmountLamports / 1e9).toFixed(6)),
            initialized_at: now.toISOString(),
          };
          if (typeof (global as any).fetch === "function") {
            // fire-and-forget; don't block user
            (global as any).fetch(subscription.webhookUrl, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(payload),
            }).catch(() => {});
          } else {
            import("node-fetch").then((m) => {
              const fetchFn = m.default || m;
              fetchFn(subscription.webhookUrl, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
              }).catch(() => {});
            }).catch(() => {});
          }
        }
      } catch (e) {
        // ignore notification errors
      }

      const html = `<!doctype html><html><body>
        <h2>Initialize complete — subscription active</h2>
        <p>Escrow funded: ${(lastBalance / 1e9).toFixed(6)} SOL (expected ${(lockedAmountLamports / 1e9).toFixed(6)} SOL)</p>
        <p>Subscription ${subscriptionId} is now active. Your first monthly release will occur on ${subscription.nextBillingDate?.toISOString()}.</p>
        <p>You can close this page.</p>
        </body></html>`;
      res.setHeader("content-type", "text/html; charset=utf-8");
      return res.status(200).send(html);
    }

    // Not yet funded: render a page that shows current escrow balance and a re-check button
    const html = `<!doctype html><html><body>
      <h2>Waiting for initialize to finalize</h2>
      <p>The transaction is not yet finalized on-chain or the escrow balance is below the expected locked amount.</p>
      <p>Escrow PDA: ${escrowPdaStr}</p>
      <p>Expected locked amount: ${(lockedAmountLamports / 1e9).toFixed(6)} SOL (${lockedAmountLamports} lamports)</p>
      <p>Current escrow balance: ${(lastBalance / 1e9).toFixed(6)} SOL (${lastBalance} lamports)</p>
      <form><input type="hidden" name="subscription_id" value="${subscriptionId}" /><button formaction="/subscription/initialize-complete" formmethod="get">Re-check now</button></form>
      <p>If you already signed the transaction, wait a few moments and try Re-check.</p>
      </body></html>`;
    res.setHeader("content-type", "text/html; charset=utf-8");
    return res.status(200).send(html);
  } catch (err) {
    console.error("initialize-complete handler failed", err);
    return res.status(500).send("internal_error");
  }
});
}





