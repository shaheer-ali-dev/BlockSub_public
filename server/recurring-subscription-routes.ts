import { Express, Request, Response } from "express";
import { v4 as uuidv4 } from "uuid";
import crypto from "crypto";
import bs58 from "bs58";
import { ApiKeyAuthenticatedRequest, authenticateApiKey } from "../shared/auth";
import {
  RecurringSubscription,
  createRecurringSubscriptionSchema,
} from "../shared/recurring-subscription-schema";

import { generateWalletConnectionQR, decryptPhantomCallbackData } from "./phantom-wallet-utils";
import { buildInitializeSubscriptionTx } from "./solana-anchor";

function getEnv(key: string, fallback?: string) {
  const v = process.env[key];
  if (typeof v === "string" && v.length > 0) return v;
  return fallback;
}

export function registerRecurringSubscriptionRoutes(app: Express) {
  // Create subscription and return wallet connection QR + deeplink
 app.post("/api/subscription", authenticateApiKey(0.0), async (req: ApiKeyAuthenticatedRequest, res: Response) => {
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

      const dappUrl = process.env.PHANTOM_DAPP_URL || "https://blocksub-public-1.onrender.com";
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

      // Try to decrypt and log the payload first (for debugging as requested)
      if (phantom_encryption_public_key && data && nonce) {
        try {
          const decrypted = decryptPhantomCallbackData(String(phantom_encryption_public_key), String(data), String(nonce));
          console.log(`[phantom-callback] decrypted payload for subscription ${subscriptionId}:`, decrypted);
          try {
            const parsed = JSON.parse(decrypted);
            console.log(`[phantom-callback] parsed payload for subscription ${subscriptionId}:`, parsed);
            const walletAddress = parsed.publicKey || parsed.public_key || parsed.pubkey || parsed.wallet || null;
            if (walletAddress) {
              console.log(`[phantom-callback] extracted publicKey for subscription ${subscriptionId}:`, walletAddress);
            } else {
              console.log(`[phantom-callback] no publicKey found in decrypted payload for subscription ${subscriptionId}`);
            }
          } catch (parseErr) {
            console.log(`[phantom-callback] decrypted payload is not valid JSON for subscription ${subscriptionId}`);
          }
        } catch (decryptErr) {
          console.log(`[phantom-callback] decryptPhantomCallbackData failed for subscription ${subscriptionId}`, { error: decryptErr instanceof Error ? decryptErr.message : String(decryptErr) });
        }
      } else {
        console.log(`[phantom-callback] missing encryption params for subscription ${subscriptionId} - skipping decryption`);
      }

      // Load subscription
      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      if (!subscription) {
        console.log(`[phantom-callback] subscription not found: ${subscriptionId}`);
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "https://blocksub-public-1.onrender.com");
        return res.redirect(`${frontendUrl}/subscription/connect-error?error=subscription_not_found`);
      }

      // If no encrypted payload, fallback to success redirect
      if (!phantom_encryption_public_key || !data || !nonce) {
        console.log(`[phantom-callback] no encrypted payload received for subscription ${subscriptionId}`);
        try { await logSubscriptionEvent(subscriptionId, 'wallet_connected', { phantom_callback: true, timestamp: new Date().toISOString() }); } catch(e){ console.log('logSubscriptionEvent failed', e); }
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "https://blocksub-public-1.onrender.com");
        return res.redirect(`${frontendUrl}/subscription/connect-success?subscription_id=${subscriptionId}`);
      }

      // Attempt decryption & parse
      let decryptedPayload: string | null = null;
      try {
        decryptedPayload = decryptPhantomCallbackData(String(phantom_encryption_public_key), String(data), String(nonce));
      } catch (e) {
        console.log(`[phantom-callback] decrypt failed for subscription ${subscriptionId}`, { error: e instanceof Error ? e.message : String(e) });
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "https://blocksub-public-1.onrender.com");
        try { await logSubscriptionEvent(subscriptionId, 'wallet_connect_failed', { error: 'callback_decrypt_failed' }); } catch(e){ console.log('logSubscriptionEvent failed', e); }
        return res.redirect(`${frontendUrl}/subscription/connect-error?error=callback_decrypt_failed`);
      }

      let parsed: any = {};
      try {
        parsed = JSON.parse(decryptedPayload as string);
      } catch (e) {
        console.log(`[phantom-callback] decrypted payload not JSON for subscription ${subscriptionId}`, { decrypted: decryptedPayload });
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "https://blocksub-public-1.onrender.com");
        try { await logSubscriptionEvent(subscriptionId, 'wallet_connect_failed', { error: 'payload_not_json' }); } catch(e){ console.log('logSubscriptionEvent failed', e); }
        return res.redirect(`${frontendUrl}/subscription/connect-error?error=payload_not_json`);
      }

      const walletAddress = parsed.publicKey || parsed.public_key || parsed.pubkey || parsed.wallet;
      if (!walletAddress) {
        console.log(`[phantom-callback] decrypted payload missing publicKey for subscription ${subscriptionId}`, { parsed });
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "https://blocksub-public-1.onrender.com");
        try { await logSubscriptionEvent(subscriptionId, 'wallet_connect_failed', { error: 'missing_public_key_in_payload' }); } catch(e){ console.log('logSubscriptionEvent failed', e); }
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
        } else {
          // convert priceUsd -> lamports (simple example; replace with real price oracle/conversion)
          const amountPerMonthLamports = Math.max(1, Math.round((subscription.priceUsd || 1) * 1e7));
          const totalMonths = (subscription.metadata && (subscription.metadata as any).totalMonths) || 12;
          const lockedAmountLamports = (subscription.metadata && (subscription.metadata as any).lockedAmountLamports) || (amountPerMonthLamports * totalMonths);

          const txInfo = await buildInitializeSubscriptionTx({
            merchantPubkey: merchant,
            subscriberPubkey: walletAddress,
            amountPerMonthLamports,
            totalMonths,
            lockedAmountLamports
          });

          // Persist anchor PDAs and amounts in metadata for the worker
          subscription.metadata = {
            ...(subscription.metadata || {}),
            anchor: {
              subscriptionPda: txInfo.subscriptionPda,
              escrowPda: txInfo.escrowPda,
              subscriptionBump: txInfo.subscriptionBump,
              escrowBump: txInfo.escrowBump,
              amountPerMonthLamports,
              totalMonths,
              lockedAmountLamports
            }
          };
          subscription.status = "pending_onchain_initialize";
          await subscription.save();

          // Build payload to send to merchant webhook / callback URL
          const webhookPayload = {
            subscription_id: subscriptionId,
            serializedTxBase64: txInfo.serializedTxBase64,
            subscription_pda: txInfo.subscriptionPda,
            escrow_pda: txInfo.escrowPda,
            status: subscription.status,
          };

          // Try to POST directly to merchant webhookUrl if available; otherwise enqueue delivery
          if (subscription.webhookUrl) {
            try {
              // Prefer node-fetch if installed; Node 18+ has global fetch - try both.
              let didPost = false;
              try {
                // If global fetch exists (Node 18+), use it
                if (typeof (global as any).fetch === 'function') {
                  await (global as any).fetch(subscription.webhookUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(webhookPayload),
                  });
                  didPost = true;
                } else {
                  // dynamic import node-fetch
                  const fetchModule = await import('node-fetch');
                  const fetchFn = fetchModule.default || fetchModule;
                  await fetchFn(subscription.webhookUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(webhookPayload),
                  });
                  didPost = true;
                }
                console.log(`[phantom-callback] posted initialize tx to webhook ${subscription.webhookUrl}`);
              } catch (postErr) {
                console.log(`[phantom-callback] direct POST to webhook failed, will enqueue delivery`, { error: postErr instanceof Error ? postErr.message : String(postErr) });
                // fallback to enqueue helper
                try {
                  const { enqueueWebhookDelivery } = await import('./webhook-delivery');
                  await enqueueWebhookDelivery({ subscriptionId, url: subscription.webhookUrl, event: 'initialize_tx_ready', payload: webhookPayload });
                  console.log('[phantom-callback] enqueued webhook delivery for initialize_tx_ready');
                } catch (enqErr) {
                  console.log('[phantom-callback] enqueueWebhookDelivery failed', enqErr);
                }
              }
            } catch (outer) {
              console.log('[phantom-callback] webhook post/enqueue encountered error', outer);
            }
          } else {
            console.log('[phantom-callback] no webhookUrl configured on subscription, skipping webhook POST');
          }
        }
      } catch (buildErr) {
        console.log('Failed to build initialize tx for subscription', { subscriptionId, error: buildErr instanceof Error ? buildErr.message : String(buildErr) });
        // keep subscription saved (walletAddress persisted), set to pending_payment so merchant can retry
        subscription.status = 'pending_payment';
        await subscription.save();
      }

