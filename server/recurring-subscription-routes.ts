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

/**
 * Minimal Recurring Subscription Routes (fresh start)
 *
 * - POST /api/subscription
 *   Creates a subscription (validated against the repo schema), persists it,
 *   builds a Phantom wallet connection QR (via generateWalletConnectionQR) and
 *   returns subscription info + wallet connection payload.
 *
 * - GET /api/recurring-subscriptions/phantom/connect-callback/:subscriptionId?
 *   Public endpoint used by Phantom to POST encrypted payloads (encrypted payload
 *   arrives as query params). This handler will attempt to decrypt the payload,
 *   log the public key obtained after decryption (as requested), attach the
 *   walletAddress to the subscription and redirect to the frontend.
 */

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
        userId: apiKey.userId,          // REQUIRED by schema
        apiKeyId: apiKey._id,           // REQUIRED by schema
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

  // Public Phantom connect callback (minimal). For now, log the public key obtained after decryption.
  // Replace the existing connect-callback handler with this implementation:

  // Public Phantom connect callback (minimal). For debugging: decrypt and log payload + public key.
  app.get("/api/recurring-subscriptions/phantom/connect-callback/:subscriptionId?", async (req: Request, res: Response) => {
    try {
      // Prefer subscriptionId from path then fallback to query
      const subscriptionId = (req.params && (req.params as any).subscriptionId) || (req.query && req.query.subscription_id);
      const phantom_encryption_public_key = (req.query.phantom_encryption_public_key || req.query.phantom_pub_key || req.query.phantom_public_key) as string | undefined;
      const data = req.query.data as string | undefined;
      const nonce = req.query.nonce as string | undefined;

      if (!subscriptionId || typeof subscriptionId !== "string") {
        console.log("Phantom callback missing subscription id", { params: req.params, query: req.query });
        return res.status(400).json({ error: "missing_subscription_id" });
      }

      // Log incoming query params (short preview)
      console.log('[routes] query params:', {
        subscriptionId,
        phantom_encryption_public_key: phantom_encryption_public_key ? `${phantom_encryption_public_key.slice(0, 12)}...` : null,
        nonce: nonce ? `${nonce.slice(0, 12)}...` : null,
        data: data ? `${data.slice(0, 12)}...` : null,
      });

      // Try to decrypt and log the payload first (for debugging as requested)
      if (phantom_encryption_public_key && data && nonce) {
        try {
          // decryptPhantomCallbackData is imported elsewhere in this file
          const decrypted = decryptPhantomCallbackData(String(phantom_encryption_public_key), String(data), String(nonce));
          // Log the entire decrypted payload (string)
          console.log(`[phantom-callback] decrypted payload for subscription ${subscriptionId}:`, decrypted);

          // Try to parse JSON and log parsed object and extracted publicKey if present
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
          // We continue below - we still want to respond/redirect, but we already logged the failure
        }
      } else {
        console.log(`[phantom-callback] missing encryption params for subscription ${subscriptionId} - skipping decryption`);
      }

      // Now load subscription and attach walletAddress if possible
      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      if (!subscription) {
        console.log(`[phantom-callback] subscription not found: ${subscriptionId}`);
        // Redirect anyway to frontend with error info
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "https://blocksub-public-1.onrender.com");
        return res.redirect(`${frontendUrl}/subscription/connect-error?error=subscription_not_found`);
      }

      // If Phantom did not send encrypted payload, fallback to redirect success (non-fatal)
      if (!phantom_encryption_public_key || !data || !nonce) {
        console.log(`[phantom-callback] no encrypted payload received for subscription ${subscriptionId}`);
        await logSubscriptionEvent(subscriptionId, 'wallet_connected', { phantom_callback: true, timestamp: new Date().toISOString() });
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "https://blocksub-public-1.onrender.com");
        return res.redirect(`${frontendUrl}/subscription/connect-success?subscription_id=${subscriptionId}`);
      }

      // Attempt decryption again and persist wallet if possible
      let decryptedPayload: string | null = null;
      try {
        decryptedPayload = decryptPhantomCallbackData(String(phantom_encryption_public_key), String(data), String(nonce));
      } catch (e) {
        console.log(`[phantom-callback] second attempt to decrypt failed for subscription ${subscriptionId}`, { error: e instanceof Error ? e.message : String(e) });
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "https://blocksub-public-1.onrender.com");
        await logSubscriptionEvent(subscriptionId, 'wallet_connect_failed', { error: 'callback_decrypt_failed' });
        return res.redirect(`${frontendUrl}/subscription/connect-error?error=callback_decrypt_failed`);
      }

      // parse decrypted payload
      let parsed: any = {};
      try {
        parsed = JSON.parse(decryptedPayload);
      } catch (e) {
        console.log(`[phantom-callback] decrypted payload not JSON for subscription ${subscriptionId}`, { decrypted: decryptedPayload });
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "https://blocksub-public-1.onrender.com");
        await logSubscriptionEvent(subscriptionId, 'wallet_connect_failed', { error: 'payload_not_json' });
        return res.redirect(`${frontendUrl}/subscription/connect-error?error=payload_not_json`);
      }

      const walletAddress = parsed.publicKey || parsed.public_key || parsed.pubkey || parsed.wallet;
      if (!walletAddress) {
        console.log(`[phantom-callback] decrypted payload missing publicKey for subscription ${subscriptionId}`, { parsed });
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "https://blocksub-public-1.onrender.com");
        await logSubscriptionEvent(subscriptionId, 'wallet_connect_failed', { error: 'missing_public_key_in_payload' });
        return res.redirect(`${frontendUrl}/subscription/connect-error?error=missing_public_key`);
      }

      // LOG the public key as you requested
      console.log(`[phantom-callback] attaching walletAddress ${walletAddress} to subscription ${subscriptionId}`);

      // Attach wallet and update subscription status
      subscription.walletAddress = walletAddress;
      subscription.status = 'pending_payment';
      await subscription.save();

      // Emit event and redirect to frontend success page
      await logSubscriptionEvent(subscriptionId, 'wallet_connected', { walletAddress, phantom_callback: true, verified: true });
      await sendWebhook(subscription, 'wallet_connected', { wallet_address: walletAddress });

      const frontendUrl = getEnv("PHANTOM_DAPP_URL", "https://blocksub-public-1.onrender.com");
      return res.redirect(`${frontendUrl}/subscription/connect-success?subscription_id=${subscriptionId}`);
    } catch (error) {
      console.log("Phantom connect callback failed (unexpected)", { error: error instanceof Error ? error.message : String(error) });
      const frontendUrl = getEnv("PHANTOM_DAPP_URL", "https://blocksub-public-1.onrender.com");
      return res.redirect(`${frontendUrl}/subscription/connect-error?error=callback_failed`);
    }
  });
}
