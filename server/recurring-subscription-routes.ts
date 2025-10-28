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
  app.get("/api/recurring-subscriptions/phantom/connect-callback/:subscriptionId?", async (req: Request, res: Response) => {
    try {
      const subscription_id = (req.params && (req.params as any).subscriptionId) || (req.query && req.query.subscription_id);
      const phantom_encryption_public_key = req.query.phantom_encryption_public_key;
      const data = req.query.data;
      const nonce = req.query.nonce;

      if (!subscription_id || typeof subscription_id !== "string") {
        return res.status(400).json({ error: "missing_subscription_id" });
      }

      const subscription = await RecurringSubscription.findOne({ subscriptionId: subscription_id });
      if (!subscription) return res.status(404).json({ error: "subscription_not_found" });

      // If no encrypted payload, redirect to frontend success (non-fatal)
      if (!phantom_encryption_public_key || !data || !nonce) {
        console.log("Phantom connect callback received without encrypted payload", { subscriptionId: subscription_id });
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "https://blocksub-public-1.com");
        return res.redirect(`${frontendUrl}/subscription/connect-success?subscription_id=${subscription_id}`);
      }

      // Attempt to decrypt the payload using existing helper
      let decrypted: string;
      try {
        decrypted = decryptPhantomCallbackData(String(phantom_encryption_public_key), String(data), String(nonce));
      } catch (e) {
        console.log("Failed to decrypt Phantom payload", { subscriptionId: subscription_id, error: e });
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "https://blocksub-public-1.com");
        return res.redirect(`${frontendUrl}/subscription/connect-error?error=callback_decrypt_failed`);
      }

      // parse decrypted payload and extract wallet address
      let parsed: any = {};
      try {
        parsed = JSON.parse(decrypted);
      } catch (e) {
        console.log("Decrypted Phantom payload is not JSON", { subscriptionId: subscription_id, decrypted });
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "https://blocksub-public-1.com");
        return res.redirect(`${frontendUrl}/subscription/connect-error?error=payload_not_json`);
      }

      const walletAddress = parsed.publicKey || parsed.public_key || parsed.pubkey || parsed.wallet;
      if (!walletAddress) {
        console.log("Phantom payload missing wallet address", { subscriptionId: subscription_id, parsed });
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "https://blocksub-public-1.com");
        return res.redirect(`${frontendUrl}/subscription/connect-error?error=missing_public_key`);
      }

      // LOG: as requested, log the public key obtained after decryption
      console.log("Phantom connect-callback decrypted public key:", { subscriptionId: subscription_id, publicKey: walletAddress });

      // Save wallet address and change status to pending_payment (subscription lifecycle handled elsewhere)
      subscription.walletAddress = walletAddress;
      subscription.status = "pending_payment";
      await subscription.save();

      // Redirect to frontend; frontend can poll subscription status or show QR/intent
      const frontendUrl = getEnv("PHANTOM_DAPP_URL", "https://blocksub-public-1.com");
      return res.redirect(`${frontendUrl}/subscription/connect-success?subscription_id=${subscription_id}`);
    } catch (err) {
      console.log("Phantom connect callback failed", { error: err instanceof Error ? err.message : String(err) });
      const frontendUrl = getEnv("PHANTOM_DAPP_URL", "https://blocksub-public-1.com");
      return res.redirect(`${frontendUrl}/subscription/connect-error?error=callback_failed`);
    }
  });
}
