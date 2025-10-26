import type { Express, Request, Response } from "express";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { authenticateApiKey, ApiKeyAuthenticatedRequest, optionalAuth } from "@shared/auth";
import { ApiKey } from "@shared/schema-mongodb";
import { PaymentOrder } from "@shared/schema-mongodb";
import { 
  RecurringSubscription, 
  SubscriptionEvent,
  createRecurringSubscriptionSchema,
  connectWalletSchema,
  updateRecurringSubscriptionSchema,
  type CreateRecurringSubscription,
  type ConnectWallet,
  type UpdateRecurringSubscription
} from "@shared/recurring-subscription-schema";
import { 
  generateWalletConnectionRequest,
  generateWalletConnectionQR,
  verifyWalletConnection,
  generateConnectionMessage,
  calculateNextBillingDate,
  calculateTrialEndDate,
  createRecurringPaymentIntent
} from "./phantom-wallet-utils";
import { buildSplApproveDelegateUnsigned } from "./solana";
import { broadcastSignedTransaction, getTransactionBySignature, extractMemoFromTransaction, getSolanaConnection } from "./solana";
import { getMint, getAssociatedTokenAddressSync } from "@solana/spl-token";

function getEnv(name: string, fallback = ""): string {
  return process.env[name] ?? fallback;
}

function getNumberEnv(name: string, fallback: number): number {
  const v = process.env[name];
  if (!v) return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

// Helper to log subscription events
async function logSubscriptionEvent(
  subscriptionId: string,
  eventType: string,
  eventData: Record<string, any> = {},
  transactionSignature?: string
) {
  try {
    await SubscriptionEvent.create({
      subscriptionId,
      eventType,
      eventData,
      transactionSignature,
    });
  } catch (error) {
    console.log("Failed to log subscription event", { 
      subscriptionId, 
      eventType, 
      error: error instanceof Error ? error.message : String(error) 
    });
  }
}

// Helper to send webhooks (if configured)
async function sendWebhook(subscription: any, eventType: string, eventData: Record<string, any> = {}) {
  if (!subscription.webhookUrl) return;

  try {
    const payload = {
      event: eventType,
      subscription_id: subscription.subscriptionId,
      data: {
        ...eventData,
        subscription: {
          id: subscription.subscriptionId,
          status: subscription.status,
          plan: subscription.plan,
          wallet_address: subscription.walletAddress,
          next_billing_date: subscription.nextBillingDate,
        }
      },
      timestamp: new Date().toISOString(),
    };

    // Verify merchant allowed webhook domains if configured on API key
    try {
      const { ApiKey } = await import('@shared/schema-mongodb');
      const apiKey = await ApiKey.findById(subscription.apiKeyId).exec();
      if (apiKey && Array.isArray(apiKey.allowedWebhookDomains) && apiKey.allowedWebhookDomains.length > 0) {
        try {
          const url = new URL(subscription.webhookUrl);
          const domain = url.hostname;
          if (!apiKey.allowedWebhookDomains.includes(domain)) {
            console.log('Webhook domain not allowed for merchant API key', { subscriptionId: subscription.subscriptionId, domain, allowed: apiKey.allowedWebhookDomains });
            return; // skip enqueueing unverified merchant webhook
          }
        } catch (e) {
          console.log('Invalid webhook URL configured', { subscriptionId: subscription.subscriptionId, url: subscription.webhookUrl });
          return;
        }
      }
    } catch (e) {
      console.log('Could not validate merchant webhook domain', { error: e });
    }

    // Enqueue webhook for reliable delivery and retries
    const { enqueueWebhookDelivery } = await import('./webhook-delivery');
    await enqueueWebhookDelivery({ subscriptionId: subscription.subscriptionId, url: subscription.webhookUrl, event: eventType, payload });
    console.log('Enqueued webhook delivery', { subscriptionId: subscription.subscriptionId, event: eventType, url: subscription.webhookUrl });
  } catch (error) {
    console.log("Webhook enqueue failed", { error: error instanceof Error ? error.message : String(error) });
  }
}

/**
 * BlockSub Recurring Subscriptions API Routes
 * 
 * This module provides middleware APIs for developers to integrate recurring payment
 * functionality using Phantom wallet on Solana. The APIs act as a complete middleware
 * solution, handling wallet connections, billing cycles, payment processing, and
 * subscription lifecycle management.
 * 
 * Key Features:
 * - Flexible plan system (developers define their own plan names and pricing)
 * - Phantom wallet integration with QR codes and deep links
 * - Automatic billing cycle management
 * - Payment failure handling with grace periods
 * - Webhook notifications for subscription events
 * - Trial period support
 * - Comprehensive event logging
 * 
 * All endpoints require API key authentication and deduct credits based on usage.
 * 
 * @param app Express application instance
 */
export function registerRecurringSubscriptionRoutes(app: Express) {
  
  /**
   * Create a new recurring subscription
   * 
   * This endpoint creates a new recurring subscription with developer-defined pricing
   * and plan names. It generates a Phantom wallet connection QR code and deep link
   * for users to connect their wallet.
   * 
   * Request Body:
   * - plan: string (any plan name defined by developer, e.g., "basic", "pro", "enterprise")
   * - priceUsd: number (subscription price in USD, 0.01 to 99999)
   * - billingInterval: "monthly" | "yearly" (billing frequency)
   * - webhookUrl?: string (optional webhook URL for subscription events)
   * - metadata?: object (optional metadata for tracking)
   * - trialDays?: number (optional trial period, 0-365 days)
   * 
   * Returns:
   * - subscription_id: unique subscription identifier
   * - wallet_connection: QR code and deep link for wallet connection
   * - subscription details and configuration
   * 
   * Cost: 1.0 credits (creates subscription, generates QR code, manages wallet connection)
   */
  app.post("/api/recurring-subscriptions",authenticateApiKey(30.0), async (req,res) => {
  try {
    // NOTE: Billing is handled by authenticateApiKey middleware (30.0 credits).
    // Do NOT call storage.deductCredits here again (would double-charge).

    const apiKey = req.apiKey!;
    const parse = createRecurringSubscriptionSchema.safeParse(req.body);

    if (!parse.success) {
      return res.status(400).json({
        error: "invalid_request",
        details: parse.error.flatten()
      });
    }

    const data = parse.data as CreateRecurringSubscription;
    // Accept additional optional fields directly from the raw body
    const raw = req.body as any;
    const merchantProvided = raw.merchant || getEnv("MERCHANT_SOL_ADDRESS");
    const tokenMintProvided = raw.tokenMint || undefined;
    const tokenAmountProvided = raw.tokenAmount || undefined; // base-units string
    const tokenAmountDecimalProvided = raw.tokenAmountDecimal || undefined; // human decimal

    // Determine asset: prefer explicit info: tokenMint => SPL; otherwise default env or SOL
    let asset: 'SOL' | 'SPL' = getEnv('RECURRING_SUBSCRIPTION_ASSET', 'SPL') === 'SOL' ? 'SOL' : 'SPL';
    if (tokenMintProvided) asset = 'SPL';
    else if (data && typeof data.priceUsd === 'number' && !tokenMintProvided) {
      // If no tokenMint and no amountLamports semantics for subscription, keep default asset
      asset = getEnv('RECURRING_SUBSCRIPTION_ASSET', 'SPL') === 'SOL' ? 'SOL' : 'SPL';
    }

    // If SPL, convert human decimal amount to base units if necessary.
    let tokenAmountBase: string | undefined = undefined;
    if (asset === 'SPL' && tokenMintProvided) {
      if (tokenAmountProvided) {
        tokenAmountBase = tokenAmountProvided;
      } else if (tokenAmountDecimalProvided) {
        try {
          tokenAmountBase = await tokenDecimalToBaseUnits(tokenMintProvided, tokenAmountDecimalProvided);
        } catch (err: any) {
          console.log("Failed to convert tokenAmountDecimal to base units", { error: err?.message });
          return res.status(400).json({ error: "invalid_token_amount", message: String(err?.message || err) });
        }
      } else {
        // No explicit token amount provided; leave undefined (we may attempt conversion later)
        tokenAmountBase = undefined;
      }
    }

    const subscriptionId = `rsub_${uuidv4().replace(/-/g, "")}`;

    // Calculate trial end date if trial is configured
    let trialEndDate: Date | undefined;
    if (data.trialDays && data.trialDays > 0) {
      trialEndDate = calculateTrialEndDate(new Date(), data.trialDays);
    }

    // Create subscription record
    const subscription = await RecurringSubscription.create({
      subscriptionId,
      userId: apiKey.userId,
      apiKeyId: apiKey._id,
      plan: data.plan,
      priceUsd: data.priceUsd,
      chain: 'solana',
      asset,
      tokenMint: tokenMintProvided || getEnv('SOLANA_USDC_MINT_ADDRESS') || undefined,
      merchantAddress: merchantProvided || undefined,
      status: 'pending_wallet_connection',
      isRecurring: true,
      billingInterval: data.billingInterval,
      failedPaymentAttempts: 0,
      maxFailedAttempts: getNumberEnv('MAX_FAILED_PAYMENT_ATTEMPTS', 3),
      gracePeriodDays: getNumberEnv('PAYMENT_GRACE_PERIOD_DAYS', 7),
      autoRenew: true,
      cancelAtPeriodEnd: false,
      webhookUrl: data.webhookUrl,
      metadata: data.metadata || {},
      trialEndDate,
    });

    // Generate wallet connection request
    const connectionRequest = generateWalletConnectionRequest(subscriptionId);
    const connectionMessage = generateConnectionMessage(subscriptionId, data.plan, data.priceUsd);
    connectionRequest.message = connectionMessage;

    const walletConnectionQR = await generateWalletConnectionQR(connectionRequest);

    // Update subscription with connection details and save connection message/nonce
    subscription.walletConnectionQR = walletConnectionQR.qrCodeDataUrl;
    subscription.walletConnectionDeeplink = walletConnectionQR.deeplink;
    subscription.metadata = {
      ...(subscription.metadata || {}),
      walletConnectionMessage: connectionRequest.message,
      walletConnectionNonce: connectionRequest.nonce,
      dappEncryptionPublicKey: connectionRequest.dappEncryptionPublicKey || null
    };
    await subscription.save();

    // Prepare to capture an initial payment intent (if created)
    let createdIntent: any | undefined = undefined;

    // If there's no trial, try to create an initial payment intent
    if (!trialEndDate) {
      // Build amount for payment intent
      let amountLamports: number | undefined = undefined;
      let tokenAmountForIntent: string | undefined = undefined;

      if (subscription.asset === 'SOL') {
        amountLamports = Math.max(1, Math.round(subscription.priceUsd * 1e7));
      } else if (subscription.asset === 'SPL') {
        if (tokenAmountBase) {
          tokenAmountForIntent = tokenAmountBase;
        } else if (subscription.tokenMint && typeof subscription.priceUsd === 'number') {
          try {
            const mint = subscription.tokenMint;
            if (mint) {
              tokenAmountForIntent = await tokenDecimalToBaseUnits(mint, String(subscription.priceUsd));
            }
          } catch (err) {
            console.log("Could not auto-convert priceUsd to token amount for intent", { error: err });
            tokenAmountForIntent = undefined;
          }
        }
      }

      // Defensive checks before creating SPL intent
      let shouldCreateIntent = true;
      if (subscription.asset === 'SPL') {
        if (!subscription.tokenMint) {
          console.log("Skipping initial payment intent: missing subscription.tokenMint", { subscriptionId: subscription.subscriptionId });
          shouldCreateIntent = false;
        }
        if (!tokenAmountForIntent) {
          console.log("Skipping initial payment intent: missing tokenAmount for SPL intent", { subscriptionId: subscription.subscriptionId, priceUsd: subscription.priceUsd });
          shouldCreateIntent = false;
        }
      }

      if (shouldCreateIntent) {
        try {
          // Wallet address is unknown at creation time; set to undefined
          const intent = await createRecurringPaymentIntent({
            subscriptionId: subscription.subscriptionId,
            walletAddress: undefined,
            assetType: subscription.asset === 'SOL' ? 'SOL' : 'SPL',
            amountLamports,
            tokenMint: subscription.tokenMint,
            tokenAmount: subscription.asset === 'SPL' ? tokenAmountForIntent : undefined,
            billingCycle: 1,
            merchantAddress: subscription.merchantAddress || merchantProvided || process.env.MERCHANT_SOL_ADDRESS,
          });

          createdIntent = intent;

          // Persist PaymentOrder for tracking so the payment worker/relayer can pick it up
          await PaymentOrder.create({
            orderId: intent.paymentId,
            subscriptionId: subscription.subscriptionId,
            status: 'pending',
            assetType: intent.amountLamports ? 'SOL' : 'SPL',
            amountLamports: intent.amountLamports ?? null,
            tokenMint: intent.tokenMint ?? null,
            tokenAmount: intent.amount ?? null,
            merchant: intent.merchantAddress || subscription.merchantAddress || process.env.MERCHANT_SOL_ADDRESS || '',
            userPubkey: null,
            memo: intent.memo || null,
            unsignedTxB64: intent.unsignedTxB64 ?? null,
            expiresAt: intent.expiresAt,
          });

          // Log that initial payment was requested
          await logSubscriptionEvent(subscriptionId, 'initial_payment_requested', {
            paymentId: intent.paymentId,
            expiresAt: intent.expiresAt,
          });
        } catch (intentErr) {
          // Non-fatal: log and continue; client will still connect and intent may be created after connect
          console.log("Failed to create initial payment intent for subscription", { subscriptionId, error: intentErr instanceof Error ? intentErr.message : String(intentErr) });
        }
      } else {
        console.log("Initial payment intent skipped (missing parameters)", { subscriptionId: subscription.subscriptionId });
      }
    }

    // Return success including initial intent if one was created
    return res.json({
      subscription_id: subscription.subscriptionId,
      status: subscription.status,
      plan: subscription.plan,
      price_usd: subscription.priceUsd,
      wallet_connection: {
        qr_data_url: subscription.walletConnectionQR,
        phantom_deeplink: subscription.walletConnectionDeeplink,
      },
      payment_intent: createdIntent ? {
        payment_id: createdIntent.paymentId,
        phantom_url: createdIntent.phantomUrl,
        qr_data_url: createdIntent.qrDataUrl,
        unsigned_tx: createdIntent.unsignedTxB64,
        expires_at: createdIntent.expiresAt,
      } : undefined,
      trial_end_date: subscription.trialEndDate?.toISOString(),
      next_billing_date: subscription.nextBillingDate?.toISOString(),
    });

  } catch (error) {
    console.log("Create recurring subscription failed", {
      error: error instanceof Error ? error.message : String(error)
    });
    return res.status(500).json({ error: "internal_error" });
  }
});    
  /**
   * Connect Phantom wallet to subscription
   * 
   * This endpoint processes the wallet connection after a user scans the QR code
   * or clicks the deep link. It verifies the wallet signature and activates the
   * subscription (or starts trial period if configured).
   * 
   * Request Body:
   * - walletAddress: string (Solana wallet address, 32-44 characters)
   * - signature: string (signature proof of wallet ownership)
   * - message: string (message that was signed for verification)
   * 
   * Returns:
   * - Updated subscription status and billing information
   * - Trial status if applicable
   * - Next billing date
   * 
   * Cost: 0.5 credits (processes wallet connection and signature verification)
   */
  app.post("/api/recurring-subscriptions/:subscriptionId/connect-wallet",  async (req, res) => {
    try {
      const { subscriptionId } = req.params;
      const parse = connectWalletSchema.safeParse(req.body);
      
      if (!parse.success) {
        return res.status(400).json({ 
          error: "invalid_request", 
          details: parse.error.flatten() 
        });
      }

      const { walletAddress, signature, message } = parse.data;
      
      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      if (!subscription) {
        return res.status(404).json({ error: "subscription_not_found" });
      }

      // Verify ownership via API key
      if (req.apiKey && subscription.apiKeyId !== req.apiKey._id) {
        return res.status(403).json({ error: "forbidden" });
      }

      if (subscription.status !== 'pending_wallet_connection') {
        return res.status(400).json({ 
          error: "invalid_status", 
          message: "Subscription must be pending wallet connection" 
        });
      }

      // Verify wallet signature
      if (!verifyWalletConnection(walletAddress, signature, message)) {
        return res.status(400).json({ error: "invalid_signature" });
      }

      // Update subscription with wallet info
      subscription.walletAddress = walletAddress;

      // If there's a trial period, set up trial, otherwise require an initial on-chain payment
      const now = new Date();
      if (subscription.trialEndDate && subscription.trialEndDate > now) {
        // Trial period - next billing date is after trial ends
        subscription.nextBillingDate = calculateNextBillingDate(
          subscription.trialEndDate, 
          subscription.billingInterval
        );
        subscription.currentPeriodStart = now;
        subscription.currentPeriodEnd = subscription.trialEndDate;
        subscription.status = 'active'; // Active during trial
        await subscription.save();
      } else {
        // No trial - do NOT mark active until a payment is confirmed.
        // Create a one-time initial payment intent (unsigned tx + phantom deeplink/QR)
        subscription.status = 'pending_payment';
        await subscription.save();

        // Create initial payment intent for this subscription so the user can complete the first charge
        const intent = await createRecurringPaymentIntent({
          subscriptionId: subscription.subscriptionId,
          walletAddress,
          assetType: subscription.asset === 'SOL' ? 'SOL' : 'SPL',
          amountLamports: subscription.asset === 'SOL' ? Math.round(subscription.priceUsd * 1e7) : undefined,
          tokenMint: subscription.tokenMint,
          tokenAmount: subscription.asset === 'SPL' ? String(Math.round(subscription.priceUsd * 1000000)) : undefined,
          billingCycle: 1,
        });

        // Persist PaymentOrder for tracking so the payment worker/relayer can pick it up
        await PaymentOrder.create({
          orderId: intent.paymentId,
          subscriptionId: subscription.subscriptionId,
          status: 'pending',
          assetType: intent.amountLamports ? 'SOL' : 'SPL',
          amountLamports: intent.amountLamports,
          tokenMint: intent.tokenMint,
          tokenAmount: intent.amount,
          merchant: intent.merchantAddress || process.env.MERCHANT_SOL_ADDRESS || '',
          userPubkey: walletAddress,
          memo: intent.memo || null,
          unsignedTxB64: intent.unsignedTxB64,
          expiresAt: intent.expiresAt,
        });

        // Log that initial payment was requested
        await logSubscriptionEvent(subscriptionId, 'initial_payment_requested', {
          paymentId: intent.paymentId,
          expiresAt: intent.expiresAt,
        });

        // Return payment intent to caller so client can show QR/Phantom link
        return res.json({
          subscription_id: subscriptionId,
          status: subscription.status,
          wallet_address: walletAddress,
          payment_intent: {
            phantom_url: intent.phantomUrl,
            qr_data_url: intent.qrDataUrl,
            unsigned_tx: intent.unsignedTxB64,
            payment_id: intent.paymentId,
            expires_at: intent.expiresAt,
          }
        });
      }

      // If subscription is SPL-based and has a token mint, return an approve intent
      let approvalIntent: any = undefined;
      if (subscription.asset === 'SPL' && subscription.tokenMint) {
        try {
          // Allow merchant to act as delegate up to the plan amount (placeholder conversion)
          const merchant = getEnv('MERCHANT_SOL_ADDRESS');
          const allowance = String(Math.round(subscription.priceUsd * 1000000)); // placeholder: 1 USD -> 1e6 token base units
          approvalIntent = await buildSplApproveDelegateUnsigned({
            userPubkey: walletAddress,
            tokenMint: subscription.tokenMint,
            delegate: merchant,
            amount: allowance,
          });
          // Save delegation details to subscription for server-side bookkeeping
          subscription.delegatePubkey = merchant;
          subscription.delegateAllowance = allowance;
          subscription.delegateApprovedAt = undefined; // will be set when approval callback is received
          await subscription.save();
        } catch (err) {
          // Non-fatal: log and continue; the merchant can still rely on on-demand phantom intents
          console.log('Failed to generate SPL approve intent', { subscriptionId, error: err instanceof Error ? err.message : String(err) });
        }
      }
      // Log wallet connection event
      await logSubscriptionEvent(subscriptionId, 'wallet_connected', {
        walletAddress,
        trialActive: !!(subscription.trialEndDate && subscription.trialEndDate > now),
      });

      // Send webhook
      await sendWebhook(subscription, 'wallet_connected', { wallet_address: walletAddress });

      return res.json({
        subscription_id: subscriptionId,
        status: subscription.status,
        wallet_address: walletAddress,
        next_billing_date: subscription.nextBillingDate?.toISOString(),
        current_period_start: subscription.currentPeriodStart?.toISOString(),
        current_period_end: subscription.currentPeriodEnd?.toISOString(),
        trial_active: !!(subscription.trialEndDate && subscription.trialEndDate > now),
        approval_intent: approvalIntent ? {
          phantom_url: approvalIntent.phantomUrl,
          qr_data_url: approvalIntent.qrDataUrl,
          unsigned_tx: approvalIntent.unsignedTxB64,
          expires_at: approvalIntent.expiresAt,
          order_id: approvalIntent.orderId,
        } : undefined,
      });

    } catch (error) {
      console.log("Connect wallet failed", { 
        error: error instanceof Error ? error.message : String(error) 
      });
      return res.status(500).json({ error: "internal_error" });
    }
  });

  /**
   * Merchant-initiated collect using delegate (immediate transfer)
   * If server has MERCHANT_SIGNING_SECRET configured, server will sign and broadcast
   * the delegate transfer on behalf of the merchant (requires secure key storage).
   * Otherwise returns an unsigned transaction + phantom deeplink/QR for the merchant
   * to sign with their delegate key (merchant wallet).
   */
  app.post("/api/recurring-subscriptions/:subscriptionId/collect", async (req, res) => {
    try {
      const { subscriptionId } = req.params;
      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      if (!subscription) return res.status(404).json({ error: 'subscription_not_found' });

      // Verify ownership via API key
      if (req.apiKey && subscription.apiKeyId !== req.apiKey._id) {
        return res.status(403).json({ error: 'forbidden' });
      }

      if (subscription.status !== 'active') {
        return res.status(400).json({ error: 'invalid_status' });
      }

      if (subscription.asset !== 'SPL' || !subscription.tokenMint) {
        return res.status(400).json({ error: 'delegate_not_applicable' });
      }

      if (!subscription.delegatePubkey || !subscription.delegateAllowance || !subscription.delegateApprovedAt) {
        return res.status(400).json({ error: 'delegate_not_approved' });
      }

      // Determine amount to collect (placeholder: use subscription.delegateAllowance or price conversion)
      const amount = subscription.delegateAllowance;

      

      // Build unsigned delegate transfer (merchant will sign)
      const transfer = await (await import('./solana')).buildSplTransferFromDelegateUnsigned({
        delegatePubkey: subscription.delegatePubkey,
        userPubkey: subscription.walletAddress!,
        merchant: process.env.MERCHANT_SOL_ADDRESS || '',
        tokenMint: subscription.tokenMint,
        tokenAmount: amount!,
      });

      // Persist PaymentOrder for tracking
      await PaymentOrder.create({
        orderId: transfer.orderId,
        status: 'pending',
        assetType: 'SPL',
        tokenMint: subscription.tokenMint,
        tokenAmount: amount,
        merchant: process.env.MERCHANT_SOL_ADDRESS || '',
        userPubkey: subscription.walletAddress,
        memo: transfer.memoText,
        unsignedTxB64: transfer.unsignedTxB64,
        expiresAt: new Date(transfer.expiresAt),
      });

      // Log event
      await logSubscriptionEvent(subscriptionId, 'payment_succeeded', { paymentId: transfer.orderId }, undefined);

      return res.json({
        order_id: transfer.orderId,
        phantom_url: transfer.phantomUrl,
        qr_data_url: transfer.qrDataUrl,
        unsigned_tx: transfer.unsignedTxB64,
        expires_at: transfer.expiresAt,
      });

    } catch (error) {
      console.log('Collect failed', { error: error instanceof Error ? error.message : String(error) });
      return res.status(500).json({ error: 'internal_error' });
    }
  });

  /**
   * Relayer callback: merchant relayer posts back signed transaction (base64)
   * Body: { orderId, signedTxB64 }
   */
  app.post('/api/recurring-subscriptions/relayer/callback', async (req, res) => {
    try {
      const { orderId, signedTxB64 } = req.body || {};
      if (!orderId || !signedTxB64) return res.status(400).json({ error: 'missing_parameters' });

      // Idempotency: check if order already has a signature
      const existing = await PaymentOrder.findOne({ orderId });
      if (!existing) return res.status(404).json({ error: 'order_not_found' });
      if (existing.signature && existing.status === 'submitted') {
        return res.json({ ok: true, signature: existing.signature, note: 'already_submitted' });
      }

      // Verify HMAC signature from relayer using the subscription's relayerSecret (or webhookSecret fallback)
  const providedSig = (req.headers['x-relayer-signature'] || req.headers['x-relayersignature'] || '') as string;
  const providedTs = (req.headers['x-timestamp'] || req.headers['xTimestamp'] || '') as string;
      let secret: string | undefined = undefined;
      if (existing.subscriptionId) {
        const sub = await RecurringSubscription.findOne({ subscriptionId: existing.subscriptionId });
        if (sub) secret = sub.relayerSecret || sub.webhookSecret;
      }

      if (secret) {
        try {
          // Timestamp freshness: reject if older than 2 minutes
          if (!providedTs) {
            console.log('Missing timestamp in relayer callback', { orderId });
            return res.status(403).json({ error: 'missing_timestamp' });
          }
          const tsNum = Number(providedTs);
          if (!Number.isFinite(tsNum)) {
            console.log('Invalid timestamp in relayer callback', { orderId, providedTs });
            return res.status(403).json({ error: 'invalid_timestamp' });
          }
          const ageMs = Date.now() - tsNum;
          if (ageMs > 2 * 60 * 1000 || ageMs < -5 * 60 * 1000) { // allow small clock skew
            console.log('Relayer callback timestamp outside allowed window', { orderId, ageMs });
            return res.status(403).json({ error: 'timestamp_out_of_range' });
          }

          const crypto = await import('crypto');
          const message = providedTs + JSON.stringify(req.body);
          const expected = crypto.createHmac('sha256', secret).update(message).digest('hex');
          if (!providedSig || expected !== providedSig) {
            console.log('Relayer HMAC verification failed', { orderId });
            return res.status(403).json({ error: 'invalid_signature' });
          }
        } catch (e) {
          console.log('Error during relayer HMAC verification', { error: e });
          return res.status(500).json({ error: 'internal_error' });
        }
      }

      // Broadcast signed tx
      const result = await (await import('./solana')).broadcastSignedTransaction(signedTxB64);

      // Mark payment order as submitted (signature) so worker can verify and confirm
      await PaymentOrder.updateOne({ orderId }, { $set: { signature: result.signature, status: 'submitted' } });

      return res.json({ ok: true, signature: result.signature });
    } catch (error) {
      console.log('Relayer callback failed', { error });
      return res.status(500).json({ error: 'internal_error' });
    }
  });

  /**
   * Get subscription details
   * 
   * Retrieves comprehensive information about a subscription including status,
   * billing information, payment history, and trial details.
   * 
   * URL Parameters:
   * - subscriptionId: string (subscription identifier)
   * 
   * Returns:
   * - Complete subscription information
   * - Billing cycle details
   * - Payment history
   * - Trial and cancellation information
   * - Metadata and configuration
   * 
   * Cost: 0.1 credits (simple database query)
   */
  app.get("/api/recurring-subscriptions/:subscriptionId",  async (req, res) => {
    try {
      const { subscriptionId } = req.params;
      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      
      if (!subscription) {
        return res.status(404).json({ error: "subscription_not_found" });
      }

      // Verify ownership via API key
      if (req.apiKey && subscription.apiKeyId !== req.apiKey._id) {
        return res.status(403).json({ error: "forbidden" });
      }

      const now = new Date();
      const trialActive = !!(subscription.trialEndDate && subscription.trialEndDate > now);

      return res.json({
        subscription_id: subscription.subscriptionId,
        status: subscription.status,
        plan: subscription.plan,
        price_usd: subscription.priceUsd,
        billing_interval: subscription.billingInterval,
        wallet_address: subscription.walletAddress,
        next_billing_date: subscription.nextBillingDate?.toISOString(),
        current_period_start: subscription.currentPeriodStart?.toISOString(),
        current_period_end: subscription.currentPeriodEnd?.toISOString(),
        last_payment_date: subscription.lastPaymentDate?.toISOString(),
        last_payment_signature: subscription.lastPaymentSignature,
        failed_payment_attempts: subscription.failedPaymentAttempts,
        auto_renew: subscription.autoRenew,
        cancel_at_period_end: subscription.cancelAtPeriodEnd,
        trial_active: trialActive,
        trial_end_date: subscription.trialEndDate?.toISOString(),
        canceled_at: subscription.canceledAt?.toISOString(),
        cancellation_reason: subscription.cancellationReason,
        created_at: subscription.createdAt.toISOString(),
        updated_at: subscription.updatedAt.toISOString(),
        metadata: subscription.metadata,
      });

    } catch (error) {
      console.log("Get subscription failed", { 
        error: error instanceof Error ? error.message : String(error) 
      });
      return res.status(500).json({ error: "internal_error" });
    }
  });

  /**
   * Update subscription settings
   * 
   * Allows updating subscription configuration including plan changes, pricing
   * adjustments, auto-renewal settings, and cancellation scheduling.
   * 
   * URL Parameters:
   * - subscriptionId: string (subscription identifier)
   * 
   * Request Body (all optional):
   * - plan?: string (new plan name)
   * - priceUsd?: number (new pricing, should be provided with plan changes)
   * - autoRenew?: boolean (enable/disable auto-renewal)
   * - webhookUrl?: string (update webhook URL)
   * - metadata?: object (update metadata)
   * - cancelAtPeriodEnd?: boolean (schedule cancellation at period end)
   * 
   * Returns:
   * - Updated subscription information
   * - List of applied changes
   * 
   * Cost: 0.3 credits (database update with validation)
   */
  app.patch("/api/recurring-subscriptions/:subscriptionId",  async (req, res) => {
    try {
      const { subscriptionId } = req.params;
      const parse = updateRecurringSubscriptionSchema.safeParse(req.body);
      
      if (!parse.success) {
        return res.status(400).json({ 
          error: "invalid_request", 
          details: parse.error.flatten() 
        });
      }

      const updates = parse.data;
      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      
      if (!subscription) {
        return res.status(404).json({ error: "subscription_not_found" });
      }

      // Verify ownership via API key
      if (req.apiKey && subscription.apiKeyId !== req.apiKey._id) {
        return res.status(403).json({ error: "forbidden" });
      }

      // Apply updates
      if (updates.plan !== undefined) {
        subscription.plan = updates.plan;
        // If plan is updated, price should also be provided
        if (updates.priceUsd !== undefined) {
          subscription.priceUsd = updates.priceUsd;
        }
      } else if (updates.priceUsd !== undefined) {
        // Allow price updates without plan changes
        subscription.priceUsd = updates.priceUsd;
      }

      if (updates.autoRenew !== undefined) {
        subscription.autoRenew = updates.autoRenew;
      }

      if (updates.webhookUrl !== undefined) {
        subscription.webhookUrl = updates.webhookUrl;
      }

      if (updates.metadata !== undefined) {
        subscription.metadata = { ...subscription.metadata, ...updates.metadata };
      }

      if (updates.cancelAtPeriodEnd !== undefined) {
        subscription.cancelAtPeriodEnd = updates.cancelAtPeriodEnd;
        
        if (updates.cancelAtPeriodEnd && subscription.status === 'active') {
          // Log scheduled cancellation
          await logSubscriptionEvent(subscriptionId, 'canceled', {
            reason: 'scheduled_for_period_end',
            cancelAtPeriodEnd: true,
          });
        }
      }

      await subscription.save();

      return res.json({
        subscription_id: subscriptionId,
        status: subscription.status,
        updated: Object.keys(updates),
      });

    } catch (error) {
      console.log("Update subscription failed", { 
        error: error instanceof Error ? error.message : String(error) 
      });
      return res.status(500).json({ error: "internal_error" });
    }
  });

  /**
   * Cancel subscription immediately
   * 
   * Cancels a subscription immediately, stopping all future billing. This action
   * cannot be undone. The subscription will remain active until the current
   * billing period ends.
   * 
   * URL Parameters:
   * - subscriptionId: string (subscription identifier)
   * 
   * Request Body:
   * - reason?: string (optional cancellation reason for tracking)
   * 
   * Returns:
   * - Updated subscription status
   * - Cancellation timestamp and reason
   * 
   * Cost: 0.3 credits (database update, event logging, webhook notification)
   */
  app.post("/api/recurring-subscriptions/:subscriptionId/cancel",  async (req: ApiKeyAuthenticatedRequest, res: Response) => {
    try {
      const { subscriptionId } = req.params;
      const { reason } = req.body;
      
      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      if (!subscription) {
        return res.status(404).json({ error: "subscription_not_found" });
      }

      // Verify ownership via API key
      if (req.apiKey && subscription.apiKeyId !== req.apiKey._id) {
        return res.status(403).json({ error: "forbidden" });
      }

      if (subscription.status === 'canceled') {
        return res.status(400).json({ error: "already_canceled" });
      }

      // Cancel immediately
      subscription.status = 'canceled';
      subscription.canceledAt = new Date();
      subscription.cancellationReason = reason || 'user_requested';
      subscription.autoRenew = false;
      
      await subscription.save();

      // Log cancellation event
      await logSubscriptionEvent(subscriptionId, 'canceled', {
        reason: subscription.cancellationReason,
        canceledAt: subscription.canceledAt,
      });

      // Send webhook
      await sendWebhook(subscription, 'canceled', { 
        reason: subscription.cancellationReason,
        canceled_at: subscription.canceledAt.toISOString(),
      });

      return res.json({
        subscription_id: subscriptionId,
        status: subscription.status,
        canceled_at: subscription.canceledAt.toISOString(),
        cancellation_reason: subscription.cancellationReason,
      });

    } catch (error) {
      console.log("Cancel subscription failed", { 
        error: error instanceof Error ? error.message : String(error) 
      });
      return res.status(500).json({ error: "internal_error" });
    }
  });

  /**
   * List user's recurring subscriptions
   * 
   * Retrieves a paginated list of all subscriptions associated with the API key.
   * Useful for dashboard views and subscription management interfaces.
   * 
   * Query Parameters:
   * - status?: string (filter by subscription status)
   * - limit?: number (results per page, default 10)
   * - offset?: number (pagination offset, default 0)
   * 
   * Returns:
   * - Array of subscription summaries
   * - Pagination information
   * - Total count and navigation flags
   * 
   * Cost: 0.2 credits (database query with pagination)
   */
  app.get("/api/recurring-subscriptions",  async (req: ApiKeyAuthenticatedRequest, res: Response) => {
    try {
      const apiKey = req.apiKey!;
      const { status, limit = 10, offset = 0 } = req.query;
      
      const query: any = { apiKeyId: apiKey._id };
      if (status && typeof status === 'string') {
        query.status = status;
      }

      const subscriptions = await RecurringSubscription.find(query)
        .sort({ createdAt: -1 })
        .limit(Number(limit))
        .skip(Number(offset))
        .exec();

      const total = await RecurringSubscription.countDocuments(query);

      return res.json({
        subscriptions: subscriptions.map(sub => ({
          subscription_id: sub.subscriptionId,
          status: sub.status,
          plan: sub.plan,
          price_usd: sub.priceUsd,
          billing_interval: sub.billingInterval,
          wallet_address: sub.walletAddress,
          next_billing_date: sub.nextBillingDate?.toISOString(),
          created_at: sub.createdAt.toISOString(),
        })),
        pagination: {
          total,
          limit: Number(limit),
          offset: Number(offset),
          has_more: Number(offset) + Number(limit) < total,
        },
      });

    } catch (error) {
      console.log("List subscriptions failed", { 
        error: error instanceof Error ? error.message : String(error) 
      });
      return res.status(500).json({ error: "internal_error" });
    }
  });

  /**
   * Analytics Overview
   * Returns aggregated merchant metrics: MRR (USD), active subscriptions, failed payments count, retention rate, credits
   */
  // Analytics overview: accepts API key (deducts credits) OR a logged-in user session (no credit deduction)
  app.get('/api/analytics/overview', optionalAuth, async (req: any, res: Response) => {
    try {
      const { getJson, setJson } = await import('./cache');
      // Determine apiKeyId(s) scope: prefer API key if present (in headers), otherwise use logged-in user's apiKeys
      const { storage } = await import('./storage');
      let apiKeyIds: string[] = [];

      // If an API key was provided via authenticateApiKey earlier, it'd be attached. Try to detect via header first
      const authHeader = req.headers.authorization || '';
      if (authHeader) {
        // Try to look up an ApiKey by the provided header value (bearer or raw)
        let keyVal = undefined;
        if (typeof authHeader === 'string') {
          if (authHeader.startsWith('Bearer ')) keyVal = authHeader.substring(7);
          else if (authHeader.startsWith('ApiKey ')) keyVal = authHeader.substring(7);
          else keyVal = authHeader;
        }

        if (keyVal) {
          const apiKeyDoc = await storage.getApiKeyByKey(keyVal);
          if (apiKeyDoc) apiKeyIds.push(apiKeyDoc._id.toString());
        }
      }

      // If no api key found, and user is authenticated, use all apiKeys belonging to the user
      if (apiKeyIds.length === 0 && req.user) {
  const apiKeys = await storage.getApiKeys(req.user._id.toString());
  apiKeyIds = apiKeys.map((k: any) => k._id.toString());
      }

      if (apiKeyIds.length === 0) {
        return res.status(401).json({ error: 'API key or login required' });
      }

  // Build a cache key scoped to apiKeyIds set
  const cacheKey = `analytics:overview:${apiKeyIds.join(',')}`;
  const cached = await getJson(cacheKey);
  if (cached) return res.json(cached);

  // Active subscriptions count
      const activeCount = await RecurringSubscription.countDocuments({ apiKeyId: { $in: apiKeyIds }, status: 'active' });

      // MRR: sum of priceUsd for active subscriptions (monthly normalized)
  const subs = await RecurringSubscription.find({ apiKeyId: { $in: apiKeyIds }, status: 'active' }).select('priceUsd billingInterval');
      let mrr = 0;
      for (const s of subs) {
        if (s.billingInterval === 'monthly') mrr += (s.priceUsd || 0);
        else if (s.billingInterval === 'yearly') mrr += ((s.priceUsd || 0) / 12);
      }

      // Failed payments in last 30 days (from SubscriptionEvent)
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const subscriptionIds = (await RecurringSubscription.find({ apiKeyId: { $in: apiKeyIds } }).select('subscriptionId')).map(x => x.subscriptionId);
  const failedCount = await SubscriptionEvent.countDocuments({ eventType: 'payment_failed', createdAt: { $gte: thirtyDaysAgo }, subscriptionId: { $in: subscriptionIds } });

      // Cohort-style retention: compute retention for cohorts created in the last 3 months
      const cohortsMonths = 3;
      const nowDate = new Date();
      const cohortRetention: { cohort: string; created: number; activeAfter30Days: number; retentionPct: number }[] = [];
      for (let m = 0; m < cohortsMonths; m++) {
        const start = new Date(nowDate.getFullYear(), nowDate.getMonth() - m, 1);
        const end = new Date(start.getFullYear(), start.getMonth() + 1, 1);
        const created = await RecurringSubscription.countDocuments({ apiKeyId: { $in: apiKeyIds }, createdAt: { $gte: start, $lt: end } });
        // Active after 30 days: subscriptions from that cohort still active now
        const ids = (await RecurringSubscription.find({ apiKeyId: { $in: apiKeyIds }, createdAt: { $gte: start, $lt: end } }).select('subscriptionId')).map(x => x.subscriptionId);
        const activeAfter = ids.length === 0 ? 0 : await RecurringSubscription.countDocuments({ subscriptionId: { $in: ids }, status: 'active' });
        const pct = created === 0 ? 100 : Math.round((activeAfter / created) * 10000) / 100;
        cohortRetention.push({ cohort: start.toISOString().slice(0,7), created, activeAfter30Days: activeAfter, retentionPct: pct });
      }

      // Credits remaining on the API key
      // If single API key scope, show its credits; otherwise aggregate
      let creditsRemaining = 0;
      if (apiKeyIds.length === 1) {
        const apiKeyDoc = await ApiKey.findById(apiKeyIds[0]);
        creditsRemaining = apiKeyDoc ? apiKeyDoc.credits : 0;
      }

      const out = {
        mrr_usd: Math.round(mrr * 100) / 100,
        active_subscriptions: activeCount,
        failed_payments_30d: failedCount,
        retention_rate_percent: cohortRetention.length ? cohortRetention[0].retentionPct : 100,
        cohort_retention: cohortRetention,
        credits_remaining: creditsRemaining,
      };

      // Cache for short TTL
      await setJson(cacheKey, out, 60);
      return res.json(out);
    } catch (error) {
      console.log('Analytics overview failed', { error });
      return res.status(500).json({ error: 'internal_error' });
    }
  });

  /**
   * Revenue timeseries (monthly) - returns last N months (default 6)
   */
  app.get('/api/analytics/revenue-timeseries', optionalAuth, async (req: any, res: Response) => {
    try {
      const { storage } = await import('./storage');
      const { getJson, setJson } = await import('./cache');
      let apiKeyIds: string[] = [];

      const authHeader = req.headers.authorization || '';
      if (authHeader) {
        let keyVal = undefined;
        if (typeof authHeader === 'string') {
          if (authHeader.startsWith('Bearer ')) keyVal = authHeader.substring(7);
          else if (authHeader.startsWith('ApiKey ')) keyVal = authHeader.substring(7);
          else keyVal = authHeader;
        }
        if (keyVal) {
          const apiKeyDoc = await storage.getApiKeyByKey(keyVal);
          if (apiKeyDoc) apiKeyIds.push(apiKeyDoc._id.toString());
        }
      }

      if (apiKeyIds.length === 0 && req.user) {
  const apiKeys = await storage.getApiKeys(req.user._id.toString());
  apiKeyIds = apiKeys.map((k: any) => k._id.toString());
      }

  if (apiKeyIds.length === 0) return res.status(401).json({ error: 'API key or login required' });

  const months = Number(req.query.months || 6);
  const cacheKey = `analytics:timeseries:${apiKeyIds.join(',')}:m${months}`;
  const cached = await getJson(cacheKey);
  if (cached) return res.json(cached);
      const now = new Date();
      const results: { month: string; revenue: number }[] = [];

      const subscriptionIds = (await RecurringSubscription.find({ apiKeyId: { $in: apiKeyIds } }).select('subscriptionId')).map(x => x.subscriptionId);

      for (let i = months - 1; i >= 0; i--) {
        const start = new Date(now.getFullYear(), now.getMonth() - i, 1);
        const end = new Date(start.getFullYear(), start.getMonth() + 1, 1);

        const succeededEvents = await SubscriptionEvent.find({
          eventType: 'payment_succeeded',
          createdAt: { $gte: start, $lt: end },
          subscriptionId: { $in: subscriptionIds }
        }).select('eventData');

        let sum = 0;
        for (const ev of succeededEvents) {
          if (ev.eventData && typeof ev.eventData.amount === 'number') sum += ev.eventData.amount;
          else if (ev.eventData && typeof ev.eventData.amount_usd === 'number') sum += ev.eventData.amount_usd;
          else if (ev.eventData && ev.eventData.amount) sum += Number(ev.eventData.amount) || 0;
        }

        // monthly MRR snapshot: sum payments in month
        results.push({ month: start.toLocaleString('default', { month: 'short' }), revenue: Math.round(sum * 100) / 100 });
      }

      const out = { timeseries: results };
      await setJson(cacheKey, out, 60);
      return res.json(out);
    } catch (error) {
      console.log('Revenue timeseries failed', { error });
      return res.status(500).json({ error: 'internal_error' });
    }
  });

  /**
   * Recent subscriptions list
   */
  app.get('/api/analytics/recent-subscriptions', optionalAuth, async (req: any, res: Response) => {
    try {
      const { storage } = await import('./storage');
      const { getJson, setJson } = await import('./cache');
      let apiKeyIds: string[] = [];

      const authHeader = req.headers.authorization || '';
      if (authHeader) {
        let keyVal = undefined;
        if (typeof authHeader === 'string') {
          if (authHeader.startsWith('Bearer ')) keyVal = authHeader.substring(7);
          else if (authHeader.startsWith('ApiKey ')) keyVal = authHeader.substring(7);
          else keyVal = authHeader;
        }
        if (keyVal) {
          const apiKeyDoc = await storage.getApiKeyByKey(keyVal);
          if (apiKeyDoc) apiKeyIds.push(apiKeyDoc._id.toString());
        }
      }

      if (apiKeyIds.length === 0 && req.user) {
  const apiKeys = await storage.getApiKeys(req.user._id.toString());
  apiKeyIds = apiKeys.map((k: any) => k._id.toString());
      }

      if (apiKeyIds.length === 0) return res.status(401).json({ error: 'API key or login required' });

  const limit = Number(req.query.limit || 10);
  const cacheKey = `analytics:recent:${apiKeyIds.join(',')}:l${limit}`;
  const cached = await getJson(cacheKey);
  if (cached) return res.json(cached);

      const subs = await RecurringSubscription.find({ apiKeyId: { $in: apiKeyIds } })
        .sort({ createdAt: -1 })
        .limit(limit)
        .exec();

      const out = {
        subscriptions: subs.map(s => ({
          subscription_id: s.subscriptionId,
          customer: s.walletAddress || null,
          amount_usd: s.priceUsd,
          interval: s.billingInterval,
          status: s.status,
          next_payment: s.nextBillingDate ? s.nextBillingDate.toISOString() : null,
          created_at: s.createdAt.toISOString(),
        }))
      };
      await setJson(cacheKey, out, 30);
      return res.json(out);
    } catch (error) {
      console.log('Recent subscriptions failed', { error });
      return res.status(500).json({ error: 'internal_error' });
    }
  });

  /**
   * Get subscription events/history
   * 
   * Retrieves the complete event history for a subscription, including creation,
   * wallet connections, payments, failures, and cancellations. Useful for
   * debugging and audit trails.
   * 
   * URL Parameters:
   * - subscriptionId: string (subscription identifier)
   * 
   * Query Parameters:
   * - limit?: number (events per page, default 20)
   * - offset?: number (pagination offset, default 0)
   * 
   * Returns:
   * - Array of subscription events with timestamps
   * - Event details and transaction signatures
   * - Pagination information
   * 
   * Cost: 0.1 credits (simple database query for event logs)
   */
  app.get("/api/recurring-subscriptions/:subscriptionId/events",  async (req: ApiKeyAuthenticatedRequest, res: Response) => {
    try {
      const { subscriptionId } = req.params;
      const { limit = 20, offset = 0 } = req.query;
      
      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      if (!subscription) {
        return res.status(404).json({ error: "subscription_not_found" });
      }

      // Verify ownership via API key
      if (req.apiKey && subscription.apiKeyId !== req.apiKey._id) {
        return res.status(403).json({ error: "forbidden" });
      }

      const events = await SubscriptionEvent.find({ subscriptionId })
        .sort({ createdAt: -1 })
        .limit(Number(limit))
        .skip(Number(offset))
        .exec();

      const total = await SubscriptionEvent.countDocuments({ subscriptionId });

      return res.json({
        events: events.map(event => ({
          event_type: event.eventType,
          event_data: event.eventData,
          transaction_signature: event.transactionSignature,
          created_at: event.createdAt.toISOString(),
        })),
        pagination: {
          total,
          limit: Number(limit),
          offset: Number(offset),
          has_more: Number(offset) + Number(limit) < total,
        },
      });

    } catch (error) {
      console.log("Get subscription events failed", { 
        error: error instanceof Error ? error.message : String(error) 
      });
      return res.status(500).json({ error: "internal_error" });
    }
  });

  /**
   * Rotate relayer secret for a subscription. Returns the plaintext secret once.
   * POST body: { subscriptionId }
   */
  app.post('/api/relayer-secret/rotate',async (req: ApiKeyAuthenticatedRequest, res: Response) => {
    try {
      const { subscriptionId } = req.body;
      if (!subscriptionId) return res.status(400).json({ error: 'missing_subscriptionId' });

      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      if (!subscription) return res.status(404).json({ error: 'subscription_not_found' });

      // Verify ownership via API key
      if (req.apiKey && subscription.apiKeyId !== req.apiKey._id) {
        return res.status(403).json({ error: 'forbidden' });
      }

      // Generate new random 32-byte secret
      const crypto = await import('crypto');
      const newSecret = crypto.randomBytes(32).toString('hex');

      // Encrypt with master key
  const { encryptWithMasterKey } = await import('./crypto-utils');
      const encrypted = encryptWithMasterKey(newSecret);

      subscription.relayerSecretEncrypted = encrypted;
      subscription.relayerSecretSetAt = new Date();
      await subscription.save();

      // Return the plaintext secret once
      return res.json({ relayerSecret: newSecret, note: 'copy_this_once' });
    } catch (error) {
      console.log('Rotate relayer secret failed', { error });
      return res.status(500).json({ error: 'internal_error' });
    }
  });

  /**
   * Phantom wallet connection callback (PUBLIC ENDPOINT)
   * 
   * This public endpoint receives callbacks from Phantom wallet after users
   * complete the wallet connection process. It does not require API key authentication
   * as it's called directly by Phantom.
   * 
   * Query Parameters:
   * - subscription_id: string (subscription identifier)
   * - phantom_encryption_public_key: string (encryption key from Phantom)
   * - data: string (encrypted connection data)
   * - nonce: string (encryption nonce)
   * 
   * This endpoint is used internally by the Phantom integration and should not
   * be called directly by developers.
   * 
   * Cost: Free (no API key required, called by Phantom)
   */app.get("/api/recurring-subscriptions/phantom/connect-callback/:subscriptionId?", async (req: Request, res: Response) => {
  try {
    // Prefer subscriptionId from path (robust) then fallback to query
    const subscription_id = (req.params && (req.params as any).subscriptionId) || (req.query && req.query.subscription_id);
    const phantom_encryption_public_key = req.query.phantom_encryption_public_key;
    const data = req.query.data;
    const nonce = req.query.nonce;

    if (!subscription_id || typeof subscription_id !== 'string') {
      return res.status(400).json({ error: "missing_subscription_id" });
    }

    const subscription = await RecurringSubscription.findOne({ subscriptionId: subscription_id });
    if (!subscription) return res.status(404).json({ error: "subscription_not_found" });

    if (subscription.status !== 'pending_wallet_connection') {
      return res.status(400).json({ error: "invalid_status", message: "Subscription must be pending wallet connection" });
    }

      // If Phantom did not send encrypted payload, fallback to log and redirect (non-fatal)
      if (!phantom_encryption_public_key || !data || !nonce) {
        console.log("Phantom connect callback received (no encrypted payload)", { subscriptionId: subscription_id, hasData: !!data, hasNonce: !!nonce });
        await logSubscriptionEvent(subscription_id, 'wallet_connected', {
          phantom_callback: true,
          timestamp: new Date().toISOString(),
        });
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "http://localhost:3000");
        return res.redirect(`${frontendUrl}/subscription/connect-success?subscription_id=${subscription_id}`);
      }

      // Attempt to decrypt the Phantom payload using server dApp encryption key
      try {
        const { decryptPhantomCallbackData } = await import('./phantom-wallet-utils');
        const decrypted = decryptPhantomCallbackData(String(phantom_encryption_public_key), String(data), String(nonce));
        // Expect decrypted JSON: { publicKey: "<base58>", signature: "<base64>" }
        let parsed: any = {};
        try { parsed = JSON.parse(decrypted); } catch (e) {
          throw new Error('decrypted_payload_not_json');
        }

        const walletAddress = parsed.publicKey || parsed.public_key || parsed.pubkey || parsed.wallet;
        const signature = parsed.signature || parsed.sig || parsed.s;
        if (!walletAddress) throw new Error('missing_public_key_in_payload');

        // Retrieve the server-stored connect message so we can verify signature
        const message = (subscription.metadata && (subscription.metadata as any).walletConnectionMessage) || '';
        if (!message) {
          throw new Error('no_connection_message_on_subscription');
        }

        // Verify signature if provided
        if (!signature) {
          throw new Error('missing_signature_in_payload');
        }

        // verify ownership via signature
        const { verifyWalletConnection } = await import('./phantom-wallet-utils');
        if (!verifyWalletConnection(walletAddress, signature, message)) {
          throw new Error('invalid_signature');
        }

        // Attach wallet to subscription and follow same logic as connect-wallet route
        subscription.walletAddress = walletAddress;

        const now = new Date();
        if (subscription.trialEndDate && subscription.trialEndDate > now) {
          // Trial period - next billing date is after trial ends
          subscription.nextBillingDate = calculateNextBillingDate(
            subscription.trialEndDate, 
            subscription.billingInterval
          );
          subscription.currentPeriodStart = now;
          subscription.currentPeriodEnd = subscription.trialEndDate;
          subscription.status = 'active'; // Active during trial
          await subscription.save();
        } else {
          // No trial - do NOT mark active until a payment is confirmed.
          // Create a one-time initial payment intent (unsigned tx + phantom deeplink/QR)
          subscription.status = 'pending_payment';
          await subscription.save();

          const intent = await createRecurringPaymentIntent({
            subscriptionId: subscription.subscriptionId,
            walletAddress,
            assetType: subscription.asset === 'SOL' ? 'SOL' : 'SPL',
            amountLamports: subscription.asset === 'SOL' ? Math.round(subscription.priceUsd * 1e7) : undefined,
            tokenMint: subscription.tokenMint,
            tokenAmount: subscription.asset === 'SPL' ? String(Math.round(subscription.priceUsd * 1000000)) : undefined,
            billingCycle: 1,
          });

          // Persist PaymentOrder for tracking so the payment worker/relayer can pick it up
          await PaymentOrder.create({
            orderId: intent.paymentId,
            subscriptionId: subscription.subscriptionId,
            status: 'pending',
            assetType: intent.amountLamports ? 'SOL' : 'SPL',
            amountLamports: intent.amountLamports,
            tokenMint: intent.tokenMint,
            tokenAmount: intent.amount,
            merchant: intent.merchantAddress || process.env.MERCHANT_SOL_ADDRESS || '',
            userPubkey: walletAddress,
            memo: intent.memo || null,
            unsignedTxB64: intent.unsignedTxB64,
            expiresAt: intent.expiresAt,
          });

          // Log that initial payment was requested
          await logSubscriptionEvent(subscription_id, 'initial_payment_requested', {
            paymentId: intent.paymentId,
            expiresAt: intent.expiresAt,
          });

          // If subscription is SPL-based and has a token mint, attempt to return an approve intent (best-effort)
          let approvalIntent: any = undefined;
          if (subscription.asset === 'SPL' && subscription.tokenMint) {
            try {
              const merchant = getEnv('MERCHANT_SOL_ADDRESS');
              const allowance = String(Math.round(subscription.priceUsd * 1000000)); // placeholder mapping
              approvalIntent = await buildSplApproveDelegateUnsigned({
                userPubkey: walletAddress,
                tokenMint: subscription.tokenMint,
                delegate: merchant,
                amount: allowance,
              });
              // Save delegation details to subscription for server-side bookkeeping
              subscription.delegatePubkey = merchant;
              subscription.delegateAllowance = allowance;
              subscription.delegateApprovedAt = undefined;
              await subscription.save();
            } catch (err) {
              console.log('Failed to generate SPL approve intent in connect-callback', { subscriptionId: subscription_id, error: err instanceof Error ? err.message : String(err) });
            }
          }

          // Redirect to frontend and include payment/order ids so frontend can show QR or status
          const frontendUrl = getEnv("PHANTOM_DAPP_URL", "http://localhost:3000");
          // include payment_id if present
          const redirectTo = intent && intent.paymentId ? `${frontendUrl}/subscription/payment-pending?subscription_id=${subscription_id}&payment_id=${encodeURIComponent(intent.paymentId)}` : `${frontendUrl}/subscription/connect-success?subscription_id=${subscription_id}`;
          return res.redirect(redirectTo);
        }

        // Log wallet connected event & send webhook
        await logSubscriptionEvent(subscription_id, 'wallet_connected', {
          walletAddress,
          phantom_callback: true,
          verified: true
        });

        await sendWebhook(subscription, 'wallet_connected', { wallet_address: walletAddress });

        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "http://localhost:3000");
        return res.redirect(`${frontendUrl}/subscription/connect-success?subscription_id=${subscription_id}`);

      } catch (decryptErr) {
        console.log('Phantom connect callback decryption/verification failed', { subscriptionId: subscription_id, error: decryptErr instanceof Error ? decryptErr.message : String(decryptErr) });
        await logSubscriptionEvent(subscription_id, 'wallet_connect_failed', { error: decryptErr instanceof Error ? decryptErr.message : String(decryptErr) });
        const frontendUrl = getEnv("PHANTOM_DAPP_URL", "http://localhost:3000");
        return res.redirect(`${frontendUrl}/subscription/connect-error?error=callback_decrypt_failed`);
      }

    } catch (error) {
      console.log("Phantom connect callback failed", { 
        error: error instanceof Error ? error.message : String(error) 
      });
      
      const frontendUrl = getEnv("PHANTOM_DAPP_URL", "http://localhost:3000");
      return res.redirect(`${frontendUrl}/subscription/connect-error?error=callback_failed`);
    }
  });
  /**
   * Phantom approval callback (PUBLIC ENDPOINT)
   * Records that the user has approved a delegate (merchant) to transfer SPL tokens.
   */
  app.get("/api/recurring-subscriptions/phantom/approve-callback", async (req: Request, res: Response) => {
    try {
      const { subscription_id, approval_order_id, signature } = req.query;

      if (!subscription_id || typeof subscription_id !== 'string') {
        return res.status(400).json({ error: 'missing_subscription_id' });
      }

      const subscription = await RecurringSubscription.findOne({ subscriptionId: subscription_id });
      if (!subscription) return res.status(404).json({ error: 'subscription_not_found' });

      // Save approval signature and timestamp
      subscription.delegateApprovedAt = new Date();
      if (signature && typeof signature === 'string') {
        subscription.delegateApprovalSignature = signature;

        // Attempt to parse the on-chain transaction to extract token account, mint, and approve details
        try {
          const tx = await getTransactionBySignature(signature as string);
          if (tx) {
            // Try to find SPL Token approve instruction by scanning message instructions
            const msg: any = tx.transaction?.message;
            const ixs = msg?.instructions || [];
            let foundApprove = false;
            for (const ix of ixs) {
              try {
                // programId may be a PublicKey object or base58 string
                const pid = ix?.programId && typeof ix.programId === 'object' && ix.programId.toBase58 ? ix.programId.toBase58() : String(ix.programId || '');
                // SPL Token program id
                if (pid === 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA') {
                  // Many RPCs return parsed instruction info under ix.parsed
                  const parsed = ix.parsed || ix;
                  // Heuristic: parsed type 'approve' or instruction name 'Approve'
                  const instrType = parsed?.type || parsed?.instruction || parsed?.name;
                  if (instrType && String(instrType).toLowerCase().includes('approve')) {
                    // Extract accounts: source token account likely in parsed.info.source or parsed.accounts[0]
                    const info = parsed?.info || {};
                    const source = info?.source || (parsed?.accounts && parsed.accounts[0]) || null;
                    const delegate = info?.delegate || info?.authority || (parsed?.accounts && parsed.accounts[1]) || null;
                    const mint = info?.mint || null;
                    const amount = info?.amount || info?.amountString || null;

                    if (source) subscription.userTokenAccount = source;
                    if (!subscription.tokenMint && mint) subscription.tokenMint = mint;
                    if (delegate) subscription.delegatePubkey = delegate;
                    if (amount) subscription.delegateAllowance = String(amount);
                    foundApprove = true;
                    break;
                  }
                }
              } catch (e) {
                // ignore parse failures per-instruction
              }
            }

            // Fallback: try to inspect postTokenBalances to infer token account and mint
            if (!subscription.userTokenAccount) {
              const postTokenBalances = tx.meta?.postTokenBalances || [];
              const preTokenBalances = tx.meta?.preTokenBalances || [];
              // look for owner matching subscription.walletAddress or any balance change
              const match = postTokenBalances.find((b: any) => b.owner === subscription.walletAddress) || postTokenBalances[0];
              if (match) {
                try {
                  if (typeof match.accountIndex === 'number' && msg?.getAccountKeys) {
                    const keys: any[] = msg.getAccountKeys ? msg.getAccountKeys() : (msg.accountKeys || []);
                    const key = keys[match.accountIndex];
                    subscription.userTokenAccount = key && key.toBase58 ? key.toBase58() : String(match.accountIndex);
                  } else {
                    // fallback to whatever is present (some RPCs return `account`)
                    const m: any = match;
                    subscription.userTokenAccount = m?.account || m?.pubkey || subscription.userTokenAccount;
                  }
                  if (!subscription.tokenMint && match.mint) subscription.tokenMint = match.mint;
                } catch (e) {
                  // ignore
                }
              }
            }
          }
        } catch (e) {
          console.log('Failed to parse approval transaction', { subscriptionId: subscription_id, error: e });
        }
      }

      await subscription.save();

      await logSubscriptionEvent(subscription_id, 'activated', { approval_order_id, signature, userTokenAccount: subscription.userTokenAccount, tokenMint: subscription.tokenMint });

      const frontendUrl = getEnv("PHANTOM_DAPP_URL", "http://localhost:3000");
      return res.redirect(`${frontendUrl}/subscription/approve-success?subscription_id=${subscription_id}`);
    } catch (error) {
      console.log('Phantom approve callback failed', { error: error instanceof Error ? error.message : String(error) });
      const frontendUrl = getEnv("PHANTOM_DAPP_URL", "http://localhost:3000");
      return res.redirect(`${frontendUrl}/subscription/approve-error?error=callback_failed`);
    }
  });

  /**
   * Delete subscription and related event logs (hard delete)
   *
   * This endpoint permanently removes the subscription document and its
   * associated SubscriptionEvent logs from the database. It requires API key
   * authentication and verifies ownership (apiKeyId) before deletion.
   *
   * URL Parameters:
   * - subscriptionId: string
   *
   * Returns:
   * - 204 No Content on success
   * - 404 if subscription not found
   * - 403 if the API key does not own the subscription
   *
   * Cost: 0.5 credits (database delete operations)
   */
  app.delete("/api/recurring-subscriptions/:subscriptionId", authenticateApiKey(0.5), async (req: ApiKeyAuthenticatedRequest, res: Response) => {
    try {
      const { subscriptionId } = req.params;

      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      if (!subscription) {
        return res.status(404).json({ error: "subscription_not_found" });
      }

      // Verify ownership via API key
      if (req.apiKey && subscription.apiKeyId !== req.apiKey._id) {
        return res.status(403).json({ error: "forbidden" });
      }

      // Delete related events first
      await SubscriptionEvent.deleteMany({ subscriptionId });

      // Delete the subscription document
      await RecurringSubscription.deleteOne({ subscriptionId });

      // Log deletion event (best-effort)
      await logSubscriptionEvent(subscriptionId, 'deleted', {
        deletedByApiKey: req.apiKey ? String(req.apiKey._id) : null,
      });

      return res.status(204).send();
    } catch (error) {
      console.log("Delete subscription failed", { 
        error: error instanceof Error ? error.message : String(error) 
      });
      return res.status(500).json({ error: "internal_error" });
    }
  });

  /**
   * Configure relayer for a specific subscription (merchant-scoped)
   * Body: { relayerUrl?: string, rotateSecret?: true }
   * If rotateSecret is set, a new 32-byte secret is generated and encrypted with master key
   */
  app.post('/api/recurring-subscriptions/:subscriptionId/relayer', authenticateApiKey(0.5), async (req: ApiKeyAuthenticatedRequest, res: Response) => {
    try {
      const { subscriptionId } = req.params;
      const { relayerUrl, rotateSecret } = req.body || {};

      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      if (!subscription) return res.status(404).json({ error: 'subscription_not_found' });

      // Verify ownership via API key
      if (req.apiKey && subscription.apiKeyId !== req.apiKey._id) {
        return res.status(403).json({ error: 'forbidden' });
      }

      if (relayerUrl !== undefined) subscription.relayerUrl = relayerUrl;

      if (rotateSecret) {
        const crypto = await import('crypto');
        const newSecret = crypto.randomBytes(32).toString('hex');
        const { encryptWithMasterKey } = await import('./crypto-utils');
        const encrypted = encryptWithMasterKey(newSecret);
        subscription.relayerSecretEncrypted = encrypted;
        subscription.relayerSecretSetAt = new Date();
        await subscription.save();

        // Return plaintext secret once
        return res.json({ relayerSecret: newSecret, note: 'copy_this_once' });
      }

      await subscription.save();
      return res.json({ ok: true, relayerUrl: subscription.relayerUrl });
    } catch (error) {
      console.log('Configure relayer failed', { error });
      return res.status(500).json({ error: 'internal_error' });
    }
  });

  /**
   * Relayer API: fetch per-subscription relayer secret (decrypted)
   * Auth: Bearer token matching RELAYER_API_KEY env var (simple shared secret for relayers)
   */
  app.get('/api/relayer/secret/:subscriptionId', async (req: Request, res: Response) => {
    try {
      const auth = req.headers.authorization || '';
      const expected = process.env.RELAYER_API_KEY || '';
      if (!auth || !expected) return res.status(403).json({ error: 'unauthorized' });
      const token = typeof auth === 'string' && auth.startsWith('Bearer ') ? auth.substring(7) : auth;
      if (token !== expected) return res.status(403).json({ error: 'unauthorized' });

      const { subscriptionId } = req.params;
      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      if (!subscription) return res.status(404).json({ error: 'subscription_not_found' });

      if (!subscription.relayerSecretEncrypted) return res.status(404).json({ error: 'no_relayer_secret' });

      const { decryptWithMasterKey } = await import('./crypto-utils');
      const secret = decryptWithMasterKey(subscription.relayerSecretEncrypted);

      return res.json({ relayerSecret: secret });
    } catch (error) {
      console.log('Relayer secret fetch failed', { error });
      return res.status(500).json({ error: 'internal_error' });
    }
  });

  /**
   * Relayer API: fetch merchant signing key for a subscription (if stored in subscription metadata)
   * The merchant signing key (if provided) should be stored encrypted in subscription.metadata.merchantSigningKeyEncrypted
   */
  app.get('/api/relayer/merchant-key/:subscriptionId', async (req: Request, res: Response) => {
    try {
      const auth = req.headers.authorization || '';
      const expected = process.env.RELAYER_API_KEY || '';
      if (!auth || !expected) return res.status(403).json({ error: 'unauthorized' });
      const token = typeof auth === 'string' && auth.startsWith('Bearer ') ? auth.substring(7) : auth;
      if (token !== expected) return res.status(403).json({ error: 'unauthorized' });

      const { subscriptionId } = req.params;
      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      if (!subscription) return res.status(404).json({ error: 'subscription_not_found' });

      const enc = (subscription.metadata && (subscription.metadata as any).merchantSigningKeyEncrypted) || null;
      if (!enc) return res.status(404).json({ error: 'no_merchant_key' });

      const { decryptWithMasterKey } = await import('./crypto-utils');
      const key = decryptWithMasterKey(enc);
      return res.json({ merchantSigningKey: key });
    } catch (error) {
      console.log('Relayer merchant key fetch failed', { error });
      return res.status(500).json({ error: 'internal_error' });
    }
  });
    }
  /**
   * Confirm payment and activate subscription (used by worker/relayer after on-chain verification)
   * This function is exported for internal worker use and not mounted as an HTTP route.
   */
  // async function confirmPaymentForSubscription(subscriptionId: string, paymentId: string, signature?: string) {
  //   try {
  //     const subscription = await RecurringSubscription.findOne({ subscriptionId });
  //     if (!subscription) {
  //       console.log('confirmPaymentForSubscription: subscription not found', { subscriptionId });
  //       return false;
  //     }

  //     // Update subscription with successful payment info
  //     subscription.lastPaymentDate = new Date();
  //     subscription.lastPaymentSignature = signature || undefined;
  //     subscription.failedPaymentAttempts = 0;
  //     subscription.gracePeriodUntil = undefined;

  //     const now = new Date();

  //     // If subscription was pending payment (initial), set current period start now
  //     if (!subscription.currentPeriodStart) subscription.currentPeriodStart = now;

  //     subscription.nextBillingDate = calculateNextBillingDate(now, subscription.billingInterval);
  //     subscription.currentPeriodEnd = new Date(subscription.nextBillingDate.getTime() - 1);

  //     // Mark active
  //     subscription.status = 'active';
  //     subscription.autoRenew = true;
  //     subscription.cancelAtPeriodEnd = false;

  //     await subscription.save();

  //     // Log event and send webhook
  //     await logSubscriptionEvent(subscriptionId, 'payment_succeeded', {
  //       payment_id: paymentId,
  //       transaction_signature: signature,
  //       amount: subscription.priceUsd,
  //       next_billing_date: subscription.nextBillingDate?.toISOString(),
  //     }, signature);

  //     await sendWebhook(subscription, 'payment_succeeded', {
  //       payment_id: paymentId,
  //       transaction_signature: signature,
  //       amount_usd: subscription.priceUsd,
  //       next_billing_date: subscription.nextBillingDate?.toISOString(),
  //     });

  //     return true;
  //   } catch (e) {
  //     console.log('confirmPaymentForSubscription failed', { subscriptionId, error: e });
  //     return false;
  //   }
  // }

  
/**
 * Confirm payment and activate subscription (used by worker/relayer after on-chain verification)
 * Exported as a module-level function so workers can call it after confirming a PaymentOrder
 */
    
export async function confirmPaymentForSubscription(subscriptionId: string, paymentId: string, signature?: string) {
  try {
    const subscription = await RecurringSubscription.findOne({ subscriptionId });
    if (!subscription) {
      console.log('confirmPaymentForSubscription: subscription not found', { subscriptionId });
      return false;
    }

    // Update subscription with successful payment info
    subscription.lastPaymentDate = new Date();
    subscription.lastPaymentSignature = signature || undefined;
    subscription.failedPaymentAttempts = 0;
    subscription.gracePeriodUntil = undefined;

    const now = new Date();

    // If subscription was pending payment (initial), set current period start now
    if (!subscription.currentPeriodStart) subscription.currentPeriodStart = now;

    subscription.nextBillingDate = calculateNextBillingDate(now, subscription.billingInterval);
    subscription.currentPeriodEnd = new Date(subscription.nextBillingDate.getTime() - 1);

    // Mark active
    subscription.status = 'active';
    subscription.autoRenew = true;
    subscription.cancelAtPeriodEnd = false;

    await subscription.save();

    // Log event and send webhook
    await logSubscriptionEvent(subscriptionId, 'payment_succeeded', {
      payment_id: paymentId,
      transaction_signature: signature,
      amount: subscription.priceUsd,
      next_billing_date: subscription.nextBillingDate?.toISOString(),
    }, signature);

    await sendWebhook(subscription, 'payment_succeeded', {
      payment_id: paymentId,
      transaction_signature: signature,
      amount_usd: subscription.priceUsd,
      next_billing_date: subscription.nextBillingDate?.toISOString(),
    });

    return true;
  } catch (e) {
    console.log('confirmPaymentForSubscription failed', { subscriptionId, error: e });
    return false;
  }
}





















