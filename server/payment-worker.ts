/**
 * PaymentWorker (no dynamic helper loading)
 *
 * - Processes due recurring subscriptions and supports billingInterval values:
 *   'daily', 'weekly', 'monthly', 'yearly' (defaults to 'monthly' if unknown)
 * - Respects trialEndDate: subscriptions in trial are skipped until trial end
 * - Supports Anchor/on-chain releases via releasePaymentForSubscription
 * - Creates off-chain payment intents via createRecurringPaymentIntent
 *
 * This version removes dynamic loadHelpers() and instead imports the helper
 * functions directly from server/webhook-delivery.ts. Put the helper file at
 * server/webhook-delivery.ts (or change the import path below).
 */

import mongoose from "mongoose";
import { RecurringSubscription } from "../shared/recurring-subscription-schema";
import type { RecurringSubscriptionType } from "../shared/recurring-subscription-schema";
import { createRecurringPaymentIntent } from "./phantom-wallet-utils";
import { releasePaymentForSubscription } from "./solana-anchor";



const DEFAULT_RECURRING_INTERVAL_MS = Number(process.env.WORKER_INTERVAL_MS || 60_000); // 60s main loop
const EXPIRED_ORDER_CHECK_INTERVAL_MS = Number(process.env.WORKER_EXPIRED_ORDER_CHECK_INTERVAL_MS || 5 * 60 * 1000); // 5m

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Calculate next billing date given a start Date and billingInterval string.
 * Supports: 'daily', 'weekly', 'monthly', 'yearly'. Defaults to monthly.
 */
function calculateNextBillingDateFrom(start: Date, billingInterval?: string): Date {
  const next = new Date(start.getTime());
  const interval = (billingInterval || "monthly").toString().toLowerCase();

  switch (interval) {
    case "daily":
    case "day":
      next.setDate(next.getDate() + 1);
      break;
    case "weekly":
    case "week":
      next.setDate(next.getDate() + 7);
      break;
    case "monthly":
    case "month": {
      // preserve day-of-month where possible
      const currentMonth = next.getMonth();
      next.setMonth(currentMonth + 1);
      break;
    }
    case "yearly":
    case "year":
      next.setFullYear(next.getFullYear() + 1);
      break;
    default: {
      const digits = (billingInterval || "").match(/(\d+)/);
      if (digits) {
        const days = Number(digits[1]);
        if (Number.isFinite(days) && days > 0) {
          next.setDate(next.getDate() + days);
          break;
        }
      }
      // fallback to 1 month
      next.setMonth(next.getMonth() + 1);
      break;
    }
  }
  return next;
}

export class PaymentWorker {
  private running = false;
  private recurringTimer?: NodeJS.Timeout;
  private expiredTimer?: NodeJS.Timeout;

  private config = {
    recurringIntervalMs: DEFAULT_RECURRING_INTERVAL_MS,
    expiredOrderCheckIntervalMs: EXPIRED_ORDER_CHECK_INTERVAL_MS,
  };

  constructor() {}

  start() {
    if (this.running) return;
    this.running = true;
    console.log("PaymentWorker starting...");

    this.recurringTimer = setInterval(() => {
      this.processDueRecurringSubscriptions().catch((e) =>
        console.log("processDueRecurringSubscriptions failed", e)
      );
    }, this.config.recurringIntervalMs);

    this.expiredTimer = setInterval(() => {
      this.markExpiredOrders().catch((e) => console.log("markExpiredOrders failed", e));
    }, this.config.expiredOrderCheckIntervalMs);

    // immediate run
    this.processDueRecurringSubscriptions().catch((e) =>
      console.log("initial processDueRecurringSubscriptions failed", e)
    );
  }

  stop() {
    this.running = false;
    if (this.recurringTimer) {
      clearInterval(this.recurringTimer);
      this.recurringTimer = undefined;
    }
    if (this.expiredTimer) {
      clearInterval(this.expiredTimer);
      this.expiredTimer = undefined;
    }
  }

  async markExpiredOrders() {
    try {
      const PaymentOrder = (mongoose.models && (mongoose.models as any).PaymentOrder) || null;
      if (!PaymentOrder) return;
      const now = new Date();
      await PaymentOrder.updateMany({ status: "pending", expiresAt: { $lte: now } }, { $set: { status: "expired" } });
    } catch (e) {
      console.log("markExpiredOrders error", e);
    }
  }

  async processDueRecurringSubscriptions() {
    try {
      const now = new Date();
      // Find active subscriptions where nextBillingDate <= now
      const dueSubs = await RecurringSubscription.find({
        status: "active",
        nextBillingDate: { $lte: now },
      }).exec();

      if (!dueSubs || dueSubs.length === 0) return;

      console.log(`PaymentWorker: found ${dueSubs.length} due subscriptions`);

      for (const subscription of dueSubs) {
        try {
          // Skip if still in trial (defensive check)
          if (subscription.trialEndDate && subscription.trialEndDate > new Date()) {
            console.log("Skipping subscription in trial", subscription.subscriptionId);
            subscription.nextBillingDate = subscription.trialEndDate;
            await subscription.save();
            continue;
          }

          // Anchor/on-chain backed
          const anchorMeta = subscription.metadata && (subscription.metadata as any).anchor;
          if (anchorMeta && anchorMeta.subscriptionPda && anchorMeta.escrowPda) {
            await this._processOnchainSubscription(subscription, anchorMeta);
            continue;
          }

          // Offchain / unsigned tx flow
          await this._processOffchainSubscription(subscription);
        } catch (innerErr) {
          console.log("Failed processing subscription", subscription.subscriptionId, innerErr);
          try {
            subscription.failedPaymentAttempts = (subscription.failedPaymentAttempts || 0) + 1;
            const backoffDays = Math.min(subscription.failedPaymentAttempts, 7);
            subscription.nextBillingDate = new Date(Date.now() + backoffDays * 24 * 3600 * 1000);
            await subscription.save();


           
          } catch (e) {
            console.log("Failed to persist failure state", subscription.subscriptionId, e);
          }
        }
      }
    } catch (e) {
      console.log("processDueRecurringSubscriptions error", e);
    }
  }

  private async _processOnchainSubscription(subscription: any, anchorMeta: any) {
    try {
      const subscriptionId = subscription.subscriptionId;
      const merchant = subscription.merchantAddress || process.env.MERCHANT_SOL_ADDRESS;
      if (!merchant) throw new Error("merchant address missing (cannot release onchain)");

      console.log("PaymentWorker: releasing onchain payment for", subscriptionId);

      // Actual on-chain transfer: relayer signs and calls releasePaymentForSubscription
      const txSig = await releasePaymentForSubscription({
        subscriptionPdaBase58: anchorMeta.subscriptionPda,
        escrowPdaBase58: anchorMeta.escrowPda,
        merchantPubkeyBase58: merchant,
      });

      // bookkeeping
      anchorMeta.monthsPaid = (anchorMeta.monthsPaid || 0) + 1;
      subscription.metadata = { ...(subscription.metadata || {}), anchor: anchorMeta };

      subscription.lastPaymentDate = new Date();
      subscription.lastPaymentSignature = txSig;
      subscription.failedPaymentAttempts = 0;

      // compute next billing based on interval
      subscription.nextBillingDate = calculateNextBillingDateFrom(new Date(), subscription.billingInterval);
      // If totalMonths defined: check completion
      if (anchorMeta.totalMonths && anchorMeta.monthsPaid >= anchorMeta.totalMonths) {
        subscription.status = "completed";
      } else {
        subscription.status = "active";
      }

      await subscription.save();

      console.log("PaymentWorker: release succeeded", subscriptionId, txSig);


     
    } catch (e) {
      console.log("release_payment error", e);
      throw e;
    }
  }

  private async _processOffchainSubscription(subscription: any) {
    try {
      const subscriptionId = subscription.subscriptionId;
      console.log("PaymentWorker: building offchain recurring intent for", subscriptionId);

      const amountLamports = Math.max(1, Math.round((subscription.priceUsd || 1) * 1e7));

      const intent = await createRecurringPaymentIntent({
        subscriptionId: subscriptionId,
        walletAddress: subscription.walletAddress || null,
        assetType: subscription.asset === "SOL" ? "SOL" : "SPL",
        amountLamports: subscription.asset === "SOL" ? amountLamports : undefined,
        tokenMint: subscription.tokenMint || undefined,
        tokenAmount: subscription.tokenAmount || undefined,
        billingCycle: 1,
        merchantAddress: subscription.merchantAddress || process.env.MERCHANT_SOL_ADDRESS,
      });

      // Persist PaymentOrder model if available
      const PaymentOrderModel = (mongoose.models as any).PaymentOrder || null;
      if (PaymentOrderModel) {
        try {
          await PaymentOrderModel.create({
            orderId: intent.paymentId,
            subscriptionId: subscriptionId,
            status: "pending",
            assetType: intent.amountLamports ? "SOL" : "SPL",
            amountLamports: intent.amountLamports,
            tokenMint: intent.tokenMint,
            tokenAmount: intent.amount,
            merchant: intent.merchantAddress || process.env.MERCHANT_SOL_ADDRESS || "",
            userPubkey: intent.walletAddress || subscription.walletAddress || null,
            memo: intent.memo || null,
            unsignedTxB64: intent.unsignedTxB64 || null,
            expiresAt: intent.expiresAt,
            createdAt: new Date(),
            updatedAt: new Date(),
          });
        } catch (e) {
          console.log("Failed to persist PaymentOrder", e);
        }
      }

      // set status pending payment and set nextBillingDate to a backstop while waiting for payment
      subscription.status = "pending_payment";
      subscription.nextBillingDate = calculateNextBillingDateFrom(new Date(), subscription.billingInterval);
      await subscription.save();

      // notify merchant about pending initial payment intent (unsigned tx)
      const webhookPayload = {
        subscription_id: subscriptionId,
        status: subscription.status,
        payment_intent: {
          payment_id: intent.paymentId,
          phantom_url: intent.phantomUrl,
          qr_data_url: intent.qrDataUrl,
          unsigned_tx: intent.unsignedTxB64,
          expires_at: intent.expiresAt,
        },
      };

     

    } catch (e) {
      console.log("createRecurringPaymentIntent failed", e);
      throw e;
    }
  }
}

// singleton and CLI run support
export const paymentWorker = new PaymentWorker();

if (require.main === module) {
  paymentWorker.start();
  process.on("SIGINT", async () => {
    console.log("SIGINT received, stopping PaymentWorker...");
    paymentWorker.stop();
    process.exit(0);
  });
}
