import { PaymentOrder, ApiKey } from "@shared/schema-mongodb";
import { RecurringSubscription, SubscriptionEvent } from "@shared/recurring-subscription-schema";
import { v4 as uuidv4 } from 'uuid';
// import { createRecurringPaymentIntent } from "./phantom-wallet-utils";
import http from 'http';
import https from 'https';

async function postJson(url: string, body: any, headers: Record<string, string> = {}) {
  return new Promise<void>((resolve, reject) => {
    try {
      const u = new URL(url);
      const isHttps = u.protocol === 'https:';
      const data = JSON.stringify(body);
      const opts: any = {
        hostname: u.hostname,
        port: u.port || (isHttps ? 443 : 80),
        path: u.pathname + (u.search || ''),
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(data),
          ...headers,
        },
      };

      const req = (isHttps ? https : http).request(opts, (res) => {
        res.setEncoding('utf8');
        let raw = '';
        res.on('data', (chunk) => raw += chunk);
        res.on('end', () => resolve());
      });

      req.on('error', (err) => reject(err));
      req.write(data);
      req.end();
    } catch (err) {
      reject(err);
    }
  });
}
import { getTransactionBySignature, extractMemoFromTransaction } from "./solana";
import { logger } from "./security";
import { inc, timing } from './metrics';
import { PublicKey } from "@solana/web3.js";
import { getAssociatedTokenAddressSync } from "@solana/spl-token";

interface WorkerConfig {
  expiredOrderCheckInterval: number; // milliseconds
  pendingOrderVerificationInterval: number; // milliseconds
  recurringBillingCheckInterval: number; // milliseconds
  maxRetries: number;
  enabled: boolean;
}

const DEFAULT_CONFIG: WorkerConfig = {
  expiredOrderCheckInterval: 60 * 1000, // 1 minute
  pendingOrderVerificationInterval: 30 * 1000, // 30 seconds
  recurringBillingCheckInterval: 60 * 1000, // 1 minute - check for due subscriptions
  maxRetries: 3,
  enabled: process.env.NODE_ENV !== 'test', // Disable in tests
};

class PaymentWorker {
  private config: WorkerConfig;
  private expiredOrderTimer?: NodeJS.Timeout;
  private pendingOrderTimer?: NodeJS.Timeout;
  private recurringBillingTimer?: NodeJS.Timeout;
  private isRunning = false;
  private instanceId: string;

  constructor(config: Partial<WorkerConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.instanceId = `${process.pid}-${uuidv4()}`;
  }

  start(): void {
    if (!this.config.enabled || this.isRunning) {
      return;
    }

    this.isRunning = true;
    logger.info('Starting payment worker', { config: this.config });

    // Start periodic tasks
    this.startExpiredOrderCheck();
    this.startPendingOrderVerification();
    this.startRecurringBillingCheck();
  }

  // Expose current running state so external supervisors can monitor
  public get running(): boolean {
    return this.isRunning;
  }

  stop(): void {
    if (!this.isRunning) {
      return;
    }

    logger.info('Stopping payment worker');
    this.isRunning = false;

    if (this.expiredOrderTimer) {
      clearInterval(this.expiredOrderTimer);
      this.expiredOrderTimer = undefined;
    }

    if (this.pendingOrderTimer) {
      clearInterval(this.pendingOrderTimer);
      this.pendingOrderTimer = undefined;
    }

    if (this.recurringBillingTimer) {
      clearInterval(this.recurringBillingTimer);
      this.recurringBillingTimer = undefined;
    }
  }

  private startExpiredOrderCheck(): void {
    this.expiredOrderTimer = setInterval(async () => {
      try {
        await this.markExpiredOrders();
      } catch (error) {
        logger.error('Error in expired order check', { error });
      }
    }, this.config.expiredOrderCheckInterval);
  }

  private startPendingOrderVerification(): void {
    this.pendingOrderTimer = setInterval(async () => {
      try {
        await this.verifyPendingOrders();
      } catch (error) {
        logger.error('Error in pending order verification', { error });
      }
    }, this.config.pendingOrderVerificationInterval);
  }

  private startRecurringBillingCheck(): void {
    this.recurringBillingTimer = setInterval(async () => {
      try {
        await this.processDueRecurringSubscriptions();
      } catch (error) {
        logger.error('Error in recurring billing check', { error });
      }
    }, this.config.recurringBillingCheckInterval);
  }

  /**
   * Find due recurring subscriptions and create non-custodial PaymentOrders (intents)
   * This keeps existing public APIs unchanged; it merely generates the unsigned
   * Phantom deeplink/QR and persists a PaymentOrder so the merchant or customer
   * can complete the payment. Webhooks and SubscriptionEvent logs are emitted.
   */  // Replace the existing method 'processDueRecurringSubscriptions' in the PaymentWorker class with the implementation below.
  // Paste this method body in place of the old one (keep it inside the same class).
  
  private async markExpiredOrders(): Promise<void> {
    const now = new Date();
    const result = await PaymentOrder.updateMany(
      {
        status: 'pending',
        expiresAt: { $lt: now }
      },
      {
        $set: { status: 'expired' }
      }
    );

    if (result.modifiedCount > 0) {
      logger.info(`Marked ${result.modifiedCount} orders as expired`);
    }
  }

  private async verifyPendingOrders(): Promise<void> {
    // Find orders that are submitted but not yet confirmed
    const submittedOrders = await PaymentOrder.find({
      status: 'submitted',
      signature: { $exists: true, $ne: null }
    }).limit(50); // Process in batches

    for (const order of submittedOrders) {
      try {
        await this.verifySubmittedOrder(order);
      } catch (error) {
        logger.error('Error verifying submitted order', {
          orderId: order.orderId,
          signature: order.signature,
          error
        });
      }
    }
  }

  private async verifySubmittedOrder(order: any): Promise<void> {
    if (!order.signature) {
      return;
    }

    try {
      const tx = await getTransactionBySignature(order.signature);
      if (!tx) {
        // Transaction not found yet, might still be processing
        return;
      }

      if (tx.meta?.err) {
        // Transaction failed
        await PaymentOrder.updateOne(
          { _id: order._id },
          { $set: { status: 'failed' } }
        );
        logger.info(`Order ${order.orderId} marked as failed due to transaction error`);
        return;
      }

      // Verify the transaction details
      const verifyResult = await this.verifyTransactionDetails(tx, order);
      if (verifyResult.ok) {
        await PaymentOrder.updateOne(
          { _id: order._id },
          { $set: { status: 'confirmed' } }
        );
        logger.info(`Order ${order.orderId} confirmed on-chain`);
        inc('payment.confirmed');
        try { timing('payment.confirmation.latency', Date.now() - (order.createdAt ? new Date(order.createdAt).getTime() : Date.now())); } catch {}

        // If this order is tied to a recurring subscription, credit the subscription's issued API key
        try {
          if (order.subscriptionId) {
            const sub = await RecurringSubscription.findOne({ subscriptionId: order.subscriptionId }).exec();
            if (sub && (sub as any).issuedApiKeyId) {
              const monthlyCredits = Number(process.env.SUBSCRIPTION_MONTHLY_CREDITS || '0');
              if (monthlyCredits > 0) {
                await ApiKey.findByIdAndUpdate((sub as any).issuedApiKeyId, { $inc: { credits: monthlyCredits } }).exec();
                logger.info('Credited issued API key for subscription', { subscriptionId: order.subscriptionId, issuedApiKeyId: (sub as any).issuedApiKeyId, credits: monthlyCredits });
              }
            }
          }
        } catch (e) {
          logger.error('Failed to credit issued API key after order confirmation', { orderId: order.orderId, error: e });
        }
        // If order belongs to a recurring subscription, call into the subscription module to confirm and activate
        try {
          if (order.subscriptionId) {
            const recurring = await import('./recurring-subscription-routes');
            if (recurring && typeof (recurring as any).confirmPaymentForSubscription === 'function') {
              await (recurring as any).confirmPaymentForSubscription(order.subscriptionId, order.orderId, order.signature);
            } else if (recurring && typeof (recurring as any).registerRecurringSubscriptionRoutes?.confirmPaymentForSubscription === 'function') {
              // fallback if helper was attached to the exported function
              await (recurring as any).registerRecurringSubscriptionRoutes.confirmPaymentForSubscription(order.subscriptionId, order.orderId, order.signature);
            }
          }
        } catch (e) {
          logger.error('Failed to notify subscription module of confirmed payment', { orderId: order.orderId, error: e });
        }
      } else {
        await PaymentOrder.updateOne(
          { _id: order._id },
          { $set: { status: 'failed' } }
        );
  logger.warn(`Order ${order.orderId} failed verification: ${verifyResult.reason}`);
  inc('payment.confirmation.failed');
        // If this order is associated with a recurring subscription, mark subscription past_due and set grace period
        try {
          if (order.subscriptionId) {
            const sub = await RecurringSubscription.findOne({ subscriptionId: order.subscriptionId }).exec();
            if (sub) {
              sub.failedPaymentAttempts = (sub.failedPaymentAttempts || 0) + 1;
              sub.status = 'past_due';
              const graceDays = Number(process.env.PAYMENT_GRACE_PERIOD_DAYS || String(sub.gracePeriodDays || 3));
              const until = new Date();
              until.setDate(until.getDate() + graceDays);
              sub.gracePeriodUntil = until;
              await sub.save();
              await SubscriptionEvent.create({ subscriptionId: sub.subscriptionId, eventType: 'payment_failed', eventData: { orderId: order.orderId, reason: verifyResult.reason } });
            }
          }
        } catch (e) {
          logger.error('Failed to update subscription after payment verification failure', { orderId: order.orderId, error: e });
        }
      }
    } catch (error) {
      logger.error('Error in transaction verification', {
        orderId: order.orderId,
        signature: order.signature,
        error
      });
    }
  }

  // Check for subscriptions whose grace period expired and auto-cancel them
  private async checkExpiredGracePeriods(): Promise<void> {
    const now = new Date();
    try {
      const expired = await RecurringSubscription.find({ status: 'past_due', gracePeriodUntil: { $lte: now } }).limit(100).exec();
      for (const sub of expired) {
        try {
          sub.status = 'canceled';
          sub.canceledAt = new Date();
          sub.cancellationReason = 'grace_period_expired';
          sub.autoRenew = false;
          await sub.save();
          await SubscriptionEvent.create({ subscriptionId: sub.subscriptionId, eventType: 'canceled', eventData: { reason: 'grace_period_expired' } });
          logger.info('Subscription auto-canceled after grace period expired', { subscriptionId: sub.subscriptionId });
        } catch (e) {
          logger.error('Failed to auto-cancel subscription after grace period', { subscriptionId: sub.subscriptionId, error: e });
        }
      }
    } catch (e) {
      logger.error('Error checking expired grace periods', { error: e });
    }
  }

  private async verifyTransactionDetails(tx: any, order: any): Promise<{ ok: boolean; reason?: string }> {
    try {
      // Check memo
      const memo = extractMemoFromTransaction(tx);
      const expectedMemo = order.memo || `order:${order.orderId}`;
      if (!memo || memo !== expectedMemo) {
        return { ok: false, reason: "memo_mismatch" };
      }

      const merchantKey = new PublicKey(order.merchant);

      if (order.assetType === 'SOL') {
        // Verify SOL transfer
        const ak = tx.transaction.message.accountKeys.map((k: any) => 
          k.toBase58 ? k.toBase58() : String(k)
        );
        const idx = ak.findIndex((k: string) => k === merchantKey.toBase58());
        if (idx === -1) return { ok: false, reason: "merchant_not_in_accounts" };

        const pre = tx.meta?.preBalances?.[idx];
        const post = tx.meta?.postBalances?.[idx];
        if (typeof pre !== "number" || typeof post !== "number") {
          return { ok: false, reason: "balance_info_missing" };
        }

        const delta = post - pre;
        if (delta < order.amountLamports) {
          return { ok: false, reason: "sol_amount_mismatch" };
        }
      } else if (order.assetType === 'SPL') {
        // Verify SPL token transfer
        const tokenMintKey = new PublicKey(order.tokenMint);
        const expectedAmount = BigInt(order.tokenAmount);
        
        const tokenBalances = tx.meta?.postTokenBalances || [];
        const preTokenBalances = tx.meta?.preTokenBalances || [];
        
        const postBalance = tokenBalances.find((b: any) => 
          b.owner === merchantKey.toBase58() && b.mint === tokenMintKey.toBase58()
        );
        const preBalance = preTokenBalances.find((b: any) => 
          b.owner === merchantKey.toBase58() && b.mint === tokenMintKey.toBase58()
        );
        
        if (!postBalance) return { ok: false, reason: "merchant_token_account_not_found" };
        
        const preAmount = preBalance ? BigInt(preBalance.uiTokenAmount.amount) : BigInt(0);
        const postAmount = BigInt(postBalance.uiTokenAmount.amount);
        const delta = postAmount - preAmount;
        
        if (delta < expectedAmount) {
          return { ok: false, reason: "spl_amount_mismatch" };
        }
      }

      return { ok: true };
    } catch (error) {
      logger.error('Error in transaction detail verification', { error });
      return { ok: false, reason: "verification_exception" };
    }
  }

  // Manual cleanup method for old records
  async cleanupOldOrders(olderThanDays = 30): Promise<number> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);

    const result = await PaymentOrder.deleteMany({
      status: { $in: ['expired', 'failed', 'confirmed'] },
      updatedAt: { $lt: cutoffDate }
    });

    logger.info(`Cleaned up ${result.deletedCount} old payment orders`);
    return result.deletedCount;
  }
}

// Export singleton instance
export const paymentWorker = new PaymentWorker();

// Auto-start in production environments
if (process.env.NODE_ENV === 'production') {
  paymentWorker.start();

}

