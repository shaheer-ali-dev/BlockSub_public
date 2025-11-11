import { WebhookDelivery } from "@shared/schema-mongodb";
import crypto from 'crypto';
import { logger } from './security';
import { inc, timing } from './metrics';

const DEFAULT_RETRY_SCHEDULE = [10 * 1000, 30 * 1000, 2 * 60 * 1000, 5 * 60 * 1000];

function getEnv(name: string, fallback = '') { return process.env[name] ?? fallback; }

export function signWebhookPayload(secret: string, payload: any): { signature: string; timestamp: string } {
  const ts = Date.now().toString();
  const body = JSON.stringify(payload);
  const sig = crypto.createHmac('sha256', secret).update(ts + body).digest('hex');
  return { signature: sig, timestamp: ts };
}

export type EnqueueWebhookOptions = {
  subscriptionId: string;
  url: string;
  event: string;
  payload: any;
  maxAttempts?: number; // maximum retry attempts
  initialDelaySeconds?: number; // delay until first retry (if immediate post failed)
  backoffMultiplier?: number; // exponential backoff multiplier
};

function isValidUrl(u: string) {
  try {
    // allow only http/https
    const parsed = new URL(u);
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
}

/**
 * enqueueWebhookDelivery
 *
 * Inserts a webhook delivery job into 'webhook_deliveries' collection.
 * Creates the collection if missing.
 *
 * Returns the insertedId object.
 */
export async function enqueueWebhookDelivery(opts: EnqueueWebhookOptions) {
  if (!opts || typeof opts !== "object") {
    throw new Error("enqueueWebhookDelivery: opts required");
  }
  const {
    subscriptionId,
    url,
    event,
    payload,
    maxAttempts = 5,
    initialDelaySeconds = 60,
    backoffMultiplier = 2,
  } = opts;

  if (!subscriptionId || typeof subscriptionId !== "string") {
    throw new Error("enqueueWebhookDelivery: subscriptionId must be a string");
  }
  if (!url || typeof url !== "string" || !isValidUrl(url)) {
    throw new Error("enqueueWebhookDelivery: url must be a valid http/https URL");
  }
  if (!event || typeof event !== "string") {
    throw new Error("enqueueWebhookDelivery: event must be a string");
  }

  // Use the raw MongoDB collection for minimal schema coupling.
  const db = (mongoose.connection && (mongoose.connection as any).db) || null;
  if (!db) {
    throw new Error("enqueueWebhookDelivery: mongoose connection not available");
  }
  const col = db.collection("webhook_deliveries");

  // Compute nextAttemptAt (first attempt is scheduled immediately by default,
  // but when this function is used as a fallback after a failed POST we schedule in the future)
  const now = new Date();
  const nextAttemptAt = new Date(Date.now() + initialDelaySeconds * 1000);

  const doc = {
    subscriptionId,
    url,
    event,
    payload,
    attempts: 0,
    maxAttempts,
    lastError: null as string | null,
    initialDelaySeconds,
    backoffMultiplier,
    nextAttemptAt,
    createdAt: now,
    updatedAt: now,
    // optional: idempotency key, headers etc. could be added
  };

  // Ensure useful indexes exist (best-effort; repeated creation is fine)
  try {
    await col.createIndex({ nextAttemptAt: 1 });
    await col.createIndex({ subscriptionId: 1 });
    await col.createIndex({ attempts: 1 });
  } catch (e) {
    // ignore index errors (race conditions on start are fine)
    // console.warn("enqueueWebhookDelivery: index creation failed", e);
  }

  const r = await col.insertOne(doc as any);
  return r.insertedId;
}

/**
 * computeNextAttemptSeconds
 *
 * Given the current attempts count and config, compute the next delay in seconds
 * (can be used by delivery worker when scheduling next try after failure).
 */
export function computeNextAttemptSeconds(attempts: number, initialDelaySeconds = 60, multiplier = 2) {
  // exponential backoff with jitter
  const base = initialDelaySeconds * Math.pow(multiplier, Math.max(0, attempts - 1));
  const jitter = Math.floor(Math.random() * Math.min(10, Math.round(base * 0.1) + 1));
  return Math.floor(base + jitter);
}

class WebhookDeliveryProcessor {
  private running = false;
  private intervalMs = 5000;

  start() {
    if (this.running) return;
    this.running = true;
    this.tick();
  }

  stop() {
    this.running = false;
  }

  private async tick() {
    while (this.running) {
      try {
        await this.processDue();
      } catch (e) {
        logger.error('Webhook delivery processor tick failed', { error: e });
      }
      await new Promise((r) => setTimeout(r, this.intervalMs));
    }
  }

  private async processDue() {
    const now = new Date();
    const due = await WebhookDelivery.find({ status: 'pending', nextAttemptAt: { $lte: now } }).limit(10).exec();
    if (!due || due.length === 0) return;
    for (const job of due) {
      await this.processJob(job);
    }
  }

  private async processJob(job: any) {
    try {
      // Determine HMAC secret: attempt to use relayer/webhook secret on subscription if present
      let signingSecret = process.env.WEBHOOK_SIGNING_SECRET || '';
      // If job.subscriptionId exists, try to fetch subscription relayer/webhook secret
      if (job.subscriptionId) {
        try {
          const { RecurringSubscription } = await import('@shared/recurring-subscription-schema');
          const sub = await RecurringSubscription.findOne({ subscriptionId: job.subscriptionId }).exec();
          if (sub) {
            // prefer webhookSecret then relayerSecretEncrypted (decrypted)
            if (sub.webhookSecret) signingSecret = sub.webhookSecret;
            else if ((sub as any).relayerSecretEncrypted) {
              try {
                const { decryptWithMasterKey } = await import('./crypto-utils');
                signingSecret = decryptWithMasterKey((sub as any).relayerSecretEncrypted);
              } catch (e) {
                logger.error('Failed to decrypt relayer secret for webhook signing', { subscriptionId: job.subscriptionId, error: e });
              }
            }
          }
        } catch (e) {
          logger.debug('Could not load subscription for webhook signing secret', { error: e });
        }
      }

      const body = job.payload;
      const headers: any = { 'Content-Type': 'application/json' };
      if (signingSecret) {
        const { signature, timestamp } = signWebhookPayload(signingSecret, body);
        headers['X-Timestamp'] = timestamp;
        headers['X-Signature'] = signature;
      }

  // Use dynamic import for fetch; ts-ignore to avoid missing @types/node-fetch in this workspace
  // @ts-ignore: dynamic import of node-fetch without types
  const fetch: any = (await import('node-fetch')).default || (globalThis as any).fetch;
      const res = await fetch(job.url, { method: 'POST', body: JSON.stringify(body), headers, timeout: 10000 });
      const text = await res.text().catch(() => '');
      job.attempts = (job.attempts || 0) + 1;
      job.lastAttemptAt = new Date();
      job.lastStatusCode = res.status;
      job.lastResponseSnippet = text ? text.substring(0, 1024) : '';
      if (res.ok) {
        job.status = 'success';
        await job.save();
        logger.info('Webhook delivered successfully', { url: job.url, event: job.event });
        inc('webhook.delivered.success');
        timing('webhook.delivery.latency', Date.now() - Number(job.createdAt || Date.now()));
        return;
      }

      // failure -> schedule next attempt or mark as failed
      const attempts = job.attempts || 1;
      const schedule = DEFAULT_RETRY_SCHEDULE;
      const nextDelay = schedule[Math.min(attempts - 1, schedule.length - 1)];
      job.nextAttemptAt = new Date(Date.now() + nextDelay);
      if (attempts >= schedule.length + 1) {
        job.status = 'failed';
      }
      await job.save();
  logger.warn('Webhook delivery failed; scheduled retry', { url: job.url, status: job.lastStatusCode, attempts: job.attempts, nextAttemptAt: job.nextAttemptAt });
  inc('webhook.delivered.failed');
      } catch (e) {
      logger.error('Webhook delivery job processing error', { id: job._id, error: e });
      try {
        job.attempts = (job.attempts || 0) + 1;
        job.lastAttemptAt = new Date();
        job.lastResponseSnippet = String((e as any)?.message || String(e)).substring(0, 1024);
        const schedule = DEFAULT_RETRY_SCHEDULE;
        job.nextAttemptAt = new Date(Date.now() + schedule[Math.min(job.attempts - 1, schedule.length - 1)]);
        if (job.attempts >= schedule.length + 1) job.status = 'failed';
        await job.save();
      } catch (ee) {
        logger.error('Failed to update webhook job after error', { id: job._id, error: ee });
      }
    }
  }
}

export const webhookDeliveryProcessor = new WebhookDeliveryProcessor();

// Auto-start the processor in production
if (process.env.NODE_ENV !== 'test') {
  webhookDeliveryProcessor.start();
}

export default webhookDeliveryProcessor;

