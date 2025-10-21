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

export async function enqueueWebhookDelivery(opts: { subscriptionId?: string; url: string; event: string; payload: any; nextAttemptAt?: Date }) {
  const doc = await WebhookDelivery.create({
    subscriptionId: opts.subscriptionId,
    url: opts.url,
    event: opts.event,
    payload: opts.payload,
    attempts: 0,
    nextAttemptAt: opts.nextAttemptAt || new Date(),
    status: 'pending',
  });
  return doc;
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
