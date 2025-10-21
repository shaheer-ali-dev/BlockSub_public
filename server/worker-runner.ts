import { paymentWorker } from './payment-worker';
import { logger } from './security';

// Supervisor loop: ensure paymentWorker is running and restart if it stops unexpectedly.
export function startWorkerSupervisor() {
  try {
    if (!paymentWorker.running) {
      logger.info('Worker supervisor starting payment worker');
      paymentWorker.start();
    }

    // Periodically check the worker is still running
    setInterval(() => {
      try {
        if (!paymentWorker.running) {
          logger.warn('Payment worker not running; restarting');
          paymentWorker.start();
        }
      } catch (err) {
        logger.error('Worker supervisor check failed', { error: err });
      }
    }, 30 * 1000); // check every 30s
  } catch (err) {
    logger.error('Failed to start worker supervisor', { error: err });
  }
}

// If this module is run directly via `node server/worker-runner.js`, start supervisor
if (require.main === module) {
  startWorkerSupervisor();
}
