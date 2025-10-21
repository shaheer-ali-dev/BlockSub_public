#!/usr/bin/env node
// Simple runner for the worker supervisor. Use this in a dedicated worker container/process.

(async () => {
  try {
    // Prefer compiled JS in dist if available
    try {
      const { startWorkerSupervisor } = require('../dist/server/worker-runner');
      startWorkerSupervisor();
      console.log('Worker supervisor started from dist');
      return;
    } catch (_) {}

    // Fallback to source TS (requires ts-node/register)
    try {
      require('ts-node/register');
      const { startWorkerSupervisor } = require('../server/worker-runner');
      startWorkerSupervisor();
      console.log('Worker supervisor started from source (ts-node)');
      return;
    } catch (err) {
      console.error('Failed to start worker supervisor:', err);
      process.exit(1);
    }
  } catch (err) {
    console.error('Unhandled error in worker runner', err);
    process.exit(1);
  }
})();
