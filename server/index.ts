import "dotenv/config";
import express, { type Request, Response, NextFunction } from "express";
import { registerRoutes } from "./routes";
import { registerAuthRoutes } from "./auth-routes";
import { setupVite, serveStatic, log } from "./vite";
import { setupSecurity, setupErrorLogging, setupGracefulShutdown, logger } from "./security";
import { initializeDatabase } from "./db";

(async () => {
  // Initialize application
  const app = express();

  // Setup comprehensive security middleware
  setupSecurity(app);

  // Body parsing middleware (after security)
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: false, limit: '10mb' }));

  // Initialize database connection
  try {
    await initializeDatabase();
    logger.info('Database initialized successfully');
    // Ensure TTL index for worker_locks.lockedUntil to auto-expire stale locks
    try {
      const mongoose = await import('mongoose');
      const db = (mongoose.connection && (mongoose.connection as any).db) || null;
      if (db) {
        const locks = db.collection('worker_locks');
        // Create index: documents expire when lockedUntil is older than now
        await locks.createIndex({ lockedUntil: 1 }, { expireAfterSeconds: 0 });
        logger.info('Ensured TTL index on worker_locks.lockedUntil');
      } else {
        logger.warn('Mongoose db instance not available; skipping worker_locks TTL index creation');
      }
    } catch (e) {
      logger.warn('Could not create TTL index for worker_locks', { error: e });
    }
  } catch (error) {
    logger.error('Failed to initialize database:', error);
    logger.warn('Continuing without database connection - some features may not work');
    logger.info('To fix: Check your MongoDB Atlas IP whitelist or connection string');
  }

  // Custom API logging middleware (enhanced)
  app.use((req, res, next) => {
    const start = Date.now();
    const path = req.path;
    let capturedJsonResponse: Record<string, any> | undefined = undefined;

    const originalResJson = res.json;
    res.json = function (bodyJson, ...args) {
      capturedJsonResponse = bodyJson;
      return originalResJson.apply(res, [bodyJson, ...args]);
    };

    res.on("finish", () => {
      const duration = Date.now() - start;
      if (path.startsWith("/api")) {
        let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
        
        // Don't log sensitive data in production
        if (process.env.NODE_ENV !== 'production' && capturedJsonResponse) {
          // Filter out sensitive fields
          const filtered = { ...capturedJsonResponse };
          if (filtered.accessToken) filtered.accessToken = '[REDACTED]';
          if (filtered.key && typeof filtered.key === 'string') {
            filtered.key = filtered.key.substring(0, 10) + '...';
          }
          logLine += ` :: ${JSON.stringify(filtered)}`;
        }

        if (logLine.length > 120) {
          logLine = logLine.slice(0, 119) + "…";
        }

        log(logLine);
      }
    });

    next();
  });

  // Register authentication routes first
  registerAuthRoutes(app);

  // Register Solana payment routes
  const { registerSolanaRoutes } = await import('./solana-routes');
  registerSolanaRoutes(app);

  // Register recurring subscription routes (mounts /api/recurring-subscriptions/* endpoints)
  const recurringModule = await import('./recurring-subscription-routes');
  if (recurringModule && typeof recurringModule.registerRecurringSubscriptionRoutes === 'function') {
    recurringModule.registerRecurringSubscriptionRoutes(app);
  }

  // Register consolidated subscriptions routes (replaces billing & recurring routes)
 

  // Register documentation routes
  const { registerDocsRoutes } = await import('./docs-routes');
  registerDocsRoutes(app);
  
  // Start payment background worker
  const { paymentWorker } = await import('./payment-worker');
  paymentWorker.start();

  // Start supervisor that ensures the worker stays running
  try {
    const { startWorkerSupervisor } = await import('./worker-runner');
    startWorkerSupervisor();
  } catch (err) {
    logger.warn('Worker supervisor failed to start', { error: err });
  }

  // Register other API routes
  const server = await registerRoutes(app);

  // Setup error logging
  setupErrorLogging(app);

  // Enhanced error handler
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    
    // Log error with more context
    logger.error('API Error:', {
      error: message,
      status,
      method: req.method,
      path: req.path,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    // Don't expose internal errors in production
    const isProduction = process.env.NODE_ENV === 'production';
    res.status(status).json({ 
      error: isProduction && status === 500 ? 'Internal Server Error' : message,
      status 
    });
  });

  // Setup graceful shutdown
  setupGracefulShutdown();

  // Importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // ALWAYS serve the app on the port specified in the environment variable PORT
  // Other ports are firewalled. Default to 3000 if not specified.
  // this serves both the API and the client.
  const port = parseInt(process.env.PORT || '3000', 10);
  
  server.listen(port, '0.0.0.0', () => {
    const formattedTime = new Intl.DateTimeFormat("en-US", {
      dateStyle: "short",
      timeStyle: "medium",
      timeZone: "America/New_York",
    }).format(new Date());
    
    logger.info(`🚀 BlockSub API Server running on port ${port} at ${formattedTime}`);
    logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
    logger.info('Security features enabled: ✓ Helmet ✓ CORS ✓ Rate Limiting ✓ Session Management ✓ JWT Auth');
    
    // Also use the existing log function for compatibility
    log(`serving on http://localhost:${port}`);
  });
})();
