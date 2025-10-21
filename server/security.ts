import helmet from 'helmet';
import compression from 'compression';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import morgan from 'morgan';
import winston from 'winston';
import type { Express } from 'express';

// Configure Winston logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'blocksub-api' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
  ],
});

// Add console transport in development
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

// Security headers configuration
const getHelmetConfig = () => {
  const isProduction = process.env.NODE_ENV === 'production';
  
  return {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        // Allow Vite dev preamble and HMR in development. Inline scripts are required by @vitejs/plugin-react.
        scriptSrc: isProduction 
          ? ["'self'"]
          : ["'self'", "'unsafe-eval'", "'unsafe-inline'", "http://localhost:*", "blob:"],
        // Explicitly set element/attr directives for CSP Level 3 aware browsers
        scriptSrcElem: isProduction 
          ? ["'self'"]
          : ["'self'", "'unsafe-eval'", "'unsafe-inline'", "http://localhost:*", "blob:"],
        scriptSrcAttr: isProduction 
          ? ["'self'"]
          : ["'self'", "'unsafe-inline'"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: isProduction 
          ? ["'self'"]
          : ["'self'", "ws://localhost:*", "http://localhost:*"],
        frameSrc: ["'none'"],
        objectSrc: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false, // Disable for API
    hsts: isProduction ? {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true,
    } : false, // Disable HSTS in development
    referrerPolicy: { policy: "same-origin" },
  } as const;
};

// CORS configuration
const corsConfig = {
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
};

// Session configuration
const getSessionConfig = () => {
  const isProduction = process.env.NODE_ENV === 'production';

  // Choose a session store based on environment availability
  // - Use MongoDB-backed store when MONGODB_URI is provided
  // - Otherwise, fall back to in-memory store so the server can run without DB (useful for local dev and smoke tests)
  const hasMongo = Boolean(process.env.MONGODB_URI);
  const store = hasMongo
    ? MongoStore.create({
        mongoUrl: process.env.MONGODB_URI as string,
        touchAfter: 24 * 3600, // Only update session once per 24 hours unless data changes
        crypto: {
          secret: process.env.SESSION_ENCRYPT_SECRET || 'session-encrypt-secret-change-in-production',
        },
      })
    : new (session as any).MemoryStore();
  
  return {
    name: 'blocksub.sid', // Change default session name
    secret: process.env.SESSION_SECRET || 'your-super-secret-session-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    store,
    cookie: {
      secure: isProduction, // HTTPS only in production
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      sameSite: isProduction ? 'strict' as const : 'lax' as const,
    },
  };
};

// Rate limiting configurations
export const rateLimitConfig = {
  // General API rate limiting
  api: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 1000, // Requests per window
    message: {
      error: 'Too many requests',
      message: 'Rate limit exceeded. Please try again later.',
    },
    standardHeaders: true,
    legacyHeaders: false,
  },
  
  // Authentication endpoints (stricter)
  auth: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Attempts per window
    message: {
      error: 'Too many authentication attempts',
      message: 'Too many login attempts. Please try again later.',
    },
    standardHeaders: true,
    legacyHeaders: false,
  },
  
  // API key operations (moderate)
  apiKeys: {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 100, // Requests per window
    message: {
      error: 'Too many API requests',
      message: 'API key rate limit exceeded. Please try again later.',
    },
    standardHeaders: true,
    legacyHeaders: false,
  },
};

// Request logging configuration
const morganConfig = process.env.NODE_ENV === 'production' 
  ? 'combined' 
  : 'dev';

// Security middleware setup
export function setupSecurity(app: Express): void {
  // Trust proxy if behind reverse proxy (for rate limiting, etc.)
  if (process.env.TRUST_PROXY) {
    app.set('trust proxy', process.env.TRUST_PROXY);
  }

  // Security headers
  app.use(helmet(getHelmetConfig()));
  
  // CORS configuration
  app.use(cors(corsConfig));
  
  // Request logging
  app.use(morgan(morganConfig, {
    stream: {
      write: (message: string) => logger.info(message.trim()),
    },
  }));
  
  // Compression
  app.use(compression({
    filter: (req, res) => {
      // Don't compress if the request includes a cache-control no-transform directive
      if (req.headers['cache-control'] && req.headers['cache-control'].includes('no-transform')) {
        return false;
      }
      
      // Use compression filter function
      return compression.filter(req, res);
    },
  }));
  
  // Cookie parsing
  app.use(cookieParser());
  
  // Session management
  app.use(session(getSessionConfig()));
  
  // Request size limiting
  app.use((req, res, next) => {
    // Limit request size to 10MB
    const maxSize = 10 * 1024 * 1024; // 10MB in bytes
    
    req.on('data', (chunk) => {
      const contentLength = parseInt(req.headers['content-length'] || '0', 10);
      if (contentLength > maxSize) {
        res.status(413).json({
          error: 'Payload too large',
          message: 'Request size exceeds the maximum allowed limit',
        });
        return;
      }
    });
    
    next();
  });
  
  // Security response headers
  app.use((req, res, next) => {
    // Remove X-Powered-By header
    res.removeHeader('X-Powered-By');
    
    // Add custom security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    
    next();
  });
  
  // API version header
  app.use((req, res, next) => {
    res.setHeader('API-Version', '1.0.0');
    next();
  });
  
  // Health check endpoint (before other routes)
  app.get('/health', (req, res) => {
    res.status(200).json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: '1.0.0',
    });
  });
  
  // Error handling for security middleware
  app.use((err: any, req: any, res: any, next: any) => {
    logger.error('Security middleware error:', {
      error: err.message,
      stack: err.stack,
      url: req.url,
      method: req.method,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });
    
    // Don't expose internal errors in production
    const isProduction = process.env.NODE_ENV === 'production';
    
    res.status(err.status || 500).json({
      error: isProduction ? 'Internal server error' : err.message,
      message: isProduction 
        ? 'An unexpected error occurred' 
        : err.message,
    });
  });
}

// Error logging middleware
export function setupErrorLogging(app: Express): void {
  app.use((err: any, req: any, res: any, next: any) => {
    // Log error details
    logger.error('Application error:', {
      error: err.message,
      stack: err.stack,
      url: req.url,
      method: req.method,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      body: req.body,
    });
    
    next(err);
  });
}

// Export logger for use in other modules
export { logger };

// Graceful shutdown handler
export function setupGracefulShutdown(): void {
  const gracefulShutdown = (signal: string) => {
    logger.info(`Received ${signal}. Starting graceful shutdown...`);
    
    // Close server and cleanup resources
    process.exit(0);
  };
  
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
  
  // Handle uncaught exceptions
  process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
    process.exit(1);
  });
  
  // Handle unhandled promise rejections
  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
  });
}