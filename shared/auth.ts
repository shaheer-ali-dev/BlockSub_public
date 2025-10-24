import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import { TokenService, SecurityUtils } from './encryption';
import { User, IUser } from './schema-mongodb';
import { connectToDatabase } from './mongodb';

// JWT Configuration
const JWT_CONFIG = {
  ACCESS_TOKEN_EXPIRY: 15 * 60,       // seconds (15m)
  REFRESH_TOKEN_EXPIRY: 7 * 24 * 60 * 60, // seconds (7d)
  ALGORITHM: 'HS512' as const,    // Strong HMAC algorithm
  ISSUER: 'blocksub-api',
  AUDIENCE: 'blocksub-client',
};

// Get JWT secrets from environment
const getJWTSecrets = () => {
  const accessSecret = process.env.JWT_ACCESS_SECRET;
  const refreshSecret = process.env.JWT_REFRESH_SECRET;
  
  if (!accessSecret || !refreshSecret) {
    throw new Error('JWT secrets must be set in environment variables');
  }
  
  if (accessSecret.length < 64 || refreshSecret.length < 64) {
    throw new Error('JWT secrets must be at least 64 characters long');
  }
  
  return { accessSecret, refreshSecret };
};

// Generate JWT secrets for setup
export const generateJWTSecrets = (): { accessSecret: string; refreshSecret: string } => {
  return {
    accessSecret: TokenService.generateSecureToken(64),
    refreshSecret: TokenService.generateSecureToken(64),
  };
};

// JWT Token Interfaces
export interface AccessTokenPayload {
  userId: string;
  username: string;
  type: 'access';
  iat?: number;
  exp?: number;
  iss?: string;
  aud?: string;
}

export interface RefreshTokenPayload {
  userId: string;
  type: 'refresh';
  tokenId: string; // Unique token ID for revocation
  iat?: number;
  exp?: number;
  iss?: string;
  aud?: string;
}

// Extended Request interface for authenticated routes
export interface AuthenticatedRequest extends Request {
  user?: IUser;
  tokenPayload?: AccessTokenPayload;
}

// Extended Request interface for API key authenticated routes
export interface ApiKeyAuthenticatedRequest extends Request {
  apiKey?: { _id: string; userId: string; name: string; key: string; credits: number; requests: number; };
}

// Authentication Service
export class AuthService {
  /**
   * Generate access and refresh tokens for a user
   */
  static async generateTokens(user: IUser): Promise<{ accessToken: string; refreshToken: string }> {
    const { accessSecret, refreshSecret } = getJWTSecrets();
    
    // Access token payload
    const accessPayload: AccessTokenPayload = {
      userId: user._id.toString(),
      username: user.username,
      type: 'access',
    };
    
    // Refresh token payload with unique token ID
    const refreshPayload: RefreshTokenPayload = {
      userId: user._id.toString(),
      type: 'refresh',
      tokenId: TokenService.generateSecureToken(16),
    };
    
    const accessToken = jwt.sign(accessPayload, accessSecret, {
      expiresIn: JWT_CONFIG.ACCESS_TOKEN_EXPIRY,
      algorithm: JWT_CONFIG.ALGORITHM,
      issuer: JWT_CONFIG.ISSUER,
      audience: JWT_CONFIG.AUDIENCE,
    });
    
    const refreshToken = jwt.sign(refreshPayload, refreshSecret, {
      expiresIn: JWT_CONFIG.REFRESH_TOKEN_EXPIRY,
      algorithm: JWT_CONFIG.ALGORITHM,
      issuer: JWT_CONFIG.ISSUER,
      audience: JWT_CONFIG.AUDIENCE,
    });
    
    return { accessToken, refreshToken };
  }
  
  /**
   * Verify and decode access token
   */
  static verifyAccessToken(token: string): AccessTokenPayload {
    const { accessSecret } = getJWTSecrets();
    
    try {
      const decoded = jwt.verify(token, accessSecret, {
        algorithms: [JWT_CONFIG.ALGORITHM],
        issuer: JWT_CONFIG.ISSUER,
        audience: JWT_CONFIG.AUDIENCE,
      }) as AccessTokenPayload;
      
      if (decoded.type !== 'access') {
        throw new Error('Invalid token type');
      }
      
      return decoded;
    } catch (error) {
      throw new Error('Invalid or expired access token');
    }
  }
  
  /**
   * Verify and decode refresh token
   */
  static verifyRefreshToken(token: string): RefreshTokenPayload {
    const { refreshSecret } = getJWTSecrets();
    
    try {
      const decoded = jwt.verify(token, refreshSecret, {
        algorithms: [JWT_CONFIG.ALGORITHM],
        issuer: JWT_CONFIG.ISSUER,
        audience: JWT_CONFIG.AUDIENCE,
      }) as RefreshTokenPayload;
      
      if (decoded.type !== 'refresh') {
        throw new Error('Invalid token type');
      }
      
      return decoded;
    } catch (error) {
      throw new Error('Invalid or expired refresh token');
    }
  }
  
  /**
   * Refresh access token using refresh token
   */
  static async refreshAccessToken(refreshToken: string): Promise<string> {
    const refreshPayload = this.verifyRefreshToken(refreshToken);
    
    // Get user from database
    await connectToDatabase();
    const user = await User.findById(refreshPayload.userId);
    
    if (!user) {
      throw new Error('User not found');
    }
    
    // Generate new access token
    const { accessSecret } = getJWTSecrets();
    const accessPayload: AccessTokenPayload = {
      userId: user._id.toString(),
      username: user.username,
      type: 'access',
    };
    
    return jwt.sign(accessPayload, accessSecret, {
      expiresIn: JWT_CONFIG.ACCESS_TOKEN_EXPIRY,
      algorithm: JWT_CONFIG.ALGORITHM,
      issuer: JWT_CONFIG.ISSUER,
      audience: JWT_CONFIG.AUDIENCE,
    });
  }
  
  /**
   * Extract token from Authorization header
   */
  static extractTokenFromHeader(authHeader?: string): string | null {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }
    
    return authHeader.substring(7); // Remove 'Bearer ' prefix
  }
  
  /**
   * Get user by token
   */
  static async getUserFromToken(token: string): Promise<IUser> {
    const payload = this.verifyAccessToken(token);
    
    await connectToDatabase();
    const user = await User.findById(payload.userId);
    
    if (!user) {
      throw new Error('User not found');
    }
    
    return user;
  }
}

// Authentication Middleware
export const authenticateToken = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const token = AuthService.extractTokenFromHeader(req.headers.authorization);
    
    if (!token) {
      res.status(401).json({ 
        error: 'Authentication required',
        message: 'Access token is missing' 
      });
      return;
    }
    
    // Verify token and get user
    const user = await AuthService.getUserFromToken(token);
    const tokenPayload = AuthService.verifyAccessToken(token);
    
    // Attach user and token info to request
    req.user = user;
    req.tokenPayload = tokenPayload;
    
    next();
  } catch (error: any) {
    res.status(401).json({ 
      error: 'Authentication failed',
      message: error.message 
    });
  }
};

// Optional authentication middleware (doesn't fail if no token)
export const optionalAuth = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const token = AuthService.extractTokenFromHeader(req.headers.authorization);
    
    if (token) {
      const user = await AuthService.getUserFromToken(token);
      const tokenPayload = AuthService.verifyAccessToken(token);
      
      req.user = user;
      req.tokenPayload = tokenPayload;
    }
    
    next();
  } catch (error) {
    // Continue without authentication if token is invalid
    next();
  }
};

// Rate limiting middleware
export const createRateLimiter = (windowMs: number, max: number) => {
  const requests = new Map<string, { count: number; resetTime: number }>();
  
  return (req: Request, res: Response, next: NextFunction): void => {
    const key = SecurityUtils.generateRateLimitKey(
      req.ip || req.connection.remoteAddress || 'unknown',
      req.path
    );
    
    const now = Date.now();
    const windowStart = now - windowMs;
    
    // Clean up old entries
    requests.forEach((v, k) => {
      if (v.resetTime < windowStart) {
        requests.delete(k);
      }
    });
    
    const current = requests.get(key) || { count: 0, resetTime: now + windowMs };
    
    if (current.resetTime < now) {
      // Reset window
      current.count = 0;
      current.resetTime = now + windowMs;
    }
    
    if (current.count >= max) {
      res.status(429).json({
        error: 'Too many requests',
        message: 'Rate limit exceeded. Please try again later.',
        retryAfter: Math.ceil((current.resetTime - now) / 1000)
      });
      return;
    }
    
    current.count++;
    requests.set(key, current);
    
    // Set rate limit headers
    res.setHeader('X-RateLimit-Limit', max.toString());
    res.setHeader('X-RateLimit-Remaining', (max - current.count).toString());
    res.setHeader('X-RateLimit-Reset', new Date(current.resetTime).toISOString());
    
    next();
  };
};

// CSRF Protection Middleware
export const csrfProtection = (req: Request, res: Response, next: NextFunction): void => {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    return next();
  }
  
  const token = (req.headers['x-csrf-token'] as string | undefined) || (req.body && req.body._csrfToken);
  const sessionToken = (req.session as any)?.csrfToken;
  
  if (!token || !sessionToken || token !== sessionToken) {
    res.status(403).json({
      error: 'CSRF token validation failed',
      message: 'Invalid or missing CSRF token'
    });
    return;
  }
  
  next();
};

// Generate CSRF token for session
export const generateCSRFToken = (req: Request): string => {
  if (!req.session) {
    throw new Error('Session is required for CSRF protection');
  }
  
  const token = SecurityUtils.generateCSRFToken();
  (req.session as any).csrfToken = token;
  return token;
};

// Input validation middleware
export const validateInput = (validations: ((req: Request) => string | null)[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const errors: string[] = [];
    
    for (const validation of validations) {
      const error = validation(req);
      if (error) {
        errors.push(error);
      }
    }
    
    if (errors.length > 0) {
      res.status(400).json({
        error: 'Validation failed',
        message: 'Input validation errors',
        details: errors
      });
      return;
    }
    
    next();
  };
};

// API Key Authentication Middleware
export const authenticateApiKey = (creditCost: number = 0.1) => {
  return async (
    req: ApiKeyAuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      // Extract API key from various possible locations
      let apiKeyValue: string | undefined;
      
      // Check Authorization header (Bearer token or API key directly)
      const authHeader = req.headers.authorization;
      if (authHeader) {
        if (authHeader.startsWith('Bearer ')) {
          apiKeyValue = authHeader.substring(7);
        } else if (authHeader.startsWith('ApiKey ')) {
          apiKeyValue = authHeader.substring(7);
        } else {
          apiKeyValue = authHeader;
        }
      }
      
      // Check x-api-key header
      if (!apiKeyValue) {
        apiKeyValue = req.headers['x-api-key'] as string;
      }
      
      // Check query parameter
      if (!apiKeyValue) {
        apiKeyValue = req.query.apiKey as string || req.query.api_key as string;
      }
      
      // Check request body
      if (!apiKeyValue && req.body) {
        apiKeyValue = req.body.apiKey || req.body.api_key;
      }
      
      if (!apiKeyValue) {
        res.status(401).json({
          error: 'API key required',
          message: 'Please provide a valid API key in the Authorization header, x-api-key header, or request body'
        });
        return;
      }
      
      // Import storage here to avoid circular dependency
      const { storage } = await import('../server/storage');
      
      // Find the API key in database
      const apiKey = await storage.getApiKeyByKey(apiKeyValue);
      
      if (!apiKey) {
        res.status(401).json({
          error: 'Invalid API key',
          message: 'The provided API key is not valid'
        });
        return;
      }
      
      // Check if API key has sufficient credits
      // if (apiKey.credits < creditCost) {
      //   res.status(402).json({
      //     error: 'Insufficient credits',
      //     message: `This API call requires ${creditCost} credits, but your API key only has ${apiKey.credits} credits remaining. Please upgrade your plan to continue using the API.`,
      //     currentCredits: apiKey.credits,
      //     requiredCredits: creditCost
      //   });
      //   return;
      // }
      
      // Deduct credits
      // const creditDeducted = await storage.deductCredits(apiKey._id.toString(), creditCost);
      
      // if (!creditDeducted) {
      //   res.status(500).json({
      //     error: 'Credit deduction failed',
      //     message: 'Unable to process the request due to a system error'
      //   });
      //   return;
      // }
      
      // Attach API key info to request (with updated credits)
      req.apiKey = {
        _id: apiKey._id.toString(),
        userId: apiKey.userId,
        name: apiKey.name,
        key: apiKey.key,
        credits: apiKey.credits,
        requests: apiKey.requests + 1
      };
      
      next();
    } catch (error: any) {
      console.error('API key authentication error:', error);
      res.status(500).json({
        error: 'Authentication failed',
        message: 'An error occurred during API key authentication'
      });
    }
  };
};

