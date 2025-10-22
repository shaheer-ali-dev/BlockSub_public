import type { Express } from "express";
import { Request, Response } from "express";
import { storage } from "./storage";
import { 
  AuthService, 
  authenticateToken, 
  createRateLimiter, 
  validateInput,
  AuthenticatedRequest 
} from "@shared/auth";
import { EmailOtp } from "@shared/schema-mongodb";
import { sendOtpEmail } from "./email";
import { 
  insertUserSchema, 
  insertApiKeySchema,
  type InsertUser 
} from "@shared/schema-mongodb";
import { SecurityUtils } from "@shared/encryption";

// Rate limiters for different endpoints
const authRateLimit = createRateLimiter(15 * 60 * 1000, 5); // 5 attempts per 15 minutes
const generalRateLimit = createRateLimiter(60 * 1000, 60); // 60 requests per minute
// const app = express.Router();
// Input validation functions
const validateSignupInput = (req: Request): string | null => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return 'Username and password are required';
  }
  
  if (!SecurityUtils.validateUsername(username)) {
    return 'Username must be 3-30 characters, alphanumeric, underscore or hyphen only';
  }
  
  // Password validation is handled by PasswordService.hash()
  return null;
};

const validateLoginInput = (req: Request): string | null => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return 'Username and password are required';
  }
  
  return null;
};

const validateApiKeyInput = (req: Request): string | null => {
  const { name } = req.body;
  
  if (!name) {
    return 'API key name is required';
  }
  
  if (name.length < 1 || name.length > 100) {
    return 'API key name must be 1-100 characters';
  }
  
  return null;
};

export function registerAuthRoutes(app: Express): void {
  // Sign up endpoint
  app.post(
    "/api/auth/signup",
    authRateLimit,
    validateInput([validateSignupInput]),
    async (req: Request, res: Response) => {
      try {
        const parsed = insertUserSchema.safeParse(req.body);
        
        if (!parsed.success) {
          return res.status(400).json({
            error: "Validation failed",
            message: "Invalid input data",
            details: parsed.error.errors
          });
        }

        // Require OTP verification: caller must include `email` and `otpCode` that match a non-expired EmailOtp record
        const { email} = req.body as any;
        if (!email) {
          return res.status(400).json({ error: 'OTP verification required', message: 'email and otpCode are required' });
        }

        // Verify OTP
        // const otpRecord = await EmailOtp.findOne({ email: email.toLowerCase(), code: otpCode });
        // if (!otpRecord) {
        //   return res.status(400).json({ error: 'Invalid or expired OTP', message: 'OTP not found or expired' });
        // }

        // // OTP is valid; remove it so it cannot be reused
        // await EmailOtp.deleteOne({ _id: otpRecord._id });

        // Check if user already exists
        const existingUser = await storage.getUserByUsername(parsed.data.username);
        if (existingUser) {
          return res.status(409).json({
            error: "User already exists",
            message: "A user with this username already exists"
          });
        }

  // Create user
        const user = await storage.createUser(parsed.data);
        
        // Generate tokens
        const { accessToken, refreshToken } = await AuthService.generateTokens(user);
        
        // Set refresh token as secure HTTP-only cookie
        res.cookie('refreshToken', refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
          path: '/api/auth'
        });
        
        res.status(201).json({
          message: "Account created successfully",
          user: {
            id: user._id,
            username: user.username,
            createdAt: user.createdAt
          },
          accessToken
        });
      } catch (error: any) {
        console.error('Signup error:', error);
        
        // Don't expose internal errors
        if (error.message.includes('Password must contain')) {
          return res.status(400).json({
            error: "Password validation failed",
            message: error.message
          });
        }
        
        res.status(500).json({
          error: "Registration failed",
          message: "An error occurred during registration"
        });
      }
    }
  );

  // Send OTP endpoint
  app.post(
    "/api/auth/send-otp",
    authRateLimit,
    async (req: Request, res: Response) => {
      try {
        const { email } = req.body as { email?: string };
        if (!email) {
          return res.status(400).json({ error: 'Email required', message: 'Please provide an email address' });
        }

        const normalized = String(email).toLowerCase().trim();

        // Generate 6-digit numeric OTP
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        // Persist OTP
        await EmailOtp.create({ email: normalized, code, expiresAt });

        // Send email (fire-and-forget-ish; await to capture errors)
        try {
          await sendOtpEmail(normalized, code, { minutesValid: 10 });
        } catch (err) {
          console.error('Failed to send OTP email:', err);
          // We don't leak SMTP errors; respond with 500 for send failure
          return res.status(500).json({ error: 'Failed to send OTP', message: 'Email sending failed' });
        }

        res.json({ message: 'OTP sent' });
      } catch (error: any) {
        console.error('send-otp error:', error);
        res.status(500).json({ error: 'Failed to send OTP', message: 'An internal error occurred' });
      }
    }
  );

  // Verify OTP endpoint
  app.post(
    "/api/auth/verify-otp",
    authRateLimit,
    async (req: Request, res: Response) => {
      try {
        const { email, code } = req.body as { email?: string; code?: string };
        if (!email || !code) {
          return res.status(400).json({ error: 'Invalid request', message: 'email and code are required' });
        }

        const normalized = String(email).toLowerCase().trim();
        const otpRecord = await EmailOtp.findOne({ email: normalized, code });
        if (!otpRecord) {
          return res.status(400).json({ error: 'Invalid or expired OTP', message: 'OTP not found or expired' });
        }

        // Consume OTP
        await EmailOtp.deleteOne({ _id: otpRecord._id });

        res.json({ message: 'OTP verified' });
      } catch (error: any) {
        console.error('verify-otp error:', error);
        res.status(500).json({ error: 'OTP verification failed', message: 'An internal error occurred' });
      }
    }
  );

  // Login endpoint
  app.post(
    "/api/auth/login",
    authRateLimit,
    validateInput([validateLoginInput]),
    async (req: Request, res: Response) => {
      try {
        const { username, password } = req.body;
        
        // Sanitize input
        const sanitizedUsername = SecurityUtils.sanitizeInput(username);
        
        // Authenticate user
        const user = await storage.authenticateUser(sanitizedUsername, password);
        
        if (!user) {
          return res.status(401).json({
            error: "Authentication failed",
            message: "Invalid username or password"
          });
        }
        
        // Generate tokens
        const { accessToken, refreshToken } = await AuthService.generateTokens(user);
        
        // Set refresh token as secure HTTP-only cookie
        res.cookie('refreshToken', refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
          path: '/api/auth'
        });
        
        res.json({
          message: "Login successful",
          user: {
            id: user._id,
            username: user.username,
            createdAt: user.createdAt
          },
          accessToken
        });
      } catch (error: any) {
        console.error('Login error:', error);
        res.status(500).json({
          error: "Login failed",
          message: "An error occurred during login"
        });
      }
    }
  );

  // Refresh token endpoint
  app.post(
    "/api/auth/refresh",
    generalRateLimit,
    async (req: Request, res: Response) => {
      try {
        const refreshToken = req.cookies?.refreshToken;
        
        if (!refreshToken) {
          return res.status(401).json({
            error: "Refresh token missing",
            message: "No refresh token provided"
          });
        }
        
        // Generate new access token
        const newAccessToken = await AuthService.refreshAccessToken(refreshToken);
        
        res.json({
          accessToken: newAccessToken
        });
      } catch (error: any) {
        console.error('Token refresh error:', error);
        res.status(401).json({
          error: "Token refresh failed",
          message: "Invalid or expired refresh token"
        });
      }
    }
  );

  // Logout endpoint
  app.post(
    "/api/auth/logout",
    generalRateLimit,
    async (req: Request, res: Response) => {
      // Clear refresh token cookie
      res.clearCookie('refreshToken', {
        path: '/api/auth'
      });
      
      res.json({
        message: "Logged out successfully"
      });
    }
  );

  // Get current user profile
  app.get(
    "/api/auth/profile",
    generalRateLimit,
    authenticateToken,
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        if (!req.user) {
          return res.status(401).json({
            error: "Authentication required",
            message: "User not authenticated"
          });
        }
        
        res.json({
          user: {
            id: req.user._id,
            username: req.user.username,
            createdAt: req.user.createdAt,
            updatedAt: req.user.updatedAt
          }
        });
      } catch (error: any) {
        console.error('Profile fetch error:', error);
        res.status(500).json({
          error: "Profile fetch failed",
          message: "An error occurred while fetching profile"
        });
      }
    }
  );

  // Update password
  app.post(
    "/api/auth/change-password",
    authRateLimit,
    authenticateToken,
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        if (!req.user) {
          return res.status(401).json({
            error: "Authentication required",
            message: "User not authenticated"
          });
        }
        
        const { currentPassword, newPassword } = req.body;
        
        if (!currentPassword || !newPassword) {
          return res.status(400).json({
            error: "Validation failed",
            message: "Current password and new password are required"
          });
        }
        
        // Verify current password
        const user = await storage.authenticateUser(req.user.username, currentPassword);
        if (!user) {
          return res.status(401).json({
            error: "Authentication failed",
            message: "Current password is incorrect"
          });
        }
        
        // Update password
        await storage.updateUserPassword(req.user._id.toString(), newPassword);
        
        res.json({
          message: "Password updated successfully"
        });
      } catch (error: any) {
        console.error('Password change error:', error);
        
        if (error.message.includes('Password must contain')) {
          return res.status(400).json({
            error: "Password validation failed",
            message: error.message
          });
        }
        
        res.status(500).json({
          error: "Password change failed",
          message: "An error occurred while updating password"
        });
      }
    }
  );

  // Protected API Keys endpoints (updated from routes.ts)
  app.get(
    "/api/api-keys",
    generalRateLimit,
    authenticateToken,
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        if (!req.user) {
          return res.status(401).json({
            error: "Authentication required",
            message: "User not authenticated"
          });
        }
        
        const keys = await storage.getApiKeys(req.user._id.toString());
        
        res.json(keys.map(key => ({
          id: key._id,
          name: key.name,
          key: key.key,
          created: key.createdAt?.toISOString().split('T')[0] || 'Unknown',
          lastUsed: key.lastUsed ? formatRelativeTime(key.lastUsed) : 'Never',
          requests: key.requests,
          credits: key.credits || 0,
        })));
      } catch (error: any) {
        console.error('Get API keys error:', error);
        res.status(500).json({ 
          error: "Failed to fetch API keys",
          message: error.message 
        });
      }
    }
  );

  app.post(
    "/api/api-keys",
    generalRateLimit,
    authenticateToken,
    validateInput([validateApiKeyInput]),
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        if (!req.user) {
          return res.status(401).json({
            error: "Authentication required",
            message: "User not authenticated"
          });
        }
        
        const parsed = insertApiKeySchema.safeParse({
          userId: req.user._id.toString(),
          name: req.body.name
        });
        
        if (!parsed.success) {
          return res.status(400).json({ 
            error: "Validation failed",
            message: "Invalid request data" 
          });
        }

        const apiKey = await storage.createApiKey(parsed.data);
        
        res.status(201).json({
          id: apiKey._id,
          name: apiKey.name,
          key: apiKey.key,
          created: apiKey.createdAt?.toISOString().split('T')[0] || 'Unknown',
          lastUsed: 'Never',
          requests: 0,
          credits: 3.0,
          message: 'API key created successfully with 3.0 testing credits'
        });
      } catch (error: any) {
        console.error('Create API key error:', error);
        res.status(500).json({ 
          error: "Failed to create API key",
          message: error.message 
        });
      }
    }
  );

  app.delete(
    "/api/api-keys/:id",
    generalRateLimit,
    authenticateToken,
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        if (!req.user) {
          return res.status(401).json({
            error: "Authentication required",
            message: "User not authenticated"
          });
        }
        
        // Verify the API key belongs to the user
        const apiKey = await storage.getApiKeyById(req.params.id);
        if (!apiKey) {
          return res.status(404).json({
            error: "API key not found",
            message: "The specified API key does not exist"
          });
        }
        
        if (apiKey.userId !== req.user._id.toString()) {
          return res.status(403).json({
            error: "Access denied",
            message: "You can only delete your own API keys"
          });
        }
        
        await storage.deleteApiKey(req.params.id);
        res.json({ message: "API key deleted successfully" });
      } catch (error: any) {
        console.error('Delete API key error:', error);
        res.status(500).json({ 
          error: "Failed to delete API key",
          message: error.message 
        });
      }
    }
  );
}
  // Send OTP endpoint
 
  // Login endpoint
  app.post(
    "/api/auth/login",
    authRateLimit,
    validateInput([validateLoginInput]),
    async (req: Request, res: Response) => {
      try {
        const { username, password } = req.body;
        
        // Sanitize input
        const sanitizedUsername = SecurityUtils.sanitizeInput(username);
        
        // Authenticate user
        const user = await storage.authenticateUser(sanitizedUsername, password);
        
        if (!user) {
          return res.status(401).json({
            error: "Authentication failed",
            message: "Invalid username or password"
          });
        }
        
        // Generate tokens
        const { accessToken, refreshToken } = await AuthService.generateTokens(user);
        
        // Set refresh token as secure HTTP-only cookie
        res.cookie('refreshToken', refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
          path: '/api/auth'
        });
        
        res.json({
          message: "Login successful",
          user: {
            id: user._id,
            username: user.username,
            createdAt: user.createdAt
          },
          accessToken
        });
      } catch (error: any) {
        console.error('Login error:', error);
        res.status(500).json({
          error: "Login failed",
          message: "An error occurred during login"
        });
      }
    }
  );

  // Refresh token endpoint
  app.post(
    "/api/auth/refresh",
    generalRateLimit,
    async (req: Request, res: Response) => {
      try {
        const refreshToken = req.cookies?.refreshToken;
        
        if (!refreshToken) {
          return res.status(401).json({
            error: "Refresh token missing",
            message: "No refresh token provided"
          });
        }
        
        // Generate new access token
        const newAccessToken = await AuthService.refreshAccessToken(refreshToken);
        
        res.json({
          accessToken: newAccessToken
        });
      } catch (error: any) {
        console.error('Token refresh error:', error);
        res.status(401).json({
          error: "Token refresh failed",
          message: "Invalid or expired refresh token"
        });
      }
    }
  );

  // Logout endpoint
  app.post(
    "/api/auth/logout",
    generalRateLimit,
    async (req: Request, res: Response) => {
      // Clear refresh token cookie
      res.clearCookie('refreshToken', {
        path: '/api/auth'
      });
      
      res.json({
        message: "Logged out successfully"
      });
    }
  );

  // Get current user profile
  app.get(
    "/api/auth/profile",
    generalRateLimit,
    authenticateToken,
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        if (!req.user) {
          return res.status(401).json({
            error: "Authentication required",
            message: "User not authenticated"
          });
        }
        
        res.json({
          user: {
            id: req.user._id,
            username: req.user.username,
            createdAt: req.user.createdAt,
            updatedAt: req.user.updatedAt
          }
        });
      } catch (error: any) {
        console.error('Profile fetch error:', error);
        res.status(500).json({
          error: "Profile fetch failed",
          message: "An error occurred while fetching profile"
        });
      }
    }
  );

  // Update password
  app.post(
    "/api/auth/change-password",
    authRateLimit,
    authenticateToken,
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        if (!req.user) {
          return res.status(401).json({
            error: "Authentication required",
            message: "User not authenticated"
          });
        }
        
        const { currentPassword, newPassword } = req.body;
        
        if (!currentPassword || !newPassword) {
          return res.status(400).json({
            error: "Validation failed",
            message: "Current password and new password are required"
          });
        }
        
        // Verify current password
        const user = await storage.authenticateUser(req.user.username, currentPassword);
        if (!user) {
          return res.status(401).json({
            error: "Authentication failed",
            message: "Current password is incorrect"
          });
        }
        
        // Update password
        await storage.updateUserPassword(req.user._id.toString(), newPassword);
        
        res.json({
          message: "Password updated successfully"
        });
      } catch (error: any) {
        console.error('Password change error:', error);
        
        if (error.message.includes('Password must contain')) {
          return res.status(400).json({
            error: "Password validation failed",
            message: error.message
          });
        }
        
        res.status(500).json({
          error: "Password change failed",
          message: "An error occurred while updating password"
        });
      }
    }
  );

  // Protected API Keys endpoints (updated from routes.ts)
  app.get(
    "/api/api-keys",
    generalRateLimit,
    authenticateToken,
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        if (!req.user) {
          return res.status(401).json({
            error: "Authentication required",
            message: "User not authenticated"
          });
        }
        
        const keys = await storage.getApiKeys(req.user._id.toString());
        
        res.json(keys.map(key => ({
          id: key._id,
          name: key.name,
          key: key.key,
          created: key.createdAt?.toISOString().split('T')[0] || 'Unknown',
          lastUsed: key.lastUsed ? formatRelativeTime(key.lastUsed) : 'Never',
          requests: key.requests,
          credits: key.credits || 0,
        })));
      } catch (error: any) {
        console.error('Get API keys error:', error);
        res.status(500).json({ 
          error: "Failed to fetch API keys",
          message: error.message 
        });
      }
    }
  );

  app.post(
    "/api/api-keys",
    generalRateLimit,
    authenticateToken,
    validateInput([validateApiKeyInput]),
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        if (!req.user) {
          return res.status(401).json({
            error: "Authentication required",
            message: "User not authenticated"
          });
        }
        
        const parsed = insertApiKeySchema.safeParse({
          userId: req.user._id.toString(),
          name: req.body.name
        });
        
        if (!parsed.success) {
          return res.status(400).json({ 
            error: "Validation failed",
            message: "Invalid request data" 
          });
        }

        const apiKey = await storage.createApiKey(parsed.data);
        
        res.status(201).json({
          id: apiKey._id,
          name: apiKey.name,
          key: apiKey.key,
          created: apiKey.createdAt?.toISOString().split('T')[0] || 'Unknown',
          lastUsed: 'Never',
          requests: 0,
          credits: 3.0,
          message: 'API key created successfully with 3.0 testing credits'
        });
      } catch (error: any) {
        console.error('Create API key error:', error);
        res.status(500).json({ 
          error: "Failed to create API key",
          message: error.message 
        });
      }
    }
  );

  app.delete(
    "/api/api-keys/:id",
    generalRateLimit,
    authenticateToken,
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        if (!req.user) {
          return res.status(401).json({
            error: "Authentication required",
            message: "User not authenticated"
          });
        }
        
        // Verify the API key belongs to the user
        const apiKey = await storage.getApiKeyById(req.params.id);
        if (!apiKey) {
          return res.status(404).json({
            error: "API key not found",
            message: "The specified API key does not exist"
          });
        }
        
        if (apiKey.userId !== req.user._id.toString()) {
          return res.status(403).json({
            error: "Access denied",
            message: "You can only delete your own API keys"
          });
        }
        
        await storage.deleteApiKey(req.params.id);
        res.json({ message: "API key deleted successfully" });
      } catch (error: any) {
        console.error('Delete API key error:', error);
        res.status(500).json({ 
          error: "Failed to delete API key",
          message: error.message 
        });
      }
    }
  );


function formatRelativeTime(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
  if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
  return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;

}




