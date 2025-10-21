var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// shared/schema-mongodb.ts
import mongoose, { Schema } from "mongoose";
import { z } from "zod";
var userSchema, apiKeySchema, paymentOrderSchema, subscriptionSchema, User, ApiKey, PaymentOrder, Subscription, emailOtpSchema, EmailOtp, insertUserSchema, insertApiKeySchema, createPaymentIntentSchema, createSubscriptionSchema;
var init_schema_mongodb = __esm({
  "shared/schema-mongodb.ts"() {
    "use strict";
    userSchema = new Schema({
      username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true
      },
      password: {
        type: String,
        required: true
      }
    }, {
      timestamps: true
    });
    apiKeySchema = new Schema({
      userId: {
        type: String,
        required: true,
        ref: "User",
        index: true
      },
      name: {
        type: String,
        required: true,
        trim: true
      },
      key: {
        type: String,
        required: true,
        unique: true
      },
      lastUsed: {
        type: Date,
        default: null
      },
      requests: {
        type: Number,
        default: 0
      },
      credits: {
        type: Number,
        default: 3
      }
    }, {
      timestamps: true
    });
    apiKeySchema.index({ createdAt: -1 });
    paymentOrderSchema = new Schema({
      orderId: { type: String, required: true, unique: true, index: true },
      subscriptionId: { type: String, required: false, index: true },
      status: { type: String, enum: ["pending", "signed", "submitted", "confirmed", "expired", "failed"], default: "pending", index: true },
      assetType: { type: String, enum: ["SOL", "SPL"], required: true, index: true },
      amountLamports: { type: Number, required: false },
      tokenMint: { type: String, required: false, index: true },
      tokenAmount: { type: String, required: false },
      merchant: { type: String, required: true, index: true },
      userPubkey: { type: String, required: false },
      memo: { type: String, required: false },
      reference: { type: String, required: false, index: true },
      unsignedTxB64: { type: String, required: false },
      signature: { type: String, required: false, index: true },
      expiresAt: { type: Date, required: true, index: true }
    }, { timestamps: true });
    paymentOrderSchema.index({ createdAt: -1 });
    paymentOrderSchema.index({ status: 1, expiresAt: 1 });
    subscriptionSchema = new Schema({
      subscriptionId: { type: String, required: true, unique: true, index: true },
      userId: { type: String, required: false, index: true },
      apiKeyId: { type: String, required: true, index: true, ref: "ApiKey" },
      plan: { type: String, enum: ["basic", "pro"], required: true, index: true },
      priceUsd: { type: Number, required: true },
      chain: { type: String, enum: ["solana", "ethereum", "bitcoin", "xrp", "other"], required: true },
      asset: { type: String, enum: ["SOL", "SPL", "ETH", "BTC", "XRP", "OTHER"], required: true },
      tokenMint: { type: String, required: false },
      orderId: { type: String, required: false, index: true },
      status: { type: String, enum: ["pending", "active", "expired", "canceled", "suspended", "past_due"], default: "pending", index: true },
      activeUntil: { type: Date, required: false },
      creditedAt: { type: Date, required: false },
      // Enhanced recurring subscription fields
      isRecurring: { type: Boolean, default: true, index: true },
      walletAddress: { type: String, required: false, index: true },
      nextBillingDate: { type: Date, required: false, index: true },
      billingInterval: { type: String, enum: ["monthly", "yearly"], default: "monthly", index: true },
      failedPaymentAttempts: { type: Number, default: 0 },
      lastPaymentDate: { type: Date, required: false },
      lastPaymentSignature: { type: String, required: false },
      canceledAt: { type: Date, required: false },
      cancellationReason: { type: String, required: false },
      gracePeriodUntil: { type: Date, required: false },
      webhookUrl: { type: String, required: false },
      metadata: { type: Schema.Types.Mixed, default: {} }
    }, { timestamps: true });
    subscriptionSchema.index({ apiKeyId: 1, status: 1 });
    subscriptionSchema.index({ nextBillingDate: 1, status: 1 });
    subscriptionSchema.index({ walletAddress: 1, status: 1 });
    subscriptionSchema.index({ isRecurring: 1, nextBillingDate: 1 });
    subscriptionSchema.index({ status: 1, gracePeriodUntil: 1 });
    User = mongoose.models.User || mongoose.model("User", userSchema);
    ApiKey = mongoose.models.ApiKey || mongoose.model("ApiKey", apiKeySchema);
    PaymentOrder = mongoose.models.PaymentOrder || mongoose.model("PaymentOrder", paymentOrderSchema);
    Subscription = mongoose.models.Subscription || mongoose.model("Subscription", subscriptionSchema);
    emailOtpSchema = new Schema({
      email: { type: String, required: true, index: true },
      code: { type: String, required: true },
      expiresAt: { type: Date, required: true, index: { expires: 0 } }
    }, { timestamps: true });
    EmailOtp = mongoose.models.EmailOtp || mongoose.model("EmailOtp", emailOtpSchema);
    insertUserSchema = z.object({
      username: z.string().min(3).max(50).toLowerCase(),
      password: z.string().min(6).max(100)
    });
    insertApiKeySchema = z.object({
      userId: z.string(),
      name: z.string().min(1).max(100).trim()
    });
    createPaymentIntentSchema = z.object({
      orderId: z.string().min(6).max(64),
      merchant: z.string().min(32),
      userPubkey: z.string().min(32).optional(),
      memo: z.string().max(128).optional(),
      // For SOL
      amountLamports: z.number().int().positive().optional(),
      // For SPL
      tokenMint: z.string().min(32).optional(),
      tokenAmount: z.string().regex(/^\d+$/).optional()
      // base units as string
    }).refine((d) => {
      const sol = typeof d.amountLamports === "number" && !d.tokenMint && !d.tokenAmount;
      const spl = !d.amountLamports && !!d.tokenMint && !!d.tokenAmount;
      return sol || spl;
    }, {
      message: "Provide either amountLamports for SOL or tokenMint+tokenAmount for SPL"
    });
    createSubscriptionSchema = z.object({
      apiKeyId: z.string().min(1),
      userPubkey: z.string().min(32),
      // Solana payer
      plan: z.enum(["basic", "pro"]).default("pro")
    });
  }
});

// shared/mongodb.ts
import mongoose2 from "mongoose";
async function connectToDatabase() {
  if (connection.isConnected) {
    console.log("Already connected to MongoDB");
    return;
  }
  try {
    const mongoUri = process.env.MONGODB_URI;
    if (!mongoUri) {
      throw new Error("MONGODB_URI environment variable is not defined");
    }
    const db = await mongoose2.connect(mongoUri, {
      bufferCommands: false,
      maxPoolSize: 10,
      // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5e3,
      // Keep trying to send operations for 5 seconds
      socketTimeoutMS: 45e3
      // Close sockets after 45 seconds of inactivity
    });
    connection.isConnected = db.connections[0].readyState;
    console.log("Connected to MongoDB successfully");
    mongoose2.connection.on("error", (error) => {
      console.error("MongoDB connection error:", error);
    });
    mongoose2.connection.on("disconnected", () => {
      console.log("MongoDB disconnected");
      connection.isConnected = 0;
    });
    process.on("SIGINT", async () => {
      await mongoose2.connection.close();
      console.log("MongoDB connection closed due to app termination");
      process.exit(0);
    });
  } catch (error) {
    console.error("Error connecting to MongoDB:", error);
    throw error;
  }
}
var connection;
var init_mongodb = __esm({
  "shared/mongodb.ts"() {
    "use strict";
    connection = {};
  }
});

// shared/encryption.ts
import bcrypt from "bcrypt";
import crypto from "crypto";
import { promisify } from "util";
var ENCRYPTION_CONFIG, PasswordService, APIKeyService, TokenService, SecurityUtils;
var init_encryption = __esm({
  "shared/encryption.ts"() {
    "use strict";
    ENCRYPTION_CONFIG = {
      // High-cost bcrypt rounds for password hashing (minimum 12 for production)
      BCRYPT_ROUNDS: 14,
      // AES-256-GCM for data encryption at rest
      ALGORITHM: "aes-256-gcm",
      KEY_LENGTH: 32,
      IV_LENGTH: 16,
      SALT_LENGTH: 32,
      TAG_LENGTH: 16,
      // Key derivation
      PBKDF2_ITERATIONS: 1e5,
      // Minimum recommended iterations
      PBKDF2_KEYLEN: 32,
      PBKDF2_DIGEST: "sha512"
    };
    PasswordService = class {
      /**
       * Hash a password using bcrypt with high cost factor
       */
      static async hash(password) {
        if (!password || password.length < 8) {
          throw new Error("Password must be at least 8 characters long");
        }
        if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/.test(password)) {
          throw new Error("Password must contain at least one lowercase letter, uppercase letter, digit, and special character");
        }
        try {
          const salt = await bcrypt.genSalt(ENCRYPTION_CONFIG.BCRYPT_ROUNDS);
          return await bcrypt.hash(password, salt);
        } catch (error) {
          throw new Error("Failed to hash password");
        }
      }
      /**
       * Verify a password against its hash
       */
      static async verify(password, hash) {
        try {
          return await bcrypt.compare(password, hash);
        } catch (error) {
          return false;
        }
      }
      /**
       * Check if password hash needs rehashing (due to increased security requirements)
       */
      static needsRehash(hash) {
        try {
          const rounds = bcrypt.getRounds(hash);
          return rounds < ENCRYPTION_CONFIG.BCRYPT_ROUNDS;
        } catch {
          return true;
        }
      }
    };
    APIKeyService = class {
      static PREFIX_LIVE = "sk_live_";
      static PREFIX_TEST = "sk_test_";
      static KEY_LENGTH = 32;
      // 256 bits
      /**
       * Generate a cryptographically secure API key
       */
      static generateApiKey(isLive = false) {
        const prefix = isLive ? this.PREFIX_LIVE : this.PREFIX_TEST;
        const randomBytes = crypto.randomBytes(this.KEY_LENGTH);
        const keyPart = randomBytes.toString("hex");
        return `${prefix}${keyPart}`;
      }
      /**
       * Validate API key format
       */
      static validateKeyFormat(apiKey) {
        const livePattern = new RegExp(`^${this.PREFIX_LIVE}[a-f0-9]{64}$`);
        const testPattern = new RegExp(`^${this.PREFIX_TEST}[a-f0-9]{64}$`);
        return livePattern.test(apiKey) || testPattern.test(apiKey);
      }
      /**
       * Check if API key is live or test
       */
      static isLiveKey(apiKey) {
        return apiKey.startsWith(this.PREFIX_LIVE);
      }
      /**
       * Hash API key for database storage (one-way hash)
       */
      static async hashKey(apiKey) {
        const salt = crypto.randomBytes(ENCRYPTION_CONFIG.SALT_LENGTH);
        const iterations = ENCRYPTION_CONFIG.PBKDF2_ITERATIONS;
        const pbkdf2 = promisify(crypto.pbkdf2);
        const hash = await pbkdf2(
          apiKey,
          salt,
          iterations,
          ENCRYPTION_CONFIG.PBKDF2_KEYLEN,
          ENCRYPTION_CONFIG.PBKDF2_DIGEST
        );
        const combined = {
          salt: salt.toString("hex"),
          iterations,
          hash: hash.toString("hex")
        };
        return Buffer.from(JSON.stringify(combined)).toString("base64");
      }
      /**
       * Verify API key against stored hash
       */
      static async verifyKey(apiKey, storedHash) {
        try {
          const combined = JSON.parse(Buffer.from(storedHash, "base64").toString("utf8"));
          const { salt, iterations, hash } = combined;
          const pbkdf2 = promisify(crypto.pbkdf2);
          const derivedKey = await pbkdf2(
            apiKey,
            Buffer.from(salt, "hex"),
            iterations,
            ENCRYPTION_CONFIG.PBKDF2_KEYLEN,
            ENCRYPTION_CONFIG.PBKDF2_DIGEST
          );
          const derivedHash = derivedKey.toString("hex");
          return crypto.timingSafeEqual(
            Buffer.from(hash, "hex"),
            Buffer.from(derivedHash, "hex")
          );
        } catch {
          return false;
        }
      }
    };
    TokenService = class {
      /**
       * Generate cryptographically secure random token
       */
      static generateSecureToken(length = 32) {
        return crypto.randomBytes(length).toString("hex");
      }
      /**
       * Generate URL-safe token
       */
      static generateURLSafeToken(length = 32) {
        return crypto.randomBytes(length).toString("base64url");
      }
      /**
       * Generate time-based token with expiration
       */
      static generateTimedToken(expirationMinutes = 60) {
        const expiry = Date.now() + expirationMinutes * 60 * 1e3;
        const randomPart = crypto.randomBytes(24).toString("hex");
        const tokenData = {
          exp: expiry,
          rnd: randomPart
        };
        return Buffer.from(JSON.stringify(tokenData)).toString("base64url");
      }
      /**
       * Verify timed token
       */
      static verifyTimedToken(token) {
        try {
          const tokenData = JSON.parse(Buffer.from(token, "base64url").toString("utf8"));
          return tokenData.exp > Date.now();
        } catch {
          return false;
        }
      }
    };
    SecurityUtils = class {
      /**
       * Sanitize user input to prevent XSS
       */
      static sanitizeInput(input) {
        return input.replace(/[<>'"&]/g, (char) => {
          const entities = {
            "<": "&lt;",
            ">": "&gt;",
            "'": "&#x27;",
            '"': "&quot;",
            "&": "&amp;"
          };
          return entities[char] || char;
        }).trim();
      }
      /**
       * Validate email format
       */
      static validateEmail(email) {
        const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        return emailRegex.test(email) && email.length <= 254;
      }
      /**
       * Validate username format
       */
      static validateUsername(username) {
        const usernameRegex = /^[a-zA-Z0-9_-]{3,30}$/;
        return usernameRegex.test(username);
      }
      /**
       * Generate CSRF token
       */
      static generateCSRFToken() {
        return crypto.randomBytes(32).toString("hex");
      }
      /**
       * Rate limiting helper - generate rate limit key
       */
      static generateRateLimitKey(ip, endpoint) {
        return `rate_limit:${ip}:${endpoint}`;
      }
    };
  }
});

// server/storage.ts
var storage_exports = {};
__export(storage_exports, {
  MongoDbStorage: () => MongoDbStorage,
  storage: () => storage
});
var MongoDbStorage, storage;
var init_storage = __esm({
  "server/storage.ts"() {
    "use strict";
    init_schema_mongodb();
    init_mongodb();
    init_encryption();
    MongoDbStorage = class {
      async ensureConnection() {
        await connectToDatabase();
      }
      async getUser(id) {
        await this.ensureConnection();
        try {
          const user = await User.findById(id).exec();
          return user || void 0;
        } catch (error) {
          console.error("Error fetching user by id:", error);
          return void 0;
        }
      }
      async getUserByUsername(username) {
        await this.ensureConnection();
        try {
          const user = await User.findOne({ username: username.toLowerCase() }).exec();
          return user || void 0;
        } catch (error) {
          console.error("Error fetching user by username:", error);
          return void 0;
        }
      }
      async createUser(insertUser) {
        await this.ensureConnection();
        try {
          const hashedPassword = await PasswordService.hash(insertUser.password);
          const user = new User({
            username: insertUser.username.toLowerCase(),
            password: hashedPassword
          });
          const savedUser = await user.save();
          return savedUser;
        } catch (error) {
          if (error.code === 11e3) {
            throw new Error("Username already exists");
          }
          console.error("Error creating user:", error);
          throw new Error("Failed to create user");
        }
      }
      async authenticateUser(username, password) {
        await this.ensureConnection();
        try {
          const user = await User.findOne({ username: username.toLowerCase() }).exec();
          if (!user) {
            return null;
          }
          const isValid = await PasswordService.verify(password, user.password);
          if (!isValid) {
            return null;
          }
          if (PasswordService.needsRehash(user.password)) {
            try {
              const newHash = await PasswordService.hash(password);
              user.password = newHash;
              await user.save();
            } catch (error) {
              console.warn("Failed to rehash password:", error);
            }
          }
          return user;
        } catch (error) {
          console.error("Error authenticating user:", error);
          return null;
        }
      }
      async updateUserPassword(userId, newPassword) {
        await this.ensureConnection();
        try {
          const hashedPassword = await PasswordService.hash(newPassword);
          const result = await User.findByIdAndUpdate(
            userId,
            { password: hashedPassword },
            { new: true }
          ).exec();
          if (!result) {
            throw new Error("User not found");
          }
        } catch (error) {
          console.error("Error updating user password:", error);
          throw new Error("Failed to update password");
        }
      }
      async getApiKeys(userId) {
        await this.ensureConnection();
        try {
          const query = userId ? { userId } : {};
          const apiKeys = await ApiKey.find(query).sort({ createdAt: -1 }).exec();
          return apiKeys;
        } catch (error) {
          console.error("Error fetching API keys:", error);
          return [];
        }
      }
      async getApiKeyById(id) {
        await this.ensureConnection();
        try {
          const apiKey = await ApiKey.findById(id).exec();
          return apiKey || void 0;
        } catch (error) {
          console.error("Error fetching API key by id:", error);
          return void 0;
        }
      }
      async createApiKey(insertApiKey) {
        await this.ensureConnection();
        try {
          const key = APIKeyService.generateApiKey(false);
          const apiKey = new ApiKey({
            userId: insertApiKey.userId,
            name: insertApiKey.name,
            key,
            requests: 0,
            credits: 30
            // Give initial credits to new API keys (platform decision)
          });
          const savedApiKey = await apiKey.save();
          return savedApiKey;
        } catch (error) {
          if (error.code === 11e3) {
            throw new Error("API key already exists");
          }
          console.error("Error creating API key:", error);
          throw new Error("Failed to create API key");
        }
      }
      async deleteApiKey(id) {
        await this.ensureConnection();
        try {
          const result = await ApiKey.findByIdAndDelete(id).exec();
          if (!result) {
            throw new Error("API key not found");
          }
        } catch (error) {
          console.error("Error deleting API key:", error);
          throw new Error("Failed to delete API key");
        }
      }
      async updateApiKeyUsage(id) {
        await this.ensureConnection();
        try {
          await ApiKey.findByIdAndUpdate(
            id,
            {
              $set: { lastUsed: /* @__PURE__ */ new Date() },
              $inc: { requests: 1 }
            },
            { new: true }
          ).exec();
        } catch (error) {
          console.error("Error updating API key usage:", error);
        }
      }
      // Additional utility methods for MongoDB
      async getApiKeyByKey(key) {
        await this.ensureConnection();
        try {
          const apiKey = await ApiKey.findOne({ key }).exec();
          return apiKey || void 0;
        } catch (error) {
          console.error("Error fetching API key by key:", error);
          return void 0;
        }
      }
      async getUsersCount() {
        await this.ensureConnection();
        try {
          return await User.countDocuments();
        } catch (error) {
          console.error("Error counting users:", error);
          return 0;
        }
      }
      async getApiKeysCount(userId) {
        await this.ensureConnection();
        try {
          const query = userId ? { userId } : {};
          return await ApiKey.countDocuments(query);
        } catch (error) {
          console.error("Error counting API keys:", error);
          return 0;
        }
      }
      async deductCredits(apiKeyId, amount) {
        await this.ensureConnection();
        try {
          const result = await ApiKey.findOneAndUpdate(
            {
              _id: apiKeyId,
              credits: { $gte: amount }
              // Only update if sufficient credits
            },
            {
              $inc: { credits: -amount, requests: 1 },
              $set: { lastUsed: /* @__PURE__ */ new Date() }
            },
            { new: true }
          ).exec();
          return !!result;
        } catch (error) {
          console.error("Error deducting credits:", error);
          return false;
        }
      }
      async getApiKeyCredits(apiKeyId) {
        await this.ensureConnection();
        try {
          const apiKey = await ApiKey.findById(apiKeyId).select("credits").exec();
          return apiKey?.credits;
        } catch (error) {
          console.error("Error fetching API key credits:", error);
          return void 0;
        }
      }
    };
    storage = new MongoDbStorage();
  }
});

// shared/auth.ts
import jwt from "jsonwebtoken";
var JWT_CONFIG, getJWTSecrets, AuthService, authenticateToken, optionalAuth, createRateLimiter, validateInput, authenticateApiKey;
var init_auth = __esm({
  "shared/auth.ts"() {
    "use strict";
    init_encryption();
    init_schema_mongodb();
    init_mongodb();
    JWT_CONFIG = {
      ACCESS_TOKEN_EXPIRY: 15 * 60,
      // seconds (15m)
      REFRESH_TOKEN_EXPIRY: 7 * 24 * 60 * 60,
      // seconds (7d)
      ALGORITHM: "HS512",
      // Strong HMAC algorithm
      ISSUER: "blocksub-api",
      AUDIENCE: "blocksub-client"
    };
    getJWTSecrets = () => {
      const accessSecret = process.env.JWT_ACCESS_SECRET;
      const refreshSecret = process.env.JWT_REFRESH_SECRET;
      if (!accessSecret || !refreshSecret) {
        throw new Error("JWT secrets must be set in environment variables");
      }
      if (accessSecret.length < 64 || refreshSecret.length < 64) {
        throw new Error("JWT secrets must be at least 64 characters long");
      }
      return { accessSecret, refreshSecret };
    };
    AuthService = class {
      /**
       * Generate access and refresh tokens for a user
       */
      static async generateTokens(user) {
        const { accessSecret, refreshSecret } = getJWTSecrets();
        const accessPayload = {
          userId: user._id.toString(),
          username: user.username,
          type: "access"
        };
        const refreshPayload = {
          userId: user._id.toString(),
          type: "refresh",
          tokenId: TokenService.generateSecureToken(16)
        };
        const accessToken = jwt.sign(accessPayload, accessSecret, {
          expiresIn: JWT_CONFIG.ACCESS_TOKEN_EXPIRY,
          algorithm: JWT_CONFIG.ALGORITHM,
          issuer: JWT_CONFIG.ISSUER,
          audience: JWT_CONFIG.AUDIENCE
        });
        const refreshToken = jwt.sign(refreshPayload, refreshSecret, {
          expiresIn: JWT_CONFIG.REFRESH_TOKEN_EXPIRY,
          algorithm: JWT_CONFIG.ALGORITHM,
          issuer: JWT_CONFIG.ISSUER,
          audience: JWT_CONFIG.AUDIENCE
        });
        return { accessToken, refreshToken };
      }
      /**
       * Verify and decode access token
       */
      static verifyAccessToken(token) {
        const { accessSecret } = getJWTSecrets();
        try {
          const decoded = jwt.verify(token, accessSecret, {
            algorithms: [JWT_CONFIG.ALGORITHM],
            issuer: JWT_CONFIG.ISSUER,
            audience: JWT_CONFIG.AUDIENCE
          });
          if (decoded.type !== "access") {
            throw new Error("Invalid token type");
          }
          return decoded;
        } catch (error) {
          throw new Error("Invalid or expired access token");
        }
      }
      /**
       * Verify and decode refresh token
       */
      static verifyRefreshToken(token) {
        const { refreshSecret } = getJWTSecrets();
        try {
          const decoded = jwt.verify(token, refreshSecret, {
            algorithms: [JWT_CONFIG.ALGORITHM],
            issuer: JWT_CONFIG.ISSUER,
            audience: JWT_CONFIG.AUDIENCE
          });
          if (decoded.type !== "refresh") {
            throw new Error("Invalid token type");
          }
          return decoded;
        } catch (error) {
          throw new Error("Invalid or expired refresh token");
        }
      }
      /**
       * Refresh access token using refresh token
       */
      static async refreshAccessToken(refreshToken) {
        const refreshPayload = this.verifyRefreshToken(refreshToken);
        await connectToDatabase();
        const user = await User.findById(refreshPayload.userId);
        if (!user) {
          throw new Error("User not found");
        }
        const { accessSecret } = getJWTSecrets();
        const accessPayload = {
          userId: user._id.toString(),
          username: user.username,
          type: "access"
        };
        return jwt.sign(accessPayload, accessSecret, {
          expiresIn: JWT_CONFIG.ACCESS_TOKEN_EXPIRY,
          algorithm: JWT_CONFIG.ALGORITHM,
          issuer: JWT_CONFIG.ISSUER,
          audience: JWT_CONFIG.AUDIENCE
        });
      }
      /**
       * Extract token from Authorization header
       */
      static extractTokenFromHeader(authHeader) {
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
          return null;
        }
        return authHeader.substring(7);
      }
      /**
       * Get user by token
       */
      static async getUserFromToken(token) {
        const payload = this.verifyAccessToken(token);
        await connectToDatabase();
        const user = await User.findById(payload.userId);
        if (!user) {
          throw new Error("User not found");
        }
        return user;
      }
    };
    authenticateToken = async (req, res, next) => {
      try {
        const token = AuthService.extractTokenFromHeader(req.headers.authorization);
        if (!token) {
          res.status(401).json({
            error: "Authentication required",
            message: "Access token is missing"
          });
          return;
        }
        const user = await AuthService.getUserFromToken(token);
        const tokenPayload = AuthService.verifyAccessToken(token);
        req.user = user;
        req.tokenPayload = tokenPayload;
        next();
      } catch (error) {
        res.status(401).json({
          error: "Authentication failed",
          message: error.message
        });
      }
    };
    optionalAuth = async (req, res, next) => {
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
        next();
      }
    };
    createRateLimiter = (windowMs, max) => {
      const requests = /* @__PURE__ */ new Map();
      return (req, res, next) => {
        const key = SecurityUtils.generateRateLimitKey(
          req.ip || req.connection.remoteAddress || "unknown",
          req.path
        );
        const now = Date.now();
        const windowStart = now - windowMs;
        requests.forEach((v, k) => {
          if (v.resetTime < windowStart) {
            requests.delete(k);
          }
        });
        const current = requests.get(key) || { count: 0, resetTime: now + windowMs };
        if (current.resetTime < now) {
          current.count = 0;
          current.resetTime = now + windowMs;
        }
        if (current.count >= max) {
          res.status(429).json({
            error: "Too many requests",
            message: "Rate limit exceeded. Please try again later.",
            retryAfter: Math.ceil((current.resetTime - now) / 1e3)
          });
          return;
        }
        current.count++;
        requests.set(key, current);
        res.setHeader("X-RateLimit-Limit", max.toString());
        res.setHeader("X-RateLimit-Remaining", (max - current.count).toString());
        res.setHeader("X-RateLimit-Reset", new Date(current.resetTime).toISOString());
        next();
      };
    };
    validateInput = (validations) => {
      return (req, res, next) => {
        const errors = [];
        for (const validation of validations) {
          const error = validation(req);
          if (error) {
            errors.push(error);
          }
        }
        if (errors.length > 0) {
          res.status(400).json({
            error: "Validation failed",
            message: "Input validation errors",
            details: errors
          });
          return;
        }
        next();
      };
    };
    authenticateApiKey = (creditCost = 0.1) => {
      return async (req, res, next) => {
        try {
          let apiKeyValue;
          const authHeader = req.headers.authorization;
          if (authHeader) {
            if (authHeader.startsWith("Bearer ")) {
              apiKeyValue = authHeader.substring(7);
            } else if (authHeader.startsWith("ApiKey ")) {
              apiKeyValue = authHeader.substring(7);
            } else {
              apiKeyValue = authHeader;
            }
          }
          if (!apiKeyValue) {
            apiKeyValue = req.headers["x-api-key"];
          }
          if (!apiKeyValue) {
            apiKeyValue = req.query.apiKey || req.query.api_key;
          }
          if (!apiKeyValue && req.body) {
            apiKeyValue = req.body.apiKey || req.body.api_key;
          }
          if (!apiKeyValue) {
            res.status(401).json({
              error: "API key required",
              message: "Please provide a valid API key in the Authorization header, x-api-key header, or request body"
            });
            return;
          }
          const { storage: storage2 } = await Promise.resolve().then(() => (init_storage(), storage_exports));
          const apiKey = await storage2.getApiKeyByKey(apiKeyValue);
          if (!apiKey) {
            res.status(401).json({
              error: "Invalid API key",
              message: "The provided API key is not valid"
            });
            return;
          }
          if (apiKey.credits < creditCost) {
            res.status(402).json({
              error: "Insufficient credits",
              message: `This API call requires ${creditCost} credits, but your API key only has ${apiKey.credits} credits remaining. Please upgrade your plan to continue using the API.`,
              currentCredits: apiKey.credits,
              requiredCredits: creditCost
            });
            return;
          }
          const creditDeducted = await storage2.deductCredits(apiKey._id.toString(), creditCost);
          if (!creditDeducted) {
            res.status(500).json({
              error: "Credit deduction failed",
              message: "Unable to process the request due to a system error"
            });
            return;
          }
          req.apiKey = {
            _id: apiKey._id.toString(),
            userId: apiKey.userId,
            name: apiKey.name,
            key: apiKey.key,
            credits: apiKey.credits - creditCost,
            requests: apiKey.requests + 1
          };
          next();
        } catch (error) {
          console.error("API key authentication error:", error);
          res.status(500).json({
            error: "Authentication failed",
            message: "An error occurred during API key authentication"
          });
        }
      };
    };
  }
});

// server/security.ts
import helmet from "helmet";
import compression from "compression";
import cors from "cors";
import cookieParser from "cookie-parser";
import session from "express-session";
import MongoStore from "connect-mongo";
import morgan from "morgan";
import winston from "winston";
function setupSecurity(app) {
  if (process.env.TRUST_PROXY) {
    app.set("trust proxy", process.env.TRUST_PROXY);
  }
  app.use(helmet(getHelmetConfig()));
  app.use(cors(corsConfig));
  app.use(morgan(morganConfig, {
    stream: {
      write: (message) => logger.info(message.trim())
    }
  }));
  app.use(compression({
    filter: (req, res) => {
      if (req.headers["cache-control"] && req.headers["cache-control"].includes("no-transform")) {
        return false;
      }
      return compression.filter(req, res);
    }
  }));
  app.use(cookieParser());
  app.use(session(getSessionConfig()));
  app.use((req, res, next) => {
    const maxSize = 10 * 1024 * 1024;
    req.on("data", (chunk) => {
      const contentLength = parseInt(req.headers["content-length"] || "0", 10);
      if (contentLength > maxSize) {
        res.status(413).json({
          error: "Payload too large",
          message: "Request size exceeds the maximum allowed limit"
        });
        return;
      }
    });
    next();
  });
  app.use((req, res, next) => {
    res.removeHeader("X-Powered-By");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    res.setHeader("Referrer-Policy", "same-origin");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    next();
  });
  app.use((req, res, next) => {
    res.setHeader("API-Version", "1.0.0");
    next();
  });
  app.get("/health", (req, res) => {
    res.status(200).json({
      status: "healthy",
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      uptime: process.uptime(),
      version: "1.0.0"
    });
  });
  app.use((err, req, res, next) => {
    logger.error("Security middleware error:", {
      error: err.message,
      stack: err.stack,
      url: req.url,
      method: req.method,
      ip: req.ip,
      userAgent: req.headers["user-agent"]
    });
    const isProduction = process.env.NODE_ENV === "production";
    res.status(err.status || 500).json({
      error: isProduction ? "Internal server error" : err.message,
      message: isProduction ? "An unexpected error occurred" : err.message
    });
  });
}
function setupErrorLogging(app) {
  app.use((err, req, res, next) => {
    logger.error("Application error:", {
      error: err.message,
      stack: err.stack,
      url: req.url,
      method: req.method,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      body: req.body
    });
    next(err);
  });
}
function setupGracefulShutdown() {
  const gracefulShutdown = (signal) => {
    logger.info(`Received ${signal}. Starting graceful shutdown...`);
    process.exit(0);
  };
  process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
  process.on("SIGINT", () => gracefulShutdown("SIGINT"));
  process.on("uncaughtException", (error) => {
    logger.error("Uncaught Exception:", error);
    process.exit(1);
  });
  process.on("unhandledRejection", (reason, promise) => {
    logger.error("Unhandled Rejection at:", promise, "reason:", reason);
    process.exit(1);
  });
}
var logger, getHelmetConfig, corsConfig, getSessionConfig, rateLimitConfig, morganConfig;
var init_security = __esm({
  "server/security.ts"() {
    "use strict";
    logger = winston.createLogger({
      level: process.env.LOG_LEVEL || "info",
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      defaultMeta: { service: "blocksub-api" },
      transports: [
        new winston.transports.File({ filename: "logs/error.log", level: "error" }),
        new winston.transports.File({ filename: "logs/combined.log" })
      ]
    });
    if (process.env.NODE_ENV !== "production") {
      logger.add(new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.simple()
        )
      }));
    }
    getHelmetConfig = () => {
      const isProduction = process.env.NODE_ENV === "production";
      return {
        contentSecurityPolicy: {
          directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            // Allow Vite dev preamble and HMR in development. Inline scripts are required by @vitejs/plugin-react.
            scriptSrc: isProduction ? ["'self'"] : ["'self'", "'unsafe-eval'", "'unsafe-inline'", "http://localhost:*", "blob:"],
            // Explicitly set element/attr directives for CSP Level 3 aware browsers
            scriptSrcElem: isProduction ? ["'self'"] : ["'self'", "'unsafe-eval'", "'unsafe-inline'", "http://localhost:*", "blob:"],
            scriptSrcAttr: isProduction ? ["'self'"] : ["'self'", "'unsafe-inline'"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: isProduction ? ["'self'"] : ["'self'", "ws://localhost:*", "http://localhost:*"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"]
          }
        },
        crossOriginEmbedderPolicy: false,
        // Disable for API
        hsts: isProduction ? {
          maxAge: 31536e3,
          // 1 year
          includeSubDomains: true,
          preload: true
        } : false,
        // Disable HSTS in development
        referrerPolicy: { policy: "same-origin" }
      };
    };
    corsConfig = {
      origin: process.env.FRONTEND_URL || "http://localhost:5173",
      credentials: true,
      optionsSuccessStatus: 200,
      methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"]
    };
    getSessionConfig = () => {
      const isProduction = process.env.NODE_ENV === "production";
      const hasMongo = Boolean(process.env.MONGODB_URI);
      const store = hasMongo ? MongoStore.create({
        mongoUrl: process.env.MONGODB_URI,
        touchAfter: 24 * 3600,
        // Only update session once per 24 hours unless data changes
        crypto: {
          secret: process.env.SESSION_ENCRYPT_SECRET || "session-encrypt-secret-change-in-production"
        }
      }) : new session.MemoryStore();
      return {
        name: "blocksub.sid",
        // Change default session name
        secret: process.env.SESSION_SECRET || "your-super-secret-session-key-change-in-production",
        resave: false,
        saveUninitialized: false,
        store,
        cookie: {
          secure: isProduction,
          // HTTPS only in production
          httpOnly: true,
          maxAge: 7 * 24 * 60 * 60 * 1e3,
          // 7 days
          sameSite: isProduction ? "strict" : "lax"
        }
      };
    };
    rateLimitConfig = {
      // General API rate limiting
      api: {
        windowMs: 15 * 60 * 1e3,
        // 15 minutes
        max: 1e3,
        // Requests per window
        message: {
          error: "Too many requests",
          message: "Rate limit exceeded. Please try again later."
        },
        standardHeaders: true,
        legacyHeaders: false
      },
      // Authentication endpoints (stricter)
      auth: {
        windowMs: 15 * 60 * 1e3,
        // 15 minutes
        max: 10,
        // Attempts per window
        message: {
          error: "Too many authentication attempts",
          message: "Too many login attempts. Please try again later."
        },
        standardHeaders: true,
        legacyHeaders: false
      },
      // API key operations (moderate)
      apiKeys: {
        windowMs: 60 * 60 * 1e3,
        // 1 hour
        max: 100,
        // Requests per window
        message: {
          error: "Too many API requests",
          message: "API key rate limit exceeded. Please try again later."
        },
        standardHeaders: true,
        legacyHeaders: false
      }
    };
    morganConfig = process.env.NODE_ENV === "production" ? "combined" : "dev";
  }
});

// server/solana.ts
var solana_exports = {};
__export(solana_exports, {
  broadcastSignedTransaction: () => broadcastSignedTransaction,
  buildSolanaPayLink: () => buildSolanaPayLink2,
  buildSplApproveDelegateUnsigned: () => buildSplApproveDelegateUnsigned,
  buildSplTransferFromDelegateUnsigned: () => buildSplTransferFromDelegateUnsigned,
  createPaymentIntentUnsigned: () => createPaymentIntentUnsigned,
  extractMemoFromTransaction: () => extractMemoFromTransaction,
  findSignaturesForAddress: () => findSignaturesForAddress2,
  getSolanaConnection: () => getSolanaConnection,
  getTransactionBySignature: () => getTransactionBySignature
});
import { Connection, PublicKey, SystemProgram, Transaction, clusterApiUrl, Keypair, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { createTransferInstruction, getAssociatedTokenAddressSync, createAssociatedTokenAccountInstruction, getAccount, TokenAccountNotFoundError, createApproveInstruction } from "@solana/spl-token";
import QRCode from "qrcode";
import { v4 as uuidv4 } from "uuid";
function getEnv2(name, fallback = "") {
  return process.env[name] ?? fallback;
}
function getSolanaConnection() {
  const cluster = getEnv2("SOLANA_CLUSTER", "devnet") || "devnet";
  const custom = getEnv2("SOLANA_RPC_URL", "");
  const endpoint = custom || clusterApiUrl(cluster);
  return new Connection(endpoint, "confirmed");
}
function buildPhantomDeeplink(params) {
  const redirect = getEnv2("PHANTOM_REDIRECT_URL", "");
  const cluster = getEnv2("SOLANA_CLUSTER", "devnet");
  const appTitle = encodeURIComponent(getEnv2("PHANTOM_DAPP_TITLE", "BlockSub"));
  const appUrl = encodeURIComponent(getEnv2("PHANTOM_DAPP_URL", "http://localhost:3000"));
  const txParam = encodeURIComponent(params.b64);
  const orderParam = encodeURIComponent(params.orderId);
  const url = `https://phantom.app/ul/v1/signTransaction?transaction=${txParam}` + (redirect ? `&redirect_uri=${encodeURIComponent(`${redirect}?order=${orderParam}`)}` : "") + `&cluster=${encodeURIComponent(cluster)}&app_url=${appUrl}&app_title=${appTitle}`;
  return url;
}
async function createPaymentIntentUnsigned(params) {
  const connection2 = getSolanaConnection();
  const orderId = params.orderId || uuidv4().replace(/-/g, "");
  const memoText = params.memoText || `order:${orderId}`;
  const userPubkey = new PublicKey(params.userPubkey);
  const merchantPubkey = new PublicKey(params.merchant);
  const tx = new Transaction();
  if (params.assetType === "SOL") {
    if (!params.amountLamports) {
      throw new Error("amountLamports is required for SOL payments");
    }
    tx.add(
      SystemProgram.transfer({
        fromPubkey: userPubkey,
        toPubkey: merchantPubkey,
        lamports: params.amountLamports
      })
    );
  } else if (params.assetType === "SPL") {
    if (!params.tokenMint || !params.tokenAmount) {
      throw new Error("tokenMint and tokenAmount are required for SPL payments");
    }
    const tokenMintPubkey = new PublicKey(params.tokenMint);
    const amount = BigInt(params.tokenAmount);
    const userAta = getAssociatedTokenAddressSync(tokenMintPubkey, userPubkey);
    const merchantAta = getAssociatedTokenAddressSync(tokenMintPubkey, merchantPubkey);
    try {
      await getAccount(connection2, merchantAta);
    } catch (error) {
      if (error instanceof TokenAccountNotFoundError) {
        tx.add(
          createAssociatedTokenAccountInstruction(
            userPubkey,
            // payer
            merchantAta,
            // ata
            merchantPubkey,
            // owner
            tokenMintPubkey
            // mint
          )
        );
      }
    }
    tx.add(
      createTransferInstruction(
        userAta,
        // source
        merchantAta,
        // destination
        userPubkey,
        // owner
        amount
        // amount
      )
    );
  } else {
    throw new Error("Invalid assetType. Must be SOL or SPL");
  }
  const memoIx = {
    keys: [],
    programId: MEMO_PROGRAM_ID,
    data: Buffer.from(memoText, "utf8")
  };
  tx.add(memoIx);
  const { blockhash, lastValidBlockHeight } = await connection2.getLatestBlockhash("finalized");
  tx.recentBlockhash = blockhash;
  tx.feePayer = userPubkey;
  const serialized = tx.serialize({ requireAllSignatures: false, verifySignatures: false });
  const b64 = Buffer.from(serialized).toString("base64");
  const phantomUrl = buildPhantomDeeplink({ b64, orderId });
  const qrDataUrl = await QRCode.toDataURL(phantomUrl);
  const expiresAt = new Date(Date.now() + 2 * 60 * 1e3).toISOString();
  return {
    orderId,
    memoText,
    unsignedTxB64: b64,
    phantomUrl,
    qrDataUrl,
    expiresAt
  };
}
async function buildSolanaPayLink2(params) {
  const merchant = params.merchant;
  const reference = Keypair.generate().publicKey.toBase58();
  let uri = `solana:${merchant}`;
  const q = [];
  if (params.assetType === "SOL" && params.amountLamports) {
    const amountSOL = Number(params.amountLamports) / LAMPORTS_PER_SOL;
    q.push(`amount=${encodeURIComponent(String(amountSOL))}`);
  } else if (params.assetType === "SPL" && params.tokenMint && params.tokenAmount) {
    q.push(`spl-token=${encodeURIComponent(params.tokenMint)}`);
    q.push(`amount=${encodeURIComponent(params.tokenAmount)}`);
  }
  q.push(`reference=${encodeURIComponent(reference)}`);
  if (params.orderId) q.push(`label=${encodeURIComponent(params.orderId)}`);
  if (q.length) uri += `?${q.join("&")}`;
  const qrDataUrl = await QRCode.toDataURL(uri);
  const expiresAt = new Date(Date.now() + (params.expiresMs ?? 2 * 60 * 1e3)).toISOString();
  return { reference, solanaPayUrl: uri, qrDataUrl, expiresAt };
}
async function findSignaturesForAddress2(reference, limit = 20) {
  const connection2 = getSolanaConnection();
  const ref = new PublicKey(reference);
  return connection2.getSignaturesForAddress(ref, { limit });
}
async function buildSplApproveDelegateUnsigned(params) {
  const connection2 = getSolanaConnection();
  const userPubkey = new PublicKey(params.userPubkey);
  const mint = new PublicKey(params.tokenMint);
  const delegatePubkey = new PublicKey(params.delegate);
  const userAta = getAssociatedTokenAddressSync(mint, userPubkey);
  const tx = new Transaction();
  const amount = BigInt(params.amount);
  const approveIx = createApproveInstruction(userAta, delegatePubkey, userPubkey, Number(amount));
  tx.add(approveIx);
  const memoText = `approve:${params.orderId || "approve_" + Date.now()}`;
  const memoIx = { keys: [], programId: MEMO_PROGRAM_ID, data: Buffer.from(memoText, "utf8") };
  tx.add(memoIx);
  const { blockhash } = await connection2.getLatestBlockhash("finalized");
  tx.recentBlockhash = blockhash;
  tx.feePayer = userPubkey;
  const serialized = tx.serialize({ requireAllSignatures: false, verifySignatures: false });
  const b64 = Buffer.from(serialized).toString("base64");
  const phantomUrl = buildPhantomDeeplink({ b64, orderId: params.orderId || "approve_" + Date.now() });
  const qrDataUrl = await QRCode.toDataURL(phantomUrl);
  return {
    orderId: params.orderId || `approve_${Date.now()}`,
    memoText,
    unsignedTxB64: b64,
    phantomUrl,
    qrDataUrl,
    expiresAt: new Date(Date.now() + 5 * 60 * 1e3).toISOString()
  };
}
async function buildSplTransferFromDelegateUnsigned(params) {
  const connection2 = getSolanaConnection();
  const userPubkey = new PublicKey(params.userPubkey);
  const merchantPubkey = new PublicKey(params.merchant);
  const mint = new PublicKey(params.tokenMint);
  const delegatePubkey = new PublicKey(params.delegatePubkey);
  const userAta = getAssociatedTokenAddressSync(mint, userPubkey);
  const merchantAta = getAssociatedTokenAddressSync(mint, merchantPubkey);
  const tx = new Transaction();
  try {
    await getAccount(connection2, merchantAta);
  } catch (error) {
    if (error instanceof TokenAccountNotFoundError) {
      tx.add(createAssociatedTokenAccountInstruction(delegatePubkey, merchantAta, merchantPubkey, mint));
    }
  }
  const amount = BigInt(params.tokenAmount);
  tx.add(createTransferInstruction(userAta, merchantAta, delegatePubkey, amount));
  const memoText = `delegate_transfer:${params.orderId || "dt_" + Date.now()}`;
  const memoIx = { keys: [], programId: MEMO_PROGRAM_ID, data: Buffer.from(memoText, "utf8") };
  tx.add(memoIx);
  const { blockhash } = await connection2.getLatestBlockhash("finalized");
  tx.recentBlockhash = blockhash;
  tx.feePayer = delegatePubkey;
  const serialized = tx.serialize({ requireAllSignatures: false, verifySignatures: false });
  const b64 = Buffer.from(serialized).toString("base64");
  const phantomUrl = buildPhantomDeeplink({ b64, orderId: params.orderId || `dt_${Date.now()}` });
  const qrDataUrl = await QRCode.toDataURL(phantomUrl);
  return {
    orderId: params.orderId || `dt_${Date.now()}`,
    memoText,
    unsignedTxB64: b64,
    phantomUrl,
    qrDataUrl,
    expiresAt: new Date(Date.now() + 5 * 60 * 1e3).toISOString()
  };
}
async function broadcastSignedTransaction(b64SignedTx) {
  const connection2 = getSolanaConnection();
  const buf = Buffer.from(b64SignedTx, "base64");
  const sig = await connection2.sendRawTransaction(buf, { skipPreflight: false, preflightCommitment: "confirmed" });
  await connection2.confirmTransaction(sig, "finalized");
  return { signature: sig };
}
async function getTransactionBySignature(signature) {
  const connection2 = getSolanaConnection();
  return await connection2.getTransaction(signature, {
    maxSupportedTransactionVersion: 0,
    commitment: "finalized"
  });
}
function extractMemoFromTransaction(tx) {
  try {
    const ixs = tx?.transaction?.message?.instructions || [];
    for (const ix of ixs) {
      if (ix?.programId?.toBase58?.() === MEMO_PROGRAM_ID.toBase58()) {
        if (typeof ix.data === "string") {
          try {
            const buf = Buffer.from(ix.data, "base64");
            return buf.toString("utf8");
          } catch {
          }
          return ix.data;
        } else if (ix.data instanceof Buffer) {
          return ix.data.toString("utf8");
        }
      }
    }
    return null;
  } catch {
    return null;
  }
}
var MEMO_PROGRAM_ID;
var init_solana = __esm({
  "server/solana.ts"() {
    "use strict";
    MEMO_PROGRAM_ID = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
  }
});

// server/solana-routes.ts
var solana_routes_exports = {};
__export(solana_routes_exports, {
  registerSolanaRoutes: () => registerSolanaRoutes
});
import { z as z2 } from "zod";
import { PublicKey as PublicKey2 } from "@solana/web3.js";
import { getAssociatedTokenAddressSync as getAssociatedTokenAddressSync2 } from "@solana/spl-token";
function getEnv3(name, fallback = "") {
  return process.env[name] ?? fallback;
}
function getNumberEnv(name, fallback) {
  const v = process.env[name];
  if (!v) return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}
async function verifyOnChain(opts) {
  try {
    const tx = await getTransactionBySignature(opts.signature);
    if (!tx) return { ok: false, reason: "transaction_not_found" };
    if (tx.meta?.err) return { ok: false, reason: "transaction_error", tx };
    const memo = extractMemoFromTransaction(tx);
    if (!memo || memo !== opts.memoText) {
      return { ok: false, reason: "memo_mismatch", tx };
    }
    const merchantKey = new PublicKey2(opts.merchant);
    if (opts.assetType === "SOL") {
      if (!opts.amountLamports) return { ok: false, reason: "missing_amount_lamports", tx };
      const message = tx.transaction.message;
      const ak = (message.accountKeys || message.getAccountKeys?.()).map((k) => k.toBase58 ? k.toBase58() : String(k));
      const idx = ak.findIndex((k) => k === merchantKey.toBase58());
      if (idx === -1) return { ok: false, reason: "merchant_not_in_accounts", tx };
      const pre = tx.meta?.preBalances?.[idx];
      const post = tx.meta?.postBalances?.[idx];
      if (typeof pre !== "number" || typeof post !== "number") return { ok: false, reason: "balance_info_missing", tx };
      const delta = post - pre;
      if (delta < opts.amountLamports) {
        return { ok: false, reason: "sol_amount_mismatch", tx };
      }
    } else if (opts.assetType === "SPL") {
      if (!opts.tokenMint || !opts.tokenAmount) return { ok: false, reason: "missing_spl_params", tx };
      const tokenMintKey = new PublicKey2(opts.tokenMint);
      const merchantAta = getAssociatedTokenAddressSync2(tokenMintKey, merchantKey);
      const expectedAmount = BigInt(opts.tokenAmount);
      const tokenBalances = tx.meta?.postTokenBalances || [];
      const preTokenBalances = tx.meta?.preTokenBalances || [];
      const postBalance = tokenBalances.find(
        (b) => b.owner === merchantKey.toBase58() && b.mint === tokenMintKey.toBase58()
      );
      const preBalance = preTokenBalances.find(
        (b) => b.owner === merchantKey.toBase58() && b.mint === tokenMintKey.toBase58()
      );
      if (!postBalance) return { ok: false, reason: "merchant_token_account_not_found", tx };
      const preAmount = preBalance ? BigInt(preBalance.uiTokenAmount.amount) : BigInt(0);
      const postAmount = BigInt(postBalance.uiTokenAmount.amount);
      const delta = postAmount - preAmount;
      if (delta < expectedAmount) {
        return { ok: false, reason: "spl_amount_mismatch", tx };
      }
    } else {
      return { ok: false, reason: "invalid_asset_type", tx };
    }
    return { ok: true, tx };
  } catch (e) {
    logger.error("verifyOnChain error", { error: e?.message });
    return { ok: false, reason: "verification_exception" };
  }
}
function registerSolanaRoutes(app) {
  app.post("/api/solana/payment-intents", authenticateApiKey(1), async (req, res) => {
    try {
      const parse = CreateIntentBody.safeParse(req.body);
      if (!parse.success) {
        return res.status(400).json({ error: "invalid_request", details: parse.error.flatten() });
      }
      const body = parse.data;
      const merchant = body.merchant || getEnv3("MERCHANT_SOL_ADDRESS");
      if (!merchant) {
        return res.status(400).json({ error: "missing_merchant", message: "Provide merchant in body or set MERCHANT_SOL_ADDRESS" });
      }
      const assetType = body.amountLamports ? "SOL" : "SPL";
      if (body.userPubkey) {
        const build = await createPaymentIntentUnsigned({
          assetType,
          amountLamports: body.amountLamports,
          tokenMint: body.tokenMint,
          tokenAmount: body.tokenAmount,
          merchant,
          userPubkey: body.userPubkey,
          orderId: body.orderId,
          memoText: body.memo || `order:${body.orderId}`
        });
        const expiresAt2 = new Date(build.expiresAt);
        await PaymentOrder.findOneAndUpdate(
          { orderId: build.orderId },
          {
            orderId: build.orderId,
            status: "pending",
            assetType,
            amountLamports: body.amountLamports,
            tokenMint: body.tokenMint,
            tokenAmount: body.tokenAmount,
            merchant,
            userPubkey: body.userPubkey,
            memo: build.memoText,
            unsignedTxB64: build.unsignedTxB64,
            expiresAt: expiresAt2
          },
          { upsert: true, new: true }
        );
        return res.status(201).json({
          orderId: build.orderId,
          phantomUrl: build.phantomUrl,
          qrDataUrl: build.qrDataUrl,
          unsignedTxB64: build.unsignedTxB64,
          expiresAt: build.expiresAt
        });
      }
      const payLink = await buildSolanaPayLink({
        merchant,
        assetType,
        amountLamports: body.amountLamports,
        tokenMint: body.tokenMint,
        tokenAmount: body.tokenAmount,
        orderId: body.orderId
      });
      const expiresAt = new Date(payLink.expiresAt);
      await PaymentOrder.findOneAndUpdate(
        { orderId: body.orderId || payLink.reference },
        {
          orderId: body.orderId || payLink.reference,
          status: "pending",
          assetType,
          amountLamports: body.amountLamports,
          tokenMint: body.tokenMint,
          tokenAmount: body.tokenAmount,
          merchant,
          userPubkey: null,
          memo: body.memo || `order:${body.orderId || payLink.reference}`,
          reference: payLink.reference,
          unsignedTxB64: null,
          expiresAt
        },
        { upsert: true, new: true }
      );
      return res.status(201).json({
        orderId: body.orderId || payLink.reference,
        reference: payLink.reference,
        solanaPayUrl: payLink.solanaPayUrl,
        qrDataUrl: payLink.qrDataUrl,
        expiresAt: payLink.expiresAt
      });
    } catch (e) {
      logger.error("create payment intent failed", { error: e?.message });
      return res.status(500).json({ error: "internal_error" });
    }
  });
  app.get("/api/solana/phantom-callback", async (req, res) => {
    try {
      const orderId = String(req.query.order || "");
      const signedTransaction = req.query.signedTransaction ? String(req.query.signedTransaction) : void 0;
      const signature = req.query.signature ? String(req.query.signature) : void 0;
      const errorCode = req.query.errorCode ? String(req.query.errorCode) : void 0;
      if (!orderId) {
        return res.status(400).send("Missing order");
      }
      const order = await PaymentOrder.findOne({ orderId });
      if (!order) return res.status(404).send("Order not found");
      if (errorCode) {
        await PaymentOrder.updateOne({ orderId }, { $set: { status: "failed" } });
        return res.status(400).send(`Wallet error: ${errorCode}`);
      }
      let txSig = signature;
      if (!txSig && signedTransaction) {
        try {
          const resSend = await broadcastSignedTransaction(signedTransaction);
          txSig = resSend.signature;
          await PaymentOrder.updateOne({ orderId }, { $set: { signature: txSig, status: "submitted" } });
        } catch (e) {
          logger.error("broadcast failed", { error: e?.message });
          await PaymentOrder.updateOne({ orderId }, { $set: { status: "failed" } });
          return res.status(500).send("Broadcast failed");
        }
      }
      if (!txSig) {
        return res.status(202).send("No signature provided yet");
      }
      const verify = await verifyOnChain({
        signature: txSig,
        merchant: order.merchant,
        assetType: order.assetType,
        amountLamports: order.amountLamports,
        tokenMint: order.tokenMint,
        tokenAmount: order.tokenAmount,
        memoText: order.memo || `order:${orderId}`
      });
      if (verify.ok) {
        await PaymentOrder.updateOne({ orderId }, { $set: { status: "confirmed", signature: txSig } });
        const memoText = order.memo || `order:${orderId}`;
        if (memoText.startsWith("subscription:")) {
          const subscriptionId = memoText.split(":")[1];
          if (subscriptionId) {
            const sub = await Subscription.findOne({ subscriptionId });
            if (sub && sub.status === "pending") {
              const activeUntil = new Date(Date.now() + 30 * 24 * 60 * 60 * 1e3);
              sub.status = "active";
              sub.activeUntil = activeUntil;
              const monthlyCredits = getNumberEnv("SUBSCRIPTION_MONTHLY_CREDITS", 0);
              if (monthlyCredits > 0 && !sub.creditedAt) {
                await ApiKey.findByIdAndUpdate(sub.apiKeyId, { $inc: { credits: monthlyCredits } }).exec();
                sub.creditedAt = /* @__PURE__ */ new Date();
              }
              await sub.save();
            }
          }
        }
      } else {
        await PaymentOrder.updateOne({ orderId }, { $set: { status: "failed", signature: txSig } });
      }
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.status(200).send(`<!doctype html><html><head><meta name=viewport content='width=device-width, initial-scale=1'>
<title>Payment ${verify.ok ? "Success" : "Issue"}</title></head><body style='font-family:system-ui;padding:24px'>
<h2>${verify.ok ? "\u2705 Payment received" : "\u26A0\uFE0F Payment issue"}</h2>
<p>Order: ${orderId}</p>
<p>Signature: ${txSig}</p>
${verify.ok ? "<p>You can close this window.</p>" : `<p>Reason: ${verify.reason || "unknown"}</p>`}
<script>setTimeout(()=>{ if (window?.close) try{window.close()}catch(e){} }, 1500)</script>
</body></html>`);
    } catch (e) {
      logger.error("phantom-callback error", { error: e?.message });
      return res.status(500).send("Internal error");
    }
  });
  app.get("/api/solana/payment-intents/:orderId", authenticateApiKey(0.1), async (req, res) => {
    try {
      const orderId = req.params.orderId;
      const order = await PaymentOrder.findOne({ orderId });
      if (!order) return res.status(404).json({ error: "not_found" });
      return res.json({
        orderId: order.orderId,
        status: order.status,
        signature: order.signature || null,
        assetType: order.assetType,
        amountLamports: order.amountLamports,
        tokenMint: order.tokenMint || null,
        tokenAmount: order.tokenAmount || null,
        merchant: order.merchant,
        memo: order.memo || null,
        expiresAt: order.expiresAt
      });
    } catch (e) {
      return res.status(500).json({ error: "internal_error" });
    }
  });
  app.post("/api/solana/payment-intents/:orderId/regenerate", authenticateApiKey(1), async (req, res) => {
    try {
      const orderId = req.params.orderId;
      const order = await PaymentOrder.findOne({ orderId });
      if (!order) return res.status(404).json({ error: "not_found" });
      if (order.status !== "pending" && order.status !== "expired") {
        return res.status(400).json({ error: "cannot_regenerate", message: "Order must be pending or expired" });
      }
      if (!order.userPubkey) {
        const payLink = await buildSolanaPayLink({
          merchant: order.merchant,
          assetType: order.assetType,
          amountLamports: order.amountLamports ?? void 0,
          tokenMint: order.tokenMint ?? void 0,
          tokenAmount: order.tokenAmount ?? void 0,
          orderId: order.orderId
        });
        const expiresAt2 = new Date(payLink.expiresAt);
        await PaymentOrder.updateOne(
          { orderId },
          { $set: { status: "pending", reference: payLink.reference, expiresAt: expiresAt2 } }
        );
        return res.json({
          orderId,
          reference: payLink.reference,
          solanaPayUrl: payLink.solanaPayUrl,
          qrDataUrl: payLink.qrDataUrl,
          expiresAt: payLink.expiresAt,
          regenerated: true
        });
      }
      const build = await createPaymentIntentUnsigned({
        assetType: order.assetType,
        amountLamports: order.amountLamports,
        tokenMint: order.tokenMint,
        tokenAmount: order.tokenAmount,
        merchant: order.merchant,
        userPubkey: order.userPubkey,
        orderId: order.orderId,
        memoText: order.memo || `order:${order.orderId}`
      });
      const expiresAt = new Date(build.expiresAt);
      await PaymentOrder.updateOne(
        { orderId },
        {
          $set: {
            status: "pending",
            unsignedTxB64: build.unsignedTxB64,
            expiresAt
          }
        }
      );
      return res.json({
        orderId: build.orderId,
        phantomUrl: build.phantomUrl,
        qrDataUrl: build.qrDataUrl,
        unsignedTxB64: build.unsignedTxB64,
        expiresAt: build.expiresAt,
        regenerated: true
      });
    } catch (e) {
      logger.error("regenerate payment intent failed", { error: e?.message });
      return res.status(500).json({ error: "internal_error" });
    }
  });
  app.post("/api/solana/verify", authenticateApiKey(0.1), async (req, res) => {
    try {
      const VerifyBody = z2.object({
        signature: z2.string().min(32),
        orderId: z2.string().min(6).optional(),
        merchant: z2.string().min(32).optional(),
        // For SOL
        amountLamports: z2.number().int().positive().optional(),
        // For SPL
        tokenMint: z2.string().min(32).optional(),
        tokenAmount: z2.string().regex(/^\d+$/).optional()
      });
      const parsed = VerifyBody.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: "invalid_request" });
      const { signature, orderId } = parsed.data;
      let merchant = parsed.data.merchant || getEnv3("MERCHANT_SOL_ADDRESS");
      let amountLamports = parsed.data.amountLamports;
      let tokenMint = parsed.data.tokenMint;
      let tokenAmount = parsed.data.tokenAmount;
      let memoText = orderId ? `order:${orderId}` : "";
      let assetType = "SOL";
      if (orderId) {
        const order = await PaymentOrder.findOne({ orderId });
        if (order) {
          merchant = order.merchant;
          assetType = order.assetType;
          amountLamports = order.amountLamports;
          tokenMint = order.tokenMint;
          tokenAmount = order.tokenAmount;
          memoText = order.memo || `order:${orderId}`;
        }
      } else {
        assetType = amountLamports ? "SOL" : "SPL";
      }
      if (!merchant || !memoText) {
        return res.status(400).json({ error: "missing_params" });
      }
      if (assetType === "SOL" && !amountLamports || assetType === "SPL" && (!tokenMint || !tokenAmount)) {
        return res.status(400).json({ error: "missing_asset_params" });
      }
      if (signature) {
        const verify = await verifyOnChain({
          signature,
          merchant,
          assetType,
          amountLamports,
          tokenMint,
          tokenAmount,
          memoText
        });
        return res.json({ ok: verify.ok, reason: verify.reason, signature });
      }
      if (orderId) {
        const order = await PaymentOrder.findOne({ orderId });
        if (order && order.reference) {
          const sigs = await findSignaturesForAddress(order.reference, 20);
          for (const s of sigs) {
            try {
              const candidate = s.signature;
              const verify = await verifyOnChain({ signature: candidate, merchant, assetType, amountLamports, tokenMint, tokenAmount, memoText });
              if (verify.ok) {
                await PaymentOrder.updateOne({ orderId }, { $set: { status: "confirmed", signature: candidate } });
                return res.json({ ok: true, signature: candidate });
              }
            } catch (e) {
            }
          }
          return res.json({ ok: false, reason: "not_found_yet" });
        }
      }
      return res.status(400).json({ error: "missing_signature_or_reference" });
    } catch (e) {
      return res.status(500).json({ error: "internal_error" });
    }
  });
}
var CreateIntentBody;
var init_solana_routes = __esm({
  "server/solana-routes.ts"() {
    "use strict";
    init_security();
    init_schema_mongodb();
    init_solana();
    init_auth();
    CreateIntentBody = z2.object({
      orderId: z2.string().min(6).max(64),
      // Make merchant optional for this endpoint (fallback to env)
      merchant: z2.string().min(32).optional(),
      userPubkey: z2.string().min(32).optional(),
      memo: z2.string().max(128).optional(),
      // SOL
      amountLamports: z2.number().int().positive().optional(),
      // SPL
      tokenMint: z2.string().min(32).optional(),
      tokenAmount: z2.string().regex(/^\d+$/).optional()
    }).refine((d) => {
      const sol = typeof d.amountLamports === "number" && !d.tokenMint && !d.tokenAmount;
      const spl = !d.amountLamports && !!d.tokenMint && !!d.tokenAmount;
      return sol || spl;
    }, {
      message: "Provide either amountLamports for SOL or tokenMint+tokenAmount for SPL"
    });
  }
});

// server/billing-routes.ts
var billing_routes_exports = {};
__export(billing_routes_exports, {
  registerBillingRoutes: () => registerBillingRoutes
});
import { v4 as uuidv42 } from "uuid";
function getEnv4(name, fallback = "") {
  return process.env[name] ?? fallback;
}
function getNumberEnv2(name, fallback) {
  const v = process.env[name];
  if (!v) return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}
function registerBillingRoutes(app) {
  app.post("/api/billing/solana/subscribe", authenticateApiKey(0), async (req, res) => {
    try {
      const apiKey = req.apiKey;
      const { userPubkey, plan } = req.body || {};
      if (!userPubkey || typeof userPubkey !== "string" || userPubkey.length < 32) {
        return res.status(400).json({ error: "invalid_request", message: "userPubkey (Solana wallet) is required" });
      }
      const resolvedPlan = plan === "basic" || plan === "pro" ? plan : "pro";
      const priceUsd = getNumberEnv2("SUBSCRIPTION_PRICE_USD", 30);
      const usdcDecimals = getNumberEnv2("SOLANA_USDC_DECIMALS", 6);
      const tokenAmount = BigInt(Math.round(priceUsd * Math.pow(10, usdcDecimals))).toString();
      const merchant = getEnv4("MERCHANT_SOL_ADDRESS");
      const usdcMint = getEnv4("SOLANA_USDC_MINT_ADDRESS");
      if (!merchant) {
        return res.status(500).json({ error: "config_error", message: "MERCHANT_SOL_ADDRESS not configured" });
      }
      if (!usdcMint) {
        return res.status(500).json({ error: "config_error", message: "SOLANA_USDC_MINT_ADDRESS not configured" });
      }
      const subscriptionId = `sub_${uuidv42().replace(/-/g, "")}`;
      const orderId = subscriptionId;
      const build = await createPaymentIntentUnsigned({
        assetType: "SPL",
        tokenMint: usdcMint,
        tokenAmount,
        merchant,
        userPubkey,
        orderId,
        memoText: `subscription:${subscriptionId}`
      });
      await Subscription.create({
        subscriptionId,
        apiKeyId: apiKey._id,
        userId: apiKey.userId,
        plan: resolvedPlan,
        priceUsd,
        chain: "solana",
        asset: "SPL",
        tokenMint: usdcMint,
        orderId,
        status: "pending"
      });
      return res.status(201).json({
        subscriptionId,
        orderId: build.orderId,
        phantomUrl: build.phantomUrl,
        qrDataUrl: build.qrDataUrl,
        unsignedTxB64: build.unsignedTxB64,
        expiresAt: build.expiresAt
      });
    } catch (e) {
      return res.status(500).json({ error: "internal_error", message: e?.message || "unexpected" });
    }
  });
  app.get("/api/billing/subscriptions/:subscriptionId", authenticateApiKey(0), async (req, res) => {
    try {
      const { subscriptionId } = req.params;
      const sub = await Subscription.findOne({ subscriptionId });
      if (!sub) return res.status(404).json({ error: "not_found" });
      if (req.apiKey && sub.apiKeyId !== req.apiKey._id) {
        return res.status(403).json({ error: "forbidden" });
      }
      let issuedApiKey = void 0;
      if (sub.status === "pending" && sub.orderId) {
        const order = await PaymentOrder.findOne({ orderId: sub.orderId });
        if (order && order.status === "confirmed") {
          const activeUntil = new Date(Date.now() + 30 * 24 * 60 * 60 * 1e3);
          sub.status = "active";
          sub.activeUntil = activeUntil;
          const monthlyCredits = getNumberEnv2("SUBSCRIPTION_MONTHLY_CREDITS", 0);
          if (monthlyCredits > 0 && !sub.creditedAt) {
            await ApiKey.findByIdAndUpdate(sub.apiKeyId, { $inc: { credits: monthlyCredits } }).exec();
            sub.creditedAt = /* @__PURE__ */ new Date();
          }
          if (sub.userId && !sub.issuedApiKeyId) {
            try {
              const newKey = await storage.createApiKey({ userId: sub.userId, name: `subscription_${sub.subscriptionId}` });
              sub.issuedApiKeyId = newKey._id;
              issuedApiKey = { id: newKey._id, key: newKey.key };
            } catch (e) {
              console.error("Failed to create issued API key for subscription activation", e);
            }
          }
          await sub.save();
        }
      }
      return res.json({
        subscriptionId: sub.subscriptionId,
        status: sub.status,
        activeUntil: sub.activeUntil || null,
        plan: sub.plan,
        chain: sub.chain,
        asset: sub.asset,
        orderId: sub.orderId || null,
        // If we just created an issued API key, include the plaintext key once (for copy-only UI). Otherwise include only id.
        issuedApiKey: issuedApiKey ? issuedApiKey : sub.issuedApiKeyId ? { id: sub.issuedApiKeyId } : void 0
      });
    } catch (e) {
      return res.status(500).json({ error: "internal_error" });
    }
  });
}
var init_billing_routes = __esm({
  "server/billing-routes.ts"() {
    "use strict";
    init_auth();
    init_schema_mongodb();
    init_storage();
    init_solana();
  }
});

// shared/recurring-subscription-schema.ts
import mongoose3, { Schema as Schema2 } from "mongoose";
import { z as z3 } from "zod";
var recurringSubscriptionSchema, subscriptionEventSchema, RecurringSubscription, SubscriptionEvent, createRecurringSubscriptionSchema, connectWalletSchema, updateRecurringSubscriptionSchema;
var init_recurring_subscription_schema = __esm({
  "shared/recurring-subscription-schema.ts"() {
    "use strict";
    recurringSubscriptionSchema = new Schema2({
      subscriptionId: { type: String, required: true, unique: true, index: true },
      userId: { type: String, required: false, index: true },
      apiKeyId: { type: String, required: true, index: true, ref: "ApiKey" },
      plan: { type: String, required: true, index: true, maxlength: 100 },
      // flexible plan name - any string
      priceUsd: { type: Number, required: true },
      chain: { type: String, enum: ["solana"], default: "solana", required: true },
      asset: { type: String, enum: ["SOL", "SPL"], required: true },
      tokenMint: { type: String, required: false, index: true },
      // Status and recurring fields
      status: {
        type: String,
        enum: ["pending_wallet_connection", "wallet_connected", "active", "past_due", "suspended", "canceled", "expired"],
        default: "pending_wallet_connection",
        index: true
      },
      isRecurring: { type: Boolean, default: true },
      walletAddress: { type: String, required: false, index: true },
      walletConnectionQR: { type: String, required: false },
      walletConnectionDeeplink: { type: String, required: false },
      // Billing cycle
      billingInterval: { type: String, enum: ["monthly", "yearly"], default: "monthly", index: true },
      nextBillingDate: { type: Date, required: false, index: true },
      lastPaymentDate: { type: Date, required: false },
      lastPaymentSignature: { type: String, required: false },
      currentPeriodStart: { type: Date, required: false },
      currentPeriodEnd: { type: Date, required: false },
      // Payment failure handling
      failedPaymentAttempts: { type: Number, default: 0 },
      maxFailedAttempts: { type: Number, default: 3 },
      gracePeriodDays: { type: Number, default: 7 },
      gracePeriodUntil: { type: Date, required: false },
      // Lifecycle
      trialEndDate: { type: Date, required: false },
      canceledAt: { type: Date, required: false },
      cancellationReason: { type: String, required: false },
      cancelAtPeriodEnd: { type: Boolean, default: false },
      // Integration
      webhookUrl: { type: String, required: false },
      webhookSecret: { type: String, required: false },
      relayerSecretEncrypted: { type: String, required: false },
      relayerSecretSetAt: { type: Date, required: false },
      metadata: { type: Schema2.Types.Mixed, default: {} },
      // Optional merchant relayer URL to which unsigned delegate-transfer intents are POSTed
      relayerUrl: { type: String, required: false },
      // Auto-renewal
      autoRenew: { type: Boolean, default: true },
      pausedAt: { type: Date, required: false },
      pauseReason: { type: String, required: false },
      // Delegation (SPL token approval) details for merchants
      delegatePubkey: { type: String, required: false },
      // delegate/approved authority pubkey (merchant)
      delegateAllowance: { type: String, required: false },
      // allowance in token base units (string to avoid precision issues)
      delegateApprovedAt: { type: Date, required: false },
      delegateApprovalSignature: { type: String, required: false }
    }, { timestamps: true });
    recurringSubscriptionSchema.index({ apiKeyId: 1, status: 1 });
    recurringSubscriptionSchema.index({ nextBillingDate: 1, status: 1 });
    recurringSubscriptionSchema.index({ walletAddress: 1, status: 1 });
    recurringSubscriptionSchema.index({ status: 1, gracePeriodUntil: 1 });
    recurringSubscriptionSchema.index({ status: 1, nextBillingDate: 1, autoRenew: 1 });
    recurringSubscriptionSchema.index({ cancelAtPeriodEnd: 1, currentPeriodEnd: 1 });
    subscriptionEventSchema = new Schema2({
      subscriptionId: { type: String, required: true, index: true },
      eventType: {
        type: String,
        enum: ["created", "wallet_connected", "activated", "payment_succeeded", "payment_failed", "renewed", "canceled", "suspended", "expired", "reactivated"],
        required: true,
        index: true
      },
      eventData: { type: Schema2.Types.Mixed, default: {} },
      transactionSignature: { type: String, required: false, index: true }
    }, { timestamps: true });
    subscriptionEventSchema.index({ subscriptionId: 1, createdAt: -1 });
    subscriptionEventSchema.index({ eventType: 1, createdAt: -1 });
    RecurringSubscription = mongoose3.models.RecurringSubscription || mongoose3.model("RecurringSubscription", recurringSubscriptionSchema);
    SubscriptionEvent = mongoose3.models.SubscriptionEvent || mongoose3.model("SubscriptionEvent", subscriptionEventSchema);
    createRecurringSubscriptionSchema = z3.object({
      plan: z3.string().min(1).max(100),
      // flexible plan name - any string
      priceUsd: z3.number().min(0.01).max(99999),
      // price in USD - developer specified
      billingInterval: z3.enum(["monthly", "yearly"]).default("monthly"),
      webhookUrl: z3.string().url().optional(),
      metadata: z3.record(z3.any()).optional(),
      trialDays: z3.number().min(0).max(365).optional()
      // trial period in days - up to 1 year
    });
    connectWalletSchema = z3.object({
      walletAddress: z3.string().min(32).max(44),
      // Solana wallet address
      signature: z3.string().min(64),
      // signature proof of wallet ownership
      message: z3.string()
      // message that was signed
    });
    updateRecurringSubscriptionSchema = z3.object({
      plan: z3.string().min(1).max(100).optional(),
      // flexible plan name - any string
      priceUsd: z3.number().min(0.01).max(99999).optional(),
      // price in USD - developer specified
      autoRenew: z3.boolean().optional(),
      webhookUrl: z3.string().url().optional(),
      metadata: z3.record(z3.any()).optional(),
      cancelAtPeriodEnd: z3.boolean().optional()
    });
  }
});

// server/phantom-wallet-utils.ts
import { PublicKey as PublicKey3, SystemProgram as SystemProgram2, Transaction as Transaction2 } from "@solana/web3.js";
import { createTransferInstruction as createTransferInstruction2, getAssociatedTokenAddressSync as getAssociatedTokenAddressSync3, createAssociatedTokenAccountInstruction as createAssociatedTokenAccountInstruction2, getAccount as getAccount2, TokenAccountNotFoundError as TokenAccountNotFoundError2 } from "@solana/spl-token";
import QRCode2 from "qrcode";
import { v4 as uuidv43 } from "uuid";
import crypto2 from "crypto";
import nacl from "tweetnacl";
function getEnv5(name, fallback = "") {
  return process.env[name] ?? fallback;
}
function generateWalletConnectionRequest(subscriptionId) {
  const nonce = crypto2.randomBytes(16).toString("hex");
  const timestamp = Date.now();
  const dappUrl = getEnv5("PHANTOM_DAPP_URL", "http://localhost:3000");
  const dappTitle = getEnv5("PHANTOM_DAPP_TITLE", "BlockSub Recurring Payments");
  const message = `Connect wallet for recurring subscription

Subscription ID: ${subscriptionId}
DApp: ${dappTitle}
Nonce: ${nonce}
Timestamp: ${timestamp}`;
  return {
    subscriptionId,
    message,
    nonce,
    timestamp,
    dappUrl,
    dappTitle,
    dappIcon: getEnv5("PHANTOM_DAPP_ICON", "")
  };
}
async function generateWalletConnectionQR(connectionRequest) {
  const baseUrl = getEnv5("PHANTOM_CALLBACK_BASE_URL", "http://localhost:3000");
  const connectionUrl = `${baseUrl}/api/recurring-subscriptions/phantom/connect-callback`;
  const params = new URLSearchParams({
    subscription_id: connectionRequest.subscriptionId,
    message: connectionRequest.message,
    nonce: connectionRequest.nonce,
    timestamp: connectionRequest.timestamp.toString(),
    dapp_url: connectionRequest.dappUrl,
    dapp_title: connectionRequest.dappTitle,
    callback_url: connectionUrl
  });
  if (connectionRequest.dappIcon) {
    params.append("dapp_icon", connectionRequest.dappIcon);
  }
  const deeplink = `https://phantom.app/ul/v1/connect?${params.toString()}`;
  const qrCodeDataUrl = String(await QRCode2.toDataURL(deeplink, {
    errorCorrectionLevel: "M",
    type: "image/png",
    quality: 0.92,
    margin: 1,
    color: {
      dark: "#000000",
      light: "#FFFFFF"
    },
    width: 256
  }));
  const expiresAt = new Date(Date.now() + 10 * 60 * 1e3);
  return {
    qrCodeDataUrl,
    deeplink,
    connectionUrl,
    message: connectionRequest.message,
    nonce: connectionRequest.nonce,
    expiresAt
  };
}
function verifyWalletConnection(publicKey, signature, message) {
  try {
    const publicKeyObj = new PublicKey3(publicKey);
    const signatureBuffer = Buffer.from(signature, "base64");
    const messageBuffer = Buffer.from(message, "utf8");
    if (signatureBuffer.length !== 64) {
      logger.error("Invalid signature length", { length: signatureBuffer.length });
      return false;
    }
    const publicKeyBytes = publicKeyObj.toBytes();
    const isValid = nacl.sign.detached.verify(
      messageBuffer,
      signatureBuffer,
      publicKeyBytes
    );
    if (!isValid) {
      logger.warn("Signature verification failed", {
        publicKey: publicKey.substring(0, 8) + "...",
        messageLength: message.length
      });
    }
    return isValid;
  } catch (error) {
    logger.error("Wallet signature verification failed", {
      error: error instanceof Error ? error.message : String(error),
      publicKey: publicKey.substring(0, 8) + "..."
    });
    return false;
  }
}
async function createRecurringPaymentIntent(params) {
  const connection2 = getSolanaConnection();
  const paymentId = `pmt_${uuidv43().replace(/-/g, "")}`;
  const merchant = getEnv5("MERCHANT_SOL_ADDRESS");
  if (!merchant) {
    throw new Error("MERCHANT_SOL_ADDRESS not configured");
  }
  const userPubkey = new PublicKey3(params.walletAddress);
  const merchantPubkey = new PublicKey3(merchant);
  const memo = `recurring:${params.subscriptionId}:${params.billingCycle}:${paymentId}`;
  const tx = new Transaction2();
  if (params.assetType === "SOL") {
    if (!params.amountLamports) {
      throw new Error("amountLamports is required for SOL payments");
    }
    tx.add(
      SystemProgram2.transfer({
        fromPubkey: userPubkey,
        toPubkey: merchantPubkey,
        lamports: params.amountLamports
      })
    );
  } else if (params.assetType === "SPL") {
    if (!params.tokenMint || !params.tokenAmount) {
      throw new Error("tokenMint and tokenAmount are required for SPL payments");
    }
    const tokenMintPubkey = new PublicKey3(params.tokenMint);
    const amount = BigInt(params.tokenAmount);
    const userAta = getAssociatedTokenAddressSync3(tokenMintPubkey, userPubkey);
    const merchantAta = getAssociatedTokenAddressSync3(tokenMintPubkey, merchantPubkey);
    try {
      await getAccount2(connection2, merchantAta);
    } catch (error) {
      if (error instanceof TokenAccountNotFoundError2) {
        tx.add(
          createAssociatedTokenAccountInstruction2(
            userPubkey,
            // payer
            merchantAta,
            // ata
            merchantPubkey,
            // owner
            tokenMintPubkey
            // mint
          )
        );
      }
    }
    tx.add(
      createTransferInstruction2(
        userAta,
        // source
        merchantAta,
        // destination
        userPubkey,
        // owner
        amount
        // amount
      )
    );
  } else {
    throw new Error("Invalid assetType. Must be SOL or SPL");
  }
  const memoIx = {
    keys: [],
    programId: MEMO_PROGRAM_ID2,
    data: Buffer.from(memo, "utf8")
  };
  tx.add(memoIx);
  const { blockhash } = await connection2.getLatestBlockhash("finalized");
  tx.recentBlockhash = blockhash;
  tx.feePayer = userPubkey;
  const serialized = tx.serialize({ requireAllSignatures: false, verifySignatures: false });
  const unsignedTxB64 = Buffer.from(serialized).toString("base64");
  const baseUrl = getEnv5("PHANTOM_CALLBACK_BASE_URL", "http://localhost:3000");
  const redirectUrl = `${baseUrl}/api/recurring-subscriptions/phantom/payment-callback?subscription_id=${params.subscriptionId}&payment_id=${paymentId}`;
  const phantomUrl = `https://phantom.app/ul/v1/signTransaction?transaction=${encodeURIComponent(unsignedTxB64)}&redirect_uri=${encodeURIComponent(redirectUrl)}&cluster=${encodeURIComponent(getEnv5("SOLANA_CLUSTER", "devnet"))}&app_url=${encodeURIComponent(getEnv5("PHANTOM_DAPP_URL", "http://localhost:3000"))}&app_title=${encodeURIComponent(getEnv5("PHANTOM_DAPP_TITLE", "BlockSub"))}`;
  const qrDataUrl = String(await QRCode2.toDataURL(phantomUrl, {
    errorCorrectionLevel: "M",
    type: "image/png",
    quality: 0.92,
    margin: 1,
    width: 256
  }));
  const expiresAt = new Date(Date.now() + 30 * 60 * 1e3);
  const dueDate = /* @__PURE__ */ new Date();
  return {
    subscriptionId: params.subscriptionId,
    paymentId,
    amount: params.tokenAmount || params.amountLamports?.toString() || "0",
    amountLamports: params.amountLamports,
    tokenMint: params.tokenMint,
    walletAddress: params.walletAddress,
    merchantAddress: merchant,
    memo,
    dueDate,
    unsignedTxB64,
    phantomUrl,
    qrDataUrl,
    expiresAt
  };
}
function generateConnectionMessage(subscriptionId, plan, priceUsd) {
  const dappTitle = getEnv5("PHANTOM_DAPP_TITLE", "BlockSub");
  const timestamp = (/* @__PURE__ */ new Date()).toISOString();
  return `\u{1F517} Connect Wallet to ${dappTitle}

\u{1F4CB} Subscription Details:
\u2022 Plan: ${plan.charAt(0).toUpperCase() + plan.slice(1)}
\u2022 Price: $${priceUsd}/month
\u2022 ID: ${subscriptionId}

\u23F0 ${timestamp}

By connecting, you authorize recurring monthly payments for this subscription until canceled.

\u{1F512} This message proves wallet ownership and cannot be replayed.`;
}
function calculateNextBillingDate(currentDate, billingInterval, currentPeriodStart) {
  const nextDate = new Date(currentPeriodStart || currentDate);
  if (billingInterval === "monthly") {
    nextDate.setMonth(nextDate.getMonth() + 1);
  } else if (billingInterval === "yearly") {
    nextDate.setFullYear(nextDate.getFullYear() + 1);
  }
  return nextDate;
}
function calculateTrialEndDate(startDate, trialDays) {
  const trialEnd = new Date(startDate);
  trialEnd.setDate(trialEnd.getDate() + trialDays);
  return trialEnd;
}
var MEMO_PROGRAM_ID2;
var init_phantom_wallet_utils = __esm({
  "server/phantom-wallet-utils.ts"() {
    "use strict";
    init_solana();
    init_security();
    MEMO_PROGRAM_ID2 = new PublicKey3("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
  }
});

// server/cache.ts
var cache_exports = {};
__export(cache_exports, {
  default: () => cache_default,
  del: () => del,
  getJson: () => getJson,
  setJson: () => setJson
});
import { createClient } from "redis";
async function getClient() {
  if (client) return client;
  if (!REDIS_URL) return null;
  client = createClient({ url: REDIS_URL });
  client.on("error", (err) => console.error("Redis Client Error", err));
  await client.connect();
  return client;
}
async function getJson(key) {
  try {
    const c = await getClient();
    if (!c) return null;
    const v = await c.get(key);
    if (!v) return null;
    return JSON.parse(v);
  } catch (e) {
    console.warn("Redis getJson failed", e);
    return null;
  }
}
async function setJson(key, value, ttlSeconds = 60) {
  try {
    const c = await getClient();
    if (!c) return;
    await c.set(key, JSON.stringify(value), { EX: ttlSeconds });
  } catch (e) {
    console.warn("Redis setJson failed", e);
  }
}
async function del(key) {
  try {
    const c = await getClient();
    if (!c) return;
    await c.del(key);
  } catch (e) {
    console.warn("Redis del failed", e);
  }
}
var REDIS_URL, client, cache_default;
var init_cache = __esm({
  "server/cache.ts"() {
    "use strict";
    REDIS_URL = process.env.REDIS_URL || "";
    client = null;
    cache_default = { getJson, setJson, del };
  }
});

// server/crypto-utils.ts
var crypto_utils_exports = {};
__export(crypto_utils_exports, {
  computeHmac: () => computeHmac,
  decryptWithMasterKey: () => decryptWithMasterKey,
  encryptWithMasterKey: () => encryptWithMasterKey
});
import crypto3 from "crypto";
function getMasterKey() {
  const key = process.env[MASTER_KEY_ENV];
  if (!key) throw new Error(`${MASTER_KEY_ENV} is not set`);
  if (/^[0-9a-fA-F]+$/.test(key) && key.length === 64) {
    return Buffer.from(key, "hex");
  }
  return Buffer.from(key, "base64");
}
function encryptWithMasterKey(plaintext) {
  const master = getMasterKey();
  if (master.length !== 32) throw new Error("RELAYER_MASTER_KEY must be 32 bytes (base64 or 64-hex)");
  const iv = crypto3.randomBytes(12);
  const cipher = crypto3.createCipheriv("aes-256-gcm", master, iv);
  const encrypted = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString("base64");
}
function decryptWithMasterKey(payloadB64) {
  const master = getMasterKey();
  if (master.length !== 32) throw new Error("RELAYER_MASTER_KEY must be 32 bytes (base64 or 64-hex)");
  const data = Buffer.from(payloadB64, "base64");
  const iv = data.slice(0, 12);
  const tag = data.slice(12, 28);
  const encrypted = data.slice(28);
  const decipher = crypto3.createDecipheriv("aes-256-gcm", master, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString("utf8");
}
function computeHmac(secret, message) {
  return crypto3.createHmac("sha256", secret).update(message).digest("hex");
}
var MASTER_KEY_ENV;
var init_crypto_utils = __esm({
  "server/crypto-utils.ts"() {
    "use strict";
    MASTER_KEY_ENV = "RELAYER_MASTER_KEY";
  }
});

// server/recurring-subscription-routes.ts
var recurring_subscription_routes_exports = {};
__export(recurring_subscription_routes_exports, {
  registerRecurringSubscriptionRoutes: () => registerRecurringSubscriptionRoutes
});
import { v4 as uuidv44 } from "uuid";
function getEnv6(name, fallback = "") {
  return process.env[name] ?? fallback;
}
function getNumberEnv3(name, fallback) {
  const v = process.env[name];
  if (!v) return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}
async function logSubscriptionEvent(subscriptionId, eventType, eventData = {}, transactionSignature) {
  try {
    await SubscriptionEvent.create({
      subscriptionId,
      eventType,
      eventData,
      transactionSignature
    });
  } catch (error) {
    logger.error("Failed to log subscription event", {
      subscriptionId,
      eventType,
      error: error instanceof Error ? error.message : String(error)
    });
  }
}
async function sendWebhook(subscription, eventType, eventData = {}) {
  if (!subscription.webhookUrl) return;
  try {
    const payload = {
      event: eventType,
      subscription_id: subscription.subscriptionId,
      data: {
        ...eventData,
        subscription: {
          id: subscription.subscriptionId,
          status: subscription.status,
          plan: subscription.plan,
          wallet_address: subscription.walletAddress,
          next_billing_date: subscription.nextBillingDate
        }
      },
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    };
    logger.info("Webhook would be sent", { url: subscription.webhookUrl, payload });
  } catch (error) {
    logger.error("Webhook delivery failed", { error: error instanceof Error ? error.message : String(error) });
  }
}
function registerRecurringSubscriptionRoutes(app) {
  app.post("/api/recurring-subscriptions", authenticateApiKey(30), async (req, res) => {
    try {
      const apiKey = req.apiKey;
      const charged = await global.storage.deductCredits(apiKey._id.toString(), 30);
      if (!charged) {
        return res.status(402).json({ error: "insufficient_credits", message: "Not enough credits to create subscription" });
      }
      const parse = createRecurringSubscriptionSchema.safeParse(req.body);
      if (!parse.success) {
        return res.status(400).json({
          error: "invalid_request",
          details: parse.error.flatten()
        });
      }
      const data = parse.data;
      const subscriptionId = `rsub_${uuidv44().replace(/-/g, "")}`;
      const priceUsd = data.priceUsd;
      let trialEndDate;
      if (data.trialDays && data.trialDays > 0) {
        trialEndDate = calculateTrialEndDate(/* @__PURE__ */ new Date(), data.trialDays);
      }
      const subscription = await RecurringSubscription.create({
        subscriptionId,
        userId: apiKey.userId,
        apiKeyId: apiKey._id,
        plan: data.plan,
        priceUsd,
        chain: "solana",
        asset: getEnv6("RECURRING_SUBSCRIPTION_ASSET", "SPL"),
        // default to SPL
        tokenMint: getEnv6("SOLANA_USDC_MINT_ADDRESS"),
        // default to USDC
        status: "pending_wallet_connection",
        isRecurring: true,
        billingInterval: data.billingInterval,
        failedPaymentAttempts: 0,
        maxFailedAttempts: getNumberEnv3("MAX_FAILED_PAYMENT_ATTEMPTS", 3),
        gracePeriodDays: getNumberEnv3("PAYMENT_GRACE_PERIOD_DAYS", 7),
        autoRenew: true,
        cancelAtPeriodEnd: false,
        webhookUrl: data.webhookUrl,
        metadata: data.metadata || {},
        trialEndDate
      });
      const connectionRequest = generateWalletConnectionRequest(subscriptionId);
      const connectionMessage = generateConnectionMessage(subscriptionId, data.plan, priceUsd);
      connectionRequest.message = connectionMessage;
      const walletConnectionQR = await generateWalletConnectionQR(connectionRequest);
      subscription.walletConnectionQR = walletConnectionQR.qrCodeDataUrl;
      subscription.walletConnectionDeeplink = walletConnectionQR.deeplink;
      await subscription.save();
      await logSubscriptionEvent(subscriptionId, "created", {
        plan: data.plan,
        priceUsd,
        billingInterval: data.billingInterval,
        trialDays: data.trialDays
      });
      return res.status(201).json({
        subscription_id: subscriptionId,
        status: subscription.status,
        plan: subscription.plan,
        price_usd: priceUsd,
        billing_interval: data.billingInterval,
        trial_end_date: trialEndDate?.toISOString(),
        wallet_connection: {
          qr_code: walletConnectionQR.qrCodeDataUrl,
          deeplink: walletConnectionQR.deeplink,
          message: connectionRequest.message,
          expires_at: walletConnectionQR.expiresAt.toISOString()
        },
        created_at: subscription.createdAt.toISOString()
      });
    } catch (error) {
      logger.error("Create recurring subscription failed", {
        error: error instanceof Error ? error.message : String(error)
      });
      return res.status(500).json({ error: "internal_error" });
    }
  });
  app.post("/api/recurring-subscriptions/:subscriptionId/connect-wallet", authenticateApiKey(1), async (req, res) => {
    try {
      const { subscriptionId } = req.params;
      const parse = connectWalletSchema.safeParse(req.body);
      if (!parse.success) {
        return res.status(400).json({
          error: "invalid_request",
          details: parse.error.flatten()
        });
      }
      const { walletAddress, signature, message } = parse.data;
      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      if (!subscription) {
        return res.status(404).json({ error: "subscription_not_found" });
      }
      if (req.apiKey && subscription.apiKeyId !== req.apiKey._id) {
        return res.status(403).json({ error: "forbidden" });
      }
      if (subscription.status !== "pending_wallet_connection") {
        return res.status(400).json({
          error: "invalid_status",
          message: "Subscription must be pending wallet connection"
        });
      }
      if (!verifyWalletConnection(walletAddress, signature, message)) {
        return res.status(400).json({ error: "invalid_signature" });
      }
      subscription.walletAddress = walletAddress;
      subscription.status = "wallet_connected";
      const now = /* @__PURE__ */ new Date();
      if (subscription.trialEndDate && subscription.trialEndDate > now) {
        subscription.nextBillingDate = calculateNextBillingDate(
          subscription.trialEndDate,
          subscription.billingInterval
        );
        subscription.currentPeriodStart = now;
        subscription.currentPeriodEnd = subscription.trialEndDate;
        subscription.status = "active";
      } else {
        subscription.currentPeriodStart = now;
        subscription.nextBillingDate = calculateNextBillingDate(
          now,
          subscription.billingInterval
        );
        subscription.currentPeriodEnd = new Date(subscription.nextBillingDate.getTime() - 1);
        subscription.status = "active";
      }
      await subscription.save();
      let approvalIntent = void 0;
      if (subscription.asset === "SPL" && subscription.tokenMint) {
        try {
          const merchant = getEnv6("MERCHANT_SOL_ADDRESS");
          const allowance = String(Math.round(subscription.priceUsd * 1e6));
          approvalIntent = await buildSplApproveDelegateUnsigned({
            userPubkey: walletAddress,
            tokenMint: subscription.tokenMint,
            delegate: merchant,
            amount: allowance
          });
          subscription.delegatePubkey = merchant;
          subscription.delegateAllowance = allowance;
          subscription.delegateApprovedAt = void 0;
          await subscription.save();
        } catch (err) {
          logger.error("Failed to generate SPL approve intent", { subscriptionId, error: err instanceof Error ? err.message : String(err) });
        }
      }
      await logSubscriptionEvent(subscriptionId, "wallet_connected", {
        walletAddress,
        trialActive: !!(subscription.trialEndDate && subscription.trialEndDate > now)
      });
      await sendWebhook(subscription, "wallet_connected", { wallet_address: walletAddress });
      return res.json({
        subscription_id: subscriptionId,
        status: subscription.status,
        wallet_address: walletAddress,
        next_billing_date: subscription.nextBillingDate?.toISOString(),
        current_period_start: subscription.currentPeriodStart?.toISOString(),
        current_period_end: subscription.currentPeriodEnd?.toISOString(),
        trial_active: !!(subscription.trialEndDate && subscription.trialEndDate > now),
        approval_intent: approvalIntent ? {
          phantom_url: approvalIntent.phantomUrl,
          qr_data_url: approvalIntent.qrDataUrl,
          unsigned_tx: approvalIntent.unsignedTxB64,
          expires_at: approvalIntent.expiresAt,
          order_id: approvalIntent.orderId
        } : void 0
      });
    } catch (error) {
      logger.error("Connect wallet failed", {
        error: error instanceof Error ? error.message : String(error)
      });
      return res.status(500).json({ error: "internal_error" });
    }
  });
  app.post("/api/recurring-subscriptions/:subscriptionId/collect", authenticateApiKey(1), async (req, res) => {
    try {
      const { subscriptionId } = req.params;
      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      if (!subscription) return res.status(404).json({ error: "subscription_not_found" });
      if (req.apiKey && subscription.apiKeyId !== req.apiKey._id) {
        return res.status(403).json({ error: "forbidden" });
      }
      if (subscription.status !== "active") {
        return res.status(400).json({ error: "invalid_status" });
      }
      if (subscription.asset !== "SPL" || !subscription.tokenMint) {
        return res.status(400).json({ error: "delegate_not_applicable" });
      }
      if (!subscription.delegatePubkey || !subscription.delegateAllowance || !subscription.delegateApprovedAt) {
        return res.status(400).json({ error: "delegate_not_approved" });
      }
      const amount = subscription.delegateAllowance;
      const merchantSigningSecret = process.env.MERCHANT_SIGNING_SECRET || "";
      if (merchantSigningSecret) {
      }
      const transfer = await (await Promise.resolve().then(() => (init_solana(), solana_exports))).buildSplTransferFromDelegateUnsigned({
        delegatePubkey: subscription.delegatePubkey,
        userPubkey: subscription.walletAddress,
        merchant: process.env.MERCHANT_SOL_ADDRESS || "",
        tokenMint: subscription.tokenMint,
        tokenAmount: amount
      });
      await PaymentOrder.create({
        orderId: transfer.orderId,
        status: "pending",
        assetType: "SPL",
        tokenMint: subscription.tokenMint,
        tokenAmount: amount,
        merchant: process.env.MERCHANT_SOL_ADDRESS || "",
        userPubkey: subscription.walletAddress,
        memo: transfer.memoText,
        unsignedTxB64: transfer.unsignedTxB64,
        expiresAt: new Date(transfer.expiresAt)
      });
      await logSubscriptionEvent(subscriptionId, "payment_succeeded", { paymentId: transfer.orderId }, void 0);
      return res.json({
        order_id: transfer.orderId,
        phantom_url: transfer.phantomUrl,
        qr_data_url: transfer.qrDataUrl,
        unsigned_tx: transfer.unsignedTxB64,
        expires_at: transfer.expiresAt
      });
    } catch (error) {
      logger.error("Collect failed", { error: error instanceof Error ? error.message : String(error) });
      return res.status(500).json({ error: "internal_error" });
    }
  });
  app.post("/api/recurring-subscriptions/relayer/callback", async (req, res) => {
    try {
      const { orderId, signedTxB64 } = req.body || {};
      if (!orderId || !signedTxB64) return res.status(400).json({ error: "missing_parameters" });
      const existing = await PaymentOrder.findOne({ orderId });
      if (!existing) return res.status(404).json({ error: "order_not_found" });
      if (existing.signature && existing.status === "submitted") {
        return res.json({ ok: true, signature: existing.signature, note: "already_submitted" });
      }
      const providedSig = req.headers["x-relayer-signature"] || req.headers["x-relayersignature"] || "";
      const providedTs = req.headers["x-timestamp"] || req.headers["xTimestamp"] || "";
      let secret = void 0;
      if (existing.subscriptionId) {
        const sub = await RecurringSubscription.findOne({ subscriptionId: existing.subscriptionId });
        if (sub) secret = sub.relayerSecret || sub.webhookSecret;
      }
      if (secret) {
        try {
          if (!providedTs) {
            logger.warn("Missing timestamp in relayer callback", { orderId });
            return res.status(403).json({ error: "missing_timestamp" });
          }
          const tsNum = Number(providedTs);
          if (!Number.isFinite(tsNum)) {
            logger.warn("Invalid timestamp in relayer callback", { orderId, providedTs });
            return res.status(403).json({ error: "invalid_timestamp" });
          }
          const ageMs = Date.now() - tsNum;
          if (ageMs > 2 * 60 * 1e3 || ageMs < -5 * 60 * 1e3) {
            logger.warn("Relayer callback timestamp outside allowed window", { orderId, ageMs });
            return res.status(403).json({ error: "timestamp_out_of_range" });
          }
          const crypto4 = await import("crypto");
          const message = providedTs + JSON.stringify(req.body);
          const expected = crypto4.createHmac("sha256", secret).update(message).digest("hex");
          if (!providedSig || expected !== providedSig) {
            logger.warn("Relayer HMAC verification failed", { orderId });
            return res.status(403).json({ error: "invalid_signature" });
          }
        } catch (e) {
          logger.error("Error during relayer HMAC verification", { error: e });
          return res.status(500).json({ error: "internal_error" });
        }
      }
      const result = await (await Promise.resolve().then(() => (init_solana(), solana_exports))).broadcastSignedTransaction(signedTxB64);
      await PaymentOrder.updateOne({ orderId }, { $set: { signature: result.signature, status: "submitted" } });
      return res.json({ ok: true, signature: result.signature });
    } catch (error) {
      logger.error("Relayer callback failed", { error });
      return res.status(500).json({ error: "internal_error" });
    }
  });
  app.get("/api/recurring-subscriptions/:subscriptionId", authenticateApiKey(0.1), async (req, res) => {
    try {
      const { subscriptionId } = req.params;
      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      if (!subscription) {
        return res.status(404).json({ error: "subscription_not_found" });
      }
      if (req.apiKey && subscription.apiKeyId !== req.apiKey._id) {
        return res.status(403).json({ error: "forbidden" });
      }
      const now = /* @__PURE__ */ new Date();
      const trialActive = !!(subscription.trialEndDate && subscription.trialEndDate > now);
      return res.json({
        subscription_id: subscription.subscriptionId,
        status: subscription.status,
        plan: subscription.plan,
        price_usd: subscription.priceUsd,
        billing_interval: subscription.billingInterval,
        wallet_address: subscription.walletAddress,
        next_billing_date: subscription.nextBillingDate?.toISOString(),
        current_period_start: subscription.currentPeriodStart?.toISOString(),
        current_period_end: subscription.currentPeriodEnd?.toISOString(),
        last_payment_date: subscription.lastPaymentDate?.toISOString(),
        last_payment_signature: subscription.lastPaymentSignature,
        failed_payment_attempts: subscription.failedPaymentAttempts,
        auto_renew: subscription.autoRenew,
        cancel_at_period_end: subscription.cancelAtPeriodEnd,
        trial_active: trialActive,
        trial_end_date: subscription.trialEndDate?.toISOString(),
        canceled_at: subscription.canceledAt?.toISOString(),
        cancellation_reason: subscription.cancellationReason,
        created_at: subscription.createdAt.toISOString(),
        updated_at: subscription.updatedAt.toISOString(),
        metadata: subscription.metadata
      });
    } catch (error) {
      logger.error("Get subscription failed", {
        error: error instanceof Error ? error.message : String(error)
      });
      return res.status(500).json({ error: "internal_error" });
    }
  });
  app.patch("/api/recurring-subscriptions/:subscriptionId", authenticateApiKey(0.3), async (req, res) => {
    try {
      const { subscriptionId } = req.params;
      const parse = updateRecurringSubscriptionSchema.safeParse(req.body);
      if (!parse.success) {
        return res.status(400).json({
          error: "invalid_request",
          details: parse.error.flatten()
        });
      }
      const updates = parse.data;
      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      if (!subscription) {
        return res.status(404).json({ error: "subscription_not_found" });
      }
      if (req.apiKey && subscription.apiKeyId !== req.apiKey._id) {
        return res.status(403).json({ error: "forbidden" });
      }
      if (updates.plan !== void 0) {
        subscription.plan = updates.plan;
        if (updates.priceUsd !== void 0) {
          subscription.priceUsd = updates.priceUsd;
        }
      } else if (updates.priceUsd !== void 0) {
        subscription.priceUsd = updates.priceUsd;
      }
      if (updates.autoRenew !== void 0) {
        subscription.autoRenew = updates.autoRenew;
      }
      if (updates.webhookUrl !== void 0) {
        subscription.webhookUrl = updates.webhookUrl;
      }
      if (updates.metadata !== void 0) {
        subscription.metadata = { ...subscription.metadata, ...updates.metadata };
      }
      if (updates.cancelAtPeriodEnd !== void 0) {
        subscription.cancelAtPeriodEnd = updates.cancelAtPeriodEnd;
        if (updates.cancelAtPeriodEnd && subscription.status === "active") {
          await logSubscriptionEvent(subscriptionId, "canceled", {
            reason: "scheduled_for_period_end",
            cancelAtPeriodEnd: true
          });
        }
      }
      await subscription.save();
      return res.json({
        subscription_id: subscriptionId,
        status: subscription.status,
        updated: Object.keys(updates)
      });
    } catch (error) {
      logger.error("Update subscription failed", {
        error: error instanceof Error ? error.message : String(error)
      });
      return res.status(500).json({ error: "internal_error" });
    }
  });
  app.post("/api/recurring-subscriptions/:subscriptionId/cancel", authenticateApiKey(0.3), async (req, res) => {
    try {
      const { subscriptionId } = req.params;
      const { reason } = req.body;
      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      if (!subscription) {
        return res.status(404).json({ error: "subscription_not_found" });
      }
      if (req.apiKey && subscription.apiKeyId !== req.apiKey._id) {
        return res.status(403).json({ error: "forbidden" });
      }
      if (subscription.status === "canceled") {
        return res.status(400).json({ error: "already_canceled" });
      }
      subscription.status = "canceled";
      subscription.canceledAt = /* @__PURE__ */ new Date();
      subscription.cancellationReason = reason || "user_requested";
      subscription.autoRenew = false;
      await subscription.save();
      await logSubscriptionEvent(subscriptionId, "canceled", {
        reason: subscription.cancellationReason,
        canceledAt: subscription.canceledAt
      });
      await sendWebhook(subscription, "canceled", {
        reason: subscription.cancellationReason,
        canceled_at: subscription.canceledAt.toISOString()
      });
      return res.json({
        subscription_id: subscriptionId,
        status: subscription.status,
        canceled_at: subscription.canceledAt.toISOString(),
        cancellation_reason: subscription.cancellationReason
      });
    } catch (error) {
      logger.error("Cancel subscription failed", {
        error: error instanceof Error ? error.message : String(error)
      });
      return res.status(500).json({ error: "internal_error" });
    }
  });
  app.get("/api/recurring-subscriptions", authenticateApiKey(0.2), async (req, res) => {
    try {
      const apiKey = req.apiKey;
      const { status, limit = 10, offset = 0 } = req.query;
      const query = { apiKeyId: apiKey._id };
      if (status && typeof status === "string") {
        query.status = status;
      }
      const subscriptions = await RecurringSubscription.find(query).sort({ createdAt: -1 }).limit(Number(limit)).skip(Number(offset)).exec();
      const total = await RecurringSubscription.countDocuments(query);
      return res.json({
        subscriptions: subscriptions.map((sub) => ({
          subscription_id: sub.subscriptionId,
          status: sub.status,
          plan: sub.plan,
          price_usd: sub.priceUsd,
          billing_interval: sub.billingInterval,
          wallet_address: sub.walletAddress,
          next_billing_date: sub.nextBillingDate?.toISOString(),
          created_at: sub.createdAt.toISOString()
        })),
        pagination: {
          total,
          limit: Number(limit),
          offset: Number(offset),
          has_more: Number(offset) + Number(limit) < total
        }
      });
    } catch (error) {
      logger.error("List subscriptions failed", {
        error: error instanceof Error ? error.message : String(error)
      });
      return res.status(500).json({ error: "internal_error" });
    }
  });
  app.get("/api/analytics/overview", optionalAuth, async (req, res) => {
    try {
      const { getJson: getJson2, setJson: setJson2 } = await Promise.resolve().then(() => (init_cache(), cache_exports));
      const { storage: storage2 } = await Promise.resolve().then(() => (init_storage(), storage_exports));
      let apiKeyIds = [];
      const authHeader = req.headers.authorization || "";
      if (authHeader) {
        let keyVal = void 0;
        if (typeof authHeader === "string") {
          if (authHeader.startsWith("Bearer ")) keyVal = authHeader.substring(7);
          else if (authHeader.startsWith("ApiKey ")) keyVal = authHeader.substring(7);
          else keyVal = authHeader;
        }
        if (keyVal) {
          const apiKeyDoc = await storage2.getApiKeyByKey(keyVal);
          if (apiKeyDoc) apiKeyIds.push(apiKeyDoc._id.toString());
        }
      }
      if (apiKeyIds.length === 0 && req.user) {
        const apiKeys = await storage2.getApiKeys(req.user._id.toString());
        apiKeyIds = apiKeys.map((k) => k._id.toString());
      }
      if (apiKeyIds.length === 0) {
        return res.status(401).json({ error: "API key or login required" });
      }
      const cacheKey = `analytics:overview:${apiKeyIds.join(",")}`;
      const cached = await getJson2(cacheKey);
      if (cached) return res.json(cached);
      const activeCount = await RecurringSubscription.countDocuments({ apiKeyId: { $in: apiKeyIds }, status: "active" });
      const subs = await RecurringSubscription.find({ apiKeyId: { $in: apiKeyIds }, status: "active" }).select("priceUsd billingInterval");
      let mrr = 0;
      for (const s of subs) {
        if (s.billingInterval === "monthly") mrr += s.priceUsd || 0;
        else if (s.billingInterval === "yearly") mrr += (s.priceUsd || 0) / 12;
      }
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1e3);
      const subscriptionIds = (await RecurringSubscription.find({ apiKeyId: { $in: apiKeyIds } }).select("subscriptionId")).map((x) => x.subscriptionId);
      const failedCount = await SubscriptionEvent.countDocuments({ eventType: "payment_failed", createdAt: { $gte: thirtyDaysAgo }, subscriptionId: { $in: subscriptionIds } });
      const cohortsMonths = 3;
      const nowDate = /* @__PURE__ */ new Date();
      const cohortRetention = [];
      for (let m = 0; m < cohortsMonths; m++) {
        const start = new Date(nowDate.getFullYear(), nowDate.getMonth() - m, 1);
        const end = new Date(start.getFullYear(), start.getMonth() + 1, 1);
        const created = await RecurringSubscription.countDocuments({ apiKeyId: { $in: apiKeyIds }, createdAt: { $gte: start, $lt: end } });
        const ids = (await RecurringSubscription.find({ apiKeyId: { $in: apiKeyIds }, createdAt: { $gte: start, $lt: end } }).select("subscriptionId")).map((x) => x.subscriptionId);
        const activeAfter = ids.length === 0 ? 0 : await RecurringSubscription.countDocuments({ subscriptionId: { $in: ids }, status: "active" });
        const pct = created === 0 ? 100 : Math.round(activeAfter / created * 1e4) / 100;
        cohortRetention.push({ cohort: start.toISOString().slice(0, 7), created, activeAfter30Days: activeAfter, retentionPct: pct });
      }
      let creditsRemaining = 0;
      if (apiKeyIds.length === 1) {
        const apiKeyDoc = await ApiKey.findById(apiKeyIds[0]);
        creditsRemaining = apiKeyDoc ? apiKeyDoc.credits : 0;
      }
      const out = {
        mrr_usd: Math.round(mrr * 100) / 100,
        active_subscriptions: activeCount,
        failed_payments_30d: failedCount,
        retention_rate_percent: cohortRetention.length ? cohortRetention[0].retentionPct : 100,
        cohort_retention: cohortRetention,
        credits_remaining: creditsRemaining
      };
      await setJson2(cacheKey, out, 60);
      return res.json(out);
    } catch (error) {
      logger.error("Analytics overview failed", { error });
      return res.status(500).json({ error: "internal_error" });
    }
  });
  app.get("/api/analytics/revenue-timeseries", optionalAuth, async (req, res) => {
    try {
      const { storage: storage2 } = await Promise.resolve().then(() => (init_storage(), storage_exports));
      const { getJson: getJson2, setJson: setJson2 } = await Promise.resolve().then(() => (init_cache(), cache_exports));
      let apiKeyIds = [];
      const authHeader = req.headers.authorization || "";
      if (authHeader) {
        let keyVal = void 0;
        if (typeof authHeader === "string") {
          if (authHeader.startsWith("Bearer ")) keyVal = authHeader.substring(7);
          else if (authHeader.startsWith("ApiKey ")) keyVal = authHeader.substring(7);
          else keyVal = authHeader;
        }
        if (keyVal) {
          const apiKeyDoc = await storage2.getApiKeyByKey(keyVal);
          if (apiKeyDoc) apiKeyIds.push(apiKeyDoc._id.toString());
        }
      }
      if (apiKeyIds.length === 0 && req.user) {
        const apiKeys = await storage2.getApiKeys(req.user._id.toString());
        apiKeyIds = apiKeys.map((k) => k._id.toString());
      }
      if (apiKeyIds.length === 0) return res.status(401).json({ error: "API key or login required" });
      const months = Number(req.query.months || 6);
      const cacheKey = `analytics:timeseries:${apiKeyIds.join(",")}:m${months}`;
      const cached = await getJson2(cacheKey);
      if (cached) return res.json(cached);
      const now = /* @__PURE__ */ new Date();
      const results = [];
      const subscriptionIds = (await RecurringSubscription.find({ apiKeyId: { $in: apiKeyIds } }).select("subscriptionId")).map((x) => x.subscriptionId);
      for (let i = months - 1; i >= 0; i--) {
        const start = new Date(now.getFullYear(), now.getMonth() - i, 1);
        const end = new Date(start.getFullYear(), start.getMonth() + 1, 1);
        const succeededEvents = await SubscriptionEvent.find({
          eventType: "payment_succeeded",
          createdAt: { $gte: start, $lt: end },
          subscriptionId: { $in: subscriptionIds }
        }).select("eventData");
        let sum = 0;
        for (const ev of succeededEvents) {
          if (ev.eventData && typeof ev.eventData.amount === "number") sum += ev.eventData.amount;
          else if (ev.eventData && typeof ev.eventData.amount_usd === "number") sum += ev.eventData.amount_usd;
          else if (ev.eventData && ev.eventData.amount) sum += Number(ev.eventData.amount) || 0;
        }
        results.push({ month: start.toLocaleString("default", { month: "short" }), revenue: Math.round(sum * 100) / 100 });
      }
      const out = { timeseries: results };
      await setJson2(cacheKey, out, 60);
      return res.json(out);
    } catch (error) {
      logger.error("Revenue timeseries failed", { error });
      return res.status(500).json({ error: "internal_error" });
    }
  });
  app.get("/api/analytics/recent-subscriptions", optionalAuth, async (req, res) => {
    try {
      const { storage: storage2 } = await Promise.resolve().then(() => (init_storage(), storage_exports));
      const { getJson: getJson2, setJson: setJson2 } = await Promise.resolve().then(() => (init_cache(), cache_exports));
      let apiKeyIds = [];
      const authHeader = req.headers.authorization || "";
      if (authHeader) {
        let keyVal = void 0;
        if (typeof authHeader === "string") {
          if (authHeader.startsWith("Bearer ")) keyVal = authHeader.substring(7);
          else if (authHeader.startsWith("ApiKey ")) keyVal = authHeader.substring(7);
          else keyVal = authHeader;
        }
        if (keyVal) {
          const apiKeyDoc = await storage2.getApiKeyByKey(keyVal);
          if (apiKeyDoc) apiKeyIds.push(apiKeyDoc._id.toString());
        }
      }
      if (apiKeyIds.length === 0 && req.user) {
        const apiKeys = await storage2.getApiKeys(req.user._id.toString());
        apiKeyIds = apiKeys.map((k) => k._id.toString());
      }
      if (apiKeyIds.length === 0) return res.status(401).json({ error: "API key or login required" });
      const limit = Number(req.query.limit || 10);
      const cacheKey = `analytics:recent:${apiKeyIds.join(",")}:l${limit}`;
      const cached = await getJson2(cacheKey);
      if (cached) return res.json(cached);
      const subs = await RecurringSubscription.find({ apiKeyId: { $in: apiKeyIds } }).sort({ createdAt: -1 }).limit(limit).exec();
      const out = {
        subscriptions: subs.map((s) => ({
          subscription_id: s.subscriptionId,
          customer: s.walletAddress || null,
          amount_usd: s.priceUsd,
          interval: s.billingInterval,
          status: s.status,
          next_payment: s.nextBillingDate ? s.nextBillingDate.toISOString() : null,
          created_at: s.createdAt.toISOString()
        }))
      };
      await setJson2(cacheKey, out, 30);
      return res.json(out);
    } catch (error) {
      logger.error("Recent subscriptions failed", { error });
      return res.status(500).json({ error: "internal_error" });
    }
  });
  app.get("/api/recurring-subscriptions/:subscriptionId/events", authenticateApiKey(0.1), async (req, res) => {
    try {
      const { subscriptionId } = req.params;
      const { limit = 20, offset = 0 } = req.query;
      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      if (!subscription) {
        return res.status(404).json({ error: "subscription_not_found" });
      }
      if (req.apiKey && subscription.apiKeyId !== req.apiKey._id) {
        return res.status(403).json({ error: "forbidden" });
      }
      const events = await SubscriptionEvent.find({ subscriptionId }).sort({ createdAt: -1 }).limit(Number(limit)).skip(Number(offset)).exec();
      const total = await SubscriptionEvent.countDocuments({ subscriptionId });
      return res.json({
        events: events.map((event) => ({
          event_type: event.eventType,
          event_data: event.eventData,
          transaction_signature: event.transactionSignature,
          created_at: event.createdAt.toISOString()
        })),
        pagination: {
          total,
          limit: Number(limit),
          offset: Number(offset),
          has_more: Number(offset) + Number(limit) < total
        }
      });
    } catch (error) {
      logger.error("Get subscription events failed", {
        error: error instanceof Error ? error.message : String(error)
      });
      return res.status(500).json({ error: "internal_error" });
    }
  });
  app.post("/api/relayer-secret/rotate", authenticateApiKey(1), async (req, res) => {
    try {
      const { subscriptionId } = req.body;
      if (!subscriptionId) return res.status(400).json({ error: "missing_subscriptionId" });
      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      if (!subscription) return res.status(404).json({ error: "subscription_not_found" });
      if (req.apiKey && subscription.apiKeyId !== req.apiKey._id) {
        return res.status(403).json({ error: "forbidden" });
      }
      const crypto4 = await import("crypto");
      const newSecret = crypto4.randomBytes(32).toString("hex");
      const { encryptWithMasterKey: encryptWithMasterKey2 } = await Promise.resolve().then(() => (init_crypto_utils(), crypto_utils_exports));
      const encrypted = encryptWithMasterKey2(newSecret);
      subscription.relayerSecretEncrypted = encrypted;
      subscription.relayerSecretSetAt = /* @__PURE__ */ new Date();
      await subscription.save();
      return res.json({ relayerSecret: newSecret, note: "copy_this_once" });
    } catch (error) {
      logger.error("Rotate relayer secret failed", { error });
      return res.status(500).json({ error: "internal_error" });
    }
  });
  app.get("/api/recurring-subscriptions/phantom/connect-callback", async (req, res) => {
    try {
      const { subscription_id, phantom_encryption_public_key, data, nonce } = req.query;
      if (!subscription_id || typeof subscription_id !== "string") {
        return res.status(400).json({ error: "missing_subscription_id" });
      }
      const subscription = await RecurringSubscription.findOne({ subscriptionId: subscription_id });
      if (!subscription) {
        return res.status(404).json({ error: "subscription_not_found" });
      }
      if (subscription.status !== "pending_wallet_connection") {
        return res.status(400).json({
          error: "invalid_status",
          message: "Subscription must be pending wallet connection"
        });
      }
      logger.info("Phantom wallet connection callback received", {
        subscriptionId: subscription_id,
        hasData: !!data,
        hasNonce: !!nonce
      });
      await logSubscriptionEvent(subscription_id, "wallet_connected", {
        phantom_callback: true,
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      });
      const frontendUrl = getEnv6("PHANTOM_DAPP_URL", "http://localhost:3000");
      return res.redirect(`${frontendUrl}/subscription/connect-success?subscription_id=${subscription_id}`);
    } catch (error) {
      logger.error("Phantom connect callback failed", {
        error: error instanceof Error ? error.message : String(error)
      });
      const frontendUrl = getEnv6("PHANTOM_DAPP_URL", "http://localhost:3000");
      return res.redirect(`${frontendUrl}/subscription/connect-error?error=callback_failed`);
    }
  });
  app.get("/api/recurring-subscriptions/phantom/payment-callback", async (req, res) => {
    try {
      const { subscription_id, payment_id, signature, errorCode, errorMessage } = req.query;
      if (!subscription_id || typeof subscription_id !== "string") {
        return res.status(400).json({ error: "missing_subscription_id" });
      }
      const subscription = await RecurringSubscription.findOne({ subscriptionId: subscription_id });
      if (!subscription) {
        return res.status(404).json({ error: "subscription_not_found" });
      }
      if (errorCode || errorMessage) {
        await logSubscriptionEvent(subscription_id, "payment_failed", {
          payment_id,
          phantom_error_code: errorCode,
          phantom_error_message: errorMessage,
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        });
        subscription.failedPaymentAttempts += 1;
        if (subscription.failedPaymentAttempts >= subscription.maxFailedAttempts) {
          subscription.status = "past_due";
          const gracePeriodUntil = /* @__PURE__ */ new Date();
          gracePeriodUntil.setDate(gracePeriodUntil.getDate() + subscription.gracePeriodDays);
          subscription.gracePeriodUntil = gracePeriodUntil;
        }
        await subscription.save();
        await sendWebhook(subscription, "payment_failed", {
          payment_id,
          error_code: errorCode,
          error_message: errorMessage,
          failed_attempts: subscription.failedPaymentAttempts
        });
        const frontendUrl = getEnv6("PHANTOM_DAPP_URL", "http://localhost:3000");
        return res.redirect(`${frontendUrl}/subscription/payment-failed?subscription_id=${subscription_id}&payment_id=${payment_id}`);
      }
      if (!signature || typeof signature !== "string") {
        return res.status(400).json({ error: "missing_signature" });
      }
      try {
        const txDetails = await getTransactionBySignature(signature);
        if (!txDetails || !txDetails.meta || txDetails.meta.err) {
          throw new Error("Transaction failed or not found");
        }
        const memo = extractMemoFromTransaction(txDetails);
        if (!memo || !memo.startsWith(`recurring:${subscription_id}`)) {
          throw new Error("Transaction memo does not match subscription");
        }
        subscription.lastPaymentDate = /* @__PURE__ */ new Date();
        subscription.lastPaymentSignature = signature;
        subscription.failedPaymentAttempts = 0;
        subscription.gracePeriodUntil = void 0;
        const now = /* @__PURE__ */ new Date();
        subscription.currentPeriodStart = now;
        subscription.nextBillingDate = calculateNextBillingDate(now, subscription.billingInterval);
        subscription.currentPeriodEnd = new Date(subscription.nextBillingDate.getTime() - 1);
        if (subscription.status === "past_due" || subscription.status === "suspended") {
          subscription.status = "active";
        }
        await subscription.save();
        await logSubscriptionEvent(subscription_id, "payment_succeeded", {
          payment_id,
          transaction_signature: signature,
          amount: subscription.priceUsd,
          next_billing_date: subscription.nextBillingDate?.toISOString()
        }, signature);
        await sendWebhook(subscription, "payment_succeeded", {
          payment_id,
          transaction_signature: signature,
          amount_usd: subscription.priceUsd,
          next_billing_date: subscription.nextBillingDate?.toISOString()
        });
        const frontendUrl = getEnv6("PHANTOM_DAPP_URL", "http://localhost:3000");
        return res.redirect(`${frontendUrl}/subscription/payment-success?subscription_id=${subscription_id}&payment_id=${payment_id}`);
      } catch (verificationError) {
        logger.error("Payment verification failed", {
          subscriptionId: subscription_id,
          signature,
          error: verificationError instanceof Error ? verificationError.message : String(verificationError)
        });
        await logSubscriptionEvent(subscription_id, "payment_failed", {
          payment_id,
          signature,
          verification_error: verificationError instanceof Error ? verificationError.message : String(verificationError)
        });
        const frontendUrl = getEnv6("PHANTOM_DAPP_URL", "http://localhost:3000");
        return res.redirect(`${frontendUrl}/subscription/payment-failed?subscription_id=${subscription_id}&error=verification_failed`);
      }
    } catch (error) {
      logger.error("Phantom payment callback failed", {
        error: error instanceof Error ? error.message : String(error)
      });
      const frontendUrl = getEnv6("PHANTOM_DAPP_URL", "http://localhost:3000");
      return res.redirect(`${frontendUrl}/subscription/payment-error?error=callback_failed`);
    }
  });
  app.get("/api/recurring-subscriptions/phantom/approve-callback", async (req, res) => {
    try {
      const { subscription_id, approval_order_id, signature } = req.query;
      if (!subscription_id || typeof subscription_id !== "string") {
        return res.status(400).json({ error: "missing_subscription_id" });
      }
      const subscription = await RecurringSubscription.findOne({ subscriptionId: subscription_id });
      if (!subscription) return res.status(404).json({ error: "subscription_not_found" });
      subscription.delegateApprovedAt = /* @__PURE__ */ new Date();
      if (signature && typeof signature === "string") {
        subscription.delegateApprovalSignature = signature;
      }
      await subscription.save();
      await logSubscriptionEvent(subscription_id, "activated", { approval_order_id, signature });
      const frontendUrl = getEnv6("PHANTOM_DAPP_URL", "http://localhost:3000");
      return res.redirect(`${frontendUrl}/subscription/approve-success?subscription_id=${subscription_id}`);
    } catch (error) {
      logger.error("Phantom approve callback failed", { error: error instanceof Error ? error.message : String(error) });
      const frontendUrl = getEnv6("PHANTOM_DAPP_URL", "http://localhost:3000");
      return res.redirect(`${frontendUrl}/subscription/approve-error?error=callback_failed`);
    }
  });
  app.delete("/api/recurring-subscriptions/:subscriptionId", authenticateApiKey(0.5), async (req, res) => {
    try {
      const { subscriptionId } = req.params;
      const subscription = await RecurringSubscription.findOne({ subscriptionId });
      if (!subscription) {
        return res.status(404).json({ error: "subscription_not_found" });
      }
      if (req.apiKey && subscription.apiKeyId !== req.apiKey._id) {
        return res.status(403).json({ error: "forbidden" });
      }
      await SubscriptionEvent.deleteMany({ subscriptionId });
      await RecurringSubscription.deleteOne({ subscriptionId });
      await logSubscriptionEvent(subscriptionId, "deleted", {
        deletedByApiKey: req.apiKey ? String(req.apiKey._id) : null
      });
      return res.status(204).send();
    } catch (error) {
      logger.error("Delete subscription failed", {
        error: error instanceof Error ? error.message : String(error)
      });
      return res.status(500).json({ error: "internal_error" });
    }
  });
}
var init_recurring_subscription_routes = __esm({
  "server/recurring-subscription-routes.ts"() {
    "use strict";
    init_security();
    init_auth();
    init_schema_mongodb();
    init_schema_mongodb();
    init_recurring_subscription_schema();
    init_phantom_wallet_utils();
    init_solana();
    init_solana();
  }
});

// server/docs-routes.ts
var docs_routes_exports = {};
__export(docs_routes_exports, {
  registerDocsRoutes: () => registerDocsRoutes
});
import fs2 from "fs";
import path3 from "path";
import { marked } from "marked";
function readApiDocMarkdown() {
  const mdPath = path3.resolve(process.cwd(), "API_DOCUMENTATION.md");
  if (!fs2.existsSync(mdPath)) {
    return "# API Documentation\n\nDocumentation is not available.";
  }
  return fs2.readFileSync(mdPath, "utf8");
}
function wrapHtml(body) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>BlockSub API Documentation</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --primary-color: #8b5cf6;
      --primary-hover: #7c3aed;
      --secondary-color: #06b6d4;
      --success-color: #10b981;
      --warning-color: #f59e0b;
      --error-color: #ef4444;
      --text-primary: #1f2937;
      --text-secondary: #6b7280;
      --bg-primary: #ffffff;
      --bg-secondary: #f9fafb;
      --bg-code: #f3f4f6;
      --border-color: #e5e7eb;
      --border-light: #f3f4f6;
      color-scheme: light;
    }
    
    @media (prefers-color-scheme: dark) {
      :root {
        --text-primary: #f9fafb;
        --text-secondary: #9ca3af;
        --bg-primary: #111827;
        --bg-secondary: #1f2937;
        --bg-code: #1f2937;
        --border-color: #374151;
        --border-light: #374151;
        color-scheme: dark;
      }
    }
    
    * {
      box-sizing: border-box;
    }
    
    body {
      font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      margin: 0;
      padding: 0;
      line-height: 1.7;
      color: var(--text-primary);
      background-color: var(--bg-primary);
      font-size: 16px;
    }
    
    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 2rem;
    }
    
    /* Typography */
    h1, h2, h3, h4, h5, h6 {
      line-height: 1.3;
      margin-top: 2rem;
      margin-bottom: 1rem;
      font-weight: 600;
      color: var(--text-primary);
    }
    
    h1 {
      font-size: 2.5rem;
      margin-top: 0;
      background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
      background-clip: text;
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 0.5rem;
    }
    
    h2 {
      font-size: 1.875rem;
      margin-top: 3rem;
      padding-bottom: 0.5rem;
      border-bottom: 2px solid var(--border-light);
    }
    
    h3 {
      font-size: 1.5rem;
      margin-top: 2rem;
      color: var(--primary-color);
    }
    
    h4 {
      font-size: 1.25rem;
      margin-top: 1.5rem;
    }
    
    /* Paragraphs and text */
    p {
      margin-bottom: 1.5rem;
      color: var(--text-secondary);
    }
    
    p:first-of-type {
      font-size: 1.125rem;
      color: var(--text-secondary);
    }
    
    /* Code styling */
    code {
      font-family: 'SF Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;
      background: var(--bg-code);
      padding: 0.125rem 0.375rem;
      border-radius: 0.25rem;
      font-size: 0.875rem;
      font-weight: 500;
      border: 1px solid var(--border-color);
    }
    
    pre {
      background: var(--bg-code);
      padding: 1.5rem;
      border-radius: 0.75rem;
      overflow: auto;
      border: 1px solid var(--border-color);
      margin: 1.5rem 0;
      position: relative;
    }
    
    pre code {
      background: none;
      padding: 0;
      border: none;
      font-size: 0.875rem;
    }
    
    /* Tables */
    table {
      border-collapse: collapse;
      width: 100%;
      margin: 1.5rem 0;
      border-radius: 0.5rem;
      overflow: hidden;
      border: 1px solid var(--border-color);
    }
    
    th, td {
      padding: 0.75rem 1rem;
      text-align: left;
      border-bottom: 1px solid var(--border-color);
    }
    
    th {
      background: var(--bg-secondary);
      font-weight: 600;
      color: var(--text-primary);
    }
    
    tr:last-child td {
      border-bottom: none;
    }
    
    /* Links */
    a {
      color: var(--primary-color);
      text-decoration: none;
      font-weight: 500;
      transition: color 0.2s ease;
    }
    
    a:hover {
      color: var(--primary-hover);
      text-decoration: underline;
    }
    
    /* Lists */
    ul, ol {
      margin: 1rem 0;
      padding-left: 1.5rem;
    }
    
    li {
      margin-bottom: 0.5rem;
      color: var(--text-secondary);
    }
    
    /* Table of Contents */
    .toc {
      background: var(--bg-secondary);
      border-radius: 0.75rem;
      padding: 1.5rem;
      margin: 2rem 0;
      border: 1px solid var(--border-color);
    }
    
    .toc h2 {
      margin-top: 0;
      border-bottom: none;
    }
    
    /* Status badges */
    .status-badge {
      display: inline-flex;
      align-items: center;
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    
    .status-success {
      background-color: rgba(16, 185, 129, 0.1);
      color: var(--success-color);
    }
    
    .status-warning {
      background-color: rgba(245, 158, 11, 0.1);
      color: var(--warning-color);
    }
    
    .status-error {
      background-color: rgba(239, 68, 68, 0.1);
      color: var(--error-color);
    }
    
    /* HTTP methods */
    .http-method {
      display: inline-flex;
      align-items: center;
      padding: 0.25rem 0.75rem;
      border-radius: 0.375rem;
      font-size: 0.875rem;
      font-weight: 600;
      font-family: 'SF Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;
    }
    
    .http-post {
      background-color: rgba(34, 197, 94, 0.1);
      color: #16a34a;
    }
    
    .http-get {
      background-color: rgba(59, 130, 246, 0.1);
      color: #2563eb;
    }
    
    /* Checkboxes in lists */
    li:has(input[type="checkbox"]) {
      list-style: none;
      margin-left: -1.5rem;
    }
    
    input[type="checkbox"] {
      margin-right: 0.5rem;
    }
    
    /* Separators */
    hr {
      border: none;
      height: 1px;
      background: var(--border-color);
      margin: 3rem 0;
    }
    
    /* Responsive */
    @media (max-width: 768px) {
      .container {
        padding: 1rem;
      }
      
      h1 {
        font-size: 2rem;
      }
      
      h2 {
        font-size: 1.5rem;
      }
      
      h3 {
        font-size: 1.25rem;
      }
      
      pre {
        padding: 1rem;
        overflow-x: scroll;
      }
      
      table {
        font-size: 0.875rem;
      }
      
      th, td {
        padding: 0.5rem;
      }
    }
    
    /* Scroll behavior */
    html {
      scroll-behavior: smooth;
    }
  </style>
</head>
<body>
  <div class="container">${body}</div>
  <script>
    (function() {
      function postHeight() {
        try {
          var h = document.documentElement.scrollHeight || document.body.scrollHeight || 0;
          parent.postMessage({ type: 'blocksub-docs-height', height: h }, '*');
        } catch (e) {}
      }
      window.addEventListener('load', postHeight);
      window.addEventListener('resize', function(){ setTimeout(postHeight, 50); });
      window.addEventListener('message', function(event) {
        try {
          if (event && event.data && event.data.type === 'blocksub-docs-request-height') {
            postHeight();
          }
        } catch (e) {}
      });
      // Also periodically post height in case of content that expands after load
      setInterval(postHeight, 1000);
    })();
  </script>
</body>
</html>`;
}
function registerDocsRoutes(app) {
  app.get("/api/docs/raw", (_req, res) => {
    try {
      const md = readApiDocMarkdown();
      res.setHeader("Content-Type", "text/markdown; charset=utf-8");
      res.setHeader("Cache-Control", "public, max-age=300");
      res.send(md);
    } catch (e) {
      res.status(404).json({ error: "not_found", message: e?.message || "Docs not found" });
    }
  });
  app.get("/api/docs/html", (_req, res) => {
    try {
      const md = readApiDocMarkdown();
      const html = marked.parse(md);
      const page = wrapHtml(String(html));
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("Cache-Control", "public, max-age=300");
      res.send(page);
    } catch (e) {
      res.status(404).send("Documentation not found");
    }
  });
}
var init_docs_routes = __esm({
  "server/docs-routes.ts"() {
    "use strict";
  }
});

// server/payment-worker.ts
var payment_worker_exports = {};
__export(payment_worker_exports, {
  paymentWorker: () => paymentWorker
});
import { v4 as uuidv45 } from "uuid";
import http from "http";
import https from "https";
import { PublicKey as PublicKey4 } from "@solana/web3.js";
async function postJson(url, body, headers = {}) {
  return new Promise((resolve, reject) => {
    try {
      const u = new URL(url);
      const isHttps = u.protocol === "https:";
      const data = JSON.stringify(body);
      const opts = {
        hostname: u.hostname,
        port: u.port || (isHttps ? 443 : 80),
        path: u.pathname + (u.search || ""),
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(data),
          ...headers
        }
      };
      const req = (isHttps ? https : http).request(opts, (res) => {
        res.setEncoding("utf8");
        let raw = "";
        res.on("data", (chunk) => raw += chunk);
        res.on("end", () => resolve());
      });
      req.on("error", (err) => reject(err));
      req.write(data);
      req.end();
    } catch (err) {
      reject(err);
    }
  });
}
var DEFAULT_CONFIG, PaymentWorker, paymentWorker;
var init_payment_worker = __esm({
  "server/payment-worker.ts"() {
    "use strict";
    init_schema_mongodb();
    init_recurring_subscription_schema();
    init_phantom_wallet_utils();
    init_solana();
    init_security();
    DEFAULT_CONFIG = {
      expiredOrderCheckInterval: 60 * 1e3,
      // 1 minute
      pendingOrderVerificationInterval: 30 * 1e3,
      // 30 seconds
      recurringBillingCheckInterval: 60 * 1e3,
      // 1 minute - check for due subscriptions
      maxRetries: 3,
      enabled: process.env.NODE_ENV !== "test"
      // Disable in tests
    };
    PaymentWorker = class {
      config;
      expiredOrderTimer;
      pendingOrderTimer;
      recurringBillingTimer;
      isRunning = false;
      instanceId;
      constructor(config = {}) {
        this.config = { ...DEFAULT_CONFIG, ...config };
        this.instanceId = `${process.pid}-${uuidv45()}`;
      }
      start() {
        if (!this.config.enabled || this.isRunning) {
          return;
        }
        this.isRunning = true;
        logger.info("Starting payment worker", { config: this.config });
        this.startExpiredOrderCheck();
        this.startPendingOrderVerification();
        this.startRecurringBillingCheck();
      }
      // Expose current running state so external supervisors can monitor
      get running() {
        return this.isRunning;
      }
      stop() {
        if (!this.isRunning) {
          return;
        }
        logger.info("Stopping payment worker");
        this.isRunning = false;
        if (this.expiredOrderTimer) {
          clearInterval(this.expiredOrderTimer);
          this.expiredOrderTimer = void 0;
        }
        if (this.pendingOrderTimer) {
          clearInterval(this.pendingOrderTimer);
          this.pendingOrderTimer = void 0;
        }
        if (this.recurringBillingTimer) {
          clearInterval(this.recurringBillingTimer);
          this.recurringBillingTimer = void 0;
        }
      }
      startExpiredOrderCheck() {
        this.expiredOrderTimer = setInterval(async () => {
          try {
            await this.markExpiredOrders();
          } catch (error) {
            logger.error("Error in expired order check", { error });
          }
        }, this.config.expiredOrderCheckInterval);
      }
      startPendingOrderVerification() {
        this.pendingOrderTimer = setInterval(async () => {
          try {
            await this.verifyPendingOrders();
          } catch (error) {
            logger.error("Error in pending order verification", { error });
          }
        }, this.config.pendingOrderVerificationInterval);
      }
      startRecurringBillingCheck() {
        this.recurringBillingTimer = setInterval(async () => {
          try {
            await this.processDueRecurringSubscriptions();
          } catch (error) {
            logger.error("Error in recurring billing check", { error });
          }
        }, this.config.recurringBillingCheckInterval);
      }
      /**
       * Find due recurring subscriptions and create non-custodial PaymentOrders (intents)
       * This keeps existing public APIs unchanged; it merely generates the unsigned
       * Phantom deeplink/QR and persists a PaymentOrder so the merchant or customer
       * can complete the payment. Webhooks and SubscriptionEvent logs are emitted.
       */
      async processDueRecurringSubscriptions() {
        const now = /* @__PURE__ */ new Date();
        try {
          const lockKey = "payment_worker_lock";
          const lockTTLms = Number(process.env.WORKER_LOCK_TTL_MS || String(Math.max(30 * 1e3, this.config.recurringBillingCheckInterval)));
          const db = RecurringSubscription.db;
          const locks = db.collection("worker_locks");
          const lockFilter = {
            _id: lockKey,
            $or: [{ lockedUntil: { $lt: now } }, { lockedUntil: { $exists: false } }]
          };
          const lockUpdate = {
            $set: { lockedUntil: new Date(Date.now() + lockTTLms), owner: this.instanceId, updatedAt: /* @__PURE__ */ new Date() }
          };
          const opt = { upsert: true, returnDocument: "after" };
          const res = await locks.findOneAndUpdate(lockFilter, lockUpdate, opt);
          if (!res || !res.value) {
            logger.info("Payment worker lock not acquired; another instance may be leader");
            return;
          }
          if (res.value.owner && res.value.owner !== this.instanceId && new Date(res.value.lockedUntil) > now) {
            logger.info("Payment worker lock held by another instance", { owner: res.value.owner });
            return;
          }
        } catch (e) {
          logger.error("Failed to acquire worker lock, aborting processing to avoid duplicate work", { error: e });
          return;
        }
        const dueSubs = await RecurringSubscription.find({
          status: "active",
          isRecurring: true,
          autoRenew: true,
          nextBillingDate: { $lte: now },
          walletAddress: { $exists: true, $ne: null }
        }).limit(100).exec();
        if (!dueSubs || dueSubs.length === 0) return;
        for (const sub of dueSubs) {
          try {
            let intent = null;
            if (sub.asset === "SPL" && sub.delegateApprovedAt && sub.delegatePubkey && sub.delegateAllowance) {
              try {
                intent = await (await Promise.resolve().then(() => (init_solana(), solana_exports))).buildSplTransferFromDelegateUnsigned({
                  delegatePubkey: sub.delegatePubkey,
                  userPubkey: sub.walletAddress,
                  merchant: intent?.merchant || process.env.MERCHANT_SOL_ADDRESS || "",
                  tokenMint: sub.tokenMint,
                  tokenAmount: sub.delegateAllowance
                });
              } catch (e) {
                logger.error("Failed to build delegate transfer intent", { subscriptionId: sub.subscriptionId, error: e });
                intent = null;
              }
            }
            if (!intent) {
              const billingCycle = 1;
              intent = await createRecurringPaymentIntent({
                subscriptionId: sub.subscriptionId,
                walletAddress: sub.walletAddress,
                assetType: sub.asset === "SOL" ? "SOL" : "SPL",
                amountLamports: sub.asset === "SOL" ? Math.round(sub.priceUsd * 1e7) : void 0,
                // placeholder conversion
                tokenMint: sub.tokenMint,
                tokenAmount: sub.asset === "SPL" ? String(Math.round(sub.priceUsd * 1e6)) : void 0,
                // placeholder: convert USD to token base units is merchant-specific
                billingCycle
              });
            }
            await PaymentOrder.create({
              orderId: intent.orderId || intent.paymentId || String(Date.now()),
              subscriptionId: sub.subscriptionId,
              status: "pending",
              assetType: intent.amountLamports ? "SOL" : "SPL",
              amountLamports: intent.amountLamports,
              tokenMint: intent.tokenMint,
              tokenAmount: intent.tokenAmount || intent.amount,
              merchant: intent.merchant || intent.merchantAddress || process.env.MERCHANT_SOL_ADDRESS || "",
              userPubkey: intent.walletAddress || sub.walletAddress,
              memo: intent.memo || intent.memoText || null,
              unsignedTxB64: intent.unsignedTxB64,
              expiresAt: intent.expiresAt
            });
            if (sub.relayerUrl && intent && intent.unsignedTxB64) {
              try {
                const payload = {
                  orderId: intent.orderId || intent.paymentId || String(Date.now()),
                  unsignedTxB64: intent.unsignedTxB64,
                  expiresAt: intent.expiresAt,
                  subscriptionId: sub.subscriptionId
                };
                const headers = { "Content-Type": "application/json" };
                let secret = void 0;
                if (sub.relayerSecretEncrypted) {
                  try {
                    const { decryptWithMasterKey: decryptWithMasterKey2 } = await Promise.resolve().then(() => (init_crypto_utils(), crypto_utils_exports));
                    secret = decryptWithMasterKey2(sub.relayerSecretEncrypted);
                  } catch (e) {
                    logger.error("Failed to decrypt relayer secret", { subscriptionId: sub.subscriptionId, error: e });
                  }
                }
                if (!secret && sub.webhookSecret) secret = sub.webhookSecret;
                if (secret) {
                  const timestamp = Date.now().toString();
                  const message = timestamp + JSON.stringify(payload);
                  const crypto4 = await import("crypto");
                  const sig = crypto4.createHmac("sha256", secret).update(message).digest("hex");
                  headers["X-Timestamp"] = timestamp;
                  headers["X-Relayer-Signature"] = sig;
                }
                await postJson(sub.relayerUrl, payload, headers);
              } catch (e) {
                logger.error("Failed to notify relayer", { subscriptionId: sub.subscriptionId, error: e });
              }
            }
            await SubscriptionEvent.create({
              subscriptionId: sub.subscriptionId,
              eventType: "renewed",
              eventData: {
                paymentId: intent.paymentId,
                amount: intent.amount,
                expiresAt: intent.expiresAt,
                phantomUrl: intent.phantomUrl,
                qrDataUrl: intent.qrDataUrl
              }
            });
            sub.nextBillingDate = new Date(sub.nextBillingDate.getTime() + (sub.billingInterval === "monthly" ? 30 * 24 * 60 * 60 * 1e3 : 365 * 24 * 60 * 60 * 1e3));
            await sub.save();
            logger.info("Created recurring PaymentOrder intent", { subscriptionId: sub.subscriptionId, paymentId: intent.paymentId });
          } catch (error) {
            logger.error("Failed to create recurring payment intent", { subscriptionId: sub.subscriptionId, error });
            try {
              await SubscriptionEvent.create({
                subscriptionId: sub.subscriptionId,
                eventType: "payment_failed",
                eventData: { reason: error instanceof Error ? error.message : String(error) }
              });
            } catch (e) {
              logger.error("Failed to log subscription event for intent creation failure", { subscriptionId: sub.subscriptionId, error: e });
            }
          }
        }
      }
      async markExpiredOrders() {
        const now = /* @__PURE__ */ new Date();
        const result = await PaymentOrder.updateMany(
          {
            status: "pending",
            expiresAt: { $lt: now }
          },
          {
            $set: { status: "expired" }
          }
        );
        if (result.modifiedCount > 0) {
          logger.info(`Marked ${result.modifiedCount} orders as expired`);
        }
      }
      async verifyPendingOrders() {
        const submittedOrders = await PaymentOrder.find({
          status: "submitted",
          signature: { $exists: true, $ne: null }
        }).limit(50);
        for (const order of submittedOrders) {
          try {
            await this.verifySubmittedOrder(order);
          } catch (error) {
            logger.error("Error verifying submitted order", {
              orderId: order.orderId,
              signature: order.signature,
              error
            });
          }
        }
      }
      async verifySubmittedOrder(order) {
        if (!order.signature) {
          return;
        }
        try {
          const tx = await getTransactionBySignature(order.signature);
          if (!tx) {
            return;
          }
          if (tx.meta?.err) {
            await PaymentOrder.updateOne(
              { _id: order._id },
              { $set: { status: "failed" } }
            );
            logger.info(`Order ${order.orderId} marked as failed due to transaction error`);
            return;
          }
          const verifyResult = await this.verifyTransactionDetails(tx, order);
          if (verifyResult.ok) {
            await PaymentOrder.updateOne(
              { _id: order._id },
              { $set: { status: "confirmed" } }
            );
            logger.info(`Order ${order.orderId} confirmed on-chain`);
            try {
              if (order.subscriptionId) {
                const sub = await RecurringSubscription.findOne({ subscriptionId: order.subscriptionId }).exec();
                if (sub && sub.issuedApiKeyId) {
                  const monthlyCredits = Number(process.env.SUBSCRIPTION_MONTHLY_CREDITS || "0");
                  if (monthlyCredits > 0) {
                    await ApiKey.findByIdAndUpdate(sub.issuedApiKeyId, { $inc: { credits: monthlyCredits } }).exec();
                    logger.info("Credited issued API key for subscription", { subscriptionId: order.subscriptionId, issuedApiKeyId: sub.issuedApiKeyId, credits: monthlyCredits });
                  }
                }
              }
            } catch (e) {
              logger.error("Failed to credit issued API key after order confirmation", { orderId: order.orderId, error: e });
            }
          } else {
            await PaymentOrder.updateOne(
              { _id: order._id },
              { $set: { status: "failed" } }
            );
            logger.warn(`Order ${order.orderId} failed verification: ${verifyResult.reason}`);
          }
        } catch (error) {
          logger.error("Error in transaction verification", {
            orderId: order.orderId,
            signature: order.signature,
            error
          });
        }
      }
      async verifyTransactionDetails(tx, order) {
        try {
          const memo = extractMemoFromTransaction(tx);
          const expectedMemo = order.memo || `order:${order.orderId}`;
          if (!memo || memo !== expectedMemo) {
            return { ok: false, reason: "memo_mismatch" };
          }
          const merchantKey = new PublicKey4(order.merchant);
          if (order.assetType === "SOL") {
            const ak = tx.transaction.message.accountKeys.map(
              (k) => k.toBase58 ? k.toBase58() : String(k)
            );
            const idx = ak.findIndex((k) => k === merchantKey.toBase58());
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
          } else if (order.assetType === "SPL") {
            const tokenMintKey = new PublicKey4(order.tokenMint);
            const expectedAmount = BigInt(order.tokenAmount);
            const tokenBalances = tx.meta?.postTokenBalances || [];
            const preTokenBalances = tx.meta?.preTokenBalances || [];
            const postBalance = tokenBalances.find(
              (b) => b.owner === merchantKey.toBase58() && b.mint === tokenMintKey.toBase58()
            );
            const preBalance = preTokenBalances.find(
              (b) => b.owner === merchantKey.toBase58() && b.mint === tokenMintKey.toBase58()
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
          logger.error("Error in transaction detail verification", { error });
          return { ok: false, reason: "verification_exception" };
        }
      }
      // Manual cleanup method for old records
      async cleanupOldOrders(olderThanDays = 30) {
        const cutoffDate = /* @__PURE__ */ new Date();
        cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);
        const result = await PaymentOrder.deleteMany({
          status: { $in: ["expired", "failed", "confirmed"] },
          updatedAt: { $lt: cutoffDate }
        });
        logger.info(`Cleaned up ${result.deletedCount} old payment orders`);
        return result.deletedCount;
      }
    };
    paymentWorker = new PaymentWorker();
    if (process.env.NODE_ENV === "production") {
      paymentWorker.start();
    }
  }
});

// server/worker-runner.ts
var worker_runner_exports = {};
__export(worker_runner_exports, {
  startWorkerSupervisor: () => startWorkerSupervisor
});
function startWorkerSupervisor() {
  try {
    if (!paymentWorker.running) {
      logger.info("Worker supervisor starting payment worker");
      paymentWorker.start();
    }
    setInterval(() => {
      try {
        if (!paymentWorker.running) {
          logger.warn("Payment worker not running; restarting");
          paymentWorker.start();
        }
      } catch (err) {
        logger.error("Worker supervisor check failed", { error: err });
      }
    }, 30 * 1e3);
  } catch (err) {
    logger.error("Failed to start worker supervisor", { error: err });
  }
}
var init_worker_runner = __esm({
  "server/worker-runner.ts"() {
    "use strict";
    init_payment_worker();
    init_security();
    if (__require.main === module) {
      startWorkerSupervisor();
    }
  }
});

// server/index.ts
import "dotenv/config";
import express2 from "express";

// server/routes.ts
import { createServer } from "http";
async function registerRoutes(app) {
  const httpServer = createServer(app);
  return httpServer;
}

// server/auth-routes.ts
init_storage();
init_auth();
init_schema_mongodb();

// server/email.ts
import nodemailer from "nodemailer";
function getEnv(name, fallback = "") {
  return process.env[name] ?? fallback;
}
var SMTP_USER = getEnv("EMAIL_SMTP_USER");
var SMTP_PASS = getEnv("EMAIL_SMTP_PASS");
var EMAIL_FROM = getEnv("EMAIL_FROM", SMTP_USER || "no-reply@example.com");
var transporter = nodemailer.createTransport({
  host: getEnv("EMAIL_SMTP_HOST", "smtp.gmail.com"),
  port: Number(getEnv("EMAIL_SMTP_PORT", "587")),
  secure: getEnv("EMAIL_SMTP_SECURE", "false") === "true",
  // true for 465, false for other ports
  auth: SMTP_USER && SMTP_PASS ? { user: SMTP_USER, pass: SMTP_PASS } : void 0
});
async function sendMail(opts) {
  const { to, subject, text, html } = opts;
  const mailOptions = {
    from: EMAIL_FROM,
    to,
    subject,
    text,
    html
  };
  try {
    const info = await transporter.sendMail(mailOptions);
    return {
      accepted: info.accepted || [],
      rejected: info.rejected || [],
      envelope: info.envelope || void 0,
      messageId: info.messageId
    };
  } catch (err) {
    const e = err;
    const msg = e?.message || "unknown email error";
    throw new Error(`sendMail failed: ${msg}`);
  }
}
async function sendOtpEmail(email, code, opts) {
  const minutes = opts?.minutesValid ?? 10;
  const subject = `Your verification code \u2014 expires in ${minutes} minutes`;
  const html = `<p>Your verification code is <strong>${code}</strong>.</p><p>This code will expire in ${minutes} minutes. If you didn't request this, you can ignore this email.</p>`;
  const text = `Your verification code is ${code}. It expires in ${minutes} minutes.`;
  return await sendMail({ to: email, subject, html, text });
}

// server/auth-routes.ts
init_schema_mongodb();
init_encryption();
var authRateLimit = createRateLimiter(15 * 60 * 1e3, 5);
var generalRateLimit = createRateLimiter(60 * 1e3, 60);
var validateSignupInput = (req) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return "Username and password are required";
  }
  if (!SecurityUtils.validateUsername(username)) {
    return "Username must be 3-30 characters, alphanumeric, underscore or hyphen only";
  }
  return null;
};
var validateLoginInput = (req) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return "Username and password are required";
  }
  return null;
};
var validateApiKeyInput = (req) => {
  const { name } = req.body;
  if (!name) {
    return "API key name is required";
  }
  if (name.length < 1 || name.length > 100) {
    return "API key name must be 1-100 characters";
  }
  return null;
};
function registerAuthRoutes(app) {
  app.post(
    "/api/auth/signup",
    authRateLimit,
    validateInput([validateSignupInput]),
    async (req, res) => {
      try {
        const parsed = insertUserSchema.safeParse(req.body);
        if (!parsed.success) {
          return res.status(400).json({
            error: "Validation failed",
            message: "Invalid input data",
            details: parsed.error.errors
          });
        }
        const { email, otpCode } = req.body;
        if (!email || !otpCode) {
          return res.status(400).json({ error: "OTP verification required", message: "email and otpCode are required" });
        }
        const otpRecord = await EmailOtp.findOne({ email: email.toLowerCase(), code: otpCode });
        if (!otpRecord) {
          return res.status(400).json({ error: "Invalid or expired OTP", message: "OTP not found or expired" });
        }
        await EmailOtp.deleteOne({ _id: otpRecord._id });
        const existingUser = await storage.getUserByUsername(parsed.data.username);
        if (existingUser) {
          return res.status(409).json({
            error: "User already exists",
            message: "A user with this username already exists"
          });
        }
        const user = await storage.createUser(parsed.data);
        const { accessToken, refreshToken } = await AuthService.generateTokens(user);
        res.cookie("refreshToken", refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: 7 * 24 * 60 * 60 * 1e3,
          // 7 days
          path: "/api/auth"
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
      } catch (error) {
        console.error("Signup error:", error);
        if (error.message.includes("Password must contain")) {
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
  app.post(
    "/api/auth/send-otp",
    authRateLimit,
    async (req, res) => {
      try {
        const { email } = req.body;
        if (!email) {
          return res.status(400).json({ error: "Email required", message: "Please provide an email address" });
        }
        const normalized = String(email).toLowerCase().trim();
        const code = Math.floor(1e5 + Math.random() * 9e5).toString();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1e3);
        await EmailOtp.create({ email: normalized, code, expiresAt });
        try {
          await sendOtpEmail(normalized, code, { minutesValid: 10 });
        } catch (err) {
          console.error("Failed to send OTP email:", err);
          return res.status(500).json({ error: "Failed to send OTP", message: "Email sending failed" });
        }
        res.json({ message: "OTP sent" });
      } catch (error) {
        console.error("send-otp error:", error);
        res.status(500).json({ error: "Failed to send OTP", message: "An internal error occurred" });
      }
    }
  );
  app.post(
    "/api/auth/verify-otp",
    authRateLimit,
    async (req, res) => {
      try {
        const { email, code } = req.body;
        if (!email || !code) {
          return res.status(400).json({ error: "Invalid request", message: "email and code are required" });
        }
        const normalized = String(email).toLowerCase().trim();
        const otpRecord = await EmailOtp.findOne({ email: normalized, code });
        if (!otpRecord) {
          return res.status(400).json({ error: "Invalid or expired OTP", message: "OTP not found or expired" });
        }
        await EmailOtp.deleteOne({ _id: otpRecord._id });
        res.json({ message: "OTP verified" });
      } catch (error) {
        console.error("verify-otp error:", error);
        res.status(500).json({ error: "OTP verification failed", message: "An internal error occurred" });
      }
    }
  );
  app.post(
    "/api/auth/login",
    authRateLimit,
    validateInput([validateLoginInput]),
    async (req, res) => {
      try {
        const { username, password } = req.body;
        const sanitizedUsername = SecurityUtils.sanitizeInput(username);
        const user = await storage.authenticateUser(sanitizedUsername, password);
        if (!user) {
          return res.status(401).json({
            error: "Authentication failed",
            message: "Invalid username or password"
          });
        }
        const { accessToken, refreshToken } = await AuthService.generateTokens(user);
        res.cookie("refreshToken", refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: 7 * 24 * 60 * 60 * 1e3,
          // 7 days
          path: "/api/auth"
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
      } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({
          error: "Login failed",
          message: "An error occurred during login"
        });
      }
    }
  );
  app.post(
    "/api/auth/refresh",
    generalRateLimit,
    async (req, res) => {
      try {
        const refreshToken = req.cookies?.refreshToken;
        if (!refreshToken) {
          return res.status(401).json({
            error: "Refresh token missing",
            message: "No refresh token provided"
          });
        }
        const newAccessToken = await AuthService.refreshAccessToken(refreshToken);
        res.json({
          accessToken: newAccessToken
        });
      } catch (error) {
        console.error("Token refresh error:", error);
        res.status(401).json({
          error: "Token refresh failed",
          message: "Invalid or expired refresh token"
        });
      }
    }
  );
  app.post(
    "/api/auth/logout",
    generalRateLimit,
    async (req, res) => {
      res.clearCookie("refreshToken", {
        path: "/api/auth"
      });
      res.json({
        message: "Logged out successfully"
      });
    }
  );
  app.get(
    "/api/auth/profile",
    generalRateLimit,
    authenticateToken,
    async (req, res) => {
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
      } catch (error) {
        console.error("Profile fetch error:", error);
        res.status(500).json({
          error: "Profile fetch failed",
          message: "An error occurred while fetching profile"
        });
      }
    }
  );
  app.post(
    "/api/auth/change-password",
    authRateLimit,
    authenticateToken,
    async (req, res) => {
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
        const user = await storage.authenticateUser(req.user.username, currentPassword);
        if (!user) {
          return res.status(401).json({
            error: "Authentication failed",
            message: "Current password is incorrect"
          });
        }
        await storage.updateUserPassword(req.user._id.toString(), newPassword);
        res.json({
          message: "Password updated successfully"
        });
      } catch (error) {
        console.error("Password change error:", error);
        if (error.message.includes("Password must contain")) {
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
  app.get(
    "/api/api-keys",
    generalRateLimit,
    authenticateToken,
    async (req, res) => {
      try {
        if (!req.user) {
          return res.status(401).json({
            error: "Authentication required",
            message: "User not authenticated"
          });
        }
        const keys = await storage.getApiKeys(req.user._id.toString());
        res.json(keys.map((key) => ({
          id: key._id,
          name: key.name,
          key: key.key,
          created: key.createdAt?.toISOString().split("T")[0] || "Unknown",
          lastUsed: key.lastUsed ? formatRelativeTime(key.lastUsed) : "Never",
          requests: key.requests,
          credits: key.credits || 0
        })));
      } catch (error) {
        console.error("Get API keys error:", error);
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
    async (req, res) => {
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
          created: apiKey.createdAt?.toISOString().split("T")[0] || "Unknown",
          lastUsed: "Never",
          requests: 0,
          credits: 3,
          message: "API key created successfully with 3.0 testing credits"
        });
      } catch (error) {
        console.error("Create API key error:", error);
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
    async (req, res) => {
      try {
        if (!req.user) {
          return res.status(401).json({
            error: "Authentication required",
            message: "User not authenticated"
          });
        }
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
      } catch (error) {
        console.error("Delete API key error:", error);
        res.status(500).json({
          error: "Failed to delete API key",
          message: error.message
        });
      }
    }
  );
}
function formatRelativeTime(date) {
  const now = /* @__PURE__ */ new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 6e4);
  const diffHours = Math.floor(diffMs / 36e5);
  const diffDays = Math.floor(diffMs / 864e5);
  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? "s" : ""} ago`;
  if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? "s" : ""} ago`;
  return `${diffDays} day${diffDays > 1 ? "s" : ""} ago`;
}

// server/vite.ts
import express from "express";
import fs from "fs";
import path2 from "path";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
var vite_config_default = defineConfig({
  plugins: [
    react(),
    runtimeErrorOverlay(),
    ...process.env.NODE_ENV !== "production" && process.env.REPL_ID !== void 0 ? [
      await import("@replit/vite-plugin-cartographer").then(
        (m) => m.cartographer()
      ),
      await import("@replit/vite-plugin-dev-banner").then(
        (m) => m.devBanner()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets")
    }
  },
  root: path.resolve(import.meta.dirname, "client"),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  },
  server: {
    fs: {
      strict: true,
      deny: ["**/.*"]
    }
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app.use(vite.middlewares);
  app.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path2.resolve(
        import.meta.dirname,
        "..",
        "client",
        "index.html"
      );
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app) {
  const distPath = path2.resolve(import.meta.dirname, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app.use(express.static(distPath));
  app.use("*", (_req, res) => {
    res.sendFile(path2.resolve(distPath, "index.html"));
  });
}

// server/index.ts
init_security();

// server/db.ts
init_mongodb();
init_mongodb();
var initializeDatabase = async () => {
  try {
    await connectToDatabase();
  } catch (error) {
    console.error("Failed to initialize database connection:", error);
    process.exit(1);
  }
};
initializeDatabase();

// server/index.ts
(async () => {
  const app = express2();
  setupSecurity(app);
  app.use(express2.json({ limit: "10mb" }));
  app.use(express2.urlencoded({ extended: false, limit: "10mb" }));
  try {
    await initializeDatabase();
    logger.info("Database initialized successfully");
    try {
      const mongoose4 = await import("mongoose");
      const db = mongoose4.connection && mongoose4.connection.db || null;
      if (db) {
        const locks = db.collection("worker_locks");
        await locks.createIndex({ lockedUntil: 1 }, { expireAfterSeconds: 0 });
        logger.info("Ensured TTL index on worker_locks.lockedUntil");
      } else {
        logger.warn("Mongoose db instance not available; skipping worker_locks TTL index creation");
      }
    } catch (e) {
      logger.warn("Could not create TTL index for worker_locks", { error: e });
    }
  } catch (error) {
    logger.error("Failed to initialize database:", error);
    logger.warn("Continuing without database connection - some features may not work");
    logger.info("To fix: Check your MongoDB Atlas IP whitelist or connection string");
  }
  app.use((req, res, next) => {
    const start = Date.now();
    const path4 = req.path;
    let capturedJsonResponse = void 0;
    const originalResJson = res.json;
    res.json = function(bodyJson, ...args) {
      capturedJsonResponse = bodyJson;
      return originalResJson.apply(res, [bodyJson, ...args]);
    };
    res.on("finish", () => {
      const duration = Date.now() - start;
      if (path4.startsWith("/api")) {
        let logLine = `${req.method} ${path4} ${res.statusCode} in ${duration}ms`;
        if (process.env.NODE_ENV !== "production" && capturedJsonResponse) {
          const filtered = { ...capturedJsonResponse };
          if (filtered.accessToken) filtered.accessToken = "[REDACTED]";
          if (filtered.key && typeof filtered.key === "string") {
            filtered.key = filtered.key.substring(0, 10) + "...";
          }
          logLine += ` :: ${JSON.stringify(filtered)}`;
        }
        if (logLine.length > 120) {
          logLine = logLine.slice(0, 119) + "\u2026";
        }
        log(logLine);
      }
    });
    next();
  });
  registerAuthRoutes(app);
  const { registerSolanaRoutes: registerSolanaRoutes2 } = await Promise.resolve().then(() => (init_solana_routes(), solana_routes_exports));
  registerSolanaRoutes2(app);
  const { registerBillingRoutes: registerBillingRoutes2 } = await Promise.resolve().then(() => (init_billing_routes(), billing_routes_exports));
  registerBillingRoutes2(app);
  const { registerRecurringSubscriptionRoutes: registerRecurringSubscriptionRoutes2 } = await Promise.resolve().then(() => (init_recurring_subscription_routes(), recurring_subscription_routes_exports));
  registerRecurringSubscriptionRoutes2(app);
  const { registerDocsRoutes: registerDocsRoutes2 } = await Promise.resolve().then(() => (init_docs_routes(), docs_routes_exports));
  registerDocsRoutes2(app);
  const { paymentWorker: paymentWorker2 } = await Promise.resolve().then(() => (init_payment_worker(), payment_worker_exports));
  paymentWorker2.start();
  try {
    const { startWorkerSupervisor: startWorkerSupervisor2 } = await Promise.resolve().then(() => (init_worker_runner(), worker_runner_exports));
    startWorkerSupervisor2();
  } catch (err) {
    logger.warn("Worker supervisor failed to start", { error: err });
  }
  const server = await registerRoutes(app);
  setupErrorLogging(app);
  app.use((err, req, res, next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    logger.error("API Error:", {
      error: message,
      status,
      method: req.method,
      path: req.path,
      ip: req.ip,
      userAgent: req.headers["user-agent"]
    });
    const isProduction = process.env.NODE_ENV === "production";
    res.status(status).json({
      error: isProduction && status === 500 ? "Internal Server Error" : message,
      status
    });
  });
  setupGracefulShutdown();
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const port = parseInt(process.env.PORT || "3000", 10);
  server.listen(port, "0.0.0.0", () => {
    const formattedTime = new Intl.DateTimeFormat("en-US", {
      dateStyle: "short",
      timeStyle: "medium",
      timeZone: "America/New_York"
    }).format(/* @__PURE__ */ new Date());
    logger.info(`\u{1F680} BlockSub API Server running on port ${port} at ${formattedTime}`);
    logger.info(`Environment: ${process.env.NODE_ENV || "development"}`);
    logger.info("Security features enabled: \u2713 Helmet \u2713 CORS \u2713 Rate Limiting \u2713 Session Management \u2713 JWT Auth");
    log(`serving on http://localhost:${port}`);
  });
})();
