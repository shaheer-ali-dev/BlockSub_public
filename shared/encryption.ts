import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { promisify } from 'util';

// Production-level encryption configuration
const ENCRYPTION_CONFIG = {
  // High-cost bcrypt rounds for password hashing (minimum 12 for production)
  BCRYPT_ROUNDS: 14,
  
  // AES-256-GCM for data encryption at rest
  ALGORITHM: 'aes-256-gcm' as const,
  KEY_LENGTH: 32,
  IV_LENGTH: 16,
  SALT_LENGTH: 32,
  TAG_LENGTH: 16,
  
  // Key derivation
  PBKDF2_ITERATIONS: 100000, // Minimum recommended iterations
  PBKDF2_KEYLEN: 32,
  PBKDF2_DIGEST: 'sha512' as const,
};

// Ensure encryption key is available
const getEncryptionKey = (): Buffer => {
  const key = process.env.ENCRYPTION_KEY;
  if (!key) {
    throw new Error('ENCRYPTION_KEY environment variable is required');
  }
  
  if (key.length < 64) { // 32 bytes hex encoded
    throw new Error('ENCRYPTION_KEY must be at least 64 characters (32 bytes hex)');
  }
  
  return Buffer.from(key, 'hex');
};

// Generate a cryptographically secure encryption key
export const generateEncryptionKey = (): string => {
  return crypto.randomBytes(ENCRYPTION_CONFIG.KEY_LENGTH).toString('hex');
};

// Password hashing utilities
export class PasswordService {
  /**
   * Hash a password using bcrypt with high cost factor
   */
  static async hash(password: string): Promise<string> {
    if (!password || password.length < 8) {
      throw new Error('Password must be at least 8 characters long');
    }
    
    // Add complexity validation
    if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/.test(password)) {
      throw new Error('Password must contain at least one lowercase letter, uppercase letter, digit, and special character');
    }
    
    try {
      const salt = await bcrypt.genSalt(ENCRYPTION_CONFIG.BCRYPT_ROUNDS);
      return await bcrypt.hash(password, salt);
    } catch (error) {
      throw new Error('Failed to hash password');
    }
  }

  /**
   * Verify a password against its hash
   */
  static async verify(password: string, hash: string): Promise<boolean> {
    try {
      return await bcrypt.compare(password, hash);
    } catch (error) {
      return false;
    }
  }

  /**
   * Check if password hash needs rehashing (due to increased security requirements)
   */
  static needsRehash(hash: string): boolean {
    try {
      const rounds = bcrypt.getRounds(hash);
      return rounds < ENCRYPTION_CONFIG.BCRYPT_ROUNDS;
    } catch {
      return true; // If we can't determine rounds, assume rehash needed
    }
  }
}

// Data encryption utilities for sensitive data at rest
export class DataEncryption {
  /**
   * Encrypt sensitive data using AES-256-GCM
   */
  static encrypt(plaintext: string, additionalData?: string): string {
    try {
      const key = getEncryptionKey();
      const iv = crypto.randomBytes(ENCRYPTION_CONFIG.IV_LENGTH);
      
      const cipher = crypto.createCipher(ENCRYPTION_CONFIG.ALGORITHM, key);
      cipher.setAAD(Buffer.from(additionalData || '', 'utf8'));
      
      let encrypted = cipher.update(plaintext, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      const tag = cipher.getAuthTag();
      
      // Combine IV + encrypted data + auth tag
      const result = {
        iv: iv.toString('hex'),
        data: encrypted,
        tag: tag.toString('hex'),
        aad: additionalData || ''
      };
      
      return Buffer.from(JSON.stringify(result)).toString('base64');
    } catch (error) {
      throw new Error('Encryption failed');
    }
  }

  /**
   * Decrypt data encrypted with encrypt()
   */
  static decrypt(encryptedData: string): string {
    try {
      const key = getEncryptionKey();
      const parsed = JSON.parse(Buffer.from(encryptedData, 'base64').toString('utf8'));
      
      const decipher = crypto.createDecipher(ENCRYPTION_CONFIG.ALGORITHM, key);
      
      if (parsed.aad) {
        decipher.setAAD(Buffer.from(parsed.aad, 'utf8'));
      }
      
      decipher.setAuthTag(Buffer.from(parsed.tag, 'hex'));
      
      let decrypted = decipher.update(parsed.data, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      throw new Error('Decryption failed');
    }
  }
}

// API Key generation with cryptographic security
export class APIKeyService {
  private static readonly PREFIX_LIVE = 'sk_live_';
  private static readonly PREFIX_TEST = 'sk_test_';
  private static readonly KEY_LENGTH = 32; // 256 bits

  /**
   * Generate a cryptographically secure API key
   */
  static generateApiKey(isLive: boolean = false): string {
    const prefix = isLive ? this.PREFIX_LIVE : this.PREFIX_TEST;
    const randomBytes = crypto.randomBytes(this.KEY_LENGTH);
    const keyPart = randomBytes.toString('hex');
    
    return `${prefix}${keyPart}`;
  }

  /**
   * Validate API key format
   */
  static validateKeyFormat(apiKey: string): boolean {
    const livePattern = new RegExp(`^${this.PREFIX_LIVE}[a-f0-9]{64}$`);
    const testPattern = new RegExp(`^${this.PREFIX_TEST}[a-f0-9]{64}$`);
    
    return livePattern.test(apiKey) || testPattern.test(apiKey);
  }

  /**
   * Check if API key is live or test
   */
  static isLiveKey(apiKey: string): boolean {
    return apiKey.startsWith(this.PREFIX_LIVE);
  }

  /**
   * Hash API key for database storage (one-way hash)
   */
  static async hashKey(apiKey: string): Promise<string> {
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
    
    // Store salt + iterations + hash
    const combined = {
      salt: salt.toString('hex'),
      iterations,
      hash: hash.toString('hex')
    };
    
    return Buffer.from(JSON.stringify(combined)).toString('base64');
  }

  /**
   * Verify API key against stored hash
   */
  static async verifyKey(apiKey: string, storedHash: string): Promise<boolean> {
    try {
      const combined = JSON.parse(Buffer.from(storedHash, 'base64').toString('utf8'));
      const { salt, iterations, hash } = combined;
      
      const pbkdf2 = promisify(crypto.pbkdf2);
      const derivedKey = await pbkdf2(
        apiKey,
        Buffer.from(salt, 'hex'),
        iterations,
        ENCRYPTION_CONFIG.PBKDF2_KEYLEN,
        ENCRYPTION_CONFIG.PBKDF2_DIGEST
      );
      
      const derivedHash = derivedKey.toString('hex');
      
      // Constant-time comparison to prevent timing attacks
      return crypto.timingSafeEqual(
        Buffer.from(hash, 'hex'),
        Buffer.from(derivedHash, 'hex')
      );
    } catch {
      return false;
    }
  }
}

// Secure token generation for sessions, CSRF, etc.
export class TokenService {
  /**
   * Generate cryptographically secure random token
   */
  static generateSecureToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Generate URL-safe token
   */
  static generateURLSafeToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('base64url');
  }

  /**
   * Generate time-based token with expiration
   */
  static generateTimedToken(expirationMinutes: number = 60): string {
    const expiry = Date.now() + (expirationMinutes * 60 * 1000);
    const randomPart = crypto.randomBytes(24).toString('hex');
    
    const tokenData = {
      exp: expiry,
      rnd: randomPart
    };
    
    return Buffer.from(JSON.stringify(tokenData)).toString('base64url');
  }

  /**
   * Verify timed token
   */
  static verifyTimedToken(token: string): boolean {
    try {
      const tokenData = JSON.parse(Buffer.from(token, 'base64url').toString('utf8'));
      return tokenData.exp > Date.now();
    } catch {
      return false;
    }
  }
}

// Input sanitization and validation
export class SecurityUtils {
  /**
   * Sanitize user input to prevent XSS
   */
  static sanitizeInput(input: string): string {
    return input
      .replace(/[<>'"&]/g, (char) => {
        const entities: { [key: string]: string } = {
          '<': '&lt;',
          '>': '&gt;',
          "'": '&#x27;',
          '"': '&quot;',
          '&': '&amp;'
        };
        return entities[char] || char;
      })
      .trim();
  }

  /**
   * Validate email format
   */
  static validateEmail(email: string): boolean {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email) && email.length <= 254;
  }

  /**
   * Validate username format
   */
  static validateUsername(username: string): boolean {
    // Allow alphanumeric, underscore, hyphen. 3-30 characters.
    const usernameRegex = /^[a-zA-Z0-9_-]{3,30}$/;
    return usernameRegex.test(username);
  }

  /**
   * Generate CSRF token
   */
  static generateCSRFToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Rate limiting helper - generate rate limit key
   */
  static generateRateLimitKey(ip: string, endpoint: string): string {
    return `rate_limit:${ip}:${endpoint}`;
  }
}

// Export configuration for other modules
export { ENCRYPTION_CONFIG };