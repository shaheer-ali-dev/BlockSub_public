import { type UserType, type InsertUser, type ApiKeyType, type InsertApiKey, User, ApiKey } from "@shared/schema-mongodb";
import { connectToDatabase } from "@shared/mongodb";
import { PasswordService, APIKeyService } from "@shared/encryption";

export interface IStorage {
  getUser(id: string): Promise<UserType | undefined>;
  getUserByUsername(username: string): Promise<UserType | undefined>;
  createUser(user: InsertUser): Promise<UserType>;
  authenticateUser(username: string, password: string): Promise<UserType | null>;
  updateUserPassword(userId: string, newPassword: string): Promise<void>;
  getApiKeys(userId?: string): Promise<ApiKeyType[]>;
  getApiKeyById(id: string): Promise<ApiKeyType | undefined>;
  getApiKeyByKey(key: string): Promise<ApiKeyType | undefined>;
  createApiKey(apiKey: InsertApiKey): Promise<ApiKeyType>;
  deleteApiKey(id: string): Promise<void>;
  updateApiKeyUsage(id: string): Promise<void>;
  deductCredits(apiKeyId: string, amount: number): Promise<boolean>;
  getApiKeyCredits(apiKeyId: string): Promise<number | undefined>;
}

export class MongoDbStorage implements IStorage {
  private async ensureConnection(): Promise<void> {
    await connectToDatabase();
  }

  async getUser(id: string): Promise<UserType | undefined> {
    await this.ensureConnection();
    try {
      const user = await User.findById(id).exec();
      return user || undefined;
    } catch (error) {
      console.error('Error fetching user by id:', error);
      return undefined;
    }
  }

  async getUserByUsername(username: string): Promise<UserType | undefined> {
    await this.ensureConnection();
    try {
      const user = await User.findOne({ username: username.toLowerCase() }).exec();
      return user || undefined;
    } catch (error) {
      console.error('Error fetching user by username:', error);
      return undefined;
    }
  }

  async createUser(insertUser: InsertUser): Promise<UserType> {
    await this.ensureConnection();
    try {
      // Hash password before storing
      const hashedPassword = await PasswordService.hash(insertUser.password);
      
      const user = new User({
        username: insertUser.username.toLowerCase(),
        password: hashedPassword
      });
      const savedUser = await user.save();
      return savedUser;
    } catch (error: any) {
      if (error.code === 11000) {
        throw new Error('Username already exists');
      }
      console.error('Error creating user:', error);
      throw new Error('Failed to create user');
    }
  }

  async authenticateUser(username: string, password: string): Promise<UserType | null> {
    await this.ensureConnection();
    try {
      const user = await User.findOne({ username: username.toLowerCase() }).exec();
      
      if (!user) {
        return null;
      }
      
      // Verify password
      const isValid = await PasswordService.verify(password, user.password);
      
      if (!isValid) {
        return null;
      }
      
      // Check if password needs rehashing (due to increased security)
      if (PasswordService.needsRehash(user.password)) {
        try {
          const newHash = await PasswordService.hash(password);
          user.password = newHash;
          await user.save();
        } catch (error) {
          console.warn('Failed to rehash password:', error);
          // Continue anyway, auth was successful
        }
      }
      
      return user;
    } catch (error) {
      console.error('Error authenticating user:', error);
      return null;
    }
  }

  async updateUserPassword(userId: string, newPassword: string): Promise<void> {
    await this.ensureConnection();
    try {
      const hashedPassword = await PasswordService.hash(newPassword);
      
      const result = await User.findByIdAndUpdate(
        userId,
        { password: hashedPassword },
        { new: true }
      ).exec();
      
      if (!result) {
        throw new Error('User not found');
      }
    } catch (error) {
      console.error('Error updating user password:', error);
      throw new Error('Failed to update password');
    }
  }

  async getApiKeys(userId?: string): Promise<ApiKeyType[]> {
    await this.ensureConnection();
    try {
      const query = userId ? { userId } : {};
      const apiKeys = await ApiKey.find(query).sort({ createdAt: -1 }).exec();
      return apiKeys;
    } catch (error) {
      console.error('Error fetching API keys:', error);
      return [];
    }
  }

  async getApiKeyById(id: string): Promise<ApiKeyType | undefined> {
    await this.ensureConnection();
    try {
      const apiKey = await ApiKey.findById(id).exec();
      return apiKey || undefined;
    } catch (error) {
      console.error('Error fetching API key by id:', error);
      return undefined;
    }
  }

  async createApiKey(insertApiKey: InsertApiKey): Promise<ApiKeyType> {
    await this.ensureConnection();
    try {
      // Generate cryptographically secure API key
      const key = APIKeyService.generateApiKey(false); // Always generate test keys in dev
      
      const apiKey = new ApiKey({
        userId: insertApiKey.userId,
        name: insertApiKey.name,
        key: key,
        requests: 0,
        credits: 3.0 // Give initial credits to new API keys (platform decision)
      });
      
      const savedApiKey = await apiKey.save();
      return savedApiKey;
    } catch (error: any) {
      if (error.code === 11000) {
        throw new Error('API key already exists');
      }
      console.error('Error creating API key:', error);
      throw new Error('Failed to create API key');
    }
  }

  async deleteApiKey(id: string): Promise<void> {
    await this.ensureConnection();
    try {
      const result = await ApiKey.findByIdAndDelete(id).exec();
      if (!result) {
        throw new Error('API key not found');
      }
    } catch (error) {
      console.error('Error deleting API key:', error);
      throw new Error('Failed to delete API key');
    }
  }

  async updateApiKeyUsage(id: string): Promise<void> {
    await this.ensureConnection();
    try {
      await ApiKey.findByIdAndUpdate(
        id,
        {
          $set: { lastUsed: new Date() },
          $inc: { requests: 1 }
        },
        { new: true }
      ).exec();
    } catch (error) {
      console.error('Error updating API key usage:', error);
      // Don't throw here as this is just tracking usage
    }
  }

  // Additional utility methods for MongoDB
  async getApiKeyByKey(key: string): Promise<ApiKeyType | undefined> {
    await this.ensureConnection();
    try {
      const apiKey = await ApiKey.findOne({ key }).exec();
      return apiKey || undefined;
    } catch (error) {
      console.error('Error fetching API key by key:', error);
      return undefined;
    }
  }

  async getUsersCount(): Promise<number> {
    await this.ensureConnection();
    try {
      return await User.countDocuments();
    } catch (error) {
      console.error('Error counting users:', error);
      return 0;
    }
  }

  async getApiKeysCount(userId?: string): Promise<number> {
    await this.ensureConnection();
    try {
      const query = userId ? { userId } : {};
      return await ApiKey.countDocuments(query);
    } catch (error) {
      console.error('Error counting API keys:', error);
      return 0;
    }
  }

  async deductCredits(apiKeyId: string, amount: number): Promise<boolean> {
    await this.ensureConnection();
    try {
      const result = await ApiKey.findOneAndUpdate(
        { 
          _id: apiKeyId,
          credits: { $gte: amount } // Only update if sufficient credits
        },
        {
          $inc: { credits: -amount, requests: 1 },
          $set: { lastUsed: new Date() }
        },
        { new: true }
      ).exec();
      
      return !!result; // Return true if update was successful
    } catch (error) {
      console.error('Error deducting credits:', error);
      return false;
    }
  }

  async getApiKeyCredits(apiKeyId: string): Promise<number | undefined> {
    await this.ensureConnection();
    try {
      const apiKey = await ApiKey.findById(apiKeyId).select('credits').exec();
      return apiKey?.credits;
    } catch (error) {
      console.error('Error fetching API key credits:', error);
      return undefined;
    }
  }
}

export const storage = new MongoDbStorage();
