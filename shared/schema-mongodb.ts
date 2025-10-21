import mongoose, { Schema, Document } from 'mongoose';
import { z } from "zod";

// User Interface
export interface IUser extends Document {
  _id: string;
  username: string;
  password: string;
  createdAt: Date;
  updatedAt: Date;
}

// API Key Interface
export interface IApiKey extends Document {
  _id: string;
  userId: string;
  name: string;
  key: string;
  createdAt: Date;
  lastUsed?: Date;
  requests: number;
  credits: number;
  allowedWebhookDomains?: string[];
}

// User Schema
const userSchema = new Schema<IUser>({
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

// API Key Schema
const apiKeySchema = new Schema<IApiKey>({
  userId: {
    type: String,
    required: true,
    ref: 'User',
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
  // Optional list of domains this API key is allowed to use for webhooks
  allowedWebhookDomains: { type: [String], required: false, default: [] },
  requests: {
    type: Number,
    default: 0
  },
  credits: {
    type: Number,
    default: 3.0
  }
}, {
  timestamps: true
});

// Create additional indexes for better performance (avoiding duplicates)
apiKeySchema.index({ createdAt: -1 });

// Payment Order Interface
export interface IPaymentOrder extends Document {
  _id: string;
  orderId: string;
  subscriptionId?: string; // associated recurring subscription id
  status: 'pending' | 'signed' | 'submitted' | 'confirmed' | 'expired' | 'failed';
  // Asset selection
  assetType: 'SOL' | 'SPL';
  amountLamports?: number; // for SOL only
  tokenMint?: string; // SPL mint address base58
  tokenAmount?: string; // SPL amount in base units (string to avoid JS precision issues)
  merchant: string; // merchant pubkey base58
  userPubkey?: string; // optional until connect step
  memo?: string; // e.g., order:<orderId>
  reference?: string; // optional reference pubkey base58
  unsignedTxB64?: string; // stored for debug/regeneration
  signature?: string; // tx signature if known
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

// Payment Order Schema
const paymentOrderSchema = new Schema<IPaymentOrder>({
  orderId: { type: String, required: true, unique: true, index: true },
  subscriptionId: { type: String, required: false, index: true },
  status: { type: String, enum: ['pending', 'signed', 'submitted', 'confirmed', 'expired', 'failed'], default: 'pending', index: true },
  assetType: { type: String, enum: ['SOL', 'SPL'], required: true, index: true },
  amountLamports: { type: Number, required: false },
  tokenMint: { type: String, required: false, index: true },
  tokenAmount: { type: String, required: false },
  merchant: { type: String, required: true, index: true },
  userPubkey: { type: String, required: false },
  memo: { type: String, required: false },
  reference: { type: String, required: false, index: true },
  unsignedTxB64: { type: String, required: false },
  signature: { type: String, required: false, index: true },
  expiresAt: { type: Date, required: true, index: true },
}, { timestamps: true });

paymentOrderSchema.index({ createdAt: -1 });
paymentOrderSchema.index({ status: 1, expiresAt: 1 });

// Subscription Interface
export interface ISubscription extends Document {
  _id: string;
  subscriptionId: string; // human-friendly id or UUID
  userId?: string; // owner user (optional if only apiKey ties)
  apiKeyId: string; // the API key this subscription powers
  plan: 'basic' | 'pro';
  priceUsd: number; // nominal price in USD for recordkeeping
  chain: 'solana' | 'ethereum' | 'bitcoin' | 'xrp' | 'other';
  asset: 'SOL' | 'SPL' | 'ETH' | 'BTC' | 'XRP' | 'OTHER';
  tokenMint?: string; // for SPL token payments like USDC
  orderId?: string; // associated PaymentOrder.orderId
  status: 'pending' | 'active' | 'expired' | 'canceled' | 'suspended' | 'past_due';
  activeUntil?: Date; // when active, the expiration date
  creditedAt?: Date; // set when monthly credits are granted
  
  // Enhanced recurring subscription fields
  isRecurring: boolean; // whether this is a recurring subscription
  walletAddress?: string; // connected Phantom wallet address
  nextBillingDate?: Date; // when the next payment is due
  billingInterval: 'monthly' | 'yearly'; // billing frequency
  failedPaymentAttempts: number; // track failed payment attempts
  lastPaymentDate?: Date; // last successful payment
  lastPaymentSignature?: string; // last successful transaction signature
  canceledAt?: Date; // when subscription was canceled
  cancellationReason?: string; // reason for cancellation
  gracePeriodUntil?: Date; // grace period for failed payments
  webhookUrl?: string; // optional webhook for events
  metadata?: Record<string, any>; // flexible metadata storage
  
  createdAt: Date;
  updatedAt: Date;
}

// Subscription Schema
const subscriptionSchema = new Schema<ISubscription>({
  subscriptionId: { type: String, required: true, unique: true, index: true },
  userId: { type: String, required: false, index: true },
  apiKeyId: { type: String, required: true, index: true, ref: 'ApiKey' },
  plan: { type: String, enum: ['basic', 'pro'], required: true, index: true },
  priceUsd: { type: Number, required: true },
  chain: { type: String, enum: ['solana', 'ethereum', 'bitcoin', 'xrp', 'other'], required: true },
  asset: { type: String, enum: ['SOL', 'SPL', 'ETH', 'BTC', 'XRP', 'OTHER'], required: true },
  tokenMint: { type: String, required: false },
  orderId: { type: String, required: false, index: true },
  status: { type: String, enum: ['pending', 'active', 'expired', 'canceled', 'suspended', 'past_due'], default: 'pending', index: true },
  activeUntil: { type: Date, required: false },
  creditedAt: { type: Date, required: false },
  
  // Enhanced recurring subscription fields
  isRecurring: { type: Boolean, default: true, index: true },
  walletAddress: { type: String, required: false, index: true },
  nextBillingDate: { type: Date, required: false, index: true },
  billingInterval: { type: String, enum: ['monthly', 'yearly'], default: 'monthly', index: true },
  failedPaymentAttempts: { type: Number, default: 0 },
  lastPaymentDate: { type: Date, required: false },
  lastPaymentSignature: { type: String, required: false },
  canceledAt: { type: Date, required: false },
  cancellationReason: { type: String, required: false },
  gracePeriodUntil: { type: Date, required: false },
  webhookUrl: { type: String, required: false },
  metadata: { type: Schema.Types.Mixed, default: {} },
}, { timestamps: true });

subscriptionSchema.index({ apiKeyId: 1, status: 1 });
subscriptionSchema.index({ nextBillingDate: 1, status: 1 }); // for recurring payment processing
subscriptionSchema.index({ walletAddress: 1, status: 1 }); // for wallet-based queries
subscriptionSchema.index({ isRecurring: 1, nextBillingDate: 1 }); // for billing automation
subscriptionSchema.index({ status: 1, gracePeriodUntil: 1 }); // for grace period cleanup

// Export Models
export const User = mongoose.models.User || mongoose.model<IUser>('User', userSchema);
export const ApiKey = mongoose.models.ApiKey || mongoose.model<IApiKey>('ApiKey', apiKeySchema);
export const PaymentOrder = mongoose.models.PaymentOrder || mongoose.model<IPaymentOrder>('PaymentOrder', paymentOrderSchema);

// Webhook delivery logs and queue
export interface IWebhookDelivery extends Document {
  _id: string;
  subscriptionId?: string;
  url: string;
  event: string;
  payload: any;
  attempts: number;
  nextAttemptAt?: Date;
  lastAttemptAt?: Date;
  lastStatusCode?: number;
  lastResponseSnippet?: string;
  status: 'pending' | 'success' | 'failed';
  createdAt: Date;
  updatedAt: Date;
}

const webhookDeliverySchema = new Schema<IWebhookDelivery>({
  subscriptionId: { type: String, required: false, index: true },
  url: { type: String, required: true },
  event: { type: String, required: true, index: true },
  payload: { type: Schema.Types.Mixed, required: true },
  attempts: { type: Number, default: 0 },
  nextAttemptAt: { type: Date, required: false, index: true },
  lastAttemptAt: { type: Date, required: false },
  lastStatusCode: { type: Number, required: false },
  lastResponseSnippet: { type: String, required: false },
  status: { type: String, enum: ['pending', 'success', 'failed'], default: 'pending', index: true },
}, { timestamps: true });

webhookDeliverySchema.index({ nextAttemptAt: 1, status: 1 });

export const WebhookDelivery = mongoose.models.WebhookDelivery || mongoose.model<IWebhookDelivery>('WebhookDelivery', webhookDeliverySchema);
export const Subscription = mongoose.models.Subscription || mongoose.model<ISubscription>('Subscription', subscriptionSchema);

// Email OTP schema for signup verification
export interface IEmailOtp extends Document {
  _id: string;
  email: string;
  code: string;
  createdAt: Date;
  expiresAt: Date;
}

const emailOtpSchema = new Schema<IEmailOtp>({
  email: { type: String, required: true, index: true },
  code: { type: String, required: true },
  expiresAt: { type: Date, required: true, index: { expires: 0 } },
}, { timestamps: true });

export const EmailOtp = mongoose.models.EmailOtp || mongoose.model<IEmailOtp>('EmailOtp', emailOtpSchema);

// Zod Validation Schemas
export const insertUserSchema = z.object({
  username: z.string().min(3).max(50).toLowerCase(),
  password: z.string().min(6).max(100)
});

export const insertApiKeySchema = z.object({
  userId: z.string(),
  name: z.string().min(1).max(100).trim()
});

export const createPaymentIntentSchema = z.object({
  orderId: z.string().min(6).max(64),
  merchant: z.string().min(32),
  userPubkey: z.string().min(32).optional(),
  memo: z.string().max(128).optional(),
  // For SOL
  amountLamports: z.number().int().positive().optional(),
  // For SPL
  tokenMint: z.string().min(32).optional(),
  tokenAmount: z.string().regex(/^\d+$/).optional(), // base units as string
}).refine((d) => {
  const sol = typeof d.amountLamports === 'number' && !d.tokenMint && !d.tokenAmount;
  const spl = !d.amountLamports && !!d.tokenMint && !!d.tokenAmount;
  return sol || spl;
}, {
  message: 'Provide either amountLamports for SOL or tokenMint+tokenAmount for SPL',
});

export const createSubscriptionSchema = z.object({
  apiKeyId: z.string().min(1),
  userPubkey: z.string().min(32), // Solana payer
  plan: z.enum(['basic','pro']).default('pro'),
});

// Type exports
export type InsertUser = z.infer<typeof insertUserSchema>;
export type UserType = IUser;
export type ApiKeyType = IApiKey;
export type InsertApiKey = z.infer<typeof insertApiKeySchema>;
export type PaymentOrderType = IPaymentOrder;
export type SubscriptionType = ISubscription;
