import mongoose, { Schema, Document } from 'mongoose';
import { z } from "zod";

// Recurring Subscription Interface (separate from existing subscription)
export interface IRecurringSubscription extends Document {
  _id: string;
  subscriptionId: string; // human-friendly id or UUID
  userId?: string; // owner user (optional if only apiKey ties)
  apiKeyId: string; // the API key this subscription powers
  plan: string; // flexible plan name - can be any string defined by the developer
  priceUsd: number; // nominal price in USD for recordkeeping
  chain: 'solana';
  asset: 'SOL' | 'SPL';
  tokenMint?: string; // for SPL token payments like USDC
  userTokenAccount?: string; // explicit user token account (ATA or custom)
    tokenMint?: string; // for SPL token payments like USDC
  userTokenAccount?: string; // explicit user token account (ATA or custom)

  // New fields for merchant + token billing
  merchantAddress?: string; // merchant Solana address where payments are sent
  tokenAmount?: string; // base-units string for token billing (optional store)
  
  // Recurring subscription specific fields
  status: 'pending_wallet_connection' | 'wallet_connected' | 'active' | 'past_due' | 'suspended' | 'canceled' | 'expired';
  isRecurring: boolean; // always true for this schema
  walletAddress?: string; // connected Phantom wallet address
  walletConnectionQR?: string; // QR code for wallet connection
  walletConnectionDeeplink?: string; // Phantom deeplink for wallet connection
  
  // Billing cycle management
  billingInterval: 'monthly' | 'yearly';
  nextBillingDate?: Date;
  lastPaymentDate?: Date;
  lastPaymentSignature?: string;
  currentPeriodStart?: Date;
  currentPeriodEnd?: Date;
  
  // Payment failure handling
  failedPaymentAttempts: number;
  maxFailedAttempts: number; // configurable max attempts
  gracePeriodDays: number; // grace period after failed payment
  gracePeriodUntil?: Date;
  
  // Subscription lifecycle
  trialEndDate?: Date; // optional trial period
  canceledAt?: Date;
  cancellationReason?: string;
  cancelAtPeriodEnd: boolean; // cancel at end of current billing period
  
  // Integration features
  webhookUrl?: string; // webhook for subscription events
  webhookSecret?: string; // secret for webhook verification
  // relayerSecret stored encrypted at rest
  relayerSecretEncrypted?: string;
  relayerSecretSetAt?: Date;
  metadata?: Record<string, any>; // flexible metadata storage
  
  // Auto-renewal settings
  autoRenew: boolean;
  pausedAt?: Date; // if subscription is paused
  pauseReason?: string;
  // Optional merchant relayer URL
  relayerUrl?: string;
  // Delegation (SPL token approval) details for merchants
  delegatePubkey?: string; // delegate/approved authority pubkey (merchant)
  delegateAllowance?: string; // allowance in token base units (string to avoid precision issues)
  delegateApprovedAt?: Date;
  delegateApprovalSignature?: string;
  
  
  createdAt: Date;
  updatedAt: Date;
}

// Recurring Subscription Schema
const recurringSubscriptionSchema = new Schema<IRecurringSubscription>({
  subscriptionId: { type: String, required: true, unique: true, index: true },
  userId: { type: String, required: false, index: true },
  apiKeyId: { type: String, required: true, index: true, ref: 'ApiKey' },
  plan: { type: String, required: true, index: true, maxlength: 100 }, // flexible plan name - any string
  priceUsd: { type: Number, required: true },
  chain: { type: String, enum: ['solana'], default: 'solana', required: true },
  asset: { type: String, enum: ['SOL', 'SPL'], required: true },
  tokenMint: { type: String, required: false, index: true },
  merchantAddress: { type: String, required: false, index: true }, // merchant Solana address
  tokenAmount: { type: String, required: false, default: null }, // base-units string for SPL billing

  // Status and recurring fields
  status: { 
    type: String, 
    enum: ['pending_wallet_connection', 'wallet_connected', 'active', 'past_due', 'suspended', 'canceled', 'expired'], 
    default: 'pending_wallet_connection', 
    index: true 
  },
  isRecurring: { type: Boolean, default: true },
  walletAddress: { type: String, required: false, index: true },
  walletConnectionQR: { type: String, required: false },
  walletConnectionDeeplink: { type: String, required: false },
  
  // Billing cycle
  billingInterval: { type: String, enum: ['monthly', 'yearly'], default: 'monthly', index: true },
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
  metadata: { type: Schema.Types.Mixed, default: {} },
  // Optional merchant relayer URL to which unsigned delegate-transfer intents are POSTed
  relayerUrl: { type: String, required: false },
  
  // Auto-renewal
  autoRenew: { type: Boolean, default: true },
  pausedAt: { type: Date, required: false },
  pauseReason: { type: String, required: false },
  // Delegation (SPL token approval) details for merchants
  delegatePubkey: { type: String, required: false }, // delegate/approved authority pubkey (merchant)
  delegateAllowance: { type: String, required: false }, // allowance in token base units (string to avoid precision issues)
  delegateApprovedAt: { type: Date, required: false },
  delegateApprovalSignature: { type: String, required: false },
  userTokenAccount: { type: String, required: false, index: true },
}, { timestamps: true });

// Indexes for performance
recurringSubscriptionSchema.index({ apiKeyId: 1, status: 1 });
recurringSubscriptionSchema.index({ nextBillingDate: 1, status: 1 }); // for billing processing
recurringSubscriptionSchema.index({ walletAddress: 1, status: 1 }); // for wallet queries
recurringSubscriptionSchema.index({ status: 1, gracePeriodUntil: 1 }); // for grace period cleanup
recurringSubscriptionSchema.index({ status: 1, nextBillingDate: 1, autoRenew: 1 }); // for billing automation
recurringSubscriptionSchema.index({ cancelAtPeriodEnd: 1, currentPeriodEnd: 1 }); // for end-of-period cancellations
// recurringSubscriptionSchema.index({ merchantAddress: 1 });
// recurringSubscriptionSchema.index({ tokenMint: 1 }); 
// Subscription Event Log Interface (for audit trail)
export interface ISubscriptionEvent extends Document {
  _id: string;
  subscriptionId: string;
  eventType: 'created' | 'wallet_connected' | 'activated' | 'payment_succeeded' | 'payment_failed' | 'renewed' | 'canceled' | 'suspended' | 'expired' | 'reactivated';
  eventData: Record<string, any>;
  transactionSignature?: string; // if related to blockchain transaction
  createdAt: Date;
}

// Subscription Event Schema
const subscriptionEventSchema = new Schema<ISubscriptionEvent>({
  subscriptionId: { type: String, required: true, index: true },
  eventType: { 
    type: String, 
    enum: ['created', 'wallet_connected', 'activated', 'payment_succeeded', 'payment_failed', 'renewed', 'canceled', 'suspended', 'expired', 'reactivated'],
    required: true,
    index: true
  },
  eventData: { type: Schema.Types.Mixed, default: {} },
  transactionSignature: { type: String, required: false, index: true },
}, { timestamps: true });

subscriptionEventSchema.index({ subscriptionId: 1, createdAt: -1 }); // for event history
subscriptionEventSchema.index({ eventType: 1, createdAt: -1 }); // for event type queries

// Export Models
export const RecurringSubscription = mongoose.models.RecurringSubscription || mongoose.model<IRecurringSubscription>('RecurringSubscription', recurringSubscriptionSchema);
export const SubscriptionEvent = mongoose.models.SubscriptionEvent || mongoose.model<ISubscriptionEvent>('SubscriptionEvent', subscriptionEventSchema);

// Zod Validation Schemas
export const createRecurringSubscriptionSchema = z.object({
  plan: z.string().min(1).max(100), // flexible plan name - any string
  priceUsd: z.number().min(0.01).max(99999), // price in USD - developer specified
  billingInterval: z.enum(['monthly','yearly']).default('monthly'),
  asset: z.enum(['SOL','SPL']).default('SPL'),
  tokenMint: z.string().min(32).max(64).optional(),
  webhookUrl: z.string().url().optional(),
  metadata: z.record(z.any()).optional(),
  trialDays: z.number().min(0).max(365).optional(), // trial period in days - up to 1 year
});

// Require tokenMint when asset is SPL
export const createRecurringSubscriptionSchemaRefined = createRecurringSubscriptionSchema.superRefine((data, ctx) => {
  if (data.asset === 'SPL' && !data.tokenMint) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'tokenMint is required for SPL subscriptions' });
  }
});

export const connectWalletSchema = z.object({
  walletAddress: z.string().min(32).max(44), // Solana wallet address
  signature: z.string().min(64), // signature proof of wallet ownership
  message: z.string(), // message that was signed
});

export const updateRecurringSubscriptionSchema = z.object({
  plan: z.string().min(1).max(100).optional(), // flexible plan name - any string
  priceUsd: z.number().min(0.01).max(99999).optional(), // price in USD - developer specified
  autoRenew: z.boolean().optional(),
  webhookUrl: z.string().url().optional(),
  metadata: z.record(z.any()).optional(),
  cancelAtPeriodEnd: z.boolean().optional(),
});

// Type exports
export type CreateRecurringSubscription = z.infer<typeof createRecurringSubscriptionSchema>;
export type ConnectWallet = z.infer<typeof connectWalletSchema>;
export type UpdateRecurringSubscription = z.infer<typeof updateRecurringSubscriptionSchema>;
export type RecurringSubscriptionType = IRecurringSubscription;

export type SubscriptionEventType = ISubscriptionEvent;

