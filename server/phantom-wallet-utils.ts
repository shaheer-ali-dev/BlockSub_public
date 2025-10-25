import { Connection, PublicKey, SystemProgram, Transaction, clusterApiUrl } from "@solana/web3.js";
import { createTransferInstruction, getAssociatedTokenAddressSync, createAssociatedTokenAccountInstruction, getAccount, TokenAccountNotFoundError } from "@solana/spl-token";
import QRCode from "qrcode";
import { v4 as uuidv4 } from "uuid";
import { getSolanaConnection } from "./solana";
import { logger } from "./security";
import crypto from "crypto";
import nacl from "tweetnacl";


const MEMO_PROGRAM_ID = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");

export interface WalletConnectionRequest {
  subscriptionId: string;
  message: string;
  nonce: string;
  timestamp: number;
  dappUrl: string;
  dappIcon?: string;
  dappTitle: string;
}

export interface WalletConnectionQR {
  qrCodeDataUrl: string;
  deeplink: string;
  connectionUrl: string;
  message: string;
  nonce: string;
  expiresAt: Date;
}

export interface RecurringPaymentIntent {
  subscriptionId: string;
  paymentId: string;
  amount?: string; // string for token base-units or lamports as string
  amountLamports?: number | null;
  tokenMint?: string | null;
  walletAddress?: string | null;
  merchantAddress?: string | null;
  memo?: string | null;
  unsignedTxB64?: string | null;
  phantomUrl?: string | null;
  qrDataUrl?: string | null;
  expiresAt?: Date | string | null;


function getEnv(name: string, fallback: string): string {
  return process.env[name] ?? fallback;
}

/**
 * Generate a secure connection request for Phantom wallet
 */
export function generateWalletConnectionRequest(subscriptionId: string): WalletConnectionRequest {
  const nonce = crypto.randomBytes(16).toString('hex');
  const timestamp = Date.now();
  const dappUrl = getEnv("PHANTOM_DAPP_URL", "http://localhost:3000");
  const dappTitle = getEnv("PHANTOM_DAPP_TITLE", "BlockSub Recurring Payments");
  
  const message = `Connect wallet for recurring subscription\n\nSubscription ID: ${subscriptionId}\nDApp: ${dappTitle}\nNonce: ${nonce}\nTimestamp: ${timestamp}`;

  return {
    subscriptionId,
    message,
    nonce,
    timestamp,
    dappUrl,
    dappTitle,
    dappIcon: getEnv("PHANTOM_DAPP_ICON", ""),
  };
}

/**
 * Generate QR code and deeplink for Phantom wallet connection
 */
export async function generateWalletConnectionQR(connectionRequest: WalletConnectionRequest): Promise<WalletConnectionQR> {
  const baseUrl = getEnv("PHANTOM_CALLBACK_BASE_URL", "http://localhost:3000");
  const connectionUrl = `${baseUrl}/api/recurring-subscriptions/phantom/connect-callback`;
  
  // Create connection parameters
  const params = new URLSearchParams({
    subscription_id: connectionRequest.subscriptionId,
    message: connectionRequest.message,
    nonce: connectionRequest.nonce,
    timestamp: connectionRequest.timestamp.toString(),
    dapp_url: connectionRequest.dappUrl,
    dapp_title: connectionRequest.dappTitle,
    callback_url: connectionUrl,
  });

  if (connectionRequest.dappIcon) {
    params.append('dapp_icon', connectionRequest.dappIcon);
  }

  // Create Phantom deeplink for wallet connection (not transaction signing)
  const deeplink = `https://phantom.app/ul/v1/connect?${params.toString()}`;
  
  // Generate QR code
  // `qrcode` package typings vary between versions. Cast to any to avoid
  // incompatible overloads and ensure we get a string data URL.
  const qrCodeDataUrl = String(await (QRCode as any).toDataURL(deeplink, {
    errorCorrectionLevel: 'M',
    type: 'image/png',
    quality: 0.92,
    margin: 1,
    color: {
      dark: '#000000',
      light: '#FFFFFF'
    },
    width: 256
  }));

  // Connection expires in 10 minutes
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  return {
    qrCodeDataUrl,
    deeplink,
    connectionUrl,
    message: connectionRequest.message,
    nonce: connectionRequest.nonce,
    expiresAt,
  };
}

/**
 * Verify wallet signature for connection
 */
export function verifyWalletConnection(
  publicKey: string,
  signature: string,
  message: string
): boolean {
  try {
    const publicKeyObj = new PublicKey(publicKey);
    const signatureBuffer = Buffer.from(signature, 'base64');
    const messageBuffer = Buffer.from(message, 'utf8');
    
    // Verify Ed25519 signature using Solana's built-in verification
    // The signature should be 64 bytes for Ed25519
    if (signatureBuffer.length !== 64) {
      logger.error("Invalid signature length", { length: signatureBuffer.length });
      return false;
    }
    
    // Use a proper signature verification
    // For Ed25519 verification, we use tweetnacl
    
    // Convert public key to Uint8Array (32 bytes for Ed25519)
    const publicKeyBytes = publicKeyObj.toBytes();
    
    // Verify the signature
    const isValid = nacl.sign.detached.verify(
      messageBuffer,
      signatureBuffer,
      publicKeyBytes
    );
    
    if (!isValid) {
      logger.warn("Signature verification failed", { 
        publicKey: publicKey.substring(0, 8) + '...', 
        messageLength: message.length 
      });
    }
    
    return isValid;
  } catch (error) {
    logger.error("Wallet signature verification failed", { 
      error: error instanceof Error ? error.message : String(error),
      publicKey: publicKey.substring(0, 8) + '...' 
    });
    return false;
  }
}

/**
 * Create a recurring payment intent for a subscription
 */

export async function createRecurringPaymentIntent(params: {
  subscriptionId: string;
  walletAddress: string; // payer address (user)
  assetType: 'SOL' | 'SPL';
  amountLamports?: number;
  tokenMint?: string;
  tokenAmount?: string; // base-units string for SPL
  billingCycle: number;
  merchantAddress?: string; // optional merchant override (base58)
}): Promise<RecurringPaymentIntent> {
  const connection = getSolanaConnection();
  const paymentId = `pmt_${uuidv4().replace(/-/g, "")}`;

  // merchant fallback order: params.merchantAddress -> env MERCHANT_SOL_ADDRESS
  const merchant = params.merchantAddress || process.env.MERCHANT_SOL_ADDRESS;
  if (!merchant) throw new Error("MERCHANT_SOL_ADDRESS is not configured (and no merchantAddress provided)");

  // Validate user & merchant keys
  const userPubkey = new PublicKey(params.walletAddress);
  const merchantPubkey = new PublicKey(merchant);

  // Build memo to identify recurring payment and subscription/billing cycle
  const memo = `recurring:${params.subscriptionId}:${params.billingCycle}:${paymentId}`;

  // Build tx
  const tx = new Transaction();

  if (params.assetType === 'SOL') {
    if (!params.amountLamports) throw new Error('amountLamports is required for SOL payments');
    tx.add(SystemProgram.transfer({
      fromPubkey: userPubkey,
      toPubkey: merchantPubkey,
      lamports: params.amountLamports,
    }));
  } else if (params.assetType === 'SPL') {
    if (!params.tokenMint || !params.tokenAmount) throw new Error('tokenMint and tokenAmount are required for SPL payments');

    const tokenMintPubkey = new PublicKey(params.tokenMint);
    const amount = BigInt(params.tokenAmount);

    // Derive ATAs
    const userAta = (await import("@solana/spl-token")).getAssociatedTokenAddressSync(tokenMintPubkey, userPubkey);
    const merchantAta = (await import("@solana/spl-token")).getAssociatedTokenAddressSync(tokenMintPubkey, merchantPubkey);

    // If merchant ATA doesn't exist, add create instruction (payer=user)
    try {
      await getAccount(connection, merchantAta);
    } catch (err) {
      if (err instanceof TokenAccountNotFoundError) {
        tx.add(createAssociatedTokenAccountInstruction(
          userPubkey, // payer
          merchantAta,
          merchantPubkey,
          tokenMintPubkey
        ));
      } else {
        throw err;
      }
    }

    tx.add(createTransferInstruction(
      userAta,
      merchantAta,
      userPubkey,
      amount
    ) as any);
  } else {
    throw new Error('Invalid assetType');
  }

  // Memo instruction
  const memoIx = {
    keys: [],
    programId: MEMO_PROGRAM_ID,
    data: Buffer.from(memo, "utf8"),
  } as any;
  tx.add(memoIx);

  // Set recent blockhash and fee payer
  const { blockhash } = await connection.getLatestBlockhash("finalized");
  tx.recentBlockhash = blockhash;
  tx.feePayer = userPubkey;

  // Serialize unsigned transaction
  const serialized = tx.serialize({ requireAllSignatures: false, verifySignatures: false });
  const unsignedTxB64 = Buffer.from(serialized).toString("base64");

  // Build Phantom deeplink for signTransaction (redirect to subscription payment callback)
  const baseCallback = process.env.PHANTOM_CALLBACK_BASE_URL || getEnv("PHANTOM_DAPP_URL") || "http://localhost:3000";
  const redirectUrl = `${baseCallback}/api/recurring-subscriptions/phantom/payment-callback?subscription_id=${encodeURIComponent(params.subscriptionId)}&payment_id=${encodeURIComponent(paymentId)}`;
  const phantomUrl = `https://phantom.app/ul/v1/signTransaction?transaction=${encodeURIComponent(unsignedTxB64)}` +
    `&redirect_uri=${encodeURIComponent(redirectUrl)}` +
    `&cluster=${encodeURIComponent(process.env.SOLANA_CLUSTER || "devnet")}` +
    `&app_url=${encodeURIComponent(process.env.PHANTOM_DAPP_URL || "")}` +
    `&app_title=${encodeURIComponent(process.env.PHANTOM_DAPP_TITLE || "BlockSub")}`;

  // QR for phantomUrl
  const qrDataUrl = String(await (QRCode as any).toDataURL(phantomUrl, { errorCorrectionLevel: 'M', width: 512 }));

  // Expires (approx)
  const expiresAt = new Date(Date.now() + (30 * 60 * 1000)); // 30 minutes

  const result: RecurringPaymentIntent = {
    subscriptionId: params.subscriptionId,
    paymentId,
    amount: params.tokenAmount ?? (params.amountLamports ? String(params.amountLamports) : undefined),
    amountLamports: params.amountLamports ?? null,
    tokenMint: params.tokenMint ?? null,
    walletAddress: params.walletAddress,
    merchantAddress: merchant,
    memo,
    unsignedTxB64,
    phantomUrl,
    qrDataUrl,
    expiresAt,
  };

  return result;
}/**
 * Generate a friendly message for wallet connection
 */
export function generateConnectionMessage(subscriptionId: string, plan: string, priceUsd: number): string {
  const dappTitle = getEnv("PHANTOM_DAPP_TITLE", "BlockSub");
  const timestamp = new Date().toISOString();
  
  return `🔗 Connect Wallet to ${dappTitle}

📋 Subscription Details:
• Plan: ${plan.charAt(0).toUpperCase() + plan.slice(1)}
• Price: $${priceUsd}/month
• ID: ${subscriptionId}

⏰ ${timestamp}

By connecting, you authorize recurring monthly payments for this subscription until canceled.

🔒 This message proves wallet ownership and cannot be replayed.`;
}

/**
 * Calculate next billing date based on interval
 */
export function calculateNextBillingDate(
  currentDate: Date,
  billingInterval: 'monthly' | 'yearly',
  currentPeriodStart?: Date
): Date {
  const nextDate = new Date(currentPeriodStart || currentDate);
  
  if (billingInterval === 'monthly') {
    nextDate.setMonth(nextDate.getMonth() + 1);
  } else if (billingInterval === 'yearly') {
    nextDate.setFullYear(nextDate.getFullYear() + 1);
  }
  
  return nextDate;
}

/**
 * Calculate trial end date
 */
export function calculateTrialEndDate(startDate: Date, trialDays: number): Date {
  const trialEnd = new Date(startDate);
  trialEnd.setDate(trialEnd.getDate() + trialDays);
  return trialEnd;

}

