import { Connection, PublicKey, SystemProgram, Transaction, clusterApiUrl } from "@solana/web3.js";
import { createTransferInstruction, getAssociatedTokenAddressSync, createAssociatedTokenAccountInstruction, getAccount, TokenAccountNotFoundError } from "@solana/spl-token";
import QRCode from "qrcode";
import { v4 as uuidv4 } from "uuid";
import { getSolanaConnection } from "./solana";
import { logger } from "./security";
import crypto from "crypto";
import nacl from "tweetnacl";
import bs58 from 'bs58';


const MEMO_PROGRAM_ID = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");

export interface WalletConnectionRequest {
  subscriptionId: string;
  message: string;
  nonce: string;
  timestamp: number;
  dappUrl: string;
  dappIcon?: string;
  dappTitle: string;
  dappEncryptionPublicKey?: string; // base58
}

export interface WalletConnectionQR {
  qrCodeDataUrl: string;
  deeplink: string;
  connectionUrl: string;
  message: string;
  nonce: string;
  expiresAt: Date;
  dappEncryptionPublicKey?: string;
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
}

function getEnv(name: string, fallback: string): string {
  return process.env[name] ?? fallback;
}

/**
 * Derive dApp encryption keypair from env var PHANTOM_DAPP_ENCRYPTION_PRIVATE_KEY (base64).
 * Returns { publicKeyBase58, secretKeyUint8Array }
 */
function getDappEncryptionKeypair() {
  const privB64 = process.env.PHANTOM_DAPP_ENCRYPTION_PRIVATE_KEY || getEnv("PHANTOM_DAPP_ENCRYPTION_PRIVATE_KEY", "");
  if (!privB64) {
    // no configured keypair; caller must handle absence
    return null;
  }
  const secret = Uint8Array.from(Buffer.from(privB64, "base64"));
  if (secret.length !== 32) {
    throw new Error("PHANTOM_DAPP_ENCRYPTION_PRIVATE_KEY must decode to 32 bytes (base64)");
  }
  // nacl.box.keyPair.fromSecretKey expects a 32-byte secret key
  const kp = nacl.box.keyPair.fromSecretKey(secret);
  const pubBase58 = new PublicKey(Buffer.from(kp.publicKey)).toBase58();
  return { publicKeyBase58: pubBase58, secretKey: secret };
}

/**
 * Generate a secure connection request for Phantom wallet
 */export function generateWalletConnectionRequest(subscriptionId: string): WalletConnectionRequest {
  const nonce = crypto.randomBytes(16).toString('hex');
  const timestamp = Date.now();
  const dappUrl = getEnv("PHANTOM_DAPP_URL", "https://blocksub-public.1.onrender.com");
  const dappTitle = getEnv("PHANTOM_DAPP_TITLE", "BlockSub Recurring Payments");
  
  const message = `Connect wallet for recurring subscription\n\nSubscription ID: ${subscriptionId}\nDApp: ${dappTitle}\nNonce: ${nonce}\nTimestamp: ${timestamp}`;

  // Try to include dapp encryption public key if configured
  let dappEncryptionPublicKey: string | undefined = undefined;
  try {
    const kp = getDappEncryptionKeypair();
    console.los('Using dapp public key for deeplink', { pub: kp?.publicKeyBase58 })
    if (kp) dappEncryptionPublicKey = kp.publicKeyBase58;
  } catch (e) {
    logger.debug('DApp encryption key not available or invalid', { error: e instanceof Error ? e.message : String(e) });
  }

  return {
    subscriptionId,
    message,
    nonce,
    timestamp,
    dappUrl,
    dappTitle,
    dappIcon: getEnv("PHANTOM_DAPP_ICON", ""),
    dappEncryptionPublicKey,
  };
}

/**
 * Generate QR code and deeplink for Phantom wallet connection using a compact deeplink format.
 *
 * Produces deeplink like:
 *   https://phantom.app/ul/v1/connect?app_url=<encoded_app_url>&redirect_link=<encoded_callback>&dapp_encryption_public_key=<pub>
 *
 * Rationale:
 * - Some long querystrings with many params were causing the Phantom client to not properly show the connect prompt.
 * - The compact set (app_url, redirect_link, dapp_encryption_public_key) is a known-working form and is shorter.
 *
 * Note:
 * - callback_url used by older code is mapped to redirect_link param as in the example you provided.
 * - We still preserve the message/nonce in the returned WalletConnectionQR for manual-sign verification fallback (POST /connect-wallet).
 */
export async function generateWalletConnectionQR(connectionRequest: WalletConnectionRequest): Promise<WalletConnectionQR> {
  // Use publicly reachable base for Phantom callback/redirect
  const baseCallback = getEnv("PHANTOM_CALLBACK_BASE_URL", "https://blocksub-public-1.onrender.com");
  const callbackUrl = `${baseCallback}/api/recurring-subscriptions/phantom/connect-callback/${encodeURIComponent(connectionRequest.subscriptionId)}`;

  // Short/compact deeplink params (encode values)
  const appUrlEnc = encodeURIComponent(connectionRequest.dappUrl || getEnv("PHANTOM_DAPP_URL", "https://blocksub-public-1.onrender.com"));
  const redirectLinkEnc = encodeURIComponent(callbackUrl);

  // Include public encryption key if available
  const dappPub = connectionRequest.dappEncryptionPublicKey || "Div4a4NEpSzWzT1A46zkvZaiLvwRmSHhQcxW5nS4VRfK";
  const qParams: string[] = [
    `app_url=${appUrlEnc}`,
    `redirect_link=${redirectLinkEnc}`,
      `subscription_id=${encodeURIComponent(connectionRequest.subscriptionId)}`
  ];
  if (dappPub) {
    qParams.push(`dapp_encryption_public_key=${encodeURIComponent(dappPub)}`);
  }

  const deeplink = `https://phantom.app/ul/v1/connect?${qParams.join("&")}`;

  // Generate QR code (smaller image to keep payload compact)
  const qrOptions: any = {
    errorCorrectionLevel: 'M',
    width: 320
  };
  const qrCodeDataUrl = String(await (QRCode as any).toDataURL(deeplink, qrOptions));

  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

  return {
    qrCodeDataUrl,
    deeplink,
    connectionUrl: callbackUrl,
    message: connectionRequest.message,
    nonce: connectionRequest.nonce,
    expiresAt,
    dappEncryptionPublicKey: connectionRequest.dappEncryptionPublicKey,
  };
}/**
 * Decrypt Phantom callback payload.
 * - phantomPubBase58: phantom_encryption_public_key param (base58)
 * - dataB64: data param (base64)
 * - nonceB64: nonce param (base64)
 *
 * Returns decrypted string (UTF-8) or throws.
 *
 * Notes:
 * - PHANTOM_DAPP_ENCRYPTION_PRIVATE_KEY env var must be set (base64 32 bytes).
 * - Phantom expects you to provide dapp_encryption_public_key when initiating connect (we include it above when configured).
 */

export function decryptPhantomCallbackData(phantomPub: string, dataStr: string, nonceStr: string): string {
  if (!phantomPub || !dataStr || !nonceStr) throw new Error('missing_encryption_params');

  // load server dApp secret key (base64)
  const privB64 = process.env.PHANTOM_DAPP_ENCRYPTION_PRIVATE_KEY || 'sYAfa0/DFl621Ryj5yulV5sYECUd7uNzMo32rU1WoiM=';
  if (!privB64) throw new Error('PHANTOM_DAPP_ENCRYPTION_PRIVATE_KEY not configured');
  const secretKey = Uint8Array.from(Buffer.from(privB64, 'base64'));
  if (secretKey.length !== 32) throw new Error('PHANTOM_DAPP_ENCRYPTION_PRIVATE_KEY must decode to 32 bytes (base64)');

  // phantomPub is base58 (public key)
  const phantomPubBytes = new PublicKey(phantomPub).toBytes(); // 32 bytes

  // decode ciphertext (likely base64)
  let ciphertext: Uint8Array;
  try {
    ciphertext = Uint8Array.from(Buffer.from(dataStr, 'base64'));
  } catch (e) {
    // fallback: try base58 (rare)
    try {
      ciphertext = Uint8Array.from(bs58.decode(dataStr));
    } catch (e2) {
      throw new Error('invalid_data_encoding');
    }
  }

  // decode nonce: try base64 first, then base58
  let nonce: Uint8Array | null = null;
  try {
    const b = Buffer.from(nonceStr, 'base64');
    if (b.length === 24) nonce = Uint8Array.from(b);
  } catch {}
  if (!nonce) {
    try {
      const b = bs58.decode(nonceStr);
      if (b.length === 24) nonce = Uint8Array.from(b);
    } catch {}
  }
  if (!nonce) throw new Error('invalid_nonce_encoding_or_length (expected 24 bytes)');

  // Attempt decryption
  const opened = nacl.box.open(ciphertext, nonce, phantomPubBytes, secretKey);
  if (!opened) throw new Error('decryption_failed');
  return Buffer.from(opened).toString('utf8');
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
      publicKey: publicKey ? (publicKey.substring(0, 8) + '...') : undefined
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
  const baseCallback = process.env.PHANTOM_CALLBACK_BASE_URL || getEnv("PHANTOM_DAPP_URL") || "https://blocksub-public-1.onrender.com";
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













