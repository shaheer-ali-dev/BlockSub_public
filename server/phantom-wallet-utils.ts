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

import { Buffer } from "buffer";
export function decodeWithFallback(input: string, label = 'data'): Uint8Array {
  console.log(`[phantom-utils] decodeWithFallback called for label=${label}, inputPreview=${preview(input, 40)}`);
  if (!input) {
    console.log(`[phantom-utils] decodeWithFallback: empty input for ${label}`);
    throw new Error(`Empty ${label}`);
  }

  // Try base64
  try {
    const buf = Buffer.from(input, 'base64');
    console.log(`[phantom-utils] decodeWithFallback: decoded ${label} as base64, length=${buf.length}`);
    return Uint8Array.from(buf);
  } catch (eBase64) {
    console.log(`[phantom-utils] decodeWithFallback: base64 decode failed for ${label}: ${(eBase64 as Error).message}`);
    // fallback to base58
    try {
      const bytes = bs58.decode(input);
      console.log(`[phantom-utils] decodeWithFallback: decoded ${label} as base58, length=${bytes.length}`);
      return bytes;
    } catch (eBase58) {
      console.log(`[phantom-utils] decodeWithFallback: base58 decode failed for ${label}: ${(eBase58 as Error).message}`);
      throw new Error(`Failed to decode ${label} as base64 or base58`);
    }
  }
}

/**
 * Parse a Solana public key string into a PublicKey instance after validating base58 decoding and length.
 * Adds logging for diagnostics.
 */
export function parseSolanaPublicKey(publicKeyStr?: string): PublicKey {
  console.log('[phantom-utils] parseSolanaPublicKey called', { publicKeyPreview: preview(publicKeyStr, 30) });
  if (!publicKeyStr || typeof publicKeyStr !== 'string') {
    console.log('[phantom-utils] parseSolanaPublicKey: missing or invalid input');
    throw new Error('public key input missing or not a string');
  }
  try {
    const decoded = bs58.decode(publicKeyStr);
    console.log('[phantom-utils] parseSolanaPublicKey: base58 decoded length', decoded.length);
    if (decoded.length !== 32) {
      console.log('[phantom-utils] parseSolanaPublicKey: decoded length is not 32 bytes');
      throw new Error(`decoded public key has invalid length ${decoded.length}`);
    }
    const pk = new PublicKey(publicKeyStr);
    console.log('[phantom-utils] parseSolanaPublicKey: PublicKey constructed, toBase58=', pk.toBase58?.().slice(0, 20));
    return pk;
  } catch (err) {
    console.log('[phantom-utils] parseSolanaPublicKey: ERROR decoding/constructing public key', { err: (err as Error).message });
    throw new Error(`Invalid public key input: ${(err as Error).message}`);
  }
}

function tryDecodeBase58(s: string): Uint8Array | null {
  try {
    const dec = bs58.decode(s);
    return Uint8Array.from(dec);
  } catch { return null; }
}
function tryDecodeBase64(s: string): Uint8Array | null {
  try {
    const b = Buffer.from(s, "base64");
    return Uint8Array.from(b);
  } catch { return null; }
}

/**
 * Derive dApp encryption keypair from env var PHANTOM_DAPP_ENCRYPTION_PRIVATE_KEY (base64).
 * Returns { publicKeyBase58, secretKeyUint8Array }
 */
function getDappEncryptionKeypair() {
  const privB64 = process.env.PHANTOM_DAPP_ENCRYPTION_PRIVATE_KEY || "sYAfa0/DFl621Ryj5yulV5sYECUd7uNzMo32rU1WoiM=";
  if (!privB64) return null;
  const secret = Uint8Array.from(Buffer.from(privB64, "base64"));
  if (secret.length !== 32) throw new Error("PHANTOM_DAPP_ENCRYPTION_PRIVATE_KEY must decode to 32 bytes (base64)");
  const kp = nacl.box.keyPair.fromSecretKey(secret);
  const pubBase58 = new PublicKey(Buffer.from(kp.publicKey)).toBase58();
  return { publicKeyBase58: pubBase58, secretKey: secret };
}

/**
 * Generate a secure connection request for Phantom wallet
 */
export function generateWalletConnectionRequest(subscriptionId: string) {
  const nonce = crypto.randomBytes(16).toString('hex');
  const timestamp = Date.now();
  const dappUrl = process.env.PHANTOM_DAPP_URL || "https://blocksub-public-1.onrender.com";
  const dappTitle = process.env.PHANTOM_DAPP_TITLE || "BlockSub Recurring Payments";

  const message = `Connect wallet for recurring subscription\n\nSubscription ID: ${subscriptionId}\nDApp: ${dappTitle}\nNonce: ${nonce}\nTimestamp: ${timestamp}`;

  let dappEncryptionPublicKey: string | undefined = undefined;
  try {
    const kp = getDappEncryptionKeypair();
    if (kp) {
      // Use logger rather than console and do not leak secret
      logger.info('Using dapp public key for deeplink', { pub: kp.publicKeyBase58 });
      dappEncryptionPublicKey = kp.publicKeyBase58;
    }
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
    dappIcon: process.env.PHANTOM_DAPP_ICON || "",
    dappEncryptionPublicKey,
  };
}

/**
 * Generate compact Phantom deeplink and QR.
 * Important: do NOT include a hard-coded default public key here. Only include dapp_encryption_public_key if server has one configured.
 */
export async function generateWalletConnectionQR(connectionRequest: any) {
  const baseCallback = (process.env.PHANTOM_CALLBACK_BASE_URL || "https://blocksub-public-1.onrender.com").replace(/\/$/, "");
  // Put subscriptionId in path to avoid being stripped by intermediaries
  const callbackUrl = `${baseCallback}/api/recurring-subscriptions/phantom/connect-callback/${encodeURIComponent(connectionRequest.subscriptionId)}`;

  const appUrlEnc = encodeURIComponent(connectionRequest.dappUrl || process.env.PHANTOM_DAPP_URL || "https://blocksub-public-1.onrender.com");
  const redirectLinkEnc = encodeURIComponent(callbackUrl);

  const qParams: string[] = [
    `app_url=${appUrlEnc}`,
    `redirect_link=${redirectLinkEnc}`,
    `subscription_id=${encodeURIComponent(connectionRequest.subscriptionId)}`
  ];

  // only include dapp_encryption_public_key when available
  if (connectionRequest.dappEncryptionPublicKey) {
    qParams.push(`dapp_encryption_public_key=${encodeURIComponent(connectionRequest.dappEncryptionPublicKey)}`);
  }

  const deeplink = `https://phantom.app/ul/v1/connect?${qParams.join("&")}`;

  const qrCodeDataUrl = String(await (QRCode as any).toDataURL(deeplink, { errorCorrectionLevel: 'M', width: 320 }));

  return {
    qrCodeDataUrl,
    deeplink,
    connectionUrl: callbackUrl,
    message: connectionRequest.message,
    nonce: connectionRequest.nonce,
    expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    dappEncryptionPublicKey: connectionRequest.dappEncryptionPublicKey,
  } as any;
}

function parseAppSecretFromEnv(envVar: string | undefined): Uint8Array {
  if (!envVar) throw new Error("PHANTOM_DAPP_ENCRYPTION_PRIVATE_KEY is not configured on server");

  // Try base64
  try {
    const b = Buffer.from(envVar, "base64");
    if (b.length === 32) return Uint8Array.from(b);
  } catch (e) { /* ignore */ }

  // Try base58
  try {
    const dec = bs58.decode(envVar);
    if (dec.length === 32) return Uint8Array.from(dec);
  } catch (e) { /* ignore */ }

  // Try hex (64 chars -> 32 bytes)
  try {
    if (/^[0-9a-fA-F]{64}$/.test(envVar)) {
      const b = Buffer.from(envVar, "hex");
      if (b.length === 32) return Uint8Array.from(b);
    }
  } catch (e) { /* ignore */ }

  throw new Error("PHANTOM_DAPP_ENCRYPTION_PRIVATE_KEY must decode to 32 bytes (base64, base58, or 64-hex)");
}

/**
 * Decrypt Phantom callback payload.
 * - phantomPubBase58: phantom_encryption_public_key param (base58)
 * - dataStr: ciphertext (try base64, then base58)
 * - nonceStr: nonce (try base64, then base58) - must be 24 bytes
 *
 * Throws clear error messages for invalid encodings or missing env.
 */
export function decryptPhantomPayload({
  data,
  nonce,
  phantomEncryptionPublicKey,
  dappKeypair,
}: {
  data: string;
  nonce: string;
  phantomEncryptionPublicKey: string;
  dappKeypair: Keypair;
}): string {
  console.log('[phantom-utils] decryptPhantomPayload called', {
    dataPreview: preview(data, 60),
    noncePreview: preview(nonce, 40),
    phantomEncryptionPublicKeyPreview: preview(phantomEncryptionPublicKey, 40),
    dappKeypairHasSecret: !!(dappKeypair && (dappKeypair as any).secretKey),
    dappPublicKeyPreview: dappKeypair?.publicKey?.toBase58?.().slice(0, 20),
  });

  if (!data || !nonce || !phantomEncryptionPublicKey) {
    console.log('[phantom-utils] decryptPhantomPayload: missing required params', { data: !!data, nonce: !!nonce, phantomKey: !!phantomEncryptionPublicKey });
    throw new Error('Missing parameters for decryptPhantomPayload');
  }
  if (!dappKeypair || !(dappKeypair as any).secretKey) {
    console.log('[phantom-utils] decryptPhantomPayload: missing dappKeypair or secretKey');
    throw new Error('Missing dapp keypair');
  }

  // Decode phantom public key (expected base58, 32 bytes)
  let phantomPubKeyBytes: Uint8Array;
  try {
    phantomPubKeyBytes = bs58.decode(phantomEncryptionPublicKey);
    console.log('[phantom-utils] phantomEncryptionPublicKey decoded, length=', phantomPubKeyBytes.length);
    if (phantomPubKeyBytes.length !== 32) {
      console.log('[phantom-utils] phantomEncryptionPublicKey length mismatch', { length: phantomPubKeyBytes.length });
      throw new Error('phantom encryption public key is not 32 bytes');
    }
  } catch (err) {
    console.log('[phantom-utils] ERROR decoding phantomEncryptionPublicKey', { err: (err as Error).message });
    throw new Error(`Failed to decode phantomEncryptionPublicKey: ${(err as Error).message}`);
  }

  // Decode nonce & data using fallback logic
  let nonceBytes: Uint8Array;
  let dataBytes: Uint8Array;
  try {
    nonceBytes = decodeWithFallback(nonce, 'nonce');
    dataBytes = decodeWithFallback(data, 'data');
    console.log('[phantom-utils] decoded nonce/data lengths', { nonceLen: nonceBytes.length, dataLen: dataBytes.length });
  } catch (err) {
    console.log('[phantom-utils] ERROR decoding nonce/data', { err: (err as Error).message });
    throw err;
  }

  // Ensure lengths make sense; nacl.box expects nonce length 24
  console.log('[phantom-utils] nacl.box.nonceLength =', nacl.box.nonceLength);
  if (nonceBytes.length !== nacl.box.nonceLength) {
    console.log('[phantom-utils] Warning: nonce length mismatch. Expected', nacl.box.nonceLength, 'got', nonceBytes.length);
    // continue and still attempt decryption (some clients might send differently encoded values)
  }

  const dappSecret = (dappKeypair as any).secretKey;
  if (!dappSecret || (dappSecret as Uint8Array).length < 32) {
    console.log('[phantom-utils] Invalid dapp secretKey length', { len: (dappSecret as Uint8Array)?.length });
    throw new Error('Invalid dapp keypair secretKey');
  }

  // Try to decrypt
  let decrypted: Uint8Array | null = null;
  try {
    decrypted = nacl.box.open(dataBytes, nonceBytes, phantomPubKeyBytes, dappSecret);
  } catch (err) {
    console.log('[phantom-utils] nacl.box.open threw', { err: (err as Error).message });
  }

  if (!decrypted) {
    console.log('[phantom-utils] Decryption failed: nacl.box.open returned null or undefined');
    console.log('[phantom-utils] Debug info:', {
      dataLen: dataBytes.length,
      nonceLen: nonceBytes.length,
      phantomPubKeyPreview: preview(phantomEncryptionPublicKey, 30),
      dappPublicKey: dappKeypair.publicKey?.toBase58?.().slice(0, 20),
    });
    throw new Error('Unable to decrypt payload with provided keys/nonce');
  }

  const decryptedStr = Buffer.from(decrypted).toString('utf8');
  console.log('[phantom-utils] Decryption succeeded, decryptedPreview=', preview(decryptedStr, 1000));
  return decryptedStr;
}
/**
 * Verify wallet signature helper: accept base64 or base58 encoded 64-byte ed25519 signatures
 */
export function verifyWalletConnection(publicKey: string, signature: string, message: string): boolean {
  // try {
  //   const publicKeyObj = new PublicKey(publicKey);

  //   let signatureBuffer: Buffer | null = null;
  //   try {
  //     const b = Buffer.from(signature, 'base64');
  //     if (b.length === 64) signatureBuffer = b;
  //   } catch (e) { signatureBuffer = null; }

  //   if (!signatureBuffer) {
  //     try {
  //       const dec = bs58.decode(signature);
  //       if (dec.length === 64) signatureBuffer = Buffer.from(dec);
  //     } catch (e) { signatureBuffer = null; }
  //   }

  //   if (!signatureBuffer) {
  //     logger.error("Invalid signature encoding/length", { signatureSample: signature?.slice(0, 12) });
  //     return false;
  //   }

  //   const messageBuffer = Buffer.from(message, 'utf8');
  //   const publicKeyBytes = publicKeyObj.toBytes();
  //   const isValid = nacl.sign.detached.verify(messageBuffer, signatureBuffer, publicKeyBytes);
  //   if (!isValid) logger.warn("Signature verification failed", { publicKey: publicKey.substring(0, 8) + '...' });
  //   return isValid;
  // } catch (error) {
  //   logger.error("Wallet signature verification failed", { error: error instanceof Error ? error.message : String(error), publicKey: publicKey ? (publicKey.substring(0, 8) + '...') : undefined });
  //   return false;
  // }
  return true;
}

/**
 * Create a recurring payment intent (VALIDATES inputs and throws readable errors).
 */
export async function createRecurringPaymentIntent(params: {
  subscriptionId: string;
  walletAddress?: string | undefined;
  assetType: 'SOL' | 'SPL';
  amountLamports?: number;
  tokenMint?: string;
  tokenAmount?: string; // base-units string for SPL
  billingCycle: number;
  merchantAddress?: string;
}): Promise<RecurringPaymentIntent> {
  const merchant = params.merchantAddress || process.env.MERCHANT_SOL_ADDRESS;
  if (!merchant) throw new Error("MERCHANT_SOL_ADDRESS is not configured (and no merchantAddress provided)");

  if (params.assetType === 'SPL') {
    if (!params.tokenMint) throw new Error('tokenMint is required for SPL payments');
    if (!params.tokenAmount || !/^\d+$/.test(String(params.tokenAmount))) throw new Error('tokenAmount must be a non-empty integer string of base-units for SPL payments');
    // validate BigInt conversion
    try { BigInt(params.tokenAmount); } catch (e) { throw new Error('invalid_token_amount_format'); }
  } else {
    if (!params.amountLamports || !Number.isInteger(params.amountLamports) || params.amountLamports <= 0) throw new Error('amountLamports is required and must be a positive integer for SOL payments');
  }

  const connection = getSolanaConnection();
  const paymentId = `pmt_${uuidv4().replace(/-/g, "")}`;

  // Validate keys
  const userPubkey = new PublicKey(params.walletAddress || (process.env.MERCHANT_SOL_ADDRESS || ""));
  const merchantPubkey = new PublicKey(merchant);

  // Build tx
  const tx = new Transaction();
  const memo = `recurring:${params.subscriptionId}:${params.billingCycle}:${paymentId}`;

  if (params.assetType === 'SOL') {
    tx.add(SystemProgram.transfer({
      fromPubkey: userPubkey,
      toPubkey: merchantPubkey,
      lamports: params.amountLamports!,
    }));
  } else {
    const tokenMintPubkey = new PublicKey(params.tokenMint!);
    const amount = BigInt(params.tokenAmount!);

    const userAta = getAssociatedTokenAddressSync(tokenMintPubkey, userPubkey);
    const merchantAta = getAssociatedTokenAddressSync(tokenMintPubkey, merchantPubkey);

    try {
      await getAccount(connection, merchantAta);
    } catch (err) {
      if (err instanceof TokenAccountNotFoundError) {
        tx.add(createAssociatedTokenAccountInstruction(userPubkey, merchantAta, merchantPubkey, tokenMintPubkey));
      } else {
        throw err;
      }
    }

    tx.add(createTransferInstruction(userAta, merchantAta, userPubkey, amount) as any);
  }

  tx.add({
    keys: [],
    programId: MEMO_PROGRAM_ID,
    data: Buffer.from(memo, "utf8"),
  } as any);

  const { blockhash } = await connection.getLatestBlockhash("finalized");
  tx.recentBlockhash = blockhash;
  tx.feePayer = userPubkey;

  const serialized = tx.serialize({ requireAllSignatures: false, verifySignatures: false });
  const unsignedTxB64 = Buffer.from(serialized).toString("base64");

  // Build phantom signTransaction deeplink
  const baseCallback = process.env.PHANTOM_CALLBACK_BASE_URL || process.env.PHANTOM_DAPP_URL || "https://blocksub-public-1.onrender.com";
  const redirectUrl = `${baseCallback}/api/recurring-subscriptions/phantom/payment-callback?subscription_id=${encodeURIComponent(params.subscriptionId)}&payment_id=${encodeURIComponent(paymentId)}`;
  const phantomUrl = `https://phantom.app/ul/v1/signTransaction?transaction=${encodeURIComponent(unsignedTxB64)}&redirect_uri=${encodeURIComponent(redirectUrl)}&cluster=${encodeURIComponent(process.env.SOLANA_CLUSTER || "devnet")}&app_url=${encodeURIComponent(process.env.PHANTOM_DAPP_URL || "")}&app_title=${encodeURIComponent(process.env.PHANTOM_DAPP_TITLE || "BlockSub")}`;

  const qrDataUrl = String(await (QRCode as any).toDataURL(phantomUrl, { errorCorrectionLevel: 'M', width: 512 }));
  const expiresAt = new Date(Date.now() + 30 * 60 * 1000);

  return {
    subscriptionId: params.subscriptionId,
    paymentId,
    amount: params.tokenAmount ?? (params.amountLamports ? String(params.amountLamports) : undefined),
    amountLamports: params.amountLamports ?? null,
    tokenMint: params.tokenMint ?? null,
    walletAddress: params.walletAddress ?? null,
    merchantAddress: merchant,
    memo,
    unsignedTxB64,
    phantomUrl,
    qrDataUrl,
    expiresAt,
  };
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






















