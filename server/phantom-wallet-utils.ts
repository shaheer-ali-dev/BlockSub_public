import { PublicKey} from "@solana/web3.js";
import QRCode from "qrcode";
import nacl from "tweetnacl";
import { Buffer } from "buffer";
import bs58 from "bs58";
import { v4 as uuidv4 } from "uuid";

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

export async function createRecurringPaymentIntent(opts: {
  subscriptionId: string;
  walletAddress?: string | null;
  assetType?: 'SOL' | 'SPL';
  amountLamports?: number | null;
  tokenMint?: string | null;
  tokenAmount?: string | null;
  billingCycle?: number;
  merchantAddress?: string | null;
}): Promise<{
  paymentId: string;
  unsignedTxB64?: string | null;
  phantomUrl?: string | null;
  qrDataUrl?: string | null;
  amountLamports?: number | null;
  tokenMint?: string | null;
  tokenAmount?: string | null;
  merchantAddress?: string | null;
  walletAddress?: string | null;
  expiresAt?: string | Date | null;
  memo?: string | null;
}> {
  const paymentId = `rintent_${uuidv4().replace(/-/g, '')}`;

  // Minimal placeholder response:
  return {
    paymentId,
    unsignedTxB64: null,
    phantomUrl: null,
    qrDataUrl: null,
    amountLamports: opts.amountLamports ?? null,
    tokenMint: opts.tokenMint ?? null,
    tokenAmount: opts.tokenAmount ?? null,
    merchantAddress: opts.merchantAddress ?? null,
    walletAddress: opts.walletAddress ?? null,
    expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
    memo: null,
  };
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

export async function generateWalletConnectionQR(connectionRequest: any) {
  const baseCallback = (process.env.PHANTOM_CALLBACK_BASE_URL || "").replace(/\/$/, "");

  // ✅ Fully qualified callback (never relative)
  const callbackUrl = `${baseCallback}/api/recurring-subscriptions/phantom/connect-callback/${encodeURIComponent(
    connectionRequest.subscriptionId
  )}`;

  // Encode params safely
  const appUrlEnc = encodeURIComponent(connectionRequest.dappUrl || process.env.PHANTOM_DAPP_URL || "");
  const redirectLinkEnc = encodeURIComponent(callbackUrl);

  // Core query params
  const qParams: string[] = [
    `app_url=${appUrlEnc}`,
    `redirect_link=${redirectLinkEnc}`,
    `subscription_id=${encodeURIComponent(connectionRequest.subscriptionId)}`,
    `cluster=devnet`
  ];

  // Optional: encryption pubkey for secure Phantom <-> server comm
  if (connectionRequest.dappEncryptionPublicKey) {
    qParams.push(`dapp_encryption_public_key=${encodeURIComponent(connectionRequest.dappEncryptionPublicKey)}`);
  }

  // Optional: add DApp branding (for nice UI in Phantom)
  if (process.env.PHANTOM_APP_NAME) {
    qParams.push(`app_url_title=${encodeURIComponent(process.env.PHANTOM_APP_NAME)}`);
  }
  if (process.env.PHANTOM_APP_LOGO_URL) {
    qParams.push(`app_logo_url=${encodeURIComponent(process.env.PHANTOM_APP_LOGO_URL)}`);
  }

  // ✅ Construct the deeplink
  const deeplink = `https://phantom.app/ul/v1/connect?${qParams.join("&")}`;

  // ✅ Generate QR code
  const qrCodeDataUrl = await QRCode.toDataURL(deeplink, {
    errorCorrectionLevel: "M",
    width: 320
  });

  return {
    qrCodeDataUrl,
    deeplink,
    connectionUrl: callbackUrl,
    message: connectionRequest.message,
    nonce: connectionRequest.nonce,
    expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    dappEncryptionPublicKey: connectionRequest.dappEncryptionPublicKey
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


export function decryptPhantomCallbackData(
  phantomPub: string,
  dataStr: string,
  nonceStr: string
): string {
  if (!phantomPub || !dataStr || !nonceStr) throw new Error("missing_encryption_params");

  const privRaw = process.env.PHANTOM_DAPP_ENCRYPTION_PRIVATE_KEY || '';
  const secretKey = parseAppSecretFromEnv(privRaw); // your existing parser (returns 32 bytes)
  if (secretKey.length !== 32) throw new Error("PHANTOM_DAPP_ENCRYPTION_PRIVATE_KEY must decode to 32 bytes");

  // parse phantom public key bytes (try base58 then base64)
  let phantomPubBytes: Uint8Array | null = null;
  try {
    phantomPubBytes = new PublicKey(phantomPub).toBytes();
  } catch (_) {
    phantomPubBytes = tryDecodeBase58(phantomPub) ?? tryDecodeBase64(phantomPub);
  }
  if (!phantomPubBytes) throw new Error("invalid_phantom_public_key");

  // parse nonce (try base58 then base64)
  const nonce = tryDecodeBase58(nonceStr) ?? tryDecodeBase64(nonceStr);
  if (!nonce || nonce.length !== 24) throw new Error("invalid_nonce_encoding_or_length");

  // try data decoding + decryption. Prefer base58 (Phantom commonly uses base58),
  // but attempt both and return the first that successfully decrypts.
  const tryDecrypt = (cipher: Uint8Array | null) => {
    if (!cipher) return null;
    const opened = nacl.box.open(cipher, nonce, phantomPubBytes!, secretKey);
    return opened ? Buffer.from(opened).toString("utf8") : null;
  };

  // prefer base58 first
  const decodedB58 = tryDecodeBase58(dataStr);
  const d1 = tryDecrypt(decodedB58);
  if (d1) return d1;

  // fallback base64
  const decodedB64 = tryDecodeBase64(dataStr);
  const d2 = tryDecrypt(decodedB64);
  if (d2) return d2;

  throw new Error("decryption_failed (invalid encoding or ciphertext)");
}

export async function buildInitializeUrlAndQr(subscriptionId: string, dappBaseUrl?: string) {
  const dappUrl = (dappBaseUrl || process.env.PHANTOM_DAPP_URL || "https://blocksub-public-1.onrender.com").replace(/\/$/, "");
  const initializeTxUrl = `${dappUrl}/initialize-tx/${encodeURIComponent(subscriptionId)}`;

  // Generate a QR code data URL (PNG)
  const qrOptions = { errorCorrectionLevel: "M", width: 320 };
  const initializeTxQr = String(await QRCode.toDataURL(initializeTxUrl, qrOptions));

  return { initializeTxUrl, initializeTxQr };
}




























