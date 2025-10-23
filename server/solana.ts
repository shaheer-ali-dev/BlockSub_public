import { Connection, PublicKey, SystemProgram, Transaction, clusterApiUrl, Keypair, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { createTransferInstruction, getAssociatedTokenAddressSync, createAssociatedTokenAccountInstruction, getAccount, TokenAccountNotFoundError, createApproveInstruction, createRevokeInstruction } from "@solana/spl-token";
import QRCode from "qrcode";
import { v4 as uuidv4 } from "uuid";

const MEMO_PROGRAM_ID = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");

export interface CreatePaymentParams {
  // Asset selection - either SOL or SPL
  assetType: 'SOL' | 'SPL';
  // For SOL payments
  amountLamports?: number;
  // For SPL payments
  tokenMint?: string; // mint address base58
  tokenAmount?: string; // amount in base units as string
  
  merchant: string; // base58
  userPubkey: string; // base58 (required to set fee payer and transfer source)
  orderId?: string; // optional, will be generated if not provided
  memoText?: string; // optional; defaults to `order:<orderId>`
}

export interface PaymentBuildResult {
  orderId: string;
  memoText: string;
  unsignedTxB64: string;
  phantomUrl: string;
  qrDataUrl: string;
  expiresAt: string; // ISO timestamp
}

function getEnv(name: string, fallback: string = ""): string {
  return process.env[name] ?? fallback;
}

export function getSolanaConnection(): Connection {
  const cluster = (getEnv("SOLANA_CLUSTER", "devnet") || "devnet") as
    | "mainnet-beta"
    | "devnet"
    | "testnet";
  const custom = getEnv("SOLANA_RPC_URL", "");
  const endpoint = custom || clusterApiUrl(cluster);
  // 'confirmed' to balance speed/consistency for payment flow
  return new Connection(endpoint, "confirmed");
}

function buildPhantomDeeplink(params: {
  b64: string;
  orderId: string;
}): string {
  const redirect = getEnv("PHANTOM_REDIRECT_URL", "");
  const cluster = getEnv("SOLANA_CLUSTER", "devnet");
  const appTitle = encodeURIComponent(getEnv("PHANTOM_DAPP_TITLE", "BlockSub"));
  const appUrl = encodeURIComponent(getEnv("PHANTOM_DAPP_URL", "http://localhost:3000"));
  const txParam = encodeURIComponent(params.b64);
  const orderParam = encodeURIComponent(params.orderId);

  // Phantom deeplink for signTransaction
  // Note: param names differ between versions; `redirect_uri` is commonly supported.
  const url = `https://phantom.app/ul/v1/signTransaction?transaction=${txParam}` +
    (redirect ? `&redirect_uri=${encodeURIComponent(`${redirect}?order=${orderParam}`)}` : "") +
    `&cluster=${encodeURIComponent(cluster)}` +
    `&app_url=${appUrl}` +
    `&app_title=${appTitle}`;
  return url;
}

async function ensureTokenAccount(connection: Connection, mint: PublicKey, owner: PublicKey, payer: PublicKey): Promise<PublicKey> {
  const ata = getAssociatedTokenAddressSync(mint, owner);
  
  try {
    await getAccount(connection, ata);
    return ata; // Account exists
  } catch (error) {
    if (error instanceof TokenAccountNotFoundError) {
      // Account doesn't exist, we'll need to create it in the transaction
      return ata;
    }
    throw error;
  }
}

export async function createPaymentIntentUnsigned(params: CreatePaymentParams): Promise<PaymentBuildResult> {
  const connection = getSolanaConnection();

  const orderId = params.orderId || uuidv4().replace(/-/g, "");
  const memoText = params.memoText || `order:${orderId}`;

  const userPubkey = new PublicKey(params.userPubkey);
  const merchantPubkey = new PublicKey(params.merchant);

  // Build transaction with transfer + memo
  const tx = new Transaction();

  if (params.assetType === 'SOL') {
    if (!params.amountLamports) {
      throw new Error('amountLamports is required for SOL payments');
    }
    
    tx.add(
      SystemProgram.transfer({
        fromPubkey: userPubkey,
        toPubkey: merchantPubkey,
        lamports: params.amountLamports,
      })
    );
  } else if (params.assetType === 'SPL') {
    if (!params.tokenMint || !params.tokenAmount) {
      throw new Error('tokenMint and tokenAmount are required for SPL payments');
    }
    
    const tokenMintPubkey = new PublicKey(params.tokenMint);
    const amount = BigInt(params.tokenAmount);
    
    // Get associated token accounts
    const userAta = getAssociatedTokenAddressSync(tokenMintPubkey, userPubkey);
    const merchantAta = getAssociatedTokenAddressSync(tokenMintPubkey, merchantPubkey);
    
    // Check if merchant's ATA exists, create if needed
    try {
      await getAccount(connection, merchantAta);
    } catch (error) {
      if (error instanceof TokenAccountNotFoundError) {
        // Add instruction to create merchant's ATA
        tx.add(
          createAssociatedTokenAccountInstruction(
            userPubkey, // payer
            merchantAta, // ata
            merchantPubkey, // owner
            tokenMintPubkey // mint
          )
        );
      }
    }
    
    // Add SPL token transfer instruction
    tx.add(
      createTransferInstruction(
        userAta, // source
        merchantAta, // destination
        userPubkey, // owner
        amount // amount
      )
    );
  } else {
    throw new Error('Invalid assetType. Must be SOL or SPL');
  }

  // Add memo as instruction
  const memoIx = {
    keys: [],
    programId: MEMO_PROGRAM_ID,
    data: Buffer.from(memoText, "utf8"),
  } as any; // web3.js doesn't ship a Memo helper; this is a valid low-level instruction shape
  tx.add(memoIx);

  const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash("finalized");
  tx.recentBlockhash = blockhash;
  tx.feePayer = userPubkey; // user pays fees and signs

  const serialized = tx.serialize({ requireAllSignatures: false, verifySignatures: false });
  const b64 = Buffer.from(serialized).toString("base64");

  const phantomUrl = buildPhantomDeeplink({ b64, orderId });
  const qrDataUrl = await QRCode.toDataURL(phantomUrl);

  // Approximate expiry: ~2 minutes from now (recent blockhash lifetime)
  const expiresAt = new Date(Date.now() + 2 * 60 * 1000).toISOString();

  return {
    orderId,
    memoText,
    unsignedTxB64: b64,
    phantomUrl,
    qrDataUrl,
    expiresAt,
  };
}

/**
 * Build a Solana Pay URI (solana:<merchant>?amount=...&reference=...) and return a QR and reference
 * This flow does not require the payer public key and is suitable for merchant-only intents where the
 * wallet (Phantom or other Solana Pay compatible wallet) constructs the transaction from the payer.
 *
 * Additionally returns a Phantom universal link (phantomUrl) and a QR encoding that link (phantomQrDataUrl)
 * for better compatibility with mobile camera QR scanners which prefer HTTPS universal links.
 */
export async function buildSolanaPayLink(params: {
  merchant: string;
  assetType: 'SOL' | 'SPL';
  amountLamports?: number;
  tokenMint?: string;
  tokenAmount?: string;
  orderId?: string;
  expiresMs?: number;
}): Promise<{ reference: string; solanaPayUrl: string; qrDataUrl: string; expiresAt: string; phantomUrl?: string; phantomQrDataUrl?: string }> {
  const merchant = params.merchant;
  const reference = Keypair.generate().publicKey.toBase58();
  let uri = `solana:${merchant}`;

  const q: string[] = [];
  if (params.assetType === 'SOL' && params.amountLamports) {
    const amountSOL = Number(params.amountLamports) / LAMPORTS_PER_SOL;
    q.push(`amount=${encodeURIComponent(String(amountSOL))}`);
  } else if (params.assetType === 'SPL' && params.tokenMint && params.tokenAmount) {
    // Solana Pay SPL token params: spl-token=<mint>&amount=<amount>
    q.push(`spl-token=${encodeURIComponent(params.tokenMint)}`);
    // tokenAmount is in base units; Solana Pay 'amount' expects decimal amount, but we can't easily infer decimals here.
    // We'll include the raw tokenAmount and consumers should use tokenAmount as base units in their integration.
    q.push(`amount=${encodeURIComponent(params.tokenAmount)}`);
  }

  q.push(`reference=${encodeURIComponent(reference)}`);
  if (params.orderId) q.push(`label=${encodeURIComponent(params.orderId)}`);

  if (q.length) uri += `?${q.join('&')}`;

  const qrDataUrl = await QRCode.toDataURL(uri);
  const expiresAt = new Date(Date.now() + (params.expiresMs ?? 2 * 60 * 1000)).toISOString();

  // Build Phantom universal link (best-effort). This link will be encoded as an HTTPS URL that universal links to Phantom app.
  let phantomUrl: string | undefined = undefined;
  let phantomQrDataUrl: string | undefined = undefined;
  try {
    const phantomBase = "https://phantom.app/ul/v1/transfer";
    const phantomParams: Record<string, string> = {};

    // recipient is the merchant public key (base58)
    if (params.merchant) phantomParams.recipient = params.merchant;

    // amount for SOL: convert lamports to SOL
    if (params.amountLamports && params.assetType === 'SOL') {
      const amountSol = (params.amountLamports / LAMPORTS_PER_SOL);
      phantomParams.amount = String(amountSol);
    }

    // reference — the reference public key returned earlier
    phantomParams.reference = reference;

    if (params.orderId) {
      phantomParams.label = params.orderId;
      phantomParams.message = params.orderId;
    }

    // network: mainnet by default; allow override via env
    const network = process.env.SOLANA_CLUSTER || getEnv("SOLANA_CLUSTER", "mainnet");
    if (network) phantomParams.network = network;

    // For SPL tokens: best-effort include tokenMint and tokenAmount if present.
    if (params.assetType === 'SPL' && params.tokenMint) {
      // Phantom's token param names vary; we'll include `spl-token` and `amount` similarly to Solana Pay
      phantomParams['spl-token'] = params.tokenMint;
      if (params.tokenAmount) phantomParams.amount = params.tokenAmount;
    }

    // remove empty values
    Object.keys(phantomParams).forEach(k => {
      if (!phantomParams[k]) delete phantomParams[k];
    });

    const urlSearch = new URLSearchParams(phantomParams).toString();
    phantomUrl = phantomBase + (urlSearch ? `?${urlSearch}` : "");
    phantomQrDataUrl = await QRCode.toDataURL(phantomUrl);
  } catch (e) {
    // Non-fatal: if phantom link generation fails, we still return solana pay data.
    console.warn("Failed to generate Phantom universal link or QR:", e);
  }

  return { reference, solanaPayUrl: uri, qrDataUrl, expiresAt, phantomUrl, phantomQrDataUrl };
}

/**
 * Find signatures that include activity for the provided reference public key.
 */
export async function findSignaturesForAddress(reference: string, limit = 20) {
  const connection = getSolanaConnection();
  const ref = new PublicKey(reference);
  return connection.getSignaturesForAddress(ref, { limit });
}

/**
 * Build an unsigned SPL token approve (delegate) transaction where user approves `delegate` to transfer up to `amount` tokens from their ATA.
 * Returns the unsigned tx base64 and phantom deeplink to let the user sign the approval.
 */
export async function buildSplApproveDelegateUnsigned(params: {
  userPubkey: string;
  tokenMint: string;
  delegate: string; // delegate/authority pubkey
  amount: string; // base units as string
  orderId?: string;
}) {
  const connection = getSolanaConnection();
  const userPubkey = new PublicKey(params.userPubkey);
  const mint = new PublicKey(params.tokenMint);
  const delegatePubkey = new PublicKey(params.delegate);

  const userAta = getAssociatedTokenAddressSync(mint, userPubkey);

  const tx = new Transaction();

  // Ensure user's ATA exists is expected externally (or will be created earlier)
  // Add approve instruction (delegate)
  const amount = BigInt(params.amount);
  // createApproveInstruction expects u64-compatible amount; cast as any to fit types if needed
  const approveIx = createApproveInstruction(userAta, delegatePubkey, userPubkey, amount as any);
  tx.add(approveIx as any);

  const memoText = `approve:${params.orderId || 'approve_' + Date.now()}`;
  const memoIx = { keys: [], programId: MEMO_PROGRAM_ID, data: Buffer.from(memoText, 'utf8') } as any;
  tx.add(memoIx);

  const { blockhash } = await connection.getLatestBlockhash('finalized');
  tx.recentBlockhash = blockhash;
  tx.feePayer = userPubkey;

  const serialized = tx.serialize({ requireAllSignatures: false, verifySignatures: false });
  const b64 = Buffer.from(serialized).toString('base64');

  // Phantom deeplink
  const phantomUrl = buildPhantomDeeplink({ b64, orderId: params.orderId || 'approve_' + Date.now() });
  const qrDataUrl = await QRCode.toDataURL(phantomUrl);

  return {
    orderId: params.orderId || `approve_${Date.now()}`,
    memoText,
    unsignedTxB64: b64,
    phantomUrl,
    qrDataUrl,
    expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
  } as PaymentBuildResult;
}

/**
 * Build an unsigned transfer-from instruction where delegate transfers tokens from user ATA to merchant ATA.
 * This transaction must be signed by the delegate (merchant or a configured relayer) who was approved earlier.
 */
export async function buildSplTransferFromDelegateUnsigned(params: {
  delegatePubkey: string; // payer/signing key (merchant)
  userPubkey: string;
  merchant: string;
  tokenMint: string;
  tokenAmount: string; // base units
  userTokenAccount?: string; // optional explicit token account (ATA or custom)
  orderId?: string;
}) {
  const connection = getSolanaConnection();
  const userPubkey = new PublicKey(params.userPubkey);
  const merchantPubkey = new PublicKey(params.merchant);
  const mint = new PublicKey(params.tokenMint);
  const delegatePubkey = new PublicKey(params.delegatePubkey);
  // Prefer explicit userTokenAccount when provided (prevents incorrect ATA derivation if user uses non-ATA)
  const userAta = params.userTokenAccount ? new PublicKey(params.userTokenAccount) : getAssociatedTokenAddressSync(mint, userPubkey);
  const merchantAta = getAssociatedTokenAddressSync(mint, merchantPubkey);

  const tx = new Transaction();

  // Ensure merchant ATA exists; if not, create (payer will be delegate/merchant)
  try {
    await getAccount(connection, merchantAta);
  } catch (error) {
    if (error instanceof TokenAccountNotFoundError) {
      tx.add(createAssociatedTokenAccountInstruction(delegatePubkey, merchantAta, merchantPubkey, mint));
    }
  }

  const amount = BigInt(params.tokenAmount);
  // Transfer from user's ATA to merchant ATA using delegate authority
  tx.add(createTransferInstruction(userAta, merchantAta, delegatePubkey, amount) as any);

  const memoText = `delegate_transfer:${params.orderId || 'dt_' + Date.now()}`;
  const memoIx = { keys: [], programId: MEMO_PROGRAM_ID, data: Buffer.from(memoText, 'utf8') } as any;
  tx.add(memoIx);

  const { blockhash } = await connection.getLatestBlockhash('finalized');
  tx.recentBlockhash = blockhash;
  tx.feePayer = delegatePubkey; // delegate pays the fee (merchant)

  const serialized = tx.serialize({ requireAllSignatures: false, verifySignatures: false });
  const b64 = Buffer.from(serialized).toString('base64');

  const phantomUrl = buildPhantomDeeplink({ b64, orderId: params.orderId || `dt_${Date.now()}` });
  const qrDataUrl = await QRCode.toDataURL(phantomUrl);

  return {
    orderId: params.orderId || `dt_${Date.now()}`,
    memoText,
    unsignedTxB64: b64,
    phantomUrl,
    qrDataUrl,
    expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
  } as PaymentBuildResult;
}

export async function broadcastSignedTransaction(b64SignedTx: string): Promise<{ signature: string }>{
  const connection = getSolanaConnection();
  const buf = Buffer.from(b64SignedTx, "base64");
  const sig = await connection.sendRawTransaction(buf, { skipPreflight: false, preflightCommitment: "confirmed" });
  await connection.confirmTransaction(sig, "finalized");
  return { signature: sig };
}

export async function getTransactionBySignature(signature: string) {
  const connection = getSolanaConnection();
  return await connection.getTransaction(signature, {
    maxSupportedTransactionVersion: 0,
    commitment: "finalized",
  });
}

export function extractMemoFromTransaction(tx: any): string | null {
  try {
    const ixs = tx?.transaction?.message?.instructions || [];
    for (const ix of ixs) {
      if (ix?.programId?.toBase58?.() === MEMO_PROGRAM_ID.toBase58()) {
        // In legacy decoded txs, memo data may be base64 in ix.data; in web3.js parsed, it can be raw Buffer
        if (typeof ix.data === "string") {
          // Usually base64 here; try decode
          try {
            const buf = Buffer.from(ix.data, "base64");
            return buf.toString("utf8");
          } catch {}
          return ix.data;
        } else if (ix.data instanceof Buffer) {
          return ix.data.toString("utf8");
        } else if (Array.isArray(ix.data)) {
          // some RPCs return an array of bytes
          return Buffer.from(ix.data).toString("utf8");
        }
      }
    }
    return null;
  } catch {
    return null;
  }
}
