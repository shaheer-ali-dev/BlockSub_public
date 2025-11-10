import fs from "fs";
import path from "path";
import os from "os";
import * as anchor from "@project-serum/anchor";
import { PublicKey, Transaction } from "@solana/web3.js";

/**
 * Anchor helper utilities for interacting with the Anchor program you posted.
 *
 * Environment variables expected:
 * - SOLANA_RPC_URL (eg. https://api.devnet.solana.com)
 * - ANCHOR_PROGRAM_ID (eg. program id: 2md8utuDnYAiMNysT2b9NMXPdceS4D6RCXHio1XfeWHU)
 * - RELAYER_KEYPAIR_PATH or RELAYER_PRIVATE_KEY_BASE58 (keypair used by server worker to sign release_payment txs)
 */

const RPC_URL = "https://api.devnet.solana.com"; // -- AS the anchor program is deployed for devnet for now so we going to use devnet later after getting investments we will move to mainnet
const PROGRAM_ID = new PublicKey(process.env.ANCHOR_PROGRAM_ID || "2md8utuDnYAiMNysT2b9NMXPdceS4D6RCXHio1XfeWHU");


const IDL: any = {
  version: "0.1.0",
  name: "blocksub",
  instructions: [
    {
      name: "initializeSubscription",
      accounts: [
        { name: "subscription", isMut: true, isSigner: false },
        { name: "escrowVault", isMut: true, isSigner: false },
        { name: "subscriber", isMut: true, isSigner: true },
        { name: "merchant", isMut: true, isSigner: false },
        { name: "systemProgram", isMut: false, isSigner: false }
      ],
      args: [
        { name: "merchant", type: "publicKey" },
        { name: "amountPerMonth", type: "u64" },
        { name: "totalMonths", type: "u8" },
        { name: "lockedAmount", type: "u64" }
      ]
    },
    {
      name: "releasePayment",
      accounts: [
        { name: "subscription", isMut: true, isSigner: false },
        { name: "escrowVault", isMut: true, isSigner: false },
        { name: "merchant", isMut: true, isSigner: false },
        { name: "systemProgram", isMut: false, isSigner: false }
      ],
      args: []
    },
    {
      name: "cancelSubscription",
      accounts: [
        { name: "subscription", isMut: true, isSigner: false },
        { name: "escrowVault", isMut: true, isSigner: false },
        { name: "subscriber", isMut: true, isSigner: true },
        { name: "systemProgram", isMut: false, isSigner: false }
      ],
      args: []
    }
  ],
  accounts: [
    {
      name: "Subscription",
      type: {
        kind: "struct",
        fields: [
          { name: "merchant", type: "publicKey" },
          { name: "subscriber", type: "publicKey" },
          { name: "amount_per_month", type: "u64" },
          { name: "total_months", type: "u8" },
          { name: "months_paid", type: "u8" },
          { name: "next_payment_time", type: "i64" },
          { name: "bump", type: "u8" },
          { name: "locked_amount", type: "u64" }
        ]
      }
    },
    { name: "EscrowVault", type: { kind: "struct", fields: [{ name: "bump", type: "u8" }] } }
  ]
};

function loadRelayerKeypair(): anchor.web3.Keypair | null {
  try {
    const envPath = process.env.RELAYER_KEYPAIR_PATH;
    if (envPath && fs.existsSync(envPath)) {
      const raw = JSON.parse(fs.readFileSync(envPath, "utf8"));
      return anchor.web3.Keypair.fromSecretKey(new Uint8Array(raw));
    }
    const secretBase58 = process.env.PHANTOM_DAPP_ENCRYPTION_PRIVATE_KEY;
    if (secretBase58) {
      // this expects base58-encoded bytes of the keypair JSON; if you store raw base58 of secretKey:
      const bs58 = require("bs58");
      const bytes = bs58.decode(secretBase58);
      return anchor.web3.Keypair.fromSecretKey(bytes);
    }
  } catch (e) {
    console.error("loadRelayerKeypair failed", e);
  }
  return null;
}

function getProviderWithKeypair(keypair: anchor.web3.Keypair) {
  const connection = new anchor.web3.Connection(RPC_URL, "confirmed");
  const wallet: any = {
    publicKey: keypair.publicKey,
    signTransaction: async (tx: anchor.web3.Transaction) => {
      tx.partialSign(keypair);
      return tx;
    },
    signAllTransactions: async (txs: anchor.web3.Transaction[]) => {
      txs.forEach(t => t.partialSign(keypair));
      return txs;
    }
  };
  const provider = new anchor.AnchorProvider(connection as any, wallet, anchor.AnchorProvider.defaultOptions());
  return provider;
}

function getProviderWithNoWallet() {
  const connection = new anchor.web3.Connection(RPC_URL, "confirmed");
  // A provider with a "null" wallet for creating unsigned tx
  const wallet = {
    publicKey: anchor.web3.PublicKey.default,
    signTransaction: async (tx: anchor.web3.Transaction) => {
      // no-op
      return tx;
    }
  } as any;
  return new anchor.AnchorProvider(connection as any, wallet, anchor.AnchorProvider.defaultOptions());
}

function getProgramWithProvider(provider: anchor.AnchorProvider) {
  return new anchor.Program(IDL as any, PROGRAM_ID, provider);
}

/**
 * Derive the subscription PDA and escrow PDA (match your program seeds)
 */
export async function deriveSubscriptionPDA(merchantPubkey: PublicKey, subscriberPubkey: PublicKey) {
  const seed = Buffer.from("subscription");
  const [pda, bump] = await PublicKey.findProgramAddress([seed, merchantPubkey.toBuffer(), subscriberPubkey.toBuffer()], PROGRAM_ID);
  return { subscriptionPda: pda, subscriptionBump: bump };
}

export async function deriveEscrowPDA(subscriptionPda: PublicKey) {
  const seed = Buffer.from("escrow");
  const [escrowPda, escrowBump] = await PublicKey.findProgramAddress([seed, subscriptionPda.toBuffer()], PROGRAM_ID);
  return { escrowPda, escrowBump };
}

/**
 * Build an unsigned initialize_subscription transaction for the subscriber to sign in Phantom.
 * Returns: { serializedTxBase64, subscriptionPda, escrowPda, subscriptionBump, escrowBump }
 *
 * Usage:
 * - Server calls this once subscription record exists and has merchant + subscriber public keys and amount settings.
 * - Send serializedTxBase64 to frontend; frontend asks Phantom to sign & submit it.
 */
export async function buildInitializeSubscriptionTx(params: {
  merchantPubkey: string;            // merchant wallet pubkey (string)
  subscriberPubkey: string;          // subscriber wallet pubkey (string) - will be feePayer for this tx
  amountPerMonthLamports: number;    // amount per month in lamports
  totalMonths: number;               // total months (u8)
  lockedAmountLamports: number;      // locked_amount in lamports (must be >= amountPerMonth*totalMonths)
}) {
  const merchant = new PublicKey(params.merchantPubkey);
  const subscriber = new PublicKey(params.subscriberPubkey);

  const providerNoWallet = getProviderWithNoWallet();
  const program = getProgramWithProvider(providerNoWallet);

  // derive PDAs
  const { subscriptionPda, subscriptionBump } = await deriveSubscriptionPDA(merchant, subscriber);
  const { escrowPda, escrowBump } = await deriveEscrowPDA(subscriptionPda);

  // Build the tx using Anchor methods builder to get Transaction object
  const txObj = await program.methods
    .initializeSubscription(merchant, new anchor.BN(params.amountPerMonthLamports), params.totalMonths, new anchor.BN(params.lockedAmountLamports))
    .accounts({
      subscription: subscriptionPda,
      escrowVault: escrowPda,
      subscriber: subscriber,
      merchant: merchant,
      systemProgram: anchor.web3.SystemProgram.programId
    })
    .preInstructions([])
    .postInstructions([])
    .transaction();

  // Set feePayer to subscriber and get a recent blockhash
  txObj.feePayer = subscriber;
  const connection = new anchor.web3.Connection(RPC_URL, "confirmed");
  const { blockhash } = await connection.getRecentBlockhash();
  txObj.recentBlockhash = blockhash;

  // Serialize without signatures (unsigned). Consumer (frontend/Phantom) will set feePayer and sign.
  const serialized = txObj.serialize({ requireAllSignatures: false, verifySignatures: false });
  const b64 = serialized.toString("base64");

  return {
    serializedTxBase64: b64,
    subscriptionPda: subscriptionPda.toBase58(),
    escrowPda: escrowPda.toBase58(),
    subscriptionBump,
    escrowBump
  };
}

/**
 * Server-side relayer: invoke release_payment for a subscription. The relayer must be able to sign txs.
 *
 * This function signs and broadcasts the transaction immediately using the relayer keypair (RELAYR_KEYPAIR_PATH or RELAYER_PRIVATE_KEY_BASE58).
 * Returns the RPC tx signature on success.
 */
export async function releasePaymentForSubscription(params: {
  subscriptionPdaBase58: string;
  escrowPdaBase58: string;
  merchantPubkeyBase58: string;
}) {
  const relayer = loadRelayerKeypair();
  if (!relayer) throw new Error("Relayer keypair not configured (RELAYER_KEYPAIR_PATH or RELAYER_PRIVATE_KEY_BASE58)");

  const provider = getProviderWithKeypair(relayer);
  const program = getProgramWithProvider(provider);

  const subscriptionPda = new PublicKey(params.subscriptionPdaBase58);
  const escrowPda = new PublicKey(params.escrowPdaBase58);
  const merchant = new PublicKey(params.merchantPubkeyBase58);

  // Call the release_payment RPC; Anchor will build + sign with provider wallet (relayer)
  const txSig = await program.methods
    .releasePayment()
    .accounts({
      subscription: subscriptionPda,
      escrowVault: escrowPda,
      merchant: merchant,
      systemProgram: anchor.web3.SystemProgram.programId
    })
    .rpc();

  return txSig;
}

/**
 * Cancels a subscription on-chain using the Anchor program.
 * @param subscription Object containing on-chain subscription data
 * @returns The transaction signature
 */
export async function cancelOnChainSubscription(subscription: any): Promise<string> {
  try {
    // Load the relayer keypair (server signer)
    const relayer = loadRelayerKeypair();
    if (!relayer) throw new Error("Relayer keypair not configured (RELAYER_KEYPAIR_PATH or RELAYER_PRIVATE_KEY_BASE58)");

    // Create provider & program
    const provider = getProviderWithKeypair(relayer);
    const program = getProgramWithProvider(provider);

    console.log("⏳ Sending on-chain cancel transaction for:", subscription.subscriptionId);

    // Build public keys
    const subscriptionPda = new PublicKey(subscription.onChainAddress);
    const escrowPda = new PublicKey(subscription.escrowVaultAddress);
    const subscriberPubkey = new PublicKey(subscription.userPubkey);

    // Execute cancel instruction
    const txSig = await program.methods
      .cancelSubscription()
      .accounts({
        subscription: subscriptionPda,
        escrowVault: escrowPda,
        subscriber: subscriberPubkey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    console.log("✅ Cancel TX Confirmed:", txSig);
    return txSig;
  } catch (error) {
    console.error("❌ On-chain cancel failed:", error);
    throw error;
  }
}
