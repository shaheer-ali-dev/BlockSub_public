import type { Express, Request, Response } from "express";
import { z } from "zod";
import { logger } from "./security";
import { PaymentOrder, createPaymentIntentSchema, Subscription, ApiKey } from "@shared/schema-mongodb";
import {
  createPaymentIntentUnsigned,
  broadcastSignedTransaction,
  getTransactionBySignature,
  extractMemoFromTransaction,
  buildSolanaPayLink,
  findSignaturesForAddress,
  getSolanaConnection
} from "./solana";
import { PublicKey } from "@solana/web3.js";
import { getAssociatedTokenAddressSync, getMint } from "@solana/spl-token";
import { authenticateApiKey, ApiKeyAuthenticatedRequest } from "@shared/auth";

/**
 * NOTE: This route currently implements Solana payment intents (SOL + SPL).
 * It accepts SPL tokens by either providing tokenAmount (base units) or tokenAmountDecimal (human decimal).
 * For other chains (ETH, BTC, XRP...) you'd need a separate chain-specific flow or extend this with chain adapters.
 */

const CreateIntentBody = z.object({
  orderId: z.string().min(6).max(64),
  // Make merchant optional for this endpoint (fallback to env)
  merchant: z.string().min(32).optional(),
  userPubkey: z.string().min(32).optional(),
  memo: z.string().max(128).optional(),
  // SOL
  amountLamports: z.number().int().positive().optional(),
  // SPL - either base units (tokenAmount) OR decimal string (tokenAmountDecimal)
  tokenMint: z.string().min(32).optional(),
  tokenAmount: z.string().regex(/^\d+$/).optional(), // base units as integer string
  tokenAmountDecimal: z.string().regex(/^\d+(\.\d+)?$/).optional(), // human decimal like "1.5"
  // Optional chain support - default 'solana'
  chain: z.string().optional(),
}).refine((d) => {
  const sol = typeof d.amountLamports === 'number' && !d.tokenMint && !d.tokenAmount && !d.tokenAmountDecimal;
  const spl = !d.amountLamports && !!d.tokenMint && (!!d.tokenAmount || !!d.tokenAmountDecimal);
  return sol || spl;
}, {
  message: 'Provide either amountLamports for SOL or tokenMint + (tokenAmount or tokenAmountDecimal) for SPL',
});

function getEnv(name: string, fallback = "") {
  return process.env[name] ?? fallback;
}

function getNumberEnv(name: string, fallback: number): number {
  const v = process.env[name];
  if (!v) return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

/**
 * Convert a human decimal token amount (e.g. "1.5") into base units string using on-chain mint decimals.
 * - connection: Connection instance
 * - tokenMint: base58 mint address
 * - decimalAmount: string or number representing human amount
 *
 * Returns a string representing the integer base units (suitable for on-chain comparison).
 * Throws an error for invalid inputs.
 */
async function tokenDecimalToBaseUnits(tokenMint: string, decimalAmount: string | number): Promise<string> {
  if (!tokenMint) throw new Error("missing_token_mint");
  const connection = getSolanaConnection();
  const mintPubkey = new PublicKey(tokenMint);
  const mintInfo = await getMint(connection, mintPubkey);
  const decimals = Number(mintInfo.decimals || 0);

  const decStr = String(decimalAmount).trim();
  if (!/^\d+(\.\d+)?$/.test(decStr)) throw new Error("invalid_decimal_amount");

  const [whole, frac = ""] = decStr.split(".");
  if (frac.length > decimals) {
    // Truncate fractional part to allowed decimals (avoid floating rounding surprises)
    const trimmedFrac = frac.slice(0, decimals);
    const baseStr = whole + trimmedFrac.padEnd(decimals, "0");
    return BigInt(baseStr).toString();
  } else {
    const baseStr = whole + frac.padEnd(decimals, "0");
    return BigInt(baseStr).toString();
  }
}

/**
 * Verify on-chain payment for SOL or SPL tokens.
 * Expects tokenAmount to be in base units for SPL flows.
 */
async function verifyOnChain(opts: {
  signature: string;
  merchant: string;
  assetType: 'SOL' | 'SPL';
  amountLamports?: number; // for SOL
  tokenMint?: string; // for SPL
  tokenAmount?: string; // base units string for SPL
  memoText: string;
}): Promise<{ ok: boolean; reason?: string; tx?: any }> {
  try {
    const tx = await getTransactionBySignature(opts.signature);
    if (!tx) return { ok: false, reason: "transaction_not_found" };

    if (tx.meta?.err) return { ok: false, reason: "transaction_error", tx };

    // Check memo
    const memo = extractMemoFromTransaction(tx);
    if (!memo || memo !== opts.memoText) {
      return { ok: false, reason: "memo_mismatch", tx };
    }

    // Check merchant received expected amount
    const merchantKey = new PublicKey(opts.merchant);

    if (opts.assetType === 'SOL') {
      if (!opts.amountLamports) return { ok: false, reason: "missing_amount_lamports", tx };

      const message = tx.transaction.message as any;
      const ak = (message.accountKeys || message.getAccountKeys?.()).map((k: any) => k.toBase58 ? k.toBase58() : String(k));
      const idx = ak.findIndex((k: string) => k === merchantKey.toBase58());
      if (idx === -1) return { ok: false, reason: "merchant_not_in_accounts", tx };

      const pre = tx.meta?.preBalances?.[idx];
      const post = tx.meta?.postBalances?.[idx];
      if (typeof pre !== "number" || typeof post !== "number") return { ok: false, reason: "balance_info_missing", tx };

      const delta = post - pre;
      if (delta < opts.amountLamports) {
        return { ok: false, reason: "sol_amount_mismatch", tx };
      }
    } else if (opts.assetType === 'SPL') {
      if (!opts.tokenMint || !opts.tokenAmount) return { ok: false, reason: "missing_spl_params", tx };

      const tokenMintKey = new PublicKey(opts.tokenMint);
      // merchantAta derivation (not strictly needed for verification here, but kept for clarity)
      const merchantAta = getAssociatedTokenAddressSync(tokenMintKey, merchantKey);
      const expectedAmount = BigInt(opts.tokenAmount);

      // Find token balance changes in transaction
      const tokenBalances = tx.meta?.postTokenBalances || [];
      const preTokenBalances = tx.meta?.preTokenBalances || [];

      // Find merchant's token account in the balances
      const postBalance = tokenBalances.find((b: any) =>
        b.owner === merchantKey.toBase58() && b.mint === tokenMintKey.toBase58()
      );
      const preBalance = preTokenBalances.find((b: any) =>
        b.owner === merchantKey.toBase58() && b.mint === tokenMintKey.toBase58()
      );

      if (!postBalance) return { ok: false, reason: "merchant_token_account_not_found", tx };

      // Note: some RPCs use uiTokenAmount.amount as base units string; handle safely
      const preAmount = preBalance ? BigInt(preBalance.uiTokenAmount?.amount ?? preBalance.amount ?? 0) : BigInt(0);
      const postAmount = BigInt(postBalance.uiTokenAmount?.amount ?? postBalance.amount ?? 0);
      const delta = postAmount - preAmount;

      if (delta < expectedAmount) {
        return { ok: false, reason: "spl_amount_mismatch", tx };
      }
    } else {
      return { ok: false, reason: "invalid_asset_type", tx };
    }

    return { ok: true, tx };
  } catch (e: any) {
    logger.error("verifyOnChain error", { error: e?.message, stack: e?.stack });
    return { ok: false, reason: "verification_exception" };
  }
}

export function registerSolanaRoutes(app: Express) {
  // Create a new payment intent: build unsigned tx + QR + deeplink
  app.post("/api/solana/payment-intents", authenticateApiKey(1.0), async (req: ApiKeyAuthenticatedRequest, res: Response) => {
    try {
      const parse = CreateIntentBody.safeParse(req.body);
      if (!parse.success) {
        return res.status(400).json({ error: "invalid_request", details: parse.error.flatten() });
      }

      const body = parse.data;
      const chain = (body.chain || "solana").toLowerCase();
      if (chain !== "solana") {
        // Multi-chain is not implemented here. For other chains, implement chain-specific builders.
        return res.status(501).json({ error: "not_implemented", message: `Chain ${chain} not supported in this endpoint. Use a chain-specific integration.` });
      }

      const merchant = body.merchant || getEnv("MERCHANT_SOL_ADDRESS");
      if (!merchant) {
        return res.status(400).json({ error: "missing_merchant", message: "Provide merchant in body or set MERCHANT_SOL_ADDRESS" });
      }

      // Determine asset type
      const assetType: 'SOL' | 'SPL' = body.amountLamports ? 'SOL' : 'SPL';

      // If SPL and tokenAmountDecimal provided, convert to base units first
      let finalTokenAmountBase: string | undefined = undefined;
      if (assetType === 'SPL') {
        if (body.tokenAmount) {
          finalTokenAmountBase = body.tokenAmount; // assume base units string
        } else if (body.tokenAmountDecimal) {
          try {
            finalTokenAmountBase = await tokenDecimalToBaseUnits(body.tokenMint!, body.tokenAmountDecimal);
          } catch (e: any) {
            logger.warn("Invalid tokenAmountDecimal conversion", { error: e?.message });
            return res.status(400).json({ error: "invalid_token_amount", message: String(e?.message || e) });
          }
        } else {
          return res.status(400).json({ error: "missing_token_amount", message: "Provide tokenAmount (base units) or tokenAmountDecimal (human decimal)" });
        }
      }

      // If userPubkey is provided, keep the unsigned-tx flow (wallet signs)
      if (body.userPubkey) {
        // Use base units for tokenAmount if SPL
        const build = await createPaymentIntentUnsigned({
          assetType,
          amountLamports: body.amountLamports,
          tokenMint: body.tokenMint,
          tokenAmount: finalTokenAmountBase,
          merchant,
          userPubkey: body.userPubkey,
          orderId: body.orderId,
          memoText: body.memo || `order:${body.orderId}`,
        });

        const expiresAt = new Date(build.expiresAt);
        // Upsert order (include reference if present)
        await PaymentOrder.findOneAndUpdate(
          { orderId: build.orderId },
          {
            orderId: build.orderId,
            status: "pending",
            assetType,
            amountLamports: body.amountLamports ?? null,
            tokenMint: body.tokenMint ?? null,
            tokenAmount: finalTokenAmountBase ?? null,
            merchant,
            userPubkey: body.userPubkey,
            memo: build.memoText,
            unsignedTxB64: build.unsignedTxB64,
            phantomUrl: build.phantomUrl ?? null,
            qrDataUrl: build.qrDataUrl ?? null,
            expiresAt,
          },
          { upsert: true, new: true }
        );

        return res.status(201).json({
          orderId: build.orderId,
          phantomUrl: build.phantomUrl,
          qrDataUrl: build.qrDataUrl,
          unsignedTxB64: build.unsignedTxB64,
          expiresAt: build.expiresAt,
        });
      }

      // Merchant-only flow: build a Solana Pay URI (no userPubkey required)
      // Provide the base-unit tokenAmount for storage and, where possible, include a decimal representation in the URI.
      // buildSolanaPayLink should prefer a decimal amount for the URI; pass both if available.
      const tokenDecimalForUri = (assetType === 'SPL' && body.tokenAmountDecimal)
        ? body.tokenAmountDecimal
        : (assetType === 'SPL' && finalTokenAmountBase && body.tokenMint ? (() => {
            // Convert base units back to decimal string for the URI using mint decimals
            // This is best-effort and will truncate trailing zeros.
            try {
              // synchronous-ish conversion: fetch mint decimals
              // NOTE: getMint is async; do small sync via awaited block:
              // We'll implement a safe conversion using getMint
              return null; // fallback to letting buildSolanaPayLink use tokenAmount (base units)
            } catch {
              return null;
            }
          })() : undefined);

      const payLink = await buildSolanaPayLink({
        merchant,
        assetType,
        amountLamports: body.amountLamports,
        tokenMint: body.tokenMint,
        tokenAmount: finalTokenAmountBase,
        orderId: body.orderId,
        // buildSolanaPayLink implementation may accept tokenDecimalForUri - if not, it will fallback
        // We pass it as any to avoid TypeScript error if signature is extended there.
        ...(tokenDecimalForUri ? ({ tokenDecimalAmountForUri: tokenDecimalForUri } as any) : {}),
      } as any);

      const expiresAt = new Date(payLink.expiresAt);
      // Upsert order with reference so we can verify by searching for txs that include the reference
      const orderIdToUse = body.orderId || payLink.reference;
      await PaymentOrder.findOneAndUpdate(
        { orderId: orderIdToUse },
        {
          orderId: orderIdToUse,
          status: "pending",
          assetType,
          amountLamports: body.amountLamports ?? null,
          tokenMint: body.tokenMint ?? null,
          tokenAmount: finalTokenAmountBase ?? null,
          merchant,
          userPubkey: null,
          memo: body.memo || `order:${orderIdToUse}`,
          reference: payLink.reference,
          solanaPayUrl: payLink.solanaPayUrl,
          qrDataUrl: payLink.qrDataUrl,
          phantomUrl: payLink.phantomUrl ?? null,
          phantomQrDataUrl: payLink.phantomQrDataUrl ?? null,
          unsignedTxB64: null,
          expiresAt,
        },
        { upsert: true, new: true }
      );

      return res.status(201).json({
        orderId: orderIdToUse,
        reference: payLink.reference,
        solanaPayUrl: payLink.solanaPayUrl,
        qrDataUrl: payLink.qrDataUrl,
        phantomUrl: payLink.phantomUrl ?? null,
        phantomQrDataUrl: payLink.phantomQrDataUrl ?? null,
        expiresAt: payLink.expiresAt,
      });
    } catch (e: any) {
      logger.error("create payment intent failed", { error: e?.message, stack: e?.stack });
      // Provide minimal info to client, full info in server logs only
      return res.status(500).json({ error: "internal_error", message: "Failed to create payment intent" });
    }
  });

  // Phantom redirect callback: accept signedTransaction (b64) or signature
  // Note: This endpoint doesn't require API key auth as it's a wallet redirect callback
  app.get("/api/solana/phantom-callback", async (req: Request, res: Response) => {
    try {
      const orderId = String(req.query.order || "");
      const signedTransaction = req.query.signedTransaction ? String(req.query.signedTransaction) : undefined;
      const signature = req.query.signature ? String(req.query.signature) : undefined;
      const errorCode = req.query.errorCode ? String(req.query.errorCode) : undefined;

      if (!orderId) {
        return res.status(400).send("Missing order");
      }

      const order = await PaymentOrder.findOne({ orderId });
      if (!order) return res.status(404).send("Order not found");

      if (errorCode) {
        await PaymentOrder.updateOne({ orderId }, { $set: { status: "failed" } });
        return res.status(400).send(`Wallet error: ${errorCode}`);
      }

      let txSig = signature;
      if (!txSig && signedTransaction) {
        try {
          const resSend = await broadcastSignedTransaction(signedTransaction);
          txSig = resSend.signature;
          await PaymentOrder.updateOne({ orderId }, { $set: { signature: txSig, status: "submitted" } });
        } catch (e: any) {
          logger.error("broadcast failed", { error: e?.message, stack: e?.stack });
          await PaymentOrder.updateOne({ orderId }, { $set: { status: "failed" } });
          return res.status(500).send("Broadcast failed");
        }
      }

      if (!txSig) {
        return res.status(202).send("No signature provided yet");
      }

      // Verify on-chain
      const verify = await verifyOnChain({
        signature: txSig,
        merchant: order.merchant,
        assetType: order.assetType,
        amountLamports: order.amountLamports,
        tokenMint: order.tokenMint,
        tokenAmount: order.tokenAmount,
        memoText: order.memo || `order:${orderId}`,
      });

      if (verify.ok) {
        await PaymentOrder.updateOne({ orderId }, { $set: { status: "confirmed", signature: txSig } });
        // If this order corresponds to a subscription, activate it
        const memoText = order.memo || `order:${orderId}`;
        if (memoText.startsWith('subscription:')) {
          const subscriptionId = memoText.split(':')[1];
          if (subscriptionId) {
            const sub = await Subscription.findOne({ subscriptionId });
            if (sub && sub.status === 'pending') {
              const activeUntil = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
              sub.status = 'active';
              sub.activeUntil = activeUntil;

              // Auto-credit API key once, if configured
              const monthlyCredits = getNumberEnv('SUBSCRIPTION_MONTHLY_CREDITS', 0);
              if (monthlyCredits > 0 && !sub.creditedAt) {
                await ApiKey.findByIdAndUpdate(sub.apiKeyId, { $inc: { credits: monthlyCredits } }).exec();
                sub.creditedAt = new Date();
              }

              await sub.save();
            }
          }
        }
      } else {
        await PaymentOrder.updateOne({ orderId }, { $set: { status: "failed", signature: txSig } });
      }

      // Simple HTML response suitable for Phantom in-app browser
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.status(200).send(`<!doctype html><html><head><meta name=viewport content='width=device-width, initial-scale=1'>
<title>Payment ${verify.ok ? "Success" : "Issue"}</title></head><body style='font-family:system-ui;padding:24px'>
<h2>${verify.ok ? "✅ Payment received" : "⚠️ Payment issue"}</h2>
<p>Order: ${orderId}</p>
<p>Signature: ${txSig}</p>
${verify.ok ? "<p>You can close this window.</p>" : `<p>Reason: ${verify.reason || "unknown"}</p>`}
<script>setTimeout(()=>{ if (window?.close) try{window.close()}catch(e){} }, 1500)</script>
</body></html>`);
    } catch (e: any) {
      logger.error("phantom-callback error", { error: e?.message, stack: e?.stack });
      return res.status(500).send("Internal error");
    }
  });

  // Get payment intent status
  app.get("/api/solana/payment-intents/:orderId", authenticateApiKey(0.1), async (req: ApiKeyAuthenticatedRequest, res: Response) => {
    try {
      const orderId = req.params.orderId;
      const order = await PaymentOrder.findOne({ orderId });
      if (!order) return res.status(404).json({ error: "not_found" });
      return res.json({
        orderId: order.orderId,
        status: order.status,
        signature: order.signature || null,
        assetType: order.assetType,
        amountLamports: order.amountLamports,
        tokenMint: order.tokenMint || null,
        tokenAmount: order.tokenAmount || null,
        merchant: order.merchant,
        memo: order.memo || null,
        expiresAt: order.expiresAt,
      });
    } catch (e: any) {
      logger.error("get payment intent failed", { error: e?.message, stack: e?.stack });
      return res.status(500).json({ error: "internal_error" });
    }
  });

  // Regenerate expired payment intent (refresh blockhash)
  app.post("/api/solana/payment-intents/:orderId/regenerate", authenticateApiKey(1.0), async (req: ApiKeyAuthenticatedRequest, res: Response) => {
    try {
      const orderId = req.params.orderId;
      const order = await PaymentOrder.findOne({ orderId });
      if (!order) return res.status(404).json({ error: "not_found" });

      if (order.status !== 'pending' && order.status !== 'expired') {
        return res.status(400).json({ error: "cannot_regenerate", message: "Order must be pending or expired" });
      }

      // If this is a merchant-only intent (no userPubkey), regenerate the Solana Pay link and reference
      if (!order.userPubkey) {
        const payLink = await buildSolanaPayLink({
          merchant: order.merchant,
          assetType: order.assetType,
          amountLamports: order.amountLamports ?? undefined,
          tokenMint: order.tokenMint ?? undefined,
          tokenAmount: order.tokenAmount ?? undefined,
          orderId: order.orderId,
        });

        const expiresAt = new Date(payLink.expiresAt);
        await PaymentOrder.updateOne(
          { orderId },
          { $set: { status: 'pending', reference: payLink.reference, solanaPayUrl: payLink.solanaPayUrl, qrDataUrl: payLink.qrDataUrl, phantomUrl: payLink.phantomUrl ?? null, phantomQrDataUrl: payLink.phantomQrDataUrl ?? null, expiresAt } }
        );

        return res.json({
          orderId,
          reference: payLink.reference,
          solanaPayUrl: payLink.solanaPayUrl,
          qrDataUrl: payLink.qrDataUrl,
          phantomUrl: payLink.phantomUrl ?? null,
          phantomQrDataUrl: payLink.phantomQrDataUrl ?? null,
          expiresAt: payLink.expiresAt,
          regenerated: true,
        });
      }

      // Otherwise, regenerate an unsigned tx as before
      const build = await createPaymentIntentUnsigned({
        assetType: order.assetType,
        amountLamports: order.amountLamports,
        tokenMint: order.tokenMint,
        tokenAmount: order.tokenAmount,
        merchant: order.merchant,
        userPubkey: order.userPubkey,
        orderId: order.orderId,
        memoText: order.memo || `order:${order.orderId}`,
      });

      const expiresAt = new Date(build.expiresAt);
      await PaymentOrder.updateOne(
        { orderId },
        {
          $set: {
            status: "pending",
            unsignedTxB64: build.unsignedTxB64,
            phantomUrl: build.phantomUrl ?? null,
            qrDataUrl: build.qrDataUrl ?? null,
            expiresAt,
          }
        }
      );

      return res.json({
        orderId: build.orderId,
        phantomUrl: build.phantomUrl,
        qrDataUrl: build.qrDataUrl,
        unsignedTxB64: build.unsignedTxB64,
        expiresAt: build.expiresAt,
        regenerated: true,
      });
    } catch (e: any) {
      logger.error("regenerate payment intent failed", { error: e?.message, stack: e?.stack });
      return res.status(500).json({ error: "internal_error" });
    }
  });

  // Explicit verification endpoint by signature
  app.post("/api/solana/verify", authenticateApiKey(0.1), async (req: ApiKeyAuthenticatedRequest, res: Response) => {
    try {
      const VerifyBody = z.object({
        signature: z.string().min(32),
        orderId: z.string().min(6).optional(),
        merchant: z.string().min(32).optional(),
        // For SOL
        amountLamports: z.number().int().positive().optional(),
        // For SPL
        tokenMint: z.string().min(32).optional(),
        tokenAmount: z.string().regex(/^\d+$/).optional(),
      });
      const parsed = VerifyBody.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: "invalid_request", details: parsed.error.flatten() });

      const { signature, orderId } = parsed.data;
      let merchant = parsed.data.merchant || getEnv("MERCHANT_SOL_ADDRESS");
      let amountLamports = parsed.data.amountLamports;
      let tokenMint = parsed.data.tokenMint;
      let tokenAmount = parsed.data.tokenAmount;
      let memoText = orderId ? `order:${orderId}` : "";
      let assetType: 'SOL' | 'SPL' = 'SOL';

      if (orderId) {
        const order = await PaymentOrder.findOne({ orderId });
        if (order) {
          merchant = order.merchant;
          assetType = order.assetType;
          amountLamports = order.amountLamports;
          tokenMint = order.tokenMint;
          tokenAmount = order.tokenAmount;
          memoText = order.memo || `order:${orderId}`;
        }
      } else {
        // Infer asset type from provided parameters
        assetType = amountLamports ? 'SOL' : 'SPL';
      }

      if (!merchant || !memoText) {
        return res.status(400).json({ error: "missing_params" });
      }

      if ((assetType === 'SOL' && !amountLamports) || (assetType === 'SPL' && (!tokenMint || !tokenAmount))) {
        return res.status(400).json({ error: "missing_asset_params" });
      }

      // If signature is provided, verify directly
      if (signature) {
        const verify = await verifyOnChain({
          signature,
          merchant,
          assetType,
          amountLamports,
          tokenMint,
          tokenAmount,
          memoText
        });
        return res.json({ ok: verify.ok, reason: verify.reason, signature });
      }

      // No signature provided: try to discover a related signature using saved reference on the order
      if (orderId) {
        const order = await PaymentOrder.findOne({ orderId });
        if (order && order.reference) {
          // search for signatures touching the reference
          const sigs = await findSignaturesForAddress(order.reference, 20);
          for (const s of sigs) {
            try {
              const candidate = s.signature;
              const verify = await verifyOnChain({ signature: candidate, merchant, assetType, amountLamports, tokenMint, tokenAmount, memoText });
              if (verify.ok) {
                // mark order confirmed
                await PaymentOrder.updateOne({ orderId }, { $set: { status: 'confirmed', signature: candidate } });
                return res.json({ ok: true, signature: candidate });
              }
            } catch (e) {
              // ignore individual signature verification errors
            }
          }
          // not found yet
          return res.json({ ok: false, reason: 'not_found_yet' });
        }
      }

      // Nothing to do
      return res.status(400).json({ error: 'missing_signature_or_reference' });
    } catch (e: any) {
      logger.error("verify endpoint error", { error: e?.message, stack: e?.stack });
      return res.status(500).json({ error: "internal_error" });
    }
  });
}
