import type { Express, Request, Response } from "express";
import { z } from "zod";
import { logger } from "./security";
import { PaymentOrder, createPaymentIntentSchema, Subscription, ApiKey } from "@shared/schema-mongodb";
import { createPaymentIntentUnsigned, broadcastSignedTransaction, getTransactionBySignature, extractMemoFromTransaction, buildSolanaPayLink, findSignaturesForAddress } from "./solana";
import { PublicKey } from "@solana/web3.js";
import { getAssociatedTokenAddressSync } from "@solana/spl-token";
import { authenticateApiKey, ApiKeyAuthenticatedRequest } from "@shared/auth";

const CreateIntentBody = z.object({
  orderId: z.string().min(6).max(64),
  // Make merchant optional for this endpoint (fallback to env)
  merchant: z.string().min(32).optional(),
  userPubkey: z.string().min(32).optional(),
  memo: z.string().max(128).optional(),
  // SOL
  amountLamports: z.number().int().positive().optional(),
  // SPL
  tokenMint: z.string().min(32).optional(),
  tokenAmount: z.string().regex(/^\d+$/).optional(),
}).refine((d) => {
  const sol = typeof d.amountLamports === 'number' && !d.tokenMint && !d.tokenAmount;
  const spl = !d.amountLamports && !!d.tokenMint && !!d.tokenAmount;
  return sol || spl;
}, {
  message: 'Provide either amountLamports for SOL or tokenMint+tokenAmount for SPL',
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

async function verifyOnChain(opts: {
  signature: string;
  merchant: string;
  assetType: 'SOL' | 'SPL';
  amountLamports?: number; // for SOL
  tokenMint?: string; // for SPL
  tokenAmount?: string; // for SPL
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
      
      const preAmount = preBalance ? BigInt(preBalance.uiTokenAmount.amount) : BigInt(0);
      const postAmount = BigInt(postBalance.uiTokenAmount.amount);
      const delta = postAmount - preAmount;
      
      if (delta < expectedAmount) {
        return { ok: false, reason: "spl_amount_mismatch", tx };
      }
    } else {
      return { ok: false, reason: "invalid_asset_type", tx };
    }

    return { ok: true, tx };
  } catch (e: any) {
    logger.error("verifyOnChain error", { error: e?.message });
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
      const merchant = body.merchant || getEnv("MERCHANT_SOL_ADDRESS");
      if (!merchant) {
        return res.status(400).json({ error: "missing_merchant", message: "Provide merchant in body or set MERCHANT_SOL_ADDRESS" });
      }

      // Determine asset type and validate parameters
      const assetType: 'SOL' | 'SPL' = body.amountLamports ? 'SOL' : 'SPL';

      // Build Solana Pay link (this function now also returns phantomUrl & phantomQrDataUrl)
      const payLink = await buildSolanaPayLink({
        merchant,
        assetType,
        amountLamports: body.amountLamports,
        tokenMint: body.tokenMint,
        tokenAmount: body.tokenAmount,
        orderId: body.orderId,
        expiresMs: 15 * 60 * 1000,
      });

      // Save PaymentOrder for tracking; now include phantomUrl if available
      await PaymentOrder.create({
        orderId: body.orderId,
        status: 'pending',
        assetType: assetType,
        amountLamports: body.amountLamports ?? null,
        tokenMint: body.tokenMint ?? null,
        tokenAmount: body.tokenAmount ?? null,
        merchant,
        userPubkey: body.userPubkey ?? null,
        memo: body.memo ?? null,
        unsignedTxB64: payLink.unsignedTxB64 ?? null, // if your createPaymentIntentUnsigned populates this; keep existing behavior
        expiresAt: new Date(payLink.expiresAt),
        reference: payLink.reference,
        solanaPayUrl: payLink.solanaPayUrl,
        qrDataUrl: payLink.qrDataUrl,
        phantomUrl: payLink.phantomUrl ?? undefined,
        phantomQrDataUrl: payLink.phantomQrDataUrl ?? undefined,
      });

      // Return response — include phantomUrl + phantomQrDataUrl for client convenience
      return res.status(201).json({
        orderId: body.orderId,
        reference: payLink.reference,
        solanaPayUrl: payLink.solanaPayUrl,
        qrDataUrl: payLink.qrDataUrl,
        phantomUrl: payLink.phantomUrl ?? null,
        phantomQrDataUrl: payLink.phantomQrDataUrl ?? null,
        expiresAt: payLink.expiresAt,
      });
    } catch (e: any) {
      logger.error("create payment intent failed", { error: e?.message });
      return res.status(500).json({ error: "internal_error" });
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
          logger.error("broadcast failed", { error: e?.message });
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
      logger.error("phantom-callback error", { error: e?.message });
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
          { $set: { status: 'pending', reference: payLink.reference, expiresAt } }
        );

        return res.json({
          orderId,
          reference: payLink.reference,
          solanaPayUrl: payLink.solanaPayUrl,
          qrDataUrl: payLink.qrDataUrl,
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
      logger.error("regenerate payment intent failed", { error: e?.message });
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
      if (!parsed.success) return res.status(400).json({ error: "invalid_request" });

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
      // If orderId provided and order has a reference, search signatures for that reference
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
              // ignore errors for individual signatures
            }
          }
          // not found yet
          return res.json({ ok: false, reason: 'not_found_yet' });
        }
      }

      // Nothing to do
      return res.status(400).json({ error: 'missing_signature_or_reference' });
    } catch (e: any) {
      return res.status(500).json({ error: "internal_error" });
    }
  });

}
