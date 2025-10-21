#!/usr/bin/env node
"use strict";

// Production-grade Relayer
// - Verifies incoming HMAC signed requests (timestamped) from the BlockSub worker
// - Signs unsigned transactions with the merchant key (or external signer)
// - Posts the signed transaction back to the BlockSub server callback using timestamped HMAC
// - Retries with exponential backoff when server callback fails

const http = require("http");
const crypto = require("crypto");
const fetch = require("node-fetch");
const bs58 = require("bs58");
const { Keypair, Transaction } = require("@solana/web3.js");
const pRetry = require("p-retry");

// Configuration (via env)
const PORT = Number(process.env.PORT || 8081);
const MERCHANT_SECRET_KEY = process.env.MERCHANT_SECRET_KEY; // base58 or JSON array for Keypair
const SERVER_CALLBACK = process.env.SERVER_CALLBACK || "http://localhost:3000/api/recurring-subscriptions/relayer/callback";
const EXPECTED_WORKER_SIGNATURE_HEADER = process.env.WORKER_SIGNATURE_HEADER || "x-relayer-signature";
const EXPECTED_WORKER_TIMESTAMP_HEADER = process.env.WORKER_TIMESTAMP_HEADER || "x-timestamp";
const RELAYER_SECRET = process.env.RELAYER_SECRET; // shared secret to sign responses back to server
const RELAYER_API_KEY = process.env.RELAYER_API_KEY; // API key to fetch per-subscription secrets from server
const RELAYER_SERVER_BASE = process.env.RELAYER_SERVER_BASE; // e.g. https://example.com (required if RELAYER_API_KEY is used)
const EXTERNAL_SIGNER_CMD = process.env.EXTERNAL_SIGNER_CMD; // optional external signer command

if (!MERCHANT_SECRET_KEY) {
  console.error("MERCHANT_SECRET_KEY must be set (base58 or json array of bytes). Aborting.");
  process.exit(1);
}

function loadKeypair(secret) {
  try {
    if (secret.trim().startsWith("[")) {
      const arr = JSON.parse(secret);
      return Keypair.fromSecretKey(Buffer.from(arr));
    }
    return Keypair.fromSecretKey(bs58.decode(secret));
  } catch (err) {
    console.error("Failed to parse MERCHANT_SECRET_KEY:", err);
    process.exit(1);
  }
}

const merchantKeypair = loadKeypair(MERCHANT_SECRET_KEY);
console.log("Relayer starting — merchant:", merchantKeypair.publicKey.toBase58());

function verifyHmacRequest(headers, body) {
  // Verifies a timestamped HMAC signature from the worker: signature = HMAC(secret, timestamp + JSON_BODY)
  const tsHeader = headers[EXPECTED_WORKER_TIMESTAMP_HEADER];
  const sigHeader = headers[EXPECTED_WORKER_SIGNATURE_HEADER];
  if (!sigHeader || !tsHeader) return { ok: false, reason: "missing_signature_or_timestamp" };

  const ts = String(Array.isArray(tsHeader) ? tsHeader[0] : tsHeader);
  const signature = String(Array.isArray(sigHeader) ? sigHeader[0] : sigHeader);

  // Prevent replay: only accept timestamps +/- 5 minutes
  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum)) return { ok: false, reason: "invalid_timestamp" };
  const ageMs = Date.now() - tsNum;
  if (ageMs > 5 * 60 * 1000 || ageMs < -2 * 60 * 1000) return { ok: false, reason: "timestamp_out_of_range" };

  // In production you'd lookup the subscription-specific relayer secret. For simplicity, use RELAYER_SECRET env as the shared secret.
  if (!RELAYER_SECRET) return { ok: false, reason: "relayer_secret_not_configured" };

  const expected = crypto.createHmac("sha256", RELAYER_SECRET).update(ts + body).digest("hex");
  if (expected !== signature) return { ok: false, reason: "invalid_signature" };
  return { ok: true };
}

// Verify using a provided secret (per-subscription). Returns {ok, reason}
function verifyHmacWithSecret(headers, body, secret) {
  const tsHeader = headers[EXPECTED_WORKER_TIMESTAMP_HEADER];
  const sigHeader = headers[EXPECTED_WORKER_SIGNATURE_HEADER];
  if (!sigHeader || !tsHeader) return { ok: false, reason: "missing_signature_or_timestamp" };

  const ts = String(Array.isArray(tsHeader) ? tsHeader[0] : tsHeader);
  const signature = String(Array.isArray(sigHeader) ? sigHeader[0] : sigHeader);

  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum)) return { ok: false, reason: "invalid_timestamp" };
  const ageMs = Date.now() - tsNum;
  if (ageMs > 5 * 60 * 1000 || ageMs < -2 * 60 * 1000) return { ok: false, reason: "timestamp_out_of_range" };

  if (!secret) return { ok: false, reason: "relayer_secret_not_configured" };
  const expected = crypto.createHmac("sha256", secret).update(ts + body).digest("hex");
  if (expected !== signature) return { ok: false, reason: "invalid_signature" };
  return { ok: true };
}

async function fetchRelayerSecretForSubscription(subscriptionId) {
  if (!RELAYER_API_KEY || !RELAYER_SERVER_BASE) return null;
  try {
    const url = `${RELAYER_SERVER_BASE.replace(/\/$/, "")}/api/relayer/secret/${encodeURIComponent(subscriptionId)}`;
    const res = await fetch(url, { headers: { Authorization: `Bearer ${RELAYER_API_KEY}` } });
    if (!res.ok) return null;
    const js = await res.json();
    // Expect { secret } or plain string
    if (js && js.secret) return js.secret;
    if (typeof js === "string") return js;
    return null;
  } catch (e) {
    console.error("Failed to fetch relayer secret for subscription", subscriptionId, e && e.message);
    return null;
  }
}

async function fetchMerchantKeyForSubscription(subscriptionId) {
  if (!RELAYER_API_KEY || !RELAYER_SERVER_BASE) return null;
  try {
    const url = `${RELAYER_SERVER_BASE.replace(/\/$/, "")}/api/relayer/merchant-key/${encodeURIComponent(subscriptionId)}`;
    const res = await fetch(url, { headers: { Authorization: `Bearer ${RELAYER_API_KEY}` } });
    if (!res.ok) return null;
    const js = await res.json();
    // Expect { merchantKey: string } or plain string
    if (js && js.merchantKey) return js.merchantKey;
    if (typeof js === "string") return js;
    return null;
  } catch (e) {
    console.error("Failed to fetch merchant key for subscription", subscriptionId, e && e.message);
    return null;
  }
}

async function postBackSignedTx(orderId, signedTxB64, subscriptionId, maxAttempts = 5) {
  const body = JSON.stringify({ orderId, signedTxB64 });

  // Build headers with timestamped HMAC
  const timestamp = Date.now().toString();
  const headers = { "Content-Type": "application/json", "X-Timestamp": timestamp };
  if (RELAYER_SECRET) {
    const sig = crypto.createHmac("sha256", RELAYER_SECRET).update(timestamp + body).digest("hex");
    headers["X-Relayer-Signature"] = sig;
  }

  // Use p-retry to retry POST with exponential backoff
  await pRetry(async () => {
    const res = await fetch(SERVER_CALLBACK, { method: "POST", body, headers });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      const err = new Error(`Callback failed ${res.status}: ${text}`);
      err.status = res.status;
      throw err;
    }
    return true;
  }, {
    retries: Math.min(maxAttempts, 5),
    factor: 2,
    minTimeout: 500,
  });
}

async function signTransaction(unsignedTxB64, merchantSecretOverride) {
  // Default: sign with local merchant keypair
  const txBuf = Buffer.from(unsignedTxB64, "base64");
  const tx = Transaction.from(txBuf);

  // Optionally run external signer command (for HSM / remote signer integration)
  if (EXTERNAL_SIGNER_CMD) {
    // If an external signer is required, it should accept unsigned base64 and return signed base64
    // For production, implement secure CLI or RPC signer integration. Here we fallback to local signing if external fails.
    try {
      const { execSync } = require("child_process");
      const out = execSync(`${EXTERNAL_SIGNER_CMD} '${unsignedTxB64}'`, { encoding: "utf8", timeout: 30 * 1000 });
      const res = out && out.trim();
      if (res) return res;
    } catch (e) {
      console.error("External signer failed, falling back to local key", e);
    }
  }

  // Local sign
  // If merchantSecretOverride is provided, create a temporary keypair and use it
  if (merchantSecretOverride) {
    const tempKey = loadKeypair(merchantSecretOverride);
    tx.partialSign(tempKey);
  } else {
    tx.partialSign(merchantKeypair);
  }
  const signed = tx.serialize();
  return Buffer.from(signed).toString("base64");
}

const server = http.createServer(async (req, res) => {
  if (req.method !== "POST") {
    res.writeHead(404).end();
    return;
  }

  let body = "";
  req.on("data", (chunk) => body += chunk);
  req.on("end", async () => {
    try {
      const headers = Object.fromEntries(Object.entries(req.headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
      // Validate body
      let payload;
      try { payload = JSON.parse(body); } catch (e) { throw new Error("invalid_json"); }

      const { orderId, unsignedTxB64, subscriptionId, expiresAt } = payload;
      if (!orderId || !unsignedTxB64) throw new Error("missing_order_or_tx");

      // Verify HMAC signature from the worker (timestamp + body HMAC)
      // Prefer per-subscription secret if available; fall back to RELAYER_SECRET env.
      let verify = { ok: false, reason: "missing_subscription" };
      const subId = payload.subscriptionId;
      if (subId && RELAYER_API_KEY && RELAYER_SERVER_BASE) {
        const secret = await fetchRelayerSecretForSubscription(subId);
        if (secret) verify = verifyHmacWithSecret(headers, body, secret);
      }
      // Fallback to global RELAYER_SECRET
      if (!verify.ok && RELAYER_SECRET) {
        verify = verifyHmacWithSecret(headers, body, RELAYER_SECRET);
      }
      if (!verify.ok) {
        res.writeHead(403, { "Content-Type": "application/json" }).end(JSON.stringify({ ok: false, reason: verify.reason }));
        return;
      }

      // Optional: check expiresAt to avoid signing expired intents
      if (expiresAt) {
        const exp = new Date(expiresAt).getTime();
        if (Date.now() > exp) {
          res.writeHead(410, { "Content-Type": "application/json" }).end(JSON.stringify({ ok: false, reason: "intent_expired" }));
          return;
        }
      }

      // Optionally fetch per-subscription merchant key (overrides local MERCHANT_SECRET_KEY)
      let merchantKeyToUse = MERCHANT_SECRET_KEY;
      if (subId && RELAYER_API_KEY && RELAYER_SERVER_BASE) {
        const fetched = await fetchMerchantKeyForSubscription(subId);
        if (fetched) {
          merchantKeyToUse = fetched;
          console.log(`Using per-subscription merchant key for ${subId}`);
        }
      }

      // Sign the unsigned transaction
      const signedB64 = await signTransaction(unsignedTxB64, merchantKeyToUse);

      // Post signed tx back to the server callback with retries
      try {
        await postBackSignedTx(orderId, signedB64, subscriptionId, 5);
      } catch (e) {
        console.error("Failed to POST signed tx to server callback", e);
        // Return 502 but still include signed tx so caller can choose to retry
        res.writeHead(502, { "Content-Type": "application/json" }).end(JSON.stringify({ ok: false, error: String(e), signedTxB64 }));
        return;
      }

      res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ ok: true, orderId }));
    } catch (e) {
      console.error("Relayer request failed:", e && (e.message || e));
      res.writeHead(400, { "Content-Type": "application/json" }).end(JSON.stringify({ ok: false, error: String(e && (e.message || e)) }));
    }
  });
});

server.listen(PORT, () => console.log(`Relayer listening on port ${PORT}`));
