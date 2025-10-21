# ⚡ BlockSub — Web3 Recurring Payments Reinvented  

> **The Stripe for Solana** — Seamless, secure, and programmable recurring payments powered by on-chain automation.  
 

---

## 🌍 Overview  

BlockSub is a **Web3-native subscription infrastructure** built on **Solana**, enabling developers and businesses to easily integrate **recurring, on-chain payments** into their apps — just like Stripe Subscriptions, but decentralized.  

With BlockSub, merchants can collect periodic payments, manage customer lifecycles, and trigger automated actions **without storing private keys or compromising user custody.**  

---

## 💡 Why BlockSub?  

| 🧩 Problem | 🚀 Solution |
|-------------|-------------|
| Subscription-based businesses rely on Web2 processors (Stripe, PayPal) with high fees, custody risk, and no crypto-native flows. | BlockSub offers trustless, low-fee recurring payments directly on Solana. |
| On-chain payments lack a reliable way to handle monthly or periodic billing. | BlockSub introduces relayer-based verified billing cycles with HMAC-secured callbacks. |
| Developers face complex smart contract setups. | Our plug-and-play REST API + demo relayer makes it as simple as `POST /create-subscription`. |

---

## ⚙️ How It Works  

1. **Merchant connects wallet** to BlockSub dashboard.  
2. **Customer subscribes** — a `PaymentOrder` is created and mapped to a recurring subscription.  
3. **Merchant Relayer** signs and confirms transactions securely via HMAC.  
4. **Payment Worker** processes signed orders, updates statuses, and triggers webhooks.  

### 🧠 Architecture Overview  
Merchant App → BlockSub API → Payment Worker → Relayer → Solana Network
↘ Webhooks / Dashboards ↙

---

## 🔐 Security Architecture  

- **Per-subscription HMAC secrets** for verified relayer callbacks  
- **No private keys** stored on server — merchants keep custody  
- **Replay protection** via timestamps and idempotency keys  
- **Encrypted data** at rest (AES-256) and in transit (HTTPS)  
- **JWT-based user auth** with refresh tokens and session encryption  

---

## 🧰 Tech Stack  

- **Backend:** Node.js (Express + MongoDB + Mongoose)  
- **Blockchain:** Solana Web3.js + Helius RPC  
- **Security:** HMAC verification + AES-256 encryption  
- **Relayer:** Custom-built signing service for secure transaction handling  
- **Frontend (WIP):** Next.js Dashboard for merchants  

---

💼 Key Features
✅ Recurring payments on Solana (USDC / any SPL token)
✅ Merchant-controlled relayers (no key custody)
✅ Webhook + Dashboard integration
✅ Real-time subscription lifecycle tracking
✅ Developer SDKs & REST API
✅ Stripe-like UX for blockchain

🧩 Integrations

| Platform                       | Status      |
| ------------------------------ | ----------- |
| 🪙 Solana Mainnet              | ✅           |
| 🧰 MongoDB Atlas               | ✅           |
| 🪄 Nodemailer (SMTP)           | ✅           |
| 🔗 Phantom Wallet              | ✅           |
| 🧱 Helius RPC                  | ✅           |
| 🧩 Anchor/Rust Smart Contracts | Coming Soon |


🧑‍💻 Founder

Shaheer Ali
Founder & Lead Engineer @ BlockSub
🚀 Building decentralized fintech from the ground up.
💬 x account: shaheerxdev
🌐 Website: [coming soon]

🧭 Roadmap
| Phase       | Milestone                    | Status         |
| ----------- | ---------------------------- | -------------- |
| 🏗️ Phase 1 | API + Worker + Relayer MVP   | ✅ Completed    |
| ⚡ Phase 2   | Web Dashboard + Analytics    | ✅ Completed  |
| 🪙 Phase 3  | Tokenomics + Staking System  | ⏳ Planned      |
| 🌍 Phase 4  | Global Launch + Merchant SDK | 🔜 Coming Soon |

🧠 Want to Contribute?
Pull requests, feedback, and ideas are always welcome!
Fork the repo
Create a feature branch
Submit a PR and describe your improvement



