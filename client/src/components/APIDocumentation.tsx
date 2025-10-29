import OneTimeKeyModal from './OneTimeKeyModal';
import React, { useMemo, useState } from 'react';
import {
  SidebarProvider,
  Sidebar,
  SidebarHeader,
  SidebarContent,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
  SidebarInset,
  SidebarSeparator,
  SidebarTrigger,
} from '@/components/ui/sidebar';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { CodeTabs } from '@/components/CodeTabs';
import { BookOpen, ExternalLink, Code2, Zap, Shield, Layers } from 'lucide-react';

function InteractiveOneTimeKeyDemo() {
  const [apiKey, setApiKey] = useState('');
  const [subscriptionId, setSubscriptionId] = useState('');
  const [modalOpen, setModalOpen] = useState(false);
  const [oneTimeKey, setOneTimeKey] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const poll = async () => {
    try {
      setLoading(true);
      const res = await fetch(`/api/billing/subscriptions/${subscriptionId}`, { headers: { Authorization: apiKey.startsWith('Bearer') ? apiKey : `ApiKey ${apiKey}` } });
      const sd = await res.json();
      if (sd?.issuedApiKey && sd.issuedApiKey.key) {
        setOneTimeKey(sd.issuedApiKey.key);
        setModalOpen(true);
      } else {
        alert('No one-time key returned. Status: ' + (sd?.status || 'unknown'));
      }
    } catch (e: any) {
      alert('Polling failed: ' + (e?.message || String(e)));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex gap-2">
        <input className="input" placeholder="API Key or Bearer token" value={apiKey} onChange={(e) => setApiKey(e.target.value)} />
        <input className="input" placeholder="subscription id" value={subscriptionId} onChange={(e) => setSubscriptionId(e.target.value)} />
        <button className="btn" onClick={poll} disabled={loading || !subscriptionId || !apiKey}>{loading ? 'Polling…' : 'Poll & Show Key'}</button>
      </div>
      <OneTimeKeyModal open={modalOpen} onClose={() => { setModalOpen(false); setOneTimeKey(null); }} keyValue={oneTimeKey ?? undefined} />
    </div>
  );
}

export function APIDocumentation() {
  const baseUrl = useMemo(() => {
    if (typeof window === 'undefined') return 'http://localhost:5173';
    return window.location.origin;
  }, []);

  // 💳 Create One-Time Payment (Merchant Flow Only — Safe for Public Docs)
  // Supports SOL and SPL (USDC etc.) payments
 const createOneTimeSamples = {
  curl: `curl -X POST ${baseUrl}/api/solana/payment-intents \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer <API_KEY>" \\
  -d '{
    "orderId": "order_123456",
    /* merchant (merchant wallet address) is REQUIRED */
    "merchant": "<your_merchant_wallet>",
    /* For SOL payments (lamports) */
    "amountLamports": 100000000,
    /* Or for fiat-denominated flows */
    "amountUsd": 5.00,
    /* Currency hint */
    "currency": "USD",
    "memo": "Payment for order #123456",
    /* chain/network */
    "chain": "solana",
    /* optional callback/webhook */
    "webhookUrl": "https://example.com/payment-webhook",
    /* metadata/free-form object */
    "metadata": { "customer_id": "cus_123", "note": "gift" },
    /* optional expiry in ISO or epoch */
    "expiresAt": "2025-11-01T00:00:00Z",
    /* optional payer/customer wallet reference (client-provided) */
    "customerWallet": "4f2...Example",
    /* allow partial payments or holds */
    "allowPartial": false,
    /* optional reference string for the tx or payment */
    "reference": "ref_987654",
    /* Optional SPL token payment fields (OPTIONAL): tokenMint, tokenAmount (base units), tokenAmountDecimal (human), tokenDecimals */
    "tokenMint": "So11111111111111111111111111111111111111112",
    "tokenAmount": "1000000",
    "tokenAmountDecimal": "1.0",
    "tokenDecimals": 9
  }'`,

  javascript: `// Node 18+ or Browser
await fetch('${baseUrl}/api/solana/payment-intents', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer <API_KEY>'
  },
  body: JSON.stringify({
    orderId: 'order_123456',
    // merchant (merchant wallet) is REQUIRED
    merchant: '<your_merchant_wallet>',
    // For SOL
    amountLamports: 100000000,
    // Or optional fiat/other representations:
    amountUsd: 5.00,
    currency: 'USD',
    memo: 'Payment for order #123456',
    chain: 'solana',
    webhookUrl: 'https://example.com/payment-webhook',
    metadata: { customer_id: 'cus_123', note: 'gift' },
    expiresAt: '2025-11-01T00:00:00Z',
    customerWallet: '4f2...Example',
    allowPartial: false,
    reference: 'ref_987654',
    // Optional SPL token fields (OPTIONAL):
    tokenMint: 'So11111111111111111111111111111111111111112', // optional
    tokenAmount: '1000000', // base units (string recommended for big ints)
    tokenAmountDecimal: '1.0', // human readable (optional)
    tokenDecimals: 9 // optional
  })
}).then(r => r.json())`,

  python: `import requests
r = requests.post(
  '${baseUrl}/api/solana/payment-intents',
  headers={'Authorization': 'Bearer <API_KEY>', 'Content-Type': 'application/json'},
  json={
    'orderId': 'order_123456',
    # merchant (merchant wallet) is REQUIRED
    'merchant': '<your_merchant_wallet>',
    # For SOL
    'amountLamports': 100000000,
    # Optional fiat representation
    'amountUsd': 5.00,
    'currency': 'USD',
    'memo': 'Payment for order #123456',
    'chain': 'solana',
    'webhookUrl': 'https://example.com/payment-webhook',
    'metadata': {'customer_id': 'cus_123', 'note': 'gift'},
    'expiresAt': '2025-11-01T00:00:00Z',
    'customerWallet': '4f2...Example',
    'allowPartial': False,
    'reference': 'ref_987654',
    # Optional SPL token fields (OPTIONAL)
    'tokenMint': 'So11111111111111111111111111111111111111112',
    'tokenAmount': '1000000',
    'tokenAmountDecimal': '1.0',
    'tokenDecimals': 9
  }
)
print(r.json())`,

  go: `package main
import (
  "bytes"
  "encoding/json"
  "fmt"
  "net/http"
)
func main() {
  body := map[string]any{
    "orderId": "order_123456",
    // merchant (merchant wallet) is REQUIRED
    "merchant": "<your_merchant_wallet>",
    // For SOL
    "amountLamports": 100000000,
    // Optional
    "amountUsd": 5.00,
    "currency": "USD",
    "memo": "Payment for order #123456",
    "chain": "solana",
    "webhookUrl": "https://example.com/payment-webhook",
    "metadata": map[string]any{"customer_id":"cus_123","note":"gift"},
    "expiresAt": "2025-11-01T00:00:00Z",
    "customerWallet": "4f2...Example",
    "allowPartial": false,
    "reference": "ref_987654",
    // Optional SPL token fields:
    "tokenMint": "So11111111111111111111111111111111111111112",
    "tokenAmount": "1000000",
    "tokenAmountDecimal": "1.0",
    "tokenDecimals": 9,
  }
  b, _ := json.Marshal(body)
  req, _ := http.NewRequest("POST", "${baseUrl}/api/solana/payment-intents", bytes.NewReader(b))
  req.Header.Set("Authorization", "Bearer <API_KEY>")
  req.Header.Set("Content-Type", "application/json")
  resp, err := http.DefaultClient.Do(req)
  if err != nil { panic(err) }
  defer resp.Body.Close()
  fmt.Println(resp.Status)
}`,

  ruby: `require 'net/http'
require 'json'
uri = URI('${baseUrl}/api/solana/payment-intents')
req = Net::HTTP::Post.new(uri, 'Content-Type' => 'application/json')
req['Authorization'] = 'Bearer <API_KEY>'
req.body = {
  orderId: 'order_123456',
  merchant: '<your_merchant_wallet>', # REQUIRED
  amountLamports: 100000000,
  amountUsd: 5.00,
  currency: 'USD',
  memo: 'Payment for order #123456',
  chain: 'solana',
  webhookUrl: 'https://example.com/payment-webhook',
  metadata: { customer_id: 'cus_123', note: 'gift' },
  expiresAt: '2025-11-01T00:00:00Z',
  customerWallet: '4f2...Example',
  allowPartial: false,
  reference: 'ref_987654',
  # Optional SPL fields:
  tokenMint: 'So11111111111111111111111111111111111111112',
  tokenAmount: '1000000',
  tokenAmountDecimal: '1.0',
  tokenDecimals: 9
}.to_json
res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') { |http| http.request(req) }
puts res.body`,

  php: `<?php
$ch = curl_init('${baseUrl}/api/solana/payment-intents');
$data = [
  'orderId' => 'order_123456',
  'merchant' => '<your_merchant_wallet>', // REQUIRED
  'amountLamports' => 100000000,
  'amountUsd' => 5.00,
  'currency' => 'USD',
  'memo' => 'Payment for order #123456',
  'chain' => 'solana',
  'webhookUrl' => 'https://example.com/payment-webhook',
  'metadata' => ['customer_id' => 'cus_123', 'note' => 'gift'],
  'expiresAt' => '2025-11-01T00:00:00Z',
  'customerWallet' => '4f2...Example',
  'allowPartial' => false,
  'reference' => 'ref_987654',
  // Optional SPL token fields:
  'tokenMint' => 'So11111111111111111111111111111111111111112',
  'tokenAmount' => '1000000',
  'tokenAmountDecimal' => '1.0',
  'tokenDecimals' => 9
];
curl_setopt_array($ch, [
  CURLOPT_POST => true,
  CURLOPT_HTTPHEADER => [
    'Content-Type: application/json',
    'Authorization: Bearer <API_KEY>'
  ],
  CURLOPT_POSTFIELDS => json_encode($data),
  CURLOPT_RETURNTRANSFER => true,
]);
$response = curl_exec($ch);
curl_close($ch);
echo $response;`
} as const;

  const checkStatusSamples = {
    curl: `curl -X GET ${baseUrl}/api/solana/payment-intents/order_123456 \\
  -H "Authorization: Bearer bsk_test_1234567890abcdef1234567890abcdef"
# Alternatively:
# curl -X GET ${baseUrl}/api/solana/payment-intents/order_123456 \\
#   -H "x-api-key: bsk_test_1234567890abcdef1234567890abcdef"`,
    javascript: `await fetch('${baseUrl}/api/solana/payment-intents/order_123456', {
  headers: {
    'Authorization': 'Bearer bsk_test_1234567890abcdef1234567890abcdef'
    // Alternatively: 'x-api-key': 'bsk_test_1234567890abcdef1234567890abcdef'
  }
}).then(r => r.json())`,
    python: `import requests
headers = {
  'Authorization': 'Bearer bsk_test_1234567890abcdef1234567890abcdef'
  # Alternatively: 'x-api-key': 'bsk_test_1234567890abcdef1234567890abcdef'
}
print(requests.get('${baseUrl}/api/solana/payment-intents/order_123456', headers=headers).json())`,
    go: `package main
import (
  "fmt"
  "net/http"
)
func main(){
  req, _ := http.NewRequest("GET", "${baseUrl}/api/solana/payment-intents/order_123456", nil)
  req.Header.Set("Authorization", "Bearer bsk_test_1234567890abcdef1234567890abcdef")
  // Alternatively: req.Header.Set("x-api-key", "bsk_test_1234567890abcdef1234567890abcdef")
  resp, _ := http.DefaultClient.Do(req)
  fmt.Println(resp.Status)
}`,
    ruby: `require 'net/http'
uri = URI('${baseUrl}/api/solana/payment-intents/order_123456')
req = Net::HTTP::Get.new(uri)
req['Authorization'] = 'Bearer bsk_test_1234567890abcdef1234567890abcdef'
# Alternatively: req['x-api-key'] = 'bsk_test_1234567890abcdef1234567890abcdef'
res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') { |http| http.request(req) }
puts res.body`,
    php: `<?php
$ch = curl_init('${baseUrl}/api/solana/payment-intents/order_123456');
$headers = [
  'Authorization: Bearer bsk_test_1234567890abcdef1234567890abcdef'
  // Alternatively: 'x-api-key: bsk_test_1234567890abcdef1234567890abcdef'
];
curl_setopt_array($ch, [
  CURLOPT_CUSTOMREQUEST => 'GET',
  CURLOPT_HTTPHEADER => $headers,
  CURLOPT_RETURNTRANSFER => true,
]);
$response = curl_exec($ch);
curl_close($ch);
echo $response;`
  } as const;


  // Recurring subscription examples
  // NOTE: webhookUrl is REQUIRED for recurring subscriptions (server will POST initialize tx and webhook events to this URL)
  const recurringCreateSamples = {
  curl: `curl -X POST ${baseUrl}/api/recurring-subscriptions \\
  -H "Authorization: Bearer bsk_test_1234567890abcdef1234567890abcdef" \\
  -H "Content-Type: application/json" \\
  -d '{
    "plan": "basic",
    "priceUsd": 5.00,
    "billingInterval": "monthly",
    /* merchantWalletAddress is REQUIRED for recurring subscriptions */
    "merchantWalletAddress": "0xABCDEF0123456789abcdef0123456789ABCDEF01",
    /* webhookUrl is REQUIRED for recurring subscriptions */
    "webhookUrl": "https://example.com/webhook",
    "metadata": { "customer_id": "cus_123", "order_id": "ord_456" },
    /* trial (days) */
    "trialDays": 7,
    /* optional fields commonly supported */
    "quantity": 1,
    "autoRenew": true,
    "startDate": "2025-11-01T00:00:00Z",
    /* token payment fields: OPTIONAL (tokenMintAddress, tokenAmount, tokenDecimals) */
    "tokenMintAddress": "So11111111111111111111111111111111111111112",
    "tokenAmount": 0.1,
    "tokenDecimals": 9
  }'`,

  javascript: `await fetch('${baseUrl}/api/recurring-subscriptions', {
  method: 'POST',
  headers: { 
    'Content-Type': 'application/json',
    'Authorization': 'Bearer bsk_test_1234567890abcdef1234567890abcdef'
  },
  body: JSON.stringify({
    plan: 'basic',
    priceUsd: 5.00,
    billingInterval: 'monthly',
    // merchantWalletAddress is REQUIRED
    merchantWalletAddress: '0xABCDEF0123456789abcdef0123456789ABCDEF01',
    // webhookUrl is REQUIRED
    webhookUrl: 'https://example.com/webhook',
    metadata: { customer_id: 'cus_123', order_id: 'ord_456' },
    trialDays: 7,
    quantity: 1,
    autoRenew: true,
    startDate: '2025-11-01T00:00:00Z',
    // Optional token payment fields:
    tokenMintAddress: 'So11111111111111111111111111111111111111112', // optional
    tokenAmount: 0.1, // optional
    tokenDecimals: 9 // optional
  })
}).then(r => r.json())`,

  python: `import requests
headers = {
  'Authorization': 'Bearer bsk_test_1234567890abcdef1234567890abcdef',
  'Content-Type': 'application/json'
}
r = requests.post('${baseUrl}/api/recurring-subscriptions', headers=headers, json={
  'plan': 'basic',
  'priceUsd': 5.00,
  'billingInterval': 'monthly',
  # merchantWalletAddress is REQUIRED
  'merchantWalletAddress': '0xABCDEF0123456789abcdef1234567890ABCDEF01',
  # webhookUrl is REQUIRED
  'webhookUrl': 'https://example.com/webhook',
  'metadata': {'customer_id': 'cus_123', 'order_id': 'ord_456'},
  'trialDays': 7,
  'quantity': 1,
  'autoRenew': True,
  'startDate': '2025-11-01T00:00:00Z',
  # Optional token-related fields:
  'tokenMintAddress': 'So11111111111111111111111111111111111111112',
  'tokenAmount': 0.1,
  'tokenDecimals': 9
})
print(r.json())`,

  go: `package main
import (
  "bytes"
  "encoding/json"
  "fmt"
  "net/http"
)
func main(){
  body := map[string]any{
    "plan": "basic",
    "priceUsd": 5.00,
    "billingInterval": "monthly",
    // merchantWalletAddress is REQUIRED
    "merchantWalletAddress": "0xABCDEF0123456789abcdef0123456789ABCDEF01",
    // webhookUrl is REQUIRED
    "webhookUrl": "https://example.com/webhook",
    "metadata": map[string]any{"customer_id":"cus_123", "order_id":"ord_456"},
    "trialDays": 7,
    "quantity": 1,
    "autoRenew": true,
    "startDate": "2025-11-01T00:00:00Z",
    // Optional token payment fields:
    "tokenMintAddress": "So11111111111111111111111111111111111111112",
    "tokenAmount": 0.1,
    "tokenDecimals": 9,
  }
  b,_ := json.Marshal(body)
  req, err := http.NewRequest("POST", "${baseUrl}/api/recurring-subscriptions", bytes.NewReader(b))
  if err != nil { panic(err) }
  req.Header.Set("Content-Type", "application/json")
  req.Header.Set("Authorization", "Bearer bsk_test_1234567890abcdef1234567890abcdef")
  resp, err := http.DefaultClient.Do(req)
  if err!=nil { panic(err) }
  defer resp.Body.Close()
  fmt.Println(resp.Status)
}`,

  ruby: `require 'net/http'
require 'json'
uri = URI('${baseUrl}/api/recurring-subscriptions')
req = Net::HTTP::Post.new(uri, {
  'Content-Type' => 'application/json',
  'Authorization' => 'Bearer bsk_test_1234567890abcdef1234567890abcdef'
})
req.body = {
  plan: 'basic',
  priceUsd: 5.00,
  billingInterval: 'monthly',
  # merchantWalletAddress is REQUIRED
  merchantWalletAddress: '0xABCDEF0123456789abcdef0123456789ABCDEF01',
  # webhookUrl is REQUIRED
  webhookUrl: 'https://example.com/webhook',
  metadata: { customer_id: 'cus_123', order_id: 'ord_456' },
  trialDays: 7,
  quantity: 1,
  autoRenew: true,
  startDate: '2025-11-01T00:00:00Z',
  # Optional token payment fields:
  tokenMintAddress: 'So11111111111111111111111111111111111111112',
  tokenAmount: 0.1,
  tokenDecimals: 9
}.to_json
res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') { |http| http.request(req) }
puts res.body`,

  php: `<?php
$ch = curl_init('${baseUrl}/api/recurring-subscriptions');
$data = [
  'plan' => 'basic',
  'priceUsd' => 5.00,
  'billingInterval' => 'monthly',
  // merchantWalletAddress is REQUIRED
  'merchantWalletAddress' => '0xABCDEF0123456789abcdef1234567890ABCDEF01',
  // webhookUrl is REQUIRED
  'webhookUrl' => 'https://example.com/webhook',
  'metadata' => ['customer_id' => 'cus_123', 'order_id' => 'ord_456'],
  'trialDays' => 7,
  'quantity' => 1,
  'autoRenew' => true,
  'startDate' => '2025-11-01T00:00:00Z',
  // Optional token payment fields:
  'tokenMintAddress' => 'So11111111111111111111111111111111111111112',
  'tokenAmount' => 0.1,
  'tokenDecimals' => 9
];
$headers = [
  'Content-Type: application/json',
  'Authorization: Bearer bsk_test_1234567890abcdef1234567890abcdef'
];
curl_setopt_array($ch, [
  CURLOPT_POST => true,
  CURLOPT_HTTPHEADER => $headers,
  CURLOPT_POSTFIELDS => json_encode($data),
  CURLOPT_RETURNTRANSFER => true,
]);
$response = curl_exec($ch);
curl_close($ch);
echo $response;`
} as const;

  const recurringConnectSamples = {
    curl: `curl -X POST ${baseUrl}/api/recurring-subscriptions/<subscription_id>/connect-wallet \\
  -H "Authorization: Bearer bsk_test_1234567890abcdef1234567890abcdef" \\
  -H "Content-Type: application/json" \\
  -d '{"walletAddress":"<wallet>","signature":"<sig>","message":"<message>"}'`,
    javascript: `await fetch('${baseUrl}/api/recurring-subscriptions/<subscription_id>/connect-wallet', {
  method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer bsk_test_1234567890abcdef1234567890abcdef' },
  body: JSON.stringify({ walletAddress: '<wallet>', signature: '<sig>', message: '<message>' })
}).then(r => r.json())`,
   python: `import requests
headers = {'Authorization': 'Bearer bsk_test_1234567890abcdef1234567890abcdef'}
print(requests.post('${baseUrl}/api/recurring-subscriptions/<subscription_id>/connect-wallet',
    headers=headers,
    json={'walletAddress':'<wallet>', 'signature':'<sig>', 'message':'<message>'}).json())`,
    go: `package main
import ("bytes"; "encoding/json"; "fmt"; "net/http")
func main(){ b,_ := json.Marshal(map[string]string{"walletAddress":"<wallet>","signature":"<sig>","message":"<message>"}); req,_ := http.NewRequest("POST", "${baseUrl}/api/recurring-subscriptions/<sub[...]
    ruby: `require 'net/http'; require 'json'; uri = URI('${baseUrl}/api/recurring-subscriptions/<subscription_id>/connect-wallet'); req = Net::HTTP::Post.new(uri, {'Content-Type'=>'application/json',[...]
    php: `<?php
$ch = curl_init('${baseUrl}/api/recurring-subscriptions/<subscription_id>/connect-wallet');
$data = ['walletAddress'=>'<wallet>','signature'=>'<sig>','message'=>'<message>'];
$headers = ['Content-Type: application/json','Authorization: Bearer bsk_test_1234567890abcdef1234567890abcdef'];
curl_setopt_array($ch, [CURLOPT_POST=>true, CURLOPT_HTTPHEADER=>$headers, CURLOPT_POSTFIELDS=>json_encode($data), CURLOPT_RETURNTRANSFER=>true]); $resp = curl_exec($ch); curl_close($ch); echo $resp;`
  } as const;

  const recurringGetSamples = {
  curl: `curl -X GET ${baseUrl}/api/recurring-subscriptions/<subscription_id> \\
  -H "Authorization: Bearer bsk_test_1234567890abcdef1234567890abcdef"`,

  javascript: `await fetch('${baseUrl}/api/recurring-subscriptions/<subscription_id>', {
  method: 'GET',
  headers: { 'Authorization': 'Bearer bsk_test_1234567890abcdef1234567890abcdef' }
}).then(r => r.json())`,

  python: `import requests
headers = {'Authorization': 'Bearer bsk_test_1234567890abcdef1234567890abcdef'}
response = requests.get('${baseUrl}/api/recurring-subscriptions/<subscription_id>', headers=headers)
print(response.json())`,

  go: `package main
import ("fmt"; "net/http"; "io"; "os")
func main() {
  req, _ := http.NewRequest("GET", "${baseUrl}/api/recurring-subscriptions/<subscription_id>", nil)
  req.Header.Set("Authorization", "Bearer bsk_test_1234567890abcdef1234567890abcdef")
  resp, _ := http.DefaultClient.Do(req)
  defer resp.Body.Close()
  body, _ := io.ReadAll(resp.Body)
  fmt.Println(string(body))
}`,

  ruby: `require 'net/http'
require 'json'
uri = URI('${baseUrl}/api/recurring-subscriptions/<subscription_id>')
req = Net::HTTP::Get.new(uri, { 'Authorization' => 'Bearer bsk_test_1234567890abcdef1234567890abcdef' })
res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') { |http| http.request(req) }
puts res.body`,

  php: `<?php
$ch = curl_init('${baseUrl}/api/recurring-subscriptions/<subscription_id>');
$headers = ['Authorization: Bearer bsk_test_1234567890abcdef1234567890abcdef'];
curl_setopt_array($ch, [
  CURLOPT_CUSTOMREQUEST => 'GET',
  CURLOPT_HTTPHEADER => $headers,
  CURLOPT_RETURNTRANSFER => true
]);
$resp = curl_exec($ch);
curl_close($ch);
echo $resp;`
} as const;
const recurringCancelSamples = {
  curl: `curl -X DELETE ${baseUrl}/api/recurring-subscriptions/<subscription_id> \\
  -H "Authorization: Bearer bsk_test_1234567890abcdef1234567890abcdef" \\
  -H "Content-Type: application/json" \\
  -d '{"reason":"user_requested"}'`,

  javascript: `await fetch('${baseUrl}/api/recurring-subscriptions/<subscription_id>', {
  method: 'DELETE',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer bsk_test_1234567890abcdef1234567890abcdef'
  },
  body: JSON.stringify({ reason: 'user_requested' })
}).then(r => r.json())`,

  python: `import requests
headers = {'Authorization': 'Bearer bsk_test_1234567890abcdef1234567890abcdef'}
print(requests.delete('${baseUrl}/api/recurring-subscriptions/<subscription_id>', headers=headers, json={'reason':'user_requested'}).json())`,

  go: `package main
import ("bytes"; "encoding/json"; "fmt"; "net/http")
func main(){
  b,_ := json.Marshal(map[string]string{"reason":"user_requested"})
  req,_ := http.NewRequest("DELETE", "${baseUrl}/api/recurring-subscriptions/<subscription_id>", bytes.NewReader(b))
  req.Header.Set("Content-Type","application/json")
  req.Header.Set("Authorization","Bearer bsk_test_1234567890abcdef1234567890abcdef")
  resp,_ := http.DefaultClient.Do(req)
  defer resp.Body.Close()
  fmt.Println(resp.Status)
}`,

  ruby: `require 'net/http'; require 'json'
uri = URI('${baseUrl}/api/recurring-subscriptions/<subscription_id>')
req = Net::HTTP::Delete.new(uri, {'Content-Type'=>'application/json','Authorization'=>'Bearer bsk_test_1234567890abcdef1234567890abcdef'})
req.body = { reason: 'user_requested' }.to_json
res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') { |http| http.request(req) }
puts res.body`,

  php: `<?php
$ch = curl_init('${baseUrl}/api/recurring-subscriptions/<subscription_id>');
$data = ['reason'=>'user_requested'];
$headers = ['Content-Type: application/json','Authorization: Bearer bsk_test_1234567890abcdef1234567890abcdef'];
curl_setopt_array($ch, [CURLOPT_CUSTOMREQUEST=>'DELETE', CURLOPT_HTTPHEADER=>$headers, CURLOPT_POSTFIELDS=>json_encode($data), CURLOPT_RETURNTRANSFER=>true]);
$resp = curl_exec($ch);
curl_close($ch);
echo $resp;`
} as const;

  return (
    <div className="w-full">
      <SidebarProvider defaultOpen={true}>
        <div className="flex w-full min-h-screen">
<Sidebar className="w-64 border-r border-border bg-background flex-shrink-0 relative mt-0">
            <SidebarHeader className="border-b border-sidebar-border">
              <div className="px-2 pt-2 pb-3">
                <div className="flex items-center gap-2 mb-2">
                  <div className="p-1.5 rounded-md bg-primary text-primary-foreground">
                    <Code2 className="w-4 h-4" />
                  </div>
                  <h2 className="text-sm font-semibold text-sidebar-foreground">API Documentation</h2>
                </div>
                <p className="text-xs text-sidebar-foreground/70">Comprehensive integration guides and examples</p>
              </div>
            </SidebarHeader>
          
          <SidebarContent className="py-2">
            {/* Quick Start */}
            <SidebarGroup>
              <SidebarGroupLabel className="text-xs uppercase tracking-wider text-sidebar-foreground/60 font-medium px-2">
                <Zap className="w-3 h-3 mr-1" />
                Quick Start
              </SidebarGroupLabel>
              <SidebarMenu>
                <SidebarMenuItem>
                  <SidebarMenuButton asChild className="hover:bg-sidebar-accent hover:text-sidebar-accent-foreground">
                    <a href="#overview" className="flex items-center gap-2">
                      <div className="w-1.5 h-1.5 rounded-full bg-primary" />
                      Overview
                    </a>
                  </SidebarMenuButton>
                </SidebarMenuItem>
                <SidebarMenuItem>
                  <SidebarMenuButton asChild className="hover:bg-sidebar-accent hover:text-sidebar-accent-foreground">
                    <a href="#authentication" className="flex items-center gap-2">
                      <div className="w-1.5 h-1.5 rounded-full bg-chart-2" />
                      Authentication
                    </a>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              </SidebarMenu>
            </SidebarGroup>
            
            <SidebarSeparator />
            
            {/* One-time payments */}
            <SidebarGroup>
              <SidebarGroupLabel className="text-xs uppercase tracking-wider text-sidebar-foreground/60 font-medium px-2">
                <Layers className="w-3 h-3 mr-1" />
                One-time Payments
              </SidebarGroupLabel>
              <SidebarMenu>
                <SidebarMenuItem>
                  <SidebarMenuButton asChild className="hover:bg-sidebar-accent hover:text-sidebar-accent-foreground">
                    <a href="#otp-getting-started" className="flex items-center gap-2">
                      <div className="w-1.5 h-1.5 rounded-full bg-chart-3" />
                      Getting Started
                    </a>
                  </SidebarMenuButton>
                </SidebarMenuItem>
                <SidebarMenuItem>
                 
                </SidebarMenuItem>
              </SidebarMenu>
            </SidebarGroup>
            
            <SidebarSeparator />
            
            {/* Recurring payments */}
            <SidebarGroup>
              <SidebarGroupLabel className="text-xs uppercase tracking-wider text-sidebar-foreground/60 font-medium px-2">
                <Shield className="w-3 h-3 mr-1" />
                Recurring Payments
              </SidebarGroupLabel>
              <SidebarMenu>
                <SidebarMenuItem>
                  <SidebarMenuButton asChild className="hover:bg-sidebar-accent hover:text-sidebar-accent-foreground">
                    <a href="#rec-getting-started" className="flex items-center gap-2">
                      <div className="w-1.5 h-1.5 rounded-full bg-chart-5" />
                      Getting Started
                    </a>
                  </SidebarMenuButton>
                </SidebarMenuItem>
                <SidebarMenuItem>
                  
                </SidebarMenuItem>
              </SidebarMenu>
            </SidebarGroup>
          </SidebarContent>
        </Sidebar>

          <div className="flex-1 bg-background">
            {/* Header */}
            <div className="flex h-14 items-center gap-4 border-b border-border bg-background px-6">
              <SidebarTrigger className="hover:bg-accent hover:text-accent-foreground" />
              <div className="flex items-center gap-2 flex-1">
                <h1 className="text-lg font-semibold text-foreground">Developer Documentation</h1>
              </div>
            </div>

            <div className="w-full max-w-5xl mx-auto px-6 py-8 space-y-12">
            {/* Overview Section */}
            <section id="overview" className="space-y-6">
              <div className="space-y-3">
                <h2 className="text-3xl font-bold text-foreground">API Overview</h2>
                <p className="text-lg text-muted-foreground leading-relaxed">
                  BlockSub provides a comprehensive API for integrating Solana payments into your applications. 
                  Our API supports both one-time and recurring payment flows with simple, RESTful endpoints.
                </p>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Card className="p-6 border border-primary/20 bg-gradient-to-br from-primary/5 to-primary/10 hover:shadow-md transition-shadow">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="p-2 rounded-lg bg-primary text-primary-foreground">
                      <Zap className="w-5 h-5" />
                    </div>
                    <h3 className="font-semibold text-foreground">Fast Integration</h3>
                  </div>
                  <p className="text-sm text-muted-foreground">Get started with just a few API calls. Simple, developer-friendly endpoints.</p>
                </Card>
                
                <Card className="p-6 border border-chart-2/20 bg-gradient-to-br from-chart-2/5 to-chart-2/10 hover:shadow-md transition-shadow">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="p-2 rounded-lg bg-chart-2 text-white">
                      <Shield className="w-5 h-5" />
                    </div>
                    <h3 className="font-semibold text-foreground">Secure</h3>
                  </div>
                  <p className="text-sm text-muted-foreground">Built on Solana's secure blockchain with comprehensive validation.</p>
                </Card>
                
                <Card className="p-6 border border-chart-3/20 bg-gradient-to-br from-chart-3/5 to-chart-3/10 hover:shadow-md transition-shadow">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="p-2 rounded-lg bg-chart-3 text-white">
                      <Layers className="w-5 h-5" />
                    </div>
                    <h3 className="font-semibold text-foreground">Flexible</h3>
                  </div>
                  <p className="text-sm text-muted-foreground">Support for various payment flows and multiple programming languages.</p>
                </Card>
              </div>
              
              <Card className="p-6 bg-card border-card-border">
                <div className="space-y-4">
                  <h3 className="text-xl font-semibold text-card-foreground">Base URL</h3>
                  <p className="text-muted-foreground">All API endpoints are relative to your BlockSub instance base URL:</p>
                  <div className="p-4 rounded-lg bg-muted/50 border font-mono text-sm text-foreground select-all">
                    {baseUrl}/api
                  </div>
                </div>
              </Card>
            </section>

            {/* Authentication Section */}
           

            {/* OTP Getting Started */}
            <section id="otp-getting-started" className="space-y-6">
              <div className="space-y-3">
                <h2 className="text-2xl font-bold text-foreground">One-time Payments — Getting Started</h2>
                <p className="text-muted-foreground">
                  Create instant Solana payment intents with just a few lines of code. Perfect for e-commerce, donations, and one-off transactions.
                </p>
              </div>
              
              <Card className="p-8 bg-card border-card-border shadow-sm">
                <div className="space-y-8">
                  <CodeTabs
                    group="create-otp"
                    title="Create a Payment Intent"
                    curl={createOneTimeSamples.curl}
                    javascript={createOneTimeSamples.javascript}
                    python={createOneTimeSamples.python}
                    go={createOneTimeSamples.go}
                    ruby={createOneTimeSamples.ruby}
                    php={createOneTimeSamples.php}
                  />
                  
                  <CodeTabs
                    group="check-otp"
                    title="Check Payment Status"
                    curl={checkStatusSamples.curl}
                    javascript={checkStatusSamples.javascript}
                    python={checkStatusSamples.python}
                    go={checkStatusSamples.go}
                    ruby={checkStatusSamples.ruby}
                    php={checkStatusSamples.php}
                  />
                </div>
              </Card>
            </section>
            {/* Recurring Getting Started */}
            <section id="rec-getting-started" className="space-y-6">
              <div className="space-y-3">
                <h2 className="text-2xl font-bold text-foreground">Recurring Payments — Getting Started</h2>
                <p className="text-muted-foreground">
                  Build subscription and recurring payment flows with BlockSub's planned recurring payment features.
                </p>
              </div>
              
              <Card className="p-8 bg-gradient-to-br from-chart-5/5 to-chart-5/10 border-chart-5/20">
                <div className="space-y-6">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-chart-5/20 text-chart-5">
                      <Shield className="w-5 h-5" />
                    </div>
                    <h3 className="text-lg font-semibold text-foreground">Recurring API Examples</h3>
                  </div>
                  <p className="text-muted-foreground">
                    The following examples show how to create and manage recurring subscriptions with our API. Use your API key via
                    the Authorization header or x-api-key.
                  </p>

                  <div className="space-y-4">
                    <div className="mb-3 text-sm text-muted-foreground">
                      <strong>Important:</strong> For recurring subscriptions the <code>webhookUrl</code> field is required. The server will POST
                      the unsigned initialize transaction and subscription events (wallet_connected, initial_payment_requested, payment_succeeded, payment_failed, canceled)
                      to the configured webhook URL.
                    </div>

                    <CodeTabs
                      group="rec-create"
                      title="Create Recurring Subscription (webhookUrl is required)"
                      curl={recurringCreateSamples.curl}
                      javascript={recurringCreateSamples.javascript}
                      python={recurringCreateSamples.python}
                      go={recurringCreateSamples.go}
                      ruby={recurringCreateSamples.ruby}
                      php={recurringCreateSamples.php}
                    />

                    {/* Webhook payload docs inserted directly after the recurring-subscriptions payload examples */}
                    <Card className="p-6 bg-card border-card-border">
                      <div className="space-y-3">
                        <h4 className="text-lg font-semibold text-foreground">Webhook Delivery & Payloads</h4>

                        <p className="text-sm text-muted-foreground">
                          When you create a recurring subscription you must provide a <code>webhookUrl</code> in the request payload. The server will
                          POST events and payloads to that URL as the subscription progresses. The very first POST (the "initialize" delivery) contains an
                          unsigned Solana transaction (base64) that the subscriber must sign and submit to complete initialization.
                        </p>

                        <p className="text-sm text-muted-foreground">
                          Implementation notes (behavior comes from server code):
                        </p>
                        <ul className="list-disc ml-5 text-sm text-muted-foreground">
                          <li>The server attempts a direct HTTP POST using global fetch (Node 18+) or node-fetch. If the direct POST fails the delivery is enqueued for retry.</li>
                          <li>All webhook requests are JSON with Content-Type: application/json. Reply HTTP 200 quickly to acknowledge delivery.</li>
                          <li>The initial "initialize" payload includes the unsigned transaction in base64. Your service / client must sign and submit that transaction to complete setup.</li>
                          <li>Token-related fields are optional — subscriptions may be SOL or SPL-based. If provided you will receive token-related fields in events.</li>
                        </ul>

                        <h5 className="text-md font-medium text-foreground">Initialize payload (sent immediately after wallet connect)</h5>
                        <div className="p-4 rounded-lg bg-muted/50 border font-mono text-sm text-foreground overflow-auto">
<pre>{`{
  "subscription_id": "sub_abc123",
  "serializedTxBase64": "<base64_serialized_unsigned_transaction>",
  "subscription_pda": "<anchor_subscription_pda>",
  "escrow_pda": "<anchor_escrow_pda>",
  "status": "pending_onchain_initialize"
}`}</pre>
                        </div>

                        <p className="text-sm text-muted-foreground">
                          After initialization you'll receive further event deliveries as the subscription lifecycle continues. Example event payloads:
                        </p>

                        <div className="p-4 rounded-lg bg-muted/50 border font-mono text-sm text-foreground overflow-auto">
<pre>{`// wallet connected by the customer
{
  "event": "wallet_connected",
  "subscriptionId": "sub_abc123",
  "walletAddress": "4f2...Example",
  "connectedAt": "2025-10-29T14:30:00Z"
}

// initial payment requested (when an initial charge is required)
{
  "event": "initial_payment_requested",
  "subscriptionId": "sub_abc123",
  "amountLamports": 100000000, // for SOL flows
  "token": {
    "tokenMintAddress": "So1111...",
    "tokenAmount": "1000000",
    "tokenDecimals": 9
  },
  "requestedAt": "2025-10-29T14:30:10Z"
}

// payment succeeded
{
  "event": "payment_succeeded",
  "subscriptionId": "sub_abc123",
  "txSignature": "5y...signature",
  "amountLamports": 100000000,
  "processedAt": "2025-10-29T14:30:45Z"
}

// payment failed
{
  "event": "payment_failed",
  "subscriptionId": "sub_abc123",
  "error": "insufficient_funds",
  "details": "...",
  "failedAt": "2025-10-29T14:30:45Z"
}

// subscription canceled
{
  "event": "canceled",
  "subscriptionId": "sub_abc123",
  "reason": "user_requested",
  "canceledAt": "2025-10-30T00:00:00Z"
}`}</pre>
                        </div>

                        <p className="text-sm text-muted-foreground">
                          Quick checklist for merchant webhook endpoints:
                        </p>
                        <ul className="list-disc ml-5 text-sm text-muted-foreground">
                          <li>Accept POST JSON and respond HTTP 200 quickly (acknowledgment).</li>
                          <li>On "initialize" payload: extract <code>serializedTxBase64</code>, have the subscriber sign and submit the transaction (or direct their wallet to sign).</li>
                          <li>Handle retries: the server will enqueue deliveries if direct POST fails; be idempotent when processing events.</li>
                          <li>Validate incoming payloads (check subscription_id and expected subscription state) to avoid acting on stale events.</li>
                        </ul>
                      </div>
                    </Card>

                    <CodeTabs
                      group="rec-get"
                      title="Get Subscription Details"
                      curl={recurringGetSamples.curl}
                      javascript={recurringGetSamples.javascript}
                      python={recurringGetSamples.python}
                      go={recurringGetSamples.go}
                      ruby={recurringGetSamples.ruby}
                      php={recurringGetSamples.php}
                    />

                    <CodeTabs
                      group="rec-cancel"
                      title="Cancel Subscription (use this instead of delete)"
                      curl={recurringCancelSamples.curl}
                      javascript={recurringCancelSamples.javascript}
                      python={recurringCancelSamples.python}
                      go={recurringCancelSamples.go}
                      ruby={recurringCancelSamples.ruby}
                      php={recurringCancelSamples.php}
                    />
                  </div>
                </div>
              </Card>
            </section>

            
            </div>
          </div>
        </div>
      </SidebarProvider>
    </div>
  );
}
