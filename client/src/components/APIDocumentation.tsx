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
  curl: `curl -X POST https://block-sub-1.onrender.com/api/solana/payment-intents \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer <API_KEY>" \\
  -d '{\n    "orderId": "order_123456",\n    "merchant": "<your_merchant_wallet>",\n    "amountLamports": 100000000,\n    "memo": "Payment for order #123456",\n    "chain": "solana"\n  }'`,

  javascript: `// Node 18+ or Browser
await fetch('https://block-sub-1.onrender.com/api/solana/payment-intents', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer <API_KEY>'
  },
  body: JSON.stringify({
    orderId: 'order_123456',
    merchant: '<your_merchant_wallet>',
    amountLamports: 100000000, // for SOL
    // OR for SPL tokens:
    // tokenMint: '<SPL_TOKEN_MINT>',
    // tokenAmount: '1000000', // base units (1 USDC)
    // tokenAmountDecimal: '1.0', // optional human-readable form
    memo: 'Payment for order #123456',
    chain: 'solana'
  })
}).then(r => r.json())`,

  python: `import requests
r = requests.post(
  'https://block-sub-1.onrender.com/api/solana/payment-intents',
  headers={'Authorization': 'Bearer <API_KEY>'},
  json={
    'orderId': 'order_123456',
    'merchant': '<your_merchant_wallet>',
    'amountLamports': 100000000,
    # Optional for SPL tokens:
    # 'tokenMint': '<SPL_TOKEN_MINT>',
    # 'tokenAmount': '1000000',
    # 'tokenAmountDecimal': '1.0',
    'memo': 'Payment for order #123456',
    'chain': 'solana'
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
    "merchant": "<your_merchant_wallet>",
    "amountLamports": 100000000,
    // Optional for SPL tokens:
    // "tokenMint": "<SPL_TOKEN_MINT>",
    // "tokenAmount": "1000000",
    // "tokenAmountDecimal": "1.0",
    "memo": "Payment for order #123456",
    "chain": "solana",
  }
  b, _ := json.Marshal(body)
  req, _ := http.NewRequest("POST", "https://block-sub-1.onrender.com/api/solana/payment-intents", bytes.NewReader(b))
  req.Header.Set("Authorization", "Bearer <API_KEY>")
  req.Header.Set("Content-Type", "application/json")
  resp, err := http.DefaultClient.Do(req)
  if err != nil { panic(err) }
  defer resp.Body.Close()
  fmt.Println(resp.Status)
}`,

  ruby: `require 'net/http'
require 'json'
uri = URI('https://block-sub-1.onrender.com/api/solana/payment-intents')
req = Net::HTTP::Post.new(uri, 'Content-Type' => 'application/json')
req['Authorization'] = 'Bearer <API_KEY>'
req.body = {
  orderId: 'order_123456',
  merchant: '<your_merchant_wallet>',
  amountLamports: 100000000,
  # Optional SPL fields:
  # tokenMint: '<SPL_TOKEN_MINT>',
  # tokenAmount: '1000000',
  # tokenAmountDecimal: '1.0',
  memo: 'Payment for order #123456',
  chain: 'solana'
}.to_json
res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') { |http| http.request(req) }
puts res.body`,

  php: `<?php
$ch = curl_init('https://block-sub-1.onrender.com/api/solana/payment-intents');
$data = [
  'orderId' => 'order_123456',
  'merchant' => '<your_merchant_wallet>',
  'amountLamports' => 100000000,
  // Optional SPL fields:
  // 'tokenMint' => '<SPL_TOKEN_MINT>',
  // 'tokenAmount' => '1000000',
  // 'tokenAmountDecimal' => '1.0',
  'memo' => 'Payment for order #123456',
  'chain' => 'solana'
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


const recurringCreateSamples = {
  curl: `curl -X POST ${baseUrl}/api/recurring-subscriptions \\
  -H "Authorization: Bearer bsk_test_1234567890abcdef1234567890abcdef" \\
  -H "Content-Type: application/json" \\
  -d '{
    "plan": "basic",
    "priceUsd": 5.00,
    "billingInterval": "monthly",

    /* webhook and metadata */
    "webhookUrl": "https://example.com/webhook",
    "metadata": { "customer_id": "cus_123" },

    /* trial (days) */
    "trialDays": 7,

    "merchant": "<merchant wallet address>",
    "chain": "solana",

    /* Asset configuration:
       - For SOL payments: either omit tokenMint/tokenAmount fields (asset defaults or set asset:"SOL")
       - For SPL payments: include tokenMint and either tokenAmount (base-units) OR tokenAmountDecimal (human decimal) */
    "asset": "SPL",
    "tokenMint": "<mint address>", 
    /* prefer human decimal: the server will convert using on-chain mint.decimals */
    "tokenAmountDecimal": "5.00"
  }'`,

  javascript: `// Example using fetch (browser / node fetch)
await fetch('${baseUrl}/api/recurring-subscriptions', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer bsk_test_1234567890abcdef1234567890abcdef'
    // Or: 'x-api-key': '<your_api_key>'
  },
  body: JSON.stringify({
    // Required
    plan: 'basic',
    priceUsd: 5.00,
    billingInterval: 'monthly',
    webhookUrl: 'https://example.com/webhook',
    metadata: { customer_id: 'cus_123' },
    trialDays: 7,

    // Merchant & chain (optional)
    merchant: '<merchant walet address>',
    chain: 'solana',

    // Asset config: for SPL use tokenMint + tokenAmountDecimal (recommended)
    asset: 'SPL',
    tokenMint: '<token mint address>',
    tokenAmountDecimal: '5.00' // server will convert to base-units using mint.decimals
    // OR tokenAmount: '5000000' (base-units) if you already have it
  })
}).then(r => r.json())`,

  python: `# Python requests example
import requests
url = '${baseUrl}/api/recurring-subscriptions'
headers = {
  'Authorization': 'Bearer bsk_test_1234567890abcdef1234567890abcdef',
  'Content-Type': 'application/json'
}
payload = {
  "plan": "basic",
  "priceUsd": 5.00,
  "billingInterval": "monthly",
  "webhookUrl": "https://example.com/webhook",
  "metadata": { "customer_id": "cus_123" },
  "trialDays": 7,
  "merchant": "<merchant wallet address>",
  "asset": "SPL",
  "tokenMint": "<token mint address>",
  "tokenAmountDecimal": "5.00"
}
resp = requests.post(url, headers=headers, json=payload)
print(resp.status_code, resp.text)`,

  go: `// Go example (net/http)
package main

import (
  "bytes"
  "encoding/json"
  "fmt"
  "net/http"
)

func main() {
  body := map[string]any{
    "plan": "basic",
    "priceUsd": 5.00,
    "billingInterval": "monthly",
    "webhookUrl": "https://example.com/webhook",
    "metadata": map[string]any{"customer_id": "cus_123"},
    "trialDays": 7,
    "merchant": "<merchant wallet address>",
    "asset": "SPL",
    "tokenMint": "<token mint address>",
    "tokenAmountDecimal": "5.00",
  }
  b, _ := json.Marshal(body)
  req, err := http.NewRequest("POST", "${baseUrl}/api/recurring-subscriptions", bytes.NewReader(b))
  if err != nil { panic(err) }
  req.Header.Set("Content-Type", "application/json")
  req.Header.Set("Authorization", "Bearer bsk_test_1234567890abcdef1234567890abcdef")
  resp, err := http.DefaultClient.Do(req)
  if err != nil { panic(err) }
  defer resp.Body.Close()
  fmt.Println("status:", resp.Status) // check returned JSON for details
}`,

  ruby: `# Ruby example
require 'net/http'
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
  webhookUrl: 'https://example.com/webhook',
  metadata: { customer_id: 'cus_123' },
  trialDays: 7,
  merchant: '<merchant wallet address>',
  asset: 'SPL',
  tokenMint: '<token mint address>',
  tokenAmountDecimal: '5.00'
}.to_json
res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') { |http| http.request(req) }
puts res.body`,

  php: `<?php
$ch = curl_init('${baseUrl}/api/recurring-subscriptions');
$data = [
  'plan' => 'basic',
  'priceUsd' => 5.00,
  'billingInterval' => 'monthly',
  'webhookUrl' => 'https://example.com/webhook',
  'metadata' => ['customer_id' => 'cus_123'],
  'trialDays' => 7,
  'merchant' => '<merchant wallet address>',
  'asset' => 'SPL',
  'tokenMint' => '<token mint address>',
  'tokenAmountDecimal' => '5.00'
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
echo $response; ?>`
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
print(requests.post('${baseUrl}/api/recurring-subscriptions/<subscription_id>/connect-wallet', headers=headers, json={ 'walletAddress':'<wallet>', 'signature':'<sig>', 'message':'<message>' }).json())`,
    go: `package main
import ("bytes"; "encoding/json"; "fmt"; "net/http")
func main(){ b,_ := json.Marshal(map[string]string{"walletAddress":"<wallet>","signature":"<sig>","message":"<message>"}); req,_ := http.NewRequest("POST", "${baseUrl}/api/recurring-subscriptions/<subscription_id>/connect-wallet", bytes.NewReader(b)); req.Header.Set("Content-Type","application/json"); req.Header.Set("Authorization","Bearer bsk_test_1234567890abcdef1234567890abcdef"); resp,_ := http.DefaultClient.Do(req); defer resp.Body.Close(); fmt.Println(resp.Status) }`,
    ruby: `require 'net/http'; require 'json'; uri = URI('${baseUrl}/api/recurring-subscriptions/<subscription_id>/connect-wallet'); req = Net::HTTP::Post.new(uri, {'Content-Type'=>'application/json', 'Authorization'=>'Bearer bsk_test_1234567890abcdef1234567890abcdef'}); req.body = { walletAddress: '<wallet>', signature: '<sig>', message: '<message>' }.to_json; res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') { |http| http.request(req) }; puts res.body`,
    php: `<?php
$ch = curl_init('${baseUrl}/api/recurring-subscriptions/<subscription_id>/connect-wallet');
$data = ['walletAddress'=>'<wallet>','signature'=>'<sig>','message'=>'<message>'];
$headers = ['Content-Type: application/json','Authorization: Bearer bsk_test_1234567890abcdef1234567890abcdef'];
curl_setopt_array($ch, [CURLOPT_POST=>true, CURLOPT_HTTPHEADER=>$headers, CURLOPT_POSTFIELDS=>json_encode($data), CURLOPT_RETURNTRANSFER=>true]); $resp = curl_exec($ch); curl_close($ch); echo $resp;`
  } as const;

  const recurringGetSamples = {
    curl: `curl -X GET ${baseUrl}/api/recurring-subscriptions/<subscription_id> \\
  -H "Authorization: Bearer bsk_test_1234567890abcdef1234567890abcdef"`,
    javascript: `await fetch('${baseUrl}/api/recurring-subscriptions/<subscription_id>', { headers: { 'Authorization': 'Bearer bsk_test_1234567890abcdef1234567890abcdef' } }).then(r => r.json())`,
    python: `import requests
headers = {'Authorization': 'Bearer bsk_test_1234567890abcdef1234567890abcdef'}
print(requests.get('${baseUrl}/api/recurring-subscriptions/<subscription_id>', headers=headers).json())`,
    go: `package main
import ("fmt"; "net/http")
func main(){ req,_ := http.NewRequest("GET", "${baseUrl}/api/recurring-subscriptions/<subscription_id>", nil); req.Header.Set("Authorization","Bearer bsk_test_1234567890abcdef1234567890abcdef"); resp,_ := http.DefaultClient.Do(req); fmt.Println(resp.Status) }`,
    ruby: `require 'net/http'; uri = URI('${baseUrl}/api/recurring-subscriptions/<subscription_id>'); req = Net::HTTP::Get.new(uri); req['Authorization'] = 'Bearer bsk_test_1234567890abcdef1234567890abcdef'; res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') { |http| http.request(req) }; puts res.body`,
    php: `<?php
$ch = curl_init('${baseUrl}/api/recurring-subscriptions/<subscription_id>');
$headers = ['Authorization: Bearer bsk_test_1234567890abcdef1234567890abcdef'];
curl_setopt_array($ch, [CURLOPT_CUSTOMREQUEST=>'GET', CURLOPT_HTTPHEADER=>$headers, CURLOPT_RETURNTRANSFER=>true]); $resp = curl_exec($ch); curl_close($ch); echo $resp;`
  } as const;

  const recurringCancelSamples = {
    curl: `curl -X POST ${baseUrl}/api/recurring-subscriptions/<subscription_id>/cancel \\
  -H "Authorization: Bearer bsk_test_1234567890abcdef1234567890abcdef" \\
  -H "Content-Type: application/json" \\
  -d '{"reason":"user_requested"}'`,
    javascript: `await fetch('${baseUrl}/api/recurring-subscriptions/<subscription_id>/cancel', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer bsk_test_1234567890abcdef1234567890abcdef' }, body: JSON.stringify({ reason: 'user_requested' }) }).then(r => r.json())`,
    python: `import requests
headers = {'Authorization': 'Bearer bsk_test_1234567890abcdef1234567890abcdef'}
print(requests.post('${baseUrl}/api/recurring-subscriptions/<subscription_id>/cancel', headers=headers, json={'reason':'user_requested'}).json())`,
    go: `package main
import ("bytes"; "encoding/json"; "fmt"; "net/http")
func main(){ b,_ := json.Marshal(map[string]string{"reason":"user_requested"}); req,_ := http.NewRequest("POST", "${baseUrl}/api/recurring-subscriptions/<subscription_id>/cancel", bytes.NewReader(b)); req.Header.Set("Content-Type","application/json"); req.Header.Set("Authorization","Bearer bsk_test_1234567890abcdef1234567890abcdef"); resp,_ := http.DefaultClient.Do(req); defer resp.Body.Close(); fmt.Println(resp.Status) }`,
    ruby: `require 'net/http'; require 'json'; uri = URI('${baseUrl}/api/recurring-subscriptions/<subscription_id>/cancel'); req = Net::HTTP::Post.new(uri, {'Content-Type'=>'application/json','Authorization'=>'Bearer bsk_test_1234567890abcdef1234567890abcdef'}); req.body = { reason: 'user_requested' }.to_json; res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') { |http| http.request(req) }; puts res.body`,
    php: `<?php
$ch = curl_init('${baseUrl}/api/recurring-subscriptions/<subscription_id>/cancel');
$data = ['reason'=>'user_requested'];
$headers = ['Content-Type: application/json','Authorization: Bearer bsk_test_1234567890abcdef1234567890abcdef'];
curl_setopt_array($ch, [CURLOPT_POST=>true, CURLOPT_HTTPHEADER=>$headers, CURLOPT_POSTFIELDS=>json_encode($data), CURLOPT_RETURNTRANSFER=>true]); $resp = curl_exec($ch); curl_close($ch); echo $resp;`
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
                  <SidebarMenuButton asChild className="hover:bg-sidebar-accent hover:text-sidebar-accent-foreground">
                    <a href="#otp-integration" className="flex items-center gap-2">
                      <div className="w-1.5 h-1.5 rounded-full bg-chart-4" />
                      Integration Examples
                    </a>
                  </SidebarMenuButton>
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
                  <SidebarMenuButton asChild className="hover:bg-sidebar-accent hover:text-sidebar-accent-foreground">
                    <a href="#rec-integration" className="flex items-center gap-2">
                      <div className="w-1.5 h-1.5 rounded-full bg-primary" />
                      Best Practices
                    </a>
                  </SidebarMenuButton>
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
            <section id="authentication" className="space-y-4">
              <h2 className="text-2xl font-bold text-foreground">Authentication</h2>
              <Card className="p-6 bg-card border-card-border">
                <div className="space-y-4">
                  <div className="flex items-start gap-3">
                    <div className="p-2 rounded-lg bg-primary/10 text-primary mt-0.5">
                      <Shield className="w-5 h-5" />
                    </div>
                    <div className="space-y-2 flex-1">
                      <h3 className="text-lg font-semibold text-card-foreground">API Keys</h3>
                      <p className="text-muted-foreground">
                        Generate and manage API keys in the "API Keys" tab of your dashboard. 
                        For production usage, ensure all API calls include proper authentication headers.
                      </p>

                    <div className="space-y-2">
                      <h4 className="font-semibold">Relayer HMAC Example (JavaScript)</h4>
                        <pre className="rounded bg-muted/30 p-3 font-mono text-sm overflow-x-auto"><code>{`// Compute HMAC and send signed transaction back to server (Node.js)
  const crypto = require('crypto');

  function computeHmac(secret, timestamp, body) {
    return crypto.createHmac('sha256', secret).update(timestamp + body).digest('hex');
  }

  const timestamp = Date.now().toString();
  const body = JSON.stringify({ orderId: 'order_123', signedTx: '<base64_signed_tx>' });
  const signature = computeHmac(process.env.RELAYER_SECRET, timestamp, body);

  fetch('${baseUrl}/api/recurring-subscriptions/relayer/callback', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Timestamp': timestamp,
      'X-Relayer-Signature': signature,
      'Authorization': 'Bearer bsk_test_1234567890abcdef1234567890abcdef'
    },
    body
  }).then(r => r.json()).then(console.log);`}</code></pre>
                      </div>
                    </div>
                  </div>
                </div>
                </Card>
            </section>

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
                    <CodeTabs
                      group="rec-create"
                      title="Create Recurring Subscription"
                      curl={recurringCreateSamples.curl}
                      javascript={recurringCreateSamples.javascript}
                      python={recurringCreateSamples.python}
                      go={recurringCreateSamples.go}
                      ruby={recurringCreateSamples.ruby}
                      php={recurringCreateSamples.php}
                    />

                    <div className="rounded-lg bg-muted/20 border p-6">
                      <h4 className="font-semibold mb-2">Interactive: Poll subscription status and show issued key</h4>
                      <p className="text-sm text-muted-foreground mb-3">Enter an API key and subscription id to poll the status. If the server returns a one-time issued API key it will be displayed in a modal for copy.</p>
                      <InteractiveOneTimeKeyDemo />
                    </div>

                    <div className="rounded-lg bg-muted/30 border p-6">
                      <h4 className="font-semibold mb-2">Multi-step Node.js flow (create → scan → confirm)</h4>
                      <pre className="text-sm text-foreground font-mono overflow-x-auto p-4">
                        <code>{`// 1) Server: create subscription (returns wallet_connection)
const res = await fetch('${baseUrl}/api/recurring-subscriptions', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer YOUR_API_KEY' },
  body: JSON.stringify({ plan: 'pro', priceUsd: 30, billingInterval: 'monthly' })
});
const data = await res.json();
console.log('QR data URL:', data.wallet_connection.qr_code);
console.log('Phantom deeplink:', data.wallet_connection.deeplink);

// 2) User scans QR or opens deeplink in Phantom and connects wallet
// 3) After connection, call connect-wallet with signed message to verify ownership
const connectRes = await fetch('${baseUrl}/api/recurring-subscriptions/' + data.subscription_id + '/connect-wallet', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer YOUR_API_KEY' },
  body: JSON.stringify({ walletAddress: '<wallet>', signature: '<sig>', message: '<message>' })
});
const connectData = await connectRes.json();
console.log('Connect result:', connectData);

// 4) Poll subscription status until active (or handle webhook)
const poll = async () => {
  const s = await fetch('${baseUrl}/api/billing/subscriptions/' + data.subscription_id, { headers: { Authorization: 'Bearer YOUR_API_KEY' } });
  const sd = await s.json();
  console.log('Subscription status:', sd.status);
  // If the server just created an issued API key for the merchant it will return it once as sd.issuedApiKey.key
  if (sd.issuedApiKey && sd.issuedApiKey.key) {
    console.log('Issued API key (show this to merchant only once):', sd.issuedApiKey.key);
  }
}
`}</code>
                      </pre>
                    </div>

                    <CodeTabs
                      group="rec-connect"
                      title="Connect Wallet (after creation)"
                      curl={recurringConnectSamples.curl}
                      javascript={recurringConnectSamples.javascript}
                      python={recurringConnectSamples.python}
                      go={recurringConnectSamples.go}
                      ruby={recurringConnectSamples.ruby}
                      php={recurringConnectSamples.php}
                    />

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

            {/* Recurring Integration Guides */}
            <section id="rec-integration" className="space-y-6">
              <div className="space-y-3">
                <h2 className="text-2xl font-bold text-foreground">Best Practices</h2>
                <p className="text-muted-foreground">
                  Recommended approaches for implementing subscription flows with BlockSub.
                </p>
              </div>
              
              <Card className="p-8 bg-card border-card-border">
                <div className="space-y-6">
                  <div className="grid gap-6">
                    <div className="flex gap-4">
                      <div className="flex-shrink-0 w-8 h-8 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-sm font-semibold">1</div>
                      <div className="space-y-2">
                        <h4 className="font-semibold text-foreground">Store Subscription Records</h4>
                        <p className="text-muted-foreground">Maintain customer subscription data in your database with billing cycles and payment status.</p>
                      </div>
                    </div>
                    
                    <div className="flex gap-4">
                      <div className="flex-shrink-0 w-8 h-8 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-sm font-semibold">2</div>
                      <div className="space-y-2">
                        <h4 className="font-semibold text-foreground">Generate Payment Intents</h4>
                        <p className="text-muted-foreground">Create new one-time payment intents for each billing cycle using scheduled jobs.</p>
                      </div>
                    </div>
                    
                    <div className="flex gap-4">
                      <div className="flex-shrink-0 w-8 h-8 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-sm font-semibold">3</div>
                      <div className="space-y-2">
                        <h4 className="font-semibold text-foreground">Verify & Update</h4>
                        <p className="text-muted-foreground">Monitor payment confirmation on-chain and update subscription status accordingly.</p>
                      </div>
                    </div>
                  </div>
                </div>
              </Card>
              
              {/* Relayer Integration & Security */}
              <Card className="p-8 bg-card border-card-border">
                <div className="space-y-4">
                  <h3 className="text-xl font-semibold text-foreground">Relayer Integration & Security</h3>
                  <p className="text-muted-foreground">
                    For automated recurring collections without storing user private keys, BlockSub supports a merchant-run relayer model.
                    The worker will POST unsigned delegate-transfer intents to the configured <code>relayerUrl</code> and the relayer returns a signed transaction.
                  </p>

                  <div className="space-y-2">
                    <h4 className="font-semibold">Timestamped HMAC</h4>
                    <p className="text-muted-foreground">Each relayer request is authenticated with a time-bound HMAC to prevent replay and tampering. Rules:</p>
                    <ul className="list-disc ml-6 text-muted-foreground">
                      <li><strong>Header</strong>: <code>X-Timestamp</code> (milliseconds since epoch)</li>
                      <li><strong>Header</strong>: <code>X-Relayer-Signature</code> — HMAC-SHA256(secret, timestamp + JSON_BODY)</li>
                      <li>Server rejects requests older than 2 minutes (small clock skew allowed).</li>
                    </ul>
                  </div>

                  <div className="space-y-2">
                    <h4 className="font-semibold">Rotate Relayer Secret</h4>
                    <p className="text-muted-foreground">Merchants can rotate their per-subscription relayer secret. The server shows the plaintext only once — it stores the encrypted secret for later verification.</p>
                    <pre className="rounded bg-muted/30 p-3 font-mono text-sm">POST /api/relayer-secret/rotate {'{ subscriptionId: "rsub_xxx" }'}</pre>
                    <p className="text-muted-foreground">Response returns <code>relayerSecret</code> once — copy it into your relayer config. The server stores it encrypted at rest.</p>
                  </div>

                  <div className="space-y-2">
                    <h4 className="font-semibold">Short Security Design</h4>
                    <p className="text-muted-foreground">Our system protects all relayer interactions with time-bound HMAC signatures and per-subscription secrets. This prevents replay, tampering, and unauthorized signing.</p>
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
