import React, { useEffect, useState } from 'react';

export default function SolanaPayQuick({ orderId, merchant, amountLamports, memo, onSuccess, onError }: any) {
  const [intent, setIntent] = useState<any>(null);
  const [status, setStatus] = useState<string>('idle');

  useEffect(() => {
    createIntent();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function createIntent() {
    setStatus('creating');
    try {
      const resp = await fetch('/api/solana/payment-intents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ orderId, merchant, amountLamports, memo }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || 'create_failed');
      setIntent(data);
      setStatus('pending');
      pollStatus(data.orderId);
    } catch (e: any) {
      setStatus('error');
      onError?.(e.message || String(e));
    }
  }

  async function pollStatus(id: string) {
    try {
      const r = await fetch(`/api/solana/payment-intents/${id}`);
      const d = await r.json();
      setStatus(d.status || 'pending');
      if (d.status === 'confirmed') {
        onSuccess?.(d);
        return;
      }
      if (d.status === 'pending' || d.status === 'submitted') {
        setTimeout(() => pollStatus(id), 3000);
      }
    } catch (e) {
      setTimeout(() => pollStatus(id), 3000);
    }
  }

  const openWallet = () => {
    if (intent?.solanaPayUrl) window.open(intent.solanaPayUrl, '_blank');
  };

  return (
    <div>
      <h4>Pay {merchant}</h4>
      {intent && (
        <div>
          <img src={intent.qrDataUrl} alt="qr" width={240} />
          <div>
            <button onClick={openWallet}>Open in Wallet</button>
          </div>
        </div>
      )}

      <div>Status: {status}</div>
    </div>
  );
}
