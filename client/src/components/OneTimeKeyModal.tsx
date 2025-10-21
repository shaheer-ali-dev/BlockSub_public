import React from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';

interface OneTimeKeyModalProps {
  open: boolean;
  onClose: () => void;
  keyValue?: string | null;
}

export default function OneTimeKeyModal({ open, onClose, keyValue }: OneTimeKeyModalProps) {
  const copy = async () => {
    if (!keyValue) return;
    try {
      await navigator.clipboard.writeText(keyValue);
      // small feedback could be added
    } catch {}
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Your API Key — copy now</DialogTitle>
        </DialogHeader>
        <div className="mt-2">
          <p className="text-sm text-muted-foreground">This key is shown only once. Store it securely — it will not be visible again.</p>
          <div className="mt-4 p-4 bg-muted rounded-md font-mono text-sm break-all">{keyValue ?? '—'}</div>
        </div>
        <DialogFooter>
          <div className="flex gap-2">
            <Button onClick={copy} variant="secondary">Copy</Button>
            <Button onClick={onClose}>Done</Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
