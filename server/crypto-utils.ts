import crypto from 'crypto';

const MASTER_KEY_ENV = 'RELAYER_MASTER_KEY';

function getMasterKey(): Buffer {
  const key = process.env[MASTER_KEY_ENV];
  if (!key) throw new Error(`${MASTER_KEY_ENV} is not set`);
  // Accept hex or base64; normalize to Buffer of 32 bytes
  if (/^[0-9a-fA-F]+$/.test(key) && key.length === 64) {
    return Buffer.from(key, 'hex');
  }
  return Buffer.from(key, 'base64');
}

// Returns compact base64: iv(12)|tag(16)|ciphertext
export function encryptWithMasterKey(plaintext: string): string {
  const master = getMasterKey();
  if (master.length !== 32) throw new Error('RELAYER_MASTER_KEY must be 32 bytes (base64 or 64-hex)');

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', master, iv);
  const encrypted = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

export function decryptWithMasterKey(payloadB64: string): string {
  const master = getMasterKey();
  if (master.length !== 32) throw new Error('RELAYER_MASTER_KEY must be 32 bytes (base64 or 64-hex)');

  const data = Buffer.from(payloadB64, 'base64');
  const iv = data.slice(0, 12);
  const tag = data.slice(12, 28);
  const encrypted = data.slice(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', master, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString('utf8');
}

export function computeHmac(secret: string, message: string): string {
  return crypto.createHmac('sha256', secret).update(message).digest('hex');
}
