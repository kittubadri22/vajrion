import crypto from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;
const KEY_BYTES = 32;

function getKey() {
  const raw = String(process.env.EVIDENCE_ENCRYPTION_KEY || '').trim();
  if (!raw) throw new Error('EVIDENCE_ENCRYPTION_KEY is not configured.');
  if (!/^[0-9a-fA-F]{64}$/.test(raw)) {
    throw new Error('EVIDENCE_ENCRYPTION_KEY must be exactly 64 hexadecimal characters (32 bytes).');
  }
  const key = Buffer.from(raw, 'hex');
  if (key.length !== KEY_BYTES) throw new Error('Invalid evidence encryption key length.');
  return key;
}

export function encryptEvidence(buffer) {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, getKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    ciphertext,
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    algorithm: ALGORITHM,
  };
}

export function decryptEvidence(ciphertext, ivBase64, authTagBase64) {
  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    getKey(),
    Buffer.from(ivBase64, 'base64')
  );
  decipher.setAuthTag(Buffer.from(authTagBase64, 'base64'));
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function generateEvidenceEncryptionKey() {
  return crypto.randomBytes(KEY_BYTES).toString('hex');
}
