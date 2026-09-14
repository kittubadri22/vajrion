import 'dotenv/config';
import { encryptEvidence, decryptEvidence } from './encryption.js';
import crypto from 'node:crypto';

if (!process.env.EVIDENCE_ENCRYPTION_KEY || process.env.EVIDENCE_ENCRYPTION_KEY.length !== 64) {
  console.error('FAIL: EVIDENCE_ENCRYPTION_KEY must be configured in .env before running this test.');
  process.exit(1);
}
const original = Buffer.from('Vajrion encrypted evidence test — AES-256-GCM');
const a = encryptEvidence(original);
const b = encryptEvidence(original);
if (a.ciphertext.equals(original)) throw new Error('Ciphertext equals plaintext.');
if (a.ciphertext.equals(b.ciphertext) || a.iv === b.iv) throw new Error('Encryption is not randomized.');
const restored = decryptEvidence(a.ciphertext, a.iv, a.authTag);
if (!restored.equals(original)) throw new Error('Decrypt mismatch.');
const tampered = Buffer.from(a.ciphertext);
tampered[0] ^= 1;
let rejected = false;
try { decryptEvidence(tampered, a.iv, a.authTag); } catch { rejected = true; }
if (!rejected) throw new Error('Tampered ciphertext was accepted.');
console.log('PASS: AES-256-GCM encryption/decryption and tamper rejection');
console.log(`SHA-256 sample: ${crypto.createHash('sha256').update(original).digest('hex')}`);
