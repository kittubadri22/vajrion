import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

const secret = String(process.env.JWT_SECRET || '').trim();
if (!secret && (process.env.NODE_ENV === 'production' || process.env.VERCEL)) {
  throw new Error('JWT_SECRET is required in production.');
}
const effectiveSecret = secret || 'dev-only-secret-change-me';

export function hashPassword(password) { return bcrypt.hashSync(password, 12); }
export function comparePassword(password, hash) { return bcrypt.compareSync(password, hash); }
export function signToken(user) { return jwt.sign({ sub: user.id, role: user.role }, effectiveSecret, { expiresIn: '8h' }); }
export function verifyToken(token) { return jwt.verify(token, effectiveSecret); }
export function sha256Buffer(buffer) { return crypto.createHash('sha256').update(buffer).digest('hex'); }
export function sha256Text(text) { return crypto.createHash('sha256').update(text, 'utf8').digest('hex'); }
