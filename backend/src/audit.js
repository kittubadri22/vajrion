import crypto from 'node:crypto';
import { db } from './db.js';

export async function writeAudit({ actorId = null, caseDbId = null, action, entityType, entityId = '', metadata = {} }) {
  const previous = (await db.prepare('SELECT current_hash FROM audit_logs ORDER BY id DESC LIMIT 1').get())?.current_hash || 'GENESIS';
  const createdAt = new Date().toISOString();
  const canonical = JSON.stringify({ previous, actorId, caseDbId, action, entityType, entityId:String(entityId), metadata, createdAt });
  const current = crypto.createHash('sha256').update(previous + canonical).digest('hex');
  await db.prepare(`INSERT INTO audit_logs(actor_id,case_id,action,entity_type,entity_id,metadata,previous_hash,current_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?)`).run(actorId, caseDbId, action, entityType, String(entityId), JSON.stringify(metadata), previous, current, createdAt);
  return current;
}

export async function verifyAuditChain() {
  const rows = await db.prepare('SELECT * FROM audit_logs ORDER BY id ASC').all();
  let previous = 'GENESIS';
  for (const row of rows) {
    const metadata = JSON.parse(row.metadata || '{}');
    if (row.previous_hash !== previous) return { valid: false, brokenAt: row.id, reason: 'Previous hash mismatch' };
    const canonical = JSON.stringify({ previous, actorId: row.actor_id, caseDbId: row.case_id, action: row.action, entityType: row.entity_type, entityId: row.entity_id, metadata, createdAt: new Date(row.created_at).toISOString() });
    const expected = crypto.createHash('sha256').update(previous + canonical).digest('hex');
    if (expected !== row.current_hash) return { valid: false, brokenAt: row.id, reason: 'Audit hash mismatch' };
    previous = row.current_hash;
  }
  return { valid: true, count: rows.length };
}
