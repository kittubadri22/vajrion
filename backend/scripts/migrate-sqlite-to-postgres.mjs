import 'dotenv/config';
import { DatabaseSync } from 'node:sqlite';
import { db, initDb } from '../src/db.js';

const source = process.env.SQLITE_SOURCE || new URL('../data/securedocs_v2.db', import.meta.url).pathname;
const sqlite = new DatabaseSync(source);
await initDb();
if (!process.env.DATABASE_URL && !process.env.POSTGRES_URL && !process.env.POSTGRES_URL_NON_POOLING && !process.env.POSTGRES_PRISMA_URL) {
  throw new Error('Set DATABASE_URL (or a supported POSTGRES_* URL) before migrating.');
}

const tables = [
  'police_stations','users','firs','cases','fir_copies','case_important_dates','case_lawyers',
  'court_proceedings','case_officer_access','documents','case_timeline','completion_requests',
  'notifications','audit_logs'
];

for (const table of tables) {
  const columns = sqlite.prepare(`PRAGMA table_info(${table})`).all().map(x => x.name);
  if (!columns.length) continue;
  const rows = sqlite.prepare(`SELECT ${columns.map(c => `"${c}"`).join(',')} FROM ${table}`).all();
  for (const row of rows) {
    const names = columns.map(c => `"${c}"`).join(',');
    const qs = columns.map(() => '?').join(',');
    const sql = `INSERT INTO ${table} (${names}) OVERRIDING SYSTEM VALUE VALUES(${qs}) ON CONFLICT DO NOTHING`;
    const values = columns.map(c => row[c] === undefined ? null : row[c]);
    await db.prepare(sql).run(...values);
  }
  const idColumn = columns.includes('id') ? 'id' : null;
  if (idColumn) {
    await db.exec(`SELECT setval(pg_get_serial_sequence('${table}','id'), COALESCE((SELECT MAX(id) FROM ${table}), 1), true)`);
  }
  console.log(`Migrated ${table}: ${rows.length} row(s)`);
}

const auditCheck = await db.prepare('SELECT COUNT(*) n FROM audit_logs').get();
console.log(`PostgreSQL audit rows: ${auditCheck.n}`);
console.log('Migration complete. Run GET /api/audit/verify-chain to check the imported audit chain.');
await db.close();
sqlite.close();
