import 'dotenv/config';
import { db, initDb } from './db.js';

await initDb();
const tables = ['audit_logs','notifications','completion_requests','case_timeline','documents','case_officer_access','court_proceedings','case_lawyers','case_important_dates','cases','fir_copies','firs','users','police_stations'];
if (process.env.TEST_SQLITE === '1') {
  for (const table of tables) await db.prepare(`DELETE FROM ${table}`).run();
} else {
  await db.exec(`TRUNCATE TABLE ${tables.join(', ')} RESTART IDENTITY CASCADE`);
}
console.log('Vajrion PostgreSQL database reset complete.');
await db.close();
