import 'dotenv/config';
import { db, initDb } from './db.js';
import { hashPassword, sha256Buffer, sha256Text } from './security.js';
import { writeAudit } from './audit.js';

await initDb();

const stationNames = ['Gachibowli','Bachupally','Madhapur','Kondapur','Hitech city','Kokapet','Jubilee Hills','Banjara Hills','Narsingi','Manikonda','Somajiguda','Begumpet','Ameerpet','Secunderabad','Himayatnagar','Kukatpally','Miyapur','Kompally','Dilsukhnagar','Uppal'];
for (const name of stationNames) {
  await db.prepare('INSERT INTO police_stations(name,address,district,state) VALUES(?,?,?,?) ON CONFLICT(name) DO NOTHING').run(name, `${name}, Hyderabad / Secunderabad`, 'Hyderabad', 'Telangana');
}
const s1 = (await db.prepare('SELECT id FROM police_stations WHERE name=?').get('Gachibowli')).id;
const s2 = (await db.prepare('SELECT id FROM police_stations WHERE name=?').get('Madhapur')).id;

const users = [
 ['admin','System Admin','admin@securedocs.local','9000000001','admin123','ADMIN',null],
 ['dgp190','Commissioner Officer','dgp190@vajrion.local','','tgpolice2026','COMMISSIONER',null],
 ['citizen','Rahul Kumar','rahul@example.com','9000000002','citizen123','CITIZEN',null],
 ['citizen2','Priya Nair','priya@example.com','9000000003','citizen123','CITIZEN',null],
 ['police','Station Officer Anil','police@securedocs.local','9000000004','police123','POLICE',s1],
 ['police2','Station Officer Meena','police2@securedocs.local','9000000005','police123','POLICE',s2],
 ['io','Investigation Officer Ravi','io@securedocs.local','9000000006','io123','IO',s1],
 ['io2','Investigation Officer Kavya','io2@securedocs.local','9000000007','io123','IO',s2],
 ['forensic','Forensic Officer Nisha','forensic@securedocs.local','9000000009','forensic123','FORENSIC',s1],
 ['shared','Officer Shared Access','shared@securedocs.local','9000000008','shared123','IO',s1]
];
for (const u of users) {
  await db.prepare(`INSERT INTO users(username,name,email,phone,password_hash,role,police_station_id,verified,verified_at) VALUES(?,?,?,?,?,?,?,1,CURRENT_TIMESTAMP) ON CONFLICT(username) DO NOTHING`).run(u[0],u[1],u[2],u[3],hashPassword(u[4]),u[5],u[6]);
}
await db.prepare("UPDATE users SET verified=1,verified_at=COALESCE(verified_at,CURRENT_TIMESTAMP) WHERE role IN ('POLICE','IO','FORENSIC')").run();
const idByEmail = async e => (await db.prepare('SELECT id FROM users WHERE email=?').get(e)).id;
const admin=await idByEmail('admin@securedocs.local'), forensicId=await idByEmail('forensic@securedocs.local'), commissioner=await idByEmail('dgp190@vajrion.local'), citizen=await idByEmail('rahul@example.com'), police=await idByEmail('police@securedocs.local'), ravi=await idByEmail('io@securedocs.local'), shared=await idByEmail('shared@securedocs.local'), police2=await idByEmail('police2@securedocs.local'), io2=await idByEmail('io2@securedocs.local'), citizen2=await idByEmail('priya@example.com');
void admin; void commissioner;

async function seedCase({firNumber,caseId,citizenId,station,createdBy,assignedIo,incidentType,incidentDate,incidentTime,location,description,status='FIR_REGISTERED',progress=0}) {
  const existing=await db.prepare('SELECT id FROM cases WHERE case_id=?').get(caseId);
  if (existing) return existing.id;
  return db.transaction(async()=>{
    const fir=await db.prepare(`INSERT INTO firs(fir_number,case_id,citizen_id,police_station_id,created_by,incident_type,incident_date,incident_time,incident_location,description,status) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).run(firNumber,caseId,citizenId,station,createdBy,incidentType,incidentDate,incidentTime,location,description,status);
    const c=await db.prepare('INSERT INTO cases(fir_id,case_id,assigned_io_id,progress_percent,current_status,case_registration_date) VALUES(?,?,?,?,?,?)').run(fir.lastInsertRowid,caseId,assignedIo,progress,status,`${incidentDate}T${incidentTime}:00Z`);
    const stationName=(await db.prepare('SELECT name FROM police_stations WHERE id=?').get(station)).name;
    const citizenRow=await db.prepare('SELECT name,email,phone FROM users WHERE id=?').get(citizenId);
    const content=`VAJRION - OFFICIAL FIR COPY\n\nFIR Number: ${firNumber}\nCase ID: ${caseId}\nCitizen: ${citizenRow.name}\nEmail: ${citizenRow.email}\nPhone: ${citizenRow.phone||''}\nPolice Station: ${stationName}\nIncident Type: ${incidentType}\nIncident Date: ${incidentDate}\nIncident Time: ${incidentTime}\nIncident Location: ${location}\nDescription: ${description}\nCase Registration Date: ${incidentDate} ${incidentTime}`;
    await db.prepare('INSERT INTO fir_copies(fir_id,file_name,mime_type,content,sha256_hash) VALUES(?,?,?,?,?)').run(fir.lastInsertRowid,`${firNumber}.txt`,'text/plain',content,sha256Text(content));
    const cid=Number(c.lastInsertRowid);
    const ioName=(await db.prepare('SELECT name FROM users WHERE id=?').get(assignedIo)).name;
    for (const x of [['FIR_REGISTERED',`FIR ${firNumber} registered.`,'CITIZEN_VISIBLE'],['IO_ASSIGNED',`Investigation Officer ${ioName} assigned.`,'POLICE_ONLY']]) {
      await db.prepare('INSERT INTO case_timeline(case_id,actor_id,event_type,message,visibility) VALUES(?,?,?,?,?)').run(cid,createdBy,x[0],x[1],x[2]);
    }
    await writeAudit({actorId:createdBy,caseDbId:cid,action:'FIR_CREATED',entityType:'FIR',entityId:firNumber,metadata:{caseId}});
    await writeAudit({actorId:createdBy,caseDbId:cid,action:'IO_ASSIGNED',entityType:'CASE',entityId:caseId,metadata:{assignedIo}});
    await db.prepare('INSERT INTO notifications(user_id,case_id,type,title,message) VALUES(?,?,?,?,?)').run(citizenId,cid,'FIR_REGISTERED','FIR registered',`Your FIR ${firNumber} is registered. Case ID: ${caseId}.`);
    return cid;
  });
}

const case1=await seedCase({firNumber:'FIR-2026-0001',caseId:'CASE-2026-0001',citizenId:citizen,station:s1,createdBy:police,assignedIo:ravi,incidentType:'Property Theft',incidentDate:'2026-09-01',incidentTime:'22:30',location:'Market Road',description:'A valuable personal property was reported stolen during the night near Market Road.',status:'INVESTIGATION_IN_PROGRESS',progress:55});
const case2=await seedCase({firNumber:'FIR-2026-0002',caseId:'CASE-2026-0002',citizenId:citizen2,station:s2,createdBy:police2,assignedIo:io2,incidentType:'Missing Person',incidentDate:'2026-08-20',incidentTime:'20:00',location:'Railway Road',description:'A missing person report was registered after contact could not be established.',status:'CASE_CLOSED',progress:100});
const case3=await seedCase({firNumber:'FIR-2026-0003',caseId:'CASE-2026-0003',citizenId:citizen2,station:s1,createdBy:police,assignedIo:ravi,incidentType:'Property Dispute',incidentDate:'2026-08-20',incidentTime:'11:15',location:'Bachupally Main Road',description:'A property dispute case has received no recorded progress update for more than fifteen days.',status:'INVESTIGATION_IN_PROGRESS',progress:20});
void case3;

async function addOnce(selectSql, selectParams, insertSql, insertParams) {
  if (await db.prepare(selectSql).get(...selectParams)) return;
  await db.prepare(insertSql).run(...insertParams);
}
await addOnce('SELECT 1 FROM case_officer_access WHERE case_id=? AND officer_id=?',[case1,shared],'INSERT INTO case_officer_access(case_id,officer_id,granted_by,access_level) VALUES(?,?,?,?)',[case1,shared,ravi,'VIEW_CASE_DOCUMENTS']);
await addOnce('SELECT 1 FROM case_officer_access WHERE case_id=? AND officer_id=?',[case1,forensicId],'INSERT INTO case_officer_access(case_id,officer_id,granted_by,access_level) VALUES(?,?,?,?)',[case1,forensicId,ravi,'VIEW_CASE_DOCUMENTS']);
await addOnce('SELECT 1 FROM case_important_dates WHERE case_id=? AND label=?',[case1,'Next investigation review'],'INSERT INTO case_important_dates(case_id,label,date_value,notes,created_by) VALUES(?,?,?,?,?)',[case1,'Next investigation review','2026-09-10','Weekly case review.',ravi]);
await addOnce('SELECT 1 FROM case_lawyers WHERE case_id=? AND lawyer_name=?',[case1,'Adv. R. Menon'],'INSERT INTO case_lawyers(case_id,lawyer_name,bar_registration,phone,email,started_at,ended_at,is_current,notes,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)',[case1,'Adv. R. Menon','KA-BAR-998877','9000000010','menon@lawfirm.local','2026-09-02','2026-09-04',0,'Previous counsel history example.',police]);
await addOnce('SELECT 1 FROM case_lawyers WHERE case_id=? AND lawyer_name=?',[case1,'Adv. S. Prakash'],'INSERT INTO case_lawyers(case_id,lawyer_name,bar_registration,phone,email,started_at,is_current,notes,created_by) VALUES(?,?,?,?,?,?,1,?,?)',[case1,'Adv. S. Prakash','KA-BAR-112233','9000000011','prakash@lawfirm.local','2026-09-04','Representing the complainant.',police]);
await addOnce('SELECT 1 FROM court_proceedings WHERE proceeding_id=?',['CP-2026-0001'],'INSERT INTO court_proceedings(proceeding_id,case_id,proceeding_date,court_name,stage,outcome,next_hearing_date,notes,created_by) VALUES(?,?,?,?,?,?,?,?,?)',['CP-2026-0001',case2,'2026-09-01','District Court, Bengaluru','Final hearing','Case disposed','', 'Demo court proceeding history.',police2]);

const evidenceExists=await db.prepare('SELECT 1 FROM documents WHERE evidence_id=?').get('EVD-2026-0001');
if(!evidenceExists){
  const buf=Buffer.from('Demo investigation notes\nIncident: Property Theft\nLocation: Market Road\nStatus: collected and verified.','utf8');
  const hash=sha256Buffer(buf);
  await db.prepare('INSERT INTO documents(evidence_id,case_id,uploaded_by,name,document_type,description,file_name,mime_type,file_size,file_data,sha256_hash,citizen_visible) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').run('EVD-2026-0001',case1,ravi,'Investigation Notes','Investigation Report','Evidence notes from the investigation.','investigation-notes.txt','text/plain',buf.length,buf,hash,1);
  await db.prepare('INSERT INTO case_timeline(case_id,actor_id,event_type,message,visibility) VALUES(?,?,?,?,?)').run(case1,ravi,'DOCUMENT_UPLOADED','Evidence EVD-2026-0001 uploaded and hashed.','CITIZEN_VISIBLE');
  await writeAudit({actorId:ravi,caseDbId:case1,action:'DOCUMENT_UPLOADED',entityType:'DOCUMENT',entityId:'EVD-2026-0001',metadata:{sha256:hash}});
}

console.log('Seed complete. Demo credentials:');
for (const u of users) console.log(`${u[0]} / ${u[4]} (${u[5]})`);
await db.close();
