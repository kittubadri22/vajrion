import 'dotenv/config';
import crypto from 'node:crypto';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import multer from 'multer';
import { z } from 'zod';
import { db, initDb } from './db.js';
import { comparePassword, hashPassword, sha256Buffer, sha256Text, signToken } from './security.js';
import { requireAuth, allowRoles, getCase, canViewCase, canEditCase, canGrantAccess, canUploadEvidence } from './auth.js';
import { writeAudit, verifyAuditChain } from './audit.js';
import { encryptEvidence, decryptEvidence } from './encryption.js';

const app=express();
await initDb();
const PORT=Number(process.env.PORT||4000);
const ORIGIN=process.env.FRONTEND_ORIGIN||'http://localhost:5173';
const maxUpload=(Number(process.env.MAX_UPLOAD_MB)||3.5)*1024*1024;

app.use(helmet({crossOriginResourcePolicy:{policy:'cross-origin'}}));
app.use(cors({origin: ORIGIN, credentials:false}));
app.use(express.json({limit:'4mb'}));
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:maxUpload},fileFilter:(_req,file,cb)=>{const m=file.mimetype.toLowerCase();const allowed=m==='application/pdf'||m==='image/jpeg'||m==='image/png'||m.startsWith('text/')||m.startsWith('audio/')||m.startsWith('video/')||m==='application/msword'||m==='application/vnd.openxmlformats-officedocument.wordprocessingml.document';cb(null,allowed);}});
const loginLimit=rateLimit({windowMs:15*60*1000,limit:25,standardHeaders:true,legacyHeaders:false});

const STATUSES=['FIR_REGISTERED','INVESTIGATION_NOT_STARTED','INVESTIGATION_IN_PROGRESS','EVIDENCE_COLLECTION','SUSPECT_IDENTIFIED','CHARGE_SHEET_PREPARATION','INVESTIGATION_COMPLETED','CASE_CLOSED'];
const progressSchema=z.object({progressPercent:z.coerce.number().int().min(0).max(100),status:z.enum(STATUSES.filter(s=>s!=='CASE_CLOSED'))});
const firSchema=z.object({citizenName:z.string().trim().min(2,'Citizen name must be at least 2 characters.'),citizenEmail:z.string().trim().email('Enter a valid citizen email address.'),citizenPhone:z.string().trim().max(30).optional().default(''),incidentType:z.string().trim().min(2,'Incident type is required.'),incidentDate:z.string().min(8,'Incident date is required.'),incidentTime:z.string().optional(),incidentLocation:z.string().trim().min(2,'Incident location is required.'),description:z.string().trim().min(5,'Description must be at least 5 characters.'),policeStationId:z.coerce.number().int().positive()});

async function safeUser(u){
  let stationName = u.station_name || null;
  if (!stationName && u.police_station_id) stationName = (await db.prepare('SELECT name FROM police_stations WHERE id=?').get(u.police_station_id))?.name || null;
  return {id:u.id,username:u.username,name:u.name,email:u.email,phone:u.phone,role:u.role,police_station_id:u.police_station_id,station_name:stationName,area:stationName,verified:u.verified??1,verified_at:u.verified_at||null};
}
function nextNo(prefix,table){ void table; const year=new Date().getFullYear(); const stamp=new Date().toISOString().replace(/[-:TZ.]/g,'').slice(0,14); const suffix=crypto.randomBytes(2).toString('hex').toUpperCase(); return `${prefix}-${year}-${stamp}-${suffix}`; }
async function timeline(caseId,actorId,eventType,message,visibility='POLICE_ONLY'){await db.prepare('INSERT INTO case_timeline(case_id,actor_id,event_type,message,visibility) VALUES(?,?,?,?,?)').run(caseId,actorId,eventType,message,visibility);}
async function notify(userId,caseId,type,title,message){await db.prepare('INSERT INTO notifications(user_id,case_id,type,title,message) VALUES(?,?,?,?,?)').run(userId,caseId,type,title,message);}
async function assertCase(req,res,ref){const c=await getCase(ref);if(!c)return res.status(404).json({error:'Case not found'});if(!(await canViewCase(req.user,c)))return res.status(403).json({error:'You do not have access to this case.'});return c;}

app.get('/api/health',(_req,res)=>res.json({status:'ok',service:'vajrion-backend',time:new Date().toISOString()}));

app.post('/api/auth/signup',loginLimit,async(req,res)=>{
  const p=z.object({
    name:z.string().trim().min(2,'Name must be at least 2 characters.'),
    email:z.string().trim().email('Enter a valid email address.'),
    phone:z.string().trim().max(30).optional().default(''),
    username:z.string().trim().min(3,'Username must be at least 3 characters.').regex(/^[a-zA-Z0-9._-]+$/,'Username can contain letters, numbers, dot, underscore and hyphen only.'),
    password:z.string().min(8,'Password must be at least 8 characters.').regex(/[A-Z]/,'Password must contain at least one uppercase letter.').regex(/[a-z]/,'Password must contain at least one lowercase letter.').regex(/[0-9]/,'Password must contain at least one number.').regex(/[^A-Za-z0-9]/,'Password must contain at least one special character.')
  }).safeParse(req.body);
  if(!p.success)return res.status(400).json({error:p.error.issues.map(i=>i.message).join('; ')});
  if(await db.prepare('SELECT 1 FROM users WHERE lower(email)=lower(?) OR lower(username)=lower(?)').get(p.data.email,p.data.username))return res.status(409).json({error:'An account with this email or username already exists.'});
  const info=await db.prepare('INSERT INTO users(username,name,email,phone,password_hash,role,verified) VALUES(?,?,?,?,?,?,1)').run(p.data.username,p.data.name,p.data.email,p.data.phone||'',hashPassword(p.data.password),'CITIZEN');
  const u=await db.prepare('SELECT id,username,name,email,phone,role,police_station_id,verified,verified_at FROM users WHERE id=?').get(info.lastInsertRowid);
  res.status(201).json({success:true,user:await safeUser(u),message:'Citizen account created. You can now sign in.'});
});

app.post('/api/auth/login',loginLimit,async(req,res)=>{
  const p=z.object({identifier:z.string().min(2),password:z.string().min(1)}).safeParse(req.body);
  if(!p.success)return res.status(400).json({error:'Username/email and password are required'});
  const u=await db.prepare('SELECT * FROM users WHERE lower(email)=lower(?) OR lower(username)=lower(?)').get(p.data.identifier,p.data.identifier);
  if(!u||!comparePassword(p.data.password,u.password_hash))return res.status(401).json({error:'Invalid username/email or password'});
  if(['POLICE','IO','FORENSIC'].includes(u.role)&&u.verified!==1)return res.status(403).json({error:'Your officer account is awaiting Admin verification.'});
  res.json({token:signToken(u),user:await safeUser(u)});
});
app.get('/api/auth/me',requireAuth,async(req,res)=>res.json({user:await safeUser(req.user)}));
app.patch('/api/auth/password',requireAuth,async(req,res)=>{
  const p=z.object({currentPassword:z.string().min(1),newPassword:z.string().min(8,'New password must be at least 8 characters.').regex(/[A-Z]/,'New password must contain at least one uppercase letter.').regex(/[a-z]/,'New password must contain at least one lowercase letter.').regex(/[0-9]/,'New password must contain at least one number.').regex(/[^A-Za-z0-9]/,'New password must contain at least one special character.')}).safeParse(req.body);
  if(!p.success)return res.status(400).json({error:p.error.issues.map(i=>i.message).join('; ')});
  const u=await db.prepare('SELECT password_hash FROM users WHERE id=?').get(req.user.id);
  if(!u||!comparePassword(p.data.currentPassword,u.password_hash))return res.status(401).json({error:'Current password is incorrect.'});
  await db.prepare('UPDATE users SET password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(hashPassword(p.data.newPassword),req.user.id);
  await writeAudit({actorId:req.user.id,action:'PASSWORD_CHANGED',entityType:'USER',entityId:req.user.id});
  res.json({success:true,message:'Password changed successfully. Please sign in again.'});
});

app.get('/api/dashboard/stats',requireAuth,async(req,res)=>{
  let total=0,active=0,completed=0,documents=0,notifications=0;
  if(req.user.role==='CITIZEN'){
    total=(await db.prepare('SELECT COUNT(*) n FROM firs WHERE citizen_id=?').get(req.user.id)).n;
    active=(await db.prepare("SELECT COUNT(*) n FROM firs WHERE citizen_id=? AND status NOT IN ('INVESTIGATION_COMPLETED','CASE_CLOSED')").get(req.user.id)).n;
    completed=total-active; documents=(await db.prepare('SELECT COUNT(*) n FROM documents d JOIN cases c ON c.id=d.case_id JOIN firs f ON f.id=c.fir_id WHERE f.citizen_id=? AND d.citizen_visible=1').get(req.user.id)).n;
  }else if(req.user.role==='POLICE'){
    total=(await db.prepare('SELECT COUNT(*) n FROM firs WHERE police_station_id=?').get(req.user.police_station_id)).n;
    active=(await db.prepare("SELECT COUNT(*) n FROM firs WHERE police_station_id=? AND status NOT IN ('INVESTIGATION_COMPLETED','CASE_CLOSED')").get(req.user.police_station_id)).n;
    completed=total-active; documents=(await db.prepare('SELECT COUNT(*) n FROM documents d JOIN cases c ON c.id=d.case_id JOIN firs f ON f.id=c.fir_id WHERE f.police_station_id=?').get(req.user.police_station_id)).n;
  }else if(req.user.role==='IO'){
    total=(await db.prepare("SELECT COUNT(*) n FROM cases WHERE assigned_io_id=? OR id IN (SELECT case_id FROM case_officer_access WHERE officer_id=? AND revoked_at IS NULL)").get(req.user.id,req.user.id)).n;
    active=(await db.prepare("SELECT COUNT(*) n FROM cases WHERE (assigned_io_id=? OR id IN (SELECT case_id FROM case_officer_access WHERE officer_id=? AND revoked_at IS NULL)) AND current_status NOT IN ('INVESTIGATION_COMPLETED','CASE_CLOSED')").get(req.user.id,req.user.id)).n;
    completed=total-active; documents=(await db.prepare("SELECT COUNT(*) n FROM documents WHERE uploaded_by=? OR case_id IN (SELECT case_id FROM cases WHERE assigned_io_id=? OR id IN (SELECT case_id FROM case_officer_access WHERE officer_id=? AND revoked_at IS NULL))").get(req.user.id,req.user.id,req.user.id)).n;
  }else{
    total=(await db.prepare('SELECT COUNT(*) n FROM cases').get()).n; active=(await db.prepare("SELECT COUNT(*) n FROM cases WHERE current_status NOT IN ('INVESTIGATION_COMPLETED','CASE_CLOSED')").get()).n; completed=total-active; documents=(await db.prepare('SELECT COUNT(*) n FROM documents').get()).n;
  }
  notifications=(await db.prepare('SELECT COUNT(*) n FROM notifications WHERE user_id=? AND is_read=0').get(req.user.id)).n;
  res.json({total,active,completed,documents,notifications});
});

app.get('/api/firs',requireAuth,async(req,res)=>{
  let rows=[];
  if(req.user.role==='CITIZEN') rows=await db.prepare(`SELECT f.*,c.progress_percent,c.current_status,c.assigned_io_id,c.case_registration_date,ps.name station_name,io.name io_name FROM firs f JOIN cases c ON c.fir_id=f.id JOIN police_stations ps ON ps.id=f.police_station_id LEFT JOIN users io ON io.id=c.assigned_io_id WHERE f.citizen_id=? ORDER BY f.submitted_at DESC`).all(req.user.id);
  else if(req.user.role==='POLICE') rows=await db.prepare(`SELECT f.*,c.progress_percent,c.current_status,c.assigned_io_id,c.case_registration_date,ps.name station_name,u.name citizen_name,u.email citizen_email,io.name io_name FROM firs f JOIN cases c ON c.fir_id=f.id JOIN police_stations ps ON ps.id=f.police_station_id JOIN users u ON u.id=f.citizen_id LEFT JOIN users io ON io.id=c.assigned_io_id WHERE f.police_station_id=? ORDER BY f.submitted_at DESC`).all(req.user.police_station_id);
  else if(req.user.role==='IO') rows=await db.prepare(`SELECT f.*,c.progress_percent,c.current_status,c.assigned_io_id,c.case_registration_date,ps.name station_name,u.name citizen_name,u.email citizen_email,io.name io_name FROM firs f JOIN cases c ON c.fir_id=f.id JOIN police_stations ps ON ps.id=f.police_station_id JOIN users u ON u.id=f.citizen_id LEFT JOIN users io ON io.id=c.assigned_io_id WHERE c.assigned_io_id=? OR c.id IN (SELECT case_id FROM case_officer_access WHERE officer_id=? AND revoked_at IS NULL) ORDER BY f.submitted_at DESC`).all(req.user.id,req.user.id);
  else if(req.user.role==='FORENSIC') rows=await db.prepare(`SELECT f.*,c.progress_percent,c.current_status,c.assigned_io_id,c.case_registration_date,ps.name station_name,u.name citizen_name,u.email citizen_email,io.name io_name FROM firs f JOIN cases c ON c.fir_id=f.id JOIN police_stations ps ON ps.id=f.police_station_id JOIN users u ON u.id=f.citizen_id LEFT JOIN users io ON io.id=c.assigned_io_id WHERE c.id IN (SELECT case_id FROM case_officer_access WHERE officer_id=? AND revoked_at IS NULL) ORDER BY f.submitted_at DESC`).all(req.user.id);
  else if(req.user.role==='COMMISSIONER') rows=await db.prepare(`SELECT f.*,c.progress_percent,c.current_status,c.assigned_io_id,c.case_registration_date,ps.name station_name,u.name citizen_name,u.email citizen_email,io.name io_name,datetime(COALESCE((SELECT MAX(t.created_at) FROM case_timeline t WHERE t.case_id=c.id AND t.event_type='CASE_PROGRESS_UPDATED'),c.case_registration_date)) last_progress_at,CASE WHEN c.current_status NOT IN ('INVESTIGATION_COMPLETED','CASE_CLOSED') AND datetime(COALESCE((SELECT MAX(t.created_at) FROM case_timeline t WHERE t.case_id=c.id AND t.event_type='CASE_PROGRESS_UPDATED'),c.case_registration_date))<=datetime('now','-15 days') THEN 1 ELSE 0 END action_required FROM firs f JOIN cases c ON c.fir_id=f.id JOIN police_stations ps ON ps.id=f.police_station_id JOIN users u ON u.id=f.citizen_id LEFT JOIN users io ON io.id=c.assigned_io_id ORDER BY action_required DESC,f.submitted_at DESC`).all();
  else rows=await db.prepare(`SELECT f.*,c.progress_percent,c.current_status,c.assigned_io_id,c.case_registration_date,ps.name station_name,u.name citizen_name,u.email citizen_email,io.name io_name FROM firs f JOIN cases c ON c.fir_id=f.id JOIN police_stations ps ON ps.id=f.police_station_id JOIN users u ON u.id=f.citizen_id LEFT JOIN users io ON io.id=c.assigned_io_id ORDER BY f.submitted_at DESC`).all();
  res.json({firs:rows});
});

app.post('/api/firs',requireAuth,allowRoles('POLICE','ADMIN'), async(req,res)=>{
  const p=firSchema.safeParse(req.body);if(!p.success)return res.status(400).json({error:p.error.issues.map(i=>i.message).join('; ')});
  if(req.user.role==='POLICE' && !req.user.police_station_id)return res.status(403).json({error:'Your officer account has no police station assigned.'});
  const policeStationId=req.user.role==='POLICE'?req.user.police_station_id:p.data.policeStationId;
  if(!await db.prepare('SELECT 1 FROM police_stations WHERE id=?').get(policeStationId))return res.status(400).json({error:'Selected police station is not registered.'});
  let citizen=await db.prepare('SELECT * FROM users WHERE lower(email)=lower(?)').get(p.data.citizenEmail);
  let temporaryPassword=null;
  if(citizen && citizen.role!=='CITIZEN')return res.status(409).json({error:'This email belongs to a non-citizen account. Use the citizen email for the FIR.'});
  if(!citizen){temporaryPassword='citizen123';const localPart=p.data.citizenEmail.split('@')[0].replace(/[^a-zA-Z0-9._-]/g,'').slice(0,28)||'citizen';const username=`${localPart}_${Date.now().toString().slice(-6)}`;const info=await db.prepare('INSERT INTO users(username,name,email,phone,password_hash,role) VALUES(?,?,?,?,?,?)').run(username,p.data.citizenName,p.data.citizenEmail,p.data.citizenPhone,hashPassword(temporaryPassword),'CITIZEN');citizen=await db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);}
  const firNo=nextNo('FIR','firs');const caseId=nextNo('CASE','cases');
  const tx=await db.transaction(async()=>{
    const fir=await db.prepare(`INSERT INTO firs(fir_number,case_id,citizen_id,police_station_id,created_by,incident_type,incident_date,incident_time,incident_location,description,status) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).run(firNo,caseId,citizen.id,policeStationId,req.user.id,p.data.incidentType,p.data.incidentDate,p.data.incidentTime||'',p.data.incidentLocation,p.data.description,'FIR_REGISTERED');
    const c=await db.prepare('INSERT INTO cases(fir_id,case_id,progress_percent,current_status) VALUES(?,?,0,?)').run(fir.lastInsertRowid,caseId,'FIR_REGISTERED');
    const stationRow=await db.prepare('SELECT name FROM police_stations WHERE id=?').get(policeStationId); const stationName=stationRow?.name||'';
    const content=`VAJRION FIR COPY\nFIR Number: ${firNo}\nCase ID: ${caseId}\nCitizen: ${citizen.name}\nEmail: ${citizen.email}\nPhone: ${citizen.phone||''}\nPolice Station: ${stationName}\nIncident Type: ${p.data.incidentType}\nIncident Date: ${p.data.incidentDate}\nIncident Time: ${p.data.incidentTime||''}\nLocation: ${p.data.incidentLocation}\nDescription:\n${p.data.description}\nSubmitted At: ${new Date().toISOString()}`;
    await db.prepare('INSERT INTO fir_copies(fir_id,file_name,mime_type,content,sha256_hash) VALUES(?,?,?,?,?)').run(fir.lastInsertRowid,`${firNo}.txt`,'text/plain',content,sha256Text(content));
    const caseDbId=Number(c.lastInsertRowid); await timeline(caseDbId,req.user.id,'FIR_REGISTERED',`FIR ${firNo} registered for case ${caseId}.`,'CITIZEN_VISIBLE');
    await writeAudit({actorId:req.user.id,caseDbId,action:'FIR_CREATED',entityType:'FIR',entityId:firNo,metadata:{caseId,citizenEmail:citizen.email}});
    await notify(citizen.id,caseDbId,'FIR_REGISTERED','FIR registered',`Your FIR ${firNo} is registered. Case ID: ${caseId}. Sign in with your registered email to view this case.`);
    await timeline(caseDbId,req.user.id,'CITIZEN_ACCESS_ENABLED',`Citizen access enabled for ${citizen.email}.`,'POLICE_ONLY');
    return {firId:Number(fir.lastInsertRowid),caseId,firNo,temporaryPassword,citizenAccess:{enabled:true,email:citizen.email,username:citizen.username,temporaryPassword}};
  });
  res.status(201).json({success:true,...tx});
});

app.get('/api/cases/:caseId',requireAuth,async(req,res)=>{
  const c=await assertCase(req,res,req.params.caseId);if(!c||res.headersSent)return;
  const timelineRows=await db.prepare(`SELECT t.*,u.name actor_name,u.role actor_role FROM case_timeline t LEFT JOIN users u ON u.id=t.actor_id WHERE t.case_id=? ${req.user.role==='CITIZEN'?"AND t.visibility='CITIZEN_VISIBLE'":''} ORDER BY t.created_at ASC,t.id ASC`).all(c.id);
  const documents=await db.prepare(`SELECT d.id,d.evidence_id,d.name,d.document_type,d.description,d.file_name,d.mime_type,d.file_size,d.sha256_hash,d.encryption_algorithm,d.citizen_visible,d.created_at,u.name uploaded_by_name FROM documents d JOIN users u ON u.id=d.uploaded_by WHERE d.case_id=? ${req.user.role==='CITIZEN'?'AND d.citizen_visible=1':''} ORDER BY d.created_at DESC`).all(c.id);
  const importantDates=await db.prepare('SELECT * FROM case_important_dates WHERE case_id=? ORDER BY date_value ASC').all(c.id);
  const lawyers=await db.prepare('SELECT id,lawyer_name,bar_registration,phone,email,started_at,ended_at,is_current,notes FROM case_lawyers WHERE case_id=? ORDER BY started_at DESC,id DESC').all(c.id);
  const proceedings=await db.prepare('SELECT * FROM court_proceedings WHERE case_id=? ORDER BY proceeding_date DESC,id DESC').all(c.id);
  const access=await db.prepare(`SELECT a.*,u.name officer_name,u.email officer_email,u.role officer_role,ps.name station_name,g.name granted_by_name FROM case_officer_access a JOIN users u ON u.id=a.officer_id LEFT JOIN police_stations ps ON ps.id=u.police_station_id JOIN users g ON g.id=a.granted_by WHERE a.case_id=? ORDER BY a.granted_at DESC`).all(c.id);
  const completion=await db.prepare('SELECT * FROM completion_requests WHERE case_id=? ORDER BY sent_at DESC').all(c.id);
  const firCopy=await db.prepare('SELECT id,file_name,mime_type,content,sha256_hash,created_at FROM fir_copies WHERE fir_id=?').get(c.fir_id)||null;
  res.json({case:c,timeline:timelineRows,documents,importantDates,lawyers,proceedings,access,completion,firCopy});
});

app.get('/api/cases/:caseId/fir-copy',requireAuth,async(req,res)=>{const c=await assertCase(req,res,req.params.caseId);if(!c||res.headersSent)return;const copy=await db.prepare('SELECT * FROM fir_copies WHERE fir_id=?').get(c.fir_id);if(!copy)return res.status(404).json({error:'FIR copy not found'});res.json({copy});});

app.patch('/api/cases/:caseId/progress',requireAuth,allowRoles('POLICE','IO','ADMIN'),async(req,res)=>{
  const c=await assertCase(req,res,req.params.caseId);if(!c||res.headersSent)return;if(!canEditCase(req.user,c))return res.status(403).json({error:'You cannot update this case.'});
  const p=progressSchema.safeParse(req.body);if(!p.success)return res.status(400).json({error:p.error.issues.map(i=>i.message).join('; ')});
  await db.prepare("UPDATE cases SET progress_percent=?,current_status=?,updated_at=CURRENT_TIMESTAMP,completed_at=CASE WHEN ?='CASE_CLOSED' THEN CURRENT_TIMESTAMP ELSE NULL END WHERE id=?").run(p.data.progressPercent,p.data.status,p.data.status,c.id);
  await db.prepare('UPDATE firs SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(p.data.status,c.fir_id);
  await timeline(c.id,req.user.id,'CASE_PROGRESS_UPDATED',`Case progress updated to ${p.data.progressPercent}% (${p.data.status.replaceAll('_',' ')}).`,'CITIZEN_VISIBLE');
  await writeAudit({actorId:req.user.id,caseDbId:c.id,action:'CASE_PROGRESS_UPDATED',entityType:'CASE',entityId:c.case_id,metadata:p.data});
  await notify(c.citizen_id,c.id,'CASE_PROGRESS','Case progress updated',`Your case ${c.case_id} is now ${p.data.progressPercent}% complete: ${p.data.status.replaceAll('_',' ')}.`);
  res.json({success:true});
});

app.post('/api/cases/:caseId/assign-io',requireAuth,allowRoles('POLICE','ADMIN'),async(req,res)=>{
  const c=await assertCase(req,res,req.params.caseId);if(!c||res.headersSent)return;if(req.user.role==='POLICE'&&!canEditCase(req.user,c))return res.status(403).json({error:'You cannot assign officers for this case.'});
  const p=z.object({officerId:z.coerce.number().int().positive()}).safeParse(req.body);if(!p.success)return res.status(400).json({error:'officerId is required'});
  const io=await db.prepare("SELECT id,name,email,role,police_station_id,verified FROM users WHERE id=? AND role='IO'").get(p.data.officerId);if(!io)return res.status(404).json({error:'Investigation Officer not found'});if(io.verified!==1)return res.status(403).json({error:'That Investigation Officer has not been verified by an Admin yet.'});
  if(req.user.role==='POLICE'&&io.police_station_id!==req.user.police_station_id)return res.status(403).json({error:'Select an IO from your police station.'});
  await db.prepare('UPDATE cases SET assigned_io_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(io.id,c.id);
  await timeline(c.id,req.user.id,'IO_ASSIGNED',`Investigation Officer ${io.name} assigned to the case.`,'POLICE_ONLY');await writeAudit({actorId:req.user.id,caseDbId:c.id,action:'IO_ASSIGNED',entityType:'CASE',entityId:c.case_id,metadata:{ioId:io.id}});await notify(io.id,c.id,'IO_ASSIGNED','Case assigned',`You are assigned to case ${c.case_id}.`);res.json({success:true});
});

app.get('/api/officers',requireAuth,allowRoles('POLICE','IO','ADMIN'),async(req,res)=>{
  const q=String(req.query.email||'').trim().toLowerCase();
  let rows=await db.prepare("SELECT id,username,name,email,phone,role,police_station_id,verified,verified_at FROM users WHERE role IN ('POLICE','IO','FORENSIC') AND verified=1 ORDER BY name").all();
  if(req.user.role==='POLICE')rows=rows.filter(r=>r.police_station_id===req.user.police_station_id);
  if(q)rows=rows.filter(r=>r.email.toLowerCase()===q);
  res.json({officers:rows});
});

app.post('/api/cases/:caseId/access',requireAuth,allowRoles('POLICE','IO','ADMIN'),async(req,res)=>{
  const c=await assertCase(req,res,req.params.caseId);if(!c||res.headersSent)return;if(!canGrantAccess(req.user,c))return res.status(403).json({error:'You are not authorized to manage access for this case.'});
  const p=z.object({email:z.string().email(),accessLevel:z.enum(['VIEW_CASE','VIEW_CASE_DOCUMENTS'])}).safeParse(req.body);if(!p.success)return res.status(400).json({error:'Valid officer email and access level are required'});
  const officer=await db.prepare("SELECT id,name,email,role,police_station_id,verified FROM users WHERE lower(email)=lower(?) AND role IN ('POLICE','IO','FORENSIC')").get(p.data.email);if(!officer)return res.status(404).json({error:'No verified Police, Investigation, or Forensic Officer was found with that email.'});if(officer.verified!==1)return res.status(403).json({error:'That officer exists but has not been verified by an Admin yet.'});
  if(officer.id===c.assigned_io_id)return res.status(400).json({error:'That officer is already the main Investigation Officer.'});
  if(req.user.role==='POLICE' && !['IO','FORENSIC'].includes(officer.role))return res.status(400).json({error:'Police Station Officers can grant case access to verified Investigation or Forensic Officers only.'});
  if(req.user.role==='POLICE' && officer.role==='IO' && officer.police_station_id!==req.user.police_station_id)return res.status(403).json({error:'The Investigation Officer must belong to your police station.'});
  await db.prepare(`INSERT INTO case_officer_access(case_id,officer_id,granted_by,access_level,revoked_at) VALUES(?,?,?,?,NULL) ON CONFLICT(case_id,officer_id) DO UPDATE SET granted_by=excluded.granted_by,access_level=excluded.access_level,granted_at=CURRENT_TIMESTAMP,revoked_at=NULL`).run(c.id,officer.id,req.user.id,p.data.accessLevel);
  await timeline(c.id,req.user.id,'CASE_ACCESS_GRANTED',`Case access granted to ${officer.name} (${officer.email}).`,'POLICE_ONLY');await writeAudit({actorId:req.user.id,caseDbId:c.id,action:'CASE_ACCESS_GRANTED',entityType:'CASE_ACCESS',entityId:officer.id,metadata:{officerEmail:officer.email,accessLevel:p.data.accessLevel}});await notify(officer.id,c.id,'CASE_SHARED','Case access granted',`You now have access to case ${c.case_id}.`);res.status(201).json({success:true});
});
app.delete('/api/cases/:caseId/access/:accessId',requireAuth,allowRoles('IO','ADMIN'),async(req,res)=>{const c=await assertCase(req,res,req.params.caseId);if(!c||res.headersSent)return;if(!canGrantAccess(req.user,c))return res.status(403).json({error:'You are not authorized to manage access for this case.'});await db.prepare('UPDATE case_officer_access SET revoked_at=CURRENT_TIMESTAMP WHERE id=? AND case_id=?').run(req.params.accessId,c.id);await timeline(c.id,req.user.id,'CASE_ACCESS_REVOKED','Case officer access revoked.','POLICE_ONLY');await writeAudit({actorId:req.user.id,caseDbId:c.id,action:'CASE_ACCESS_REVOKED',entityType:'CASE_ACCESS',entityId:req.params.accessId});res.json({success:true});});

app.post('/api/cases/:caseId/timeline',requireAuth,allowRoles('POLICE','IO','ADMIN'),async(req,res)=>{const c=await assertCase(req,res,req.params.caseId);if(!c||res.headersSent)return;if(!canEditCase(req.user,c))return res.status(403).json({error:'You cannot add updates to this case.'});const p=z.object({eventType:z.string().min(2),message:z.string().min(2),visibility:z.enum(['POLICE_ONLY','CITIZEN_VISIBLE'])}).safeParse(req.body);if(!p.success)return res.status(400).json({error:'Event type, message and visibility are required'});await timeline(c.id,req.user.id,p.data.eventType,p.data.message,p.data.visibility);await writeAudit({actorId:req.user.id,caseDbId:c.id,action:'TIMELINE_ADDED',entityType:'CASE_TIMELINE',entityId:c.id,metadata:p.data});if(p.data.visibility==='CITIZEN_VISIBLE')await notify(c.citizen_id,c.id,'CASE_UPDATE','New case update',p.data.message);res.status(201).json({success:true});});

app.post('/api/cases/:caseId/documents',requireAuth,allowRoles('IO','FORENSIC','ADMIN'),upload.single('file'),async(req,res)=>{
  const c=await assertCase(req,res,req.params.caseId);if(!c||res.headersSent)return;if(!await canUploadEvidence(req.user,c))return res.status(403).json({error:'You cannot upload evidence to this case.'});if(!req.file)return res.status(400).json({error:'Please select a PDF, JPG, PNG, text, audio or video evidence file.'});
  const p=z.object({name:z.string().min(2),documentType:z.string().min(2),description:z.string().optional(),citizenVisible:z.string().optional()}).safeParse(req.body);if(!p.success)return res.status(400).json({error:'Document name and type are required'});
  const evidenceId=nextNo('EVD','documents');const hash=sha256Buffer(req.file.buffer);const enc=encryptEvidence(req.file.buffer);
  const info=await db.prepare('INSERT INTO documents(evidence_id,case_id,uploaded_by,name,document_type,description,file_name,mime_type,file_size,file_data,sha256_hash,encryption_iv,encryption_auth_tag,encryption_algorithm,citizen_visible) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(evidenceId,c.id,req.user.id,p.data.name,p.data.documentType,p.data.description||'',req.file.originalname,req.file.mimetype,req.file.size,enc.ciphertext,hash,enc.iv,enc.authTag,enc.algorithm,p.data.citizenVisible==='true'?1:0);
  await timeline(c.id,req.user.id,'DOCUMENT_UPLOADED',`Evidence ${evidenceId} (${p.data.name}) uploaded. SHA-256: ${hash}`,'POLICE_ONLY');await writeAudit({actorId:req.user.id,caseDbId:c.id,action:'DOCUMENT_UPLOADED',entityType:'DOCUMENT',entityId:evidenceId,metadata:{sha256:hash,name:p.data.name}});res.status(201).json({success:true,id:Number(info.lastInsertRowid),evidenceId,sha256:hash});
});
app.get('/api/cases/:caseId/documents',requireAuth,async(req,res)=>{const c=await assertCase(req,res,req.params.caseId);if(!c||res.headersSent)return;const rows=await db.prepare(`SELECT d.id,d.evidence_id,d.name,d.document_type,d.description,d.file_name,d.mime_type,d.file_size,d.sha256_hash,d.encryption_algorithm,d.citizen_visible,d.created_at,u.name uploaded_by_name FROM documents d JOIN users u ON u.id=d.uploaded_by WHERE d.case_id=? ${req.user.role==='CITIZEN'?'AND d.citizen_visible=1':''} ORDER BY d.created_at DESC`).all(c.id);res.json({documents:rows});});
app.get('/api/documents/:id',requireAuth,async(req,res)=>{
  const d=await db.prepare(`SELECT d.*,c.case_id,c.fir_id,f.citizen_id,f.police_station_id FROM documents d JOIN cases c ON c.id=d.case_id JOIN firs f ON f.id=c.fir_id WHERE d.id=?`).get(req.params.id);if(!d)return res.status(404).json({error:'Evidence not found'});const c=await getCase(d.case_id);if(!(await canViewCase(req.user,c)))return res.status(403).json({error:'You do not have access to this evidence.'});if(req.user.role==='CITIZEN'&&!d.citizen_visible)return res.status(403).json({error:'This evidence is restricted to authorized officers.'});
  const plaintext=(d.encryption_algorithm==='aes-256-gcm'&&d.encryption_iv&&d.encryption_auth_tag)?decryptEvidence(Buffer.from(d.file_data),d.encryption_iv,d.encryption_auth_tag):Buffer.from(d.file_data);res.json({document:{id:d.id,evidence_id:d.evidence_id,name:d.name,document_type:d.document_type,description:d.description,file_name:d.file_name,mime_type:d.mime_type,file_size:d.file_size,sha256_hash:d.sha256_hash,encryption_algorithm:d.encryption_algorithm||'none',citizen_visible:d.citizen_visible,created_at:d.created_at,case_id:d.case_id}});
});
app.get('/api/documents/:id/content',requireAuth,async(req,res)=>{const d=await db.prepare(`SELECT d.*,c.case_id FROM documents d JOIN cases c ON c.id=d.case_id WHERE d.id=?`).get(req.params.id);if(!d)return res.status(404).json({error:'Evidence not found'});const c=await getCase(d.case_id);if(!(await canViewCase(req.user,c)))return res.status(403).json({error:'You do not have access to this evidence.'});if(req.user.role==='CITIZEN'&&!d.citizen_visible)return res.status(403).json({error:'This evidence is restricted to authorized officers.'});const plaintext=(d.encryption_algorithm==='aes-256-gcm'&&d.encryption_iv&&d.encryption_auth_tag)?decryptEvidence(Buffer.from(d.file_data),d.encryption_iv,d.encryption_auth_tag):Buffer.from(d.file_data);res.setHeader('Content-Type',d.mime_type||'application/octet-stream');res.setHeader('Content-Disposition',`inline; filename*=UTF-8''${encodeURIComponent(d.file_name)}`);res.setHeader('X-Evidence-SHA256',d.sha256_hash);res.send(plaintext);});
app.post('/api/documents/:id/verify',requireAuth,async(req,res)=>{const d=await db.prepare(`SELECT d.*,c.case_id FROM documents d JOIN cases c ON c.id=d.case_id WHERE d.id=?`).get(req.params.id);if(!d)return res.status(404).json({error:'Evidence not found'});const c=await getCase(d.case_id);if(!(await canViewCase(req.user,c)))return res.status(403).json({error:'You do not have access to this evidence.'});const plaintext=(d.encryption_algorithm==='aes-256-gcm'&&d.encryption_iv&&d.encryption_auth_tag)?decryptEvidence(Buffer.from(d.file_data),d.encryption_iv,d.encryption_auth_tag):Buffer.from(d.file_data);const current=sha256Buffer(plaintext);const valid=current===d.sha256_hash;await timeline(c.id,req.user.id,valid?'DOCUMENT_VERIFIED':'DOCUMENT_TAMPER_DETECTED',`${d.evidence_id} ${valid?'integrity verified':'integrity check failed'}.`,'POLICE_ONLY');await writeAudit({actorId:req.user.id,caseDbId:c.id,action:valid?'DOCUMENT_VERIFIED':'DOCUMENT_TAMPER_DETECTED',entityType:'DOCUMENT',entityId:d.evidence_id,metadata:{storedHash:d.sha256_hash,currentHash:current}});res.json({valid,evidenceId:d.evidence_id,storedHash:d.sha256_hash,currentHash:current});});
app.post('/api/documents/:id/redact',requireAuth,allowRoles('IO','ADMIN'),async(req,res)=>{const d=await db.prepare(`SELECT d.*,c.case_id FROM documents d JOIN cases c ON c.id=d.case_id WHERE d.id=?`).get(req.params.id);if(!d)return res.status(404).json({error:'Evidence not found'});const c=await getCase(d.case_id);if(!canEditCase(req.user,c))return res.status(403).json({error:'You cannot redact this evidence.'});let text='';const plaintext=(d.encryption_algorithm==='aes-256-gcm'&&d.encryption_iv&&d.encryption_auth_tag)?decryptEvidence(Buffer.from(d.file_data),d.encryption_iv,d.encryption_auth_tag):Buffer.from(d.file_data);if(d.mime_type==='text/plain')text=plaintext.toString('utf8');else text=`[Preview unavailable for ${d.mime_type}. Evidence ${d.evidence_id} is stored securely in the database.]`;const redacted=text.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi,'[EMAIL REDACTED]').replace(/\b\+?\d[\d\s-]{7,}\d\b/g,'[PHONE REDACTED]');res.json({evidenceId:d.evidence_id,redacted,createdAt:new Date().toISOString()});});

app.post('/api/cases/:caseId/completion-request',requireAuth,allowRoles('POLICE'),async(req,res)=>{
  const c=await assertCase(req,res,req.params.caseId);if(!c||res.headersSent)return;
  if(req.user.id!==c.created_by)return res.status(403).json({error:'Only the Police Station Officer who created this FIR can request case closure.'});
  if(c.current_status==='CASE_CLOSED')return res.status(400).json({error:'This case is already closed.'});
  if(c.progress_percent<100)return res.status(400).json({error:'Set case progress to 100% before requesting case closure.'});
  const existing=await db.prepare("SELECT id,status FROM completion_requests WHERE case_id=? ORDER BY id DESC LIMIT 1").get(c.id);
  if(existing?.status==='PENDING')return res.status(409).json({error:'A case closure request is already waiting for citizen approval.'});
  const msg=z.object({message:z.string().min(5).optional()}).parse(req.body||{}).message||`The investigation for ${c.case_id} is complete. Please review the case and approve closure if you agree.`;
  const r=await db.prepare('INSERT INTO completion_requests(case_id,sent_by,citizen_id,message,status) VALUES(?,?,?,?,?)').run(c.id,req.user.id,c.citizen_id,msg,'PENDING');
  await notify(c.citizen_id,c.id,'COMPLETION_REQUEST','Case closure request',msg);
  await timeline(c.id,req.user.id,'CASE_CLOSURE_REQUESTED','Police Station Officer requested case closure. Waiting for citizen approval.','CITIZEN_VISIBLE');
  await writeAudit({actorId:req.user.id,caseDbId:c.id,action:'CASE_CLOSURE_REQUESTED',entityType:'COMPLETION_REQUEST',entityId:r.lastInsertRowid});
  res.status(201).json({success:true,requestId:Number(r.lastInsertRowid)});
});

app.post('/api/completion-requests/:id/respond',requireAuth,allowRoles('CITIZEN'),async(req,res)=>{
  const p=z.object({decision:z.enum(['APPROVE','REJECT'])}).safeParse(req.body||{});
  if(!p.success)return res.status(400).json({error:'Choose Approve or Reject.'});
  const r=await db.prepare('SELECT * FROM completion_requests WHERE id=? AND citizen_id=?').get(req.params.id,req.user.id);
  if(!r)return res.status(404).json({error:'Completion request not found'});
  if(r.status!=='PENDING')return res.status(409).json({error:'This closure request has already been answered.'});
  const c=await getCase(r.case_id);if(!c)return res.status(404).json({error:'Case not found'});
  const approve=p.data.decision==='APPROVE';
  const police=await db.prepare('SELECT id FROM users WHERE id=?').get(c.created_by)?.id||null;
  const tx=await db.transaction(async()=>{
    await db.prepare("UPDATE completion_requests SET status=?,responded_at=CURRENT_TIMESTAMP WHERE id=?").run(approve?'APPROVED':'REJECTED',r.id);
    if(approve){
      await db.prepare("UPDATE cases SET progress_percent=100,current_status='CASE_CLOSED',completed_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(c.id);
      await db.prepare("UPDATE firs SET status='CASE_CLOSED',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(c.fir_id);
      await timeline(c.id,req.user.id,'CASE_CLOSED','Citizen approved the closure request. Case is now closed.','CITIZEN_VISIBLE');
      if(police)await notify(police,c.id,'CASE_CLOSED','Case closed by citizen approval',`Case ${c.case_id} has been closed after the citizen approved the closure request.`);
      if(c.assigned_io_id)await notify(c.assigned_io_id,c.id,'CASE_CLOSED','Case closed by citizen approval',`Case ${c.case_id} has been closed after citizen approval.`);
      await writeAudit({actorId:req.user.id,caseDbId:c.id,action:'CASE_CLOSED_BY_CITIZEN',entityType:'CASE',entityId:c.case_id});
    }else{
      await timeline(c.id,req.user.id,'CASE_CLOSURE_REJECTED','Citizen rejected the case closure request. Case remains open.','CITIZEN_VISIBLE');
      if(police)await notify(police,c.id,'CASE_CLOSURE_REJECTED','Case closure rejected',`The citizen rejected closure of case ${c.case_id}. The case remains open.`);
      await writeAudit({actorId:req.user.id,caseDbId:c.id,action:'CASE_CLOSURE_REJECTED',entityType:'COMPLETION_REQUEST',entityId:r.id});
    }
  });
  res.json({success:true,decision:p.data.decision,caseClosed:approve});
});


app.get('/api/notifications',requireAuth,async(req,res)=>res.json({notifications:await db.prepare('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC').all(req.user.id)}));
app.patch('/api/notifications/:id/read',requireAuth,async(req,res)=>{await db.prepare('UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?').run(req.params.id,req.user.id);res.json({success:true});});

app.get('/api/cases/:caseId/important-dates',requireAuth,async(req,res)=>{const c=await assertCase(req,res,req.params.caseId);if(!c||res.headersSent)return;res.json({importantDates:await db.prepare('SELECT * FROM case_important_dates WHERE case_id=? ORDER BY date_value ASC').all(c.id)});});
app.post('/api/cases/:caseId/important-dates',requireAuth,allowRoles('POLICE','IO','ADMIN'),async(req,res)=>{const c=await assertCase(req,res,req.params.caseId);if(!c||res.headersSent)return;if(!canEditCase(req.user,c))return res.status(403).json({error:'You cannot update important dates.'});const p=z.object({label:z.string().min(2),dateValue:z.string().min(4),notes:z.string().optional()}).safeParse(req.body);if(!p.success)return res.status(400).json({error:'Label and date are required'});const r=await db.prepare('INSERT INTO case_important_dates(case_id,label,date_value,notes,created_by) VALUES(?,?,?,?,?)').run(c.id,p.data.label,p.data.dateValue,p.data.notes||'',req.user.id);await timeline(c.id,req.user.id,'IMPORTANT_DATE_ADDED',`${p.data.label}: ${p.data.dateValue}`,'POLICE_ONLY');await writeAudit({actorId:req.user.id,caseDbId:c.id,action:'IMPORTANT_DATE_ADDED',entityType:'IMPORTANT_DATE',entityId:r.lastInsertRowid,metadata:p.data});res.status(201).json({success:true});});

app.get('/api/cases/:caseId/lawyers',requireAuth,async(req,res)=>{const c=await assertCase(req,res,req.params.caseId);if(!c||res.headersSent)return;res.json({lawyers:await db.prepare('SELECT * FROM case_lawyers WHERE case_id=? ORDER BY started_at DESC,id DESC').all(c.id)});});
app.post('/api/cases/:caseId/lawyers',requireAuth,allowRoles('POLICE','ADMIN'),async(req,res)=>{const c=await assertCase(req,res,req.params.caseId);if(!c||res.headersSent)return;if(!canEditCase(req.user,c))return res.status(403).json({error:'You cannot update lawyer details.'});const p=z.object({lawyerName:z.string().min(2),barRegistration:z.string().optional(),phone:z.string().optional(),email:z.string().email().optional(),startedAt:z.string().min(4),endedAt:z.string().optional(),notes:z.string().optional()}).safeParse(req.body);if(!p.success)return res.status(400).json({error:'Lawyer name and start date are required'});await db.prepare('UPDATE case_lawyers SET is_current=0,ended_at=COALESCE(ended_at,?) WHERE case_id=? AND is_current=1').run(p.data.startedAt,c.id);const r=await db.prepare('INSERT INTO case_lawyers(case_id,lawyer_name,bar_registration,phone,email,started_at,ended_at,is_current,notes,created_by) VALUES(?,?,?,?,?,?,?,1,?,?)').run(c.id,p.data.lawyerName,p.data.barRegistration||'',p.data.phone||'',p.data.email||'',p.data.startedAt,p.data.endedAt||null,p.data.notes||'',req.user.id);await timeline(c.id,req.user.id,'LAWYER_UPDATED',`Current lawyer set to ${p.data.lawyerName}.`,'POLICE_ONLY');await writeAudit({actorId:req.user.id,caseDbId:c.id,action:'LAWYER_UPDATED',entityType:'CASE_LAWYER',entityId:r.lastInsertRowid,metadata:{lawyerName:p.data.lawyerName}});res.status(201).json({success:true});});

app.get('/api/cases/:caseId/proceedings',requireAuth,async(req,res)=>{const c=await assertCase(req,res,req.params.caseId);if(!c||res.headersSent)return;res.json({proceedings:await db.prepare('SELECT * FROM court_proceedings WHERE case_id=? ORDER BY proceeding_date DESC,id DESC').all(c.id)});});
app.post('/api/cases/:caseId/proceedings',requireAuth,allowRoles('POLICE','ADMIN'),async(req,res)=>{const c=await assertCase(req,res,req.params.caseId);if(!c||res.headersSent)return;if(!canEditCase(req.user,c))return res.status(403).json({error:'You cannot update court proceedings.'});const p=z.object({proceedingDate:z.string().min(4),courtName:z.string().min(2),stage:z.string().min(2),outcome:z.string().optional(),nextHearingDate:z.string().optional(),notes:z.string().optional()}).safeParse(req.body);if(!p.success)return res.status(400).json({error:'Court, date and stage are required'});const id=nextNo('CP','court_proceedings');const r=await db.prepare('INSERT INTO court_proceedings(proceeding_id,case_id,proceeding_date,court_name,stage,outcome,next_hearing_date,notes,created_by) VALUES(?,?,?,?,?,?,?,?,?)').run(id,c.id,p.data.proceedingDate,p.data.courtName,p.data.stage,p.data.outcome||'',p.data.nextHearingDate||'',p.data.notes||'',req.user.id);await timeline(c.id,req.user.id,'COURT_PROCEEDING_ADDED',`Court proceeding ${id} recorded.`,'POLICE_ONLY');await writeAudit({actorId:req.user.id,caseDbId:c.id,action:'COURT_PROCEEDING_ADDED',entityType:'COURT_PROCEEDING',entityId:id});res.status(201).json({success:true,proceedingId:id});});

app.get('/api/admin/officers',requireAuth,allowRoles('ADMIN'),async(_req,res)=>{
  const officers=await db.prepare(`SELECT u.id,u.username,u.name,u.email,u.phone,u.role,u.police_station_id,u.verified,u.verified_at,ps.name station_name
    FROM users u LEFT JOIN police_stations ps ON ps.id=u.police_station_id
    WHERE u.role IN ('POLICE','IO','FORENSIC') ORDER BY u.verified ASC,u.name ASC`).all();
  res.json({officers});
});

app.post('/api/admin/officers',requireAuth,allowRoles('ADMIN'),async(req,res)=>{
  const p=z.object({
    name:z.string().trim().min(2,'Officer name must be at least 2 characters.'),
    email:z.string().trim().email('Enter a valid officer email.'),
    phone:z.string().trim().max(30).optional().default(''),
    role:z.enum(['POLICE','IO','FORENSIC']),
    policeStationId:z.coerce.number().int().positive(),
    username:z.string().trim().min(3,'Username must be at least 3 characters.').regex(/^[a-zA-Z0-9._-]+$/,'Username can contain letters, numbers, dot, underscore and hyphen only.'),
    password:z.string().min(8,'Password must be at least 8 characters.').regex(/[A-Z]/,'Password must contain at least one uppercase letter.').regex(/[a-z]/,'Password must contain at least one lowercase letter.').regex(/[0-9]/,'Password must contain at least one number.').regex(/[^A-Za-z0-9]/,'Password must contain at least one special character.')
  }).safeParse(req.body);
  if(!p.success)return res.status(400).json({error:p.error.issues.map(i=>i.message).join('; ')});
  if(await db.prepare('SELECT 1 FROM users WHERE lower(email)=lower(?) OR lower(username)=lower(?)').get(p.data.email,p.data.username))return res.status(409).json({error:'An account with this email or username already exists.'});
  const username=p.data.username;
  const info=await db.prepare(`INSERT INTO users(username,name,email,phone,password_hash,role,police_station_id,verified,verified_at,verified_by) VALUES(?,?,?,?,?,?,?,?,?,?)`).run(username,p.data.name,p.data.email,p.data.phone||'',hashPassword(p.data.password),p.data.role,p.data.policeStationId,0,null,null);
  await writeAudit({actorId:req.user.id,action:'OFFICER_ACCOUNT_CREATED',entityType:'USER',entityId:info.lastInsertRowid,metadata:{name:p.data.name,email:p.data.email,role:p.data.role,policeStationId:p.data.policeStationId}});
  res.status(201).json({success:true,officerId:Number(info.lastInsertRowid),username,pendingVerification:true});
});

app.patch('/api/admin/officers/:id/verify',requireAuth,allowRoles('ADMIN'),async(req,res)=>{
  const p=z.object({verified:z.boolean().default(true)}).safeParse(req.body||{});
  if(!p.success)return res.status(400).json({error:'verified must be true or false'});
  const officer=await db.prepare("SELECT id,name,email,role FROM users WHERE id=? AND role IN ('POLICE','IO','FORENSIC')").get(req.params.id);
  if(!officer)return res.status(404).json({error:'Officer not found'});
  if(p.data.verified){
    await db.prepare('UPDATE users SET verified=1,verified_at=CURRENT_TIMESTAMP,verified_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(req.user.id,officer.id);
    await writeAudit({actorId:req.user.id,action:'OFFICER_VERIFIED',entityType:'USER',entityId:officer.id,metadata:{email:officer.email,role:officer.role}});
    await notify(officer.id,null,'OFFICER_VERIFIED','Officer account verified','Your SecureDocs officer account has been verified by Admin. You can now sign in and receive case access.');
  }else{
    await db.prepare('UPDATE users SET verified=0,verified_at=NULL,verified_by=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(officer.id);
    await writeAudit({actorId:req.user.id,action:'OFFICER_UNVERIFIED',entityType:'USER',entityId:officer.id,metadata:{email:officer.email,role:officer.role}});
  }
  res.json({success:true,verified:p.data.verified});
});

app.get('/api/admin/summary',requireAuth,allowRoles('ADMIN'),async(_req,res)=>{
  res.json({users:(await db.prepare('SELECT COUNT(*) n FROM users').get()).n,pendingOfficers:(await db.prepare("SELECT COUNT(*) n FROM users WHERE role IN ('POLICE','IO','FORENSIC') AND verified=0").get()).n,citizens:(await db.prepare("SELECT COUNT(*) n FROM users WHERE role='CITIZEN'").get()).n,police:(await db.prepare("SELECT COUNT(*) n FROM users WHERE role='POLICE'").get()).n,ios:(await db.prepare("SELECT COUNT(*) n FROM users WHERE role='IO'").get()).n,forensics:(await db.prepare("SELECT COUNT(*) n FROM users WHERE role='FORENSIC'").get()).n,stations:(await db.prepare('SELECT COUNT(*) n FROM police_stations').get()).n,firs:(await db.prepare('SELECT COUNT(*) n FROM firs').get()).n,cases:(await db.prepare('SELECT COUNT(*) n FROM cases').get()).n,documents:(await db.prepare('SELECT COUNT(*) n FROM documents').get()).n,proceedings:(await db.prepare('SELECT COUNT(*) n FROM court_proceedings').get()).n,audit:(await db.prepare('SELECT COUNT(*) n FROM audit_logs').get()).n});
});

app.get('/api/audit',requireAuth,allowRoles('ADMIN'),async(req,res)=>{let rows=await db.prepare(`SELECT a.*,u.name actor_name,u.role actor_role,c.case_id FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id LEFT JOIN cases c ON c.id=a.case_id ORDER BY a.id DESC LIMIT 300`).all();if(req.user.role==='POLICE'){const filtered=[];for(const r of rows){if(!r.case_id){filtered.push(r);continue;}const c=await getCase(r.case_id);if(c?.police_station_id===req.user.police_station_id)filtered.push(r);}rows=filtered;}if(req.user.role==='IO'){const filtered=[];for(const r of rows){if(!r.case_id){filtered.push(r);continue;}const c=await getCase(r.case_id);if(await canViewCase(req.user,c))filtered.push(r);}rows=filtered;}res.json({audit:rows});});
app.get('/api/audit/verify-chain',requireAuth,allowRoles('ADMIN'),async(_req,res)=>res.json(await verifyAuditChain()));

const ALLOWED_STATIONS=['Gachibowli','Bachupally','Madhapur','Kondapur','Hitech city','Kokapet','Jubilee Hills','Banjara Hills','Narsingi','Manikonda','Somajiguda','Begumpet','Ameerpet','Secunderabad','Himayatnagar','Kukatpally','Miyapur','Kompally','Dilsukhnagar','Uppal'];
app.get('/api/police-stations',requireAuth,async(req,res)=>{if(req.user.role==='CITIZEN')return res.json({stations:[]});const marks=ALLOWED_STATIONS.map(()=>'?').join(',');const stations=await db.prepare(`SELECT * FROM police_stations WHERE name IN (${marks}) ORDER BY name`).all(...ALLOWED_STATIONS);res.json({stations});});

app.use((err,_req,res,_next)=>{console.error(err);if(err instanceof multer.MulterError)return res.status(400).json({error:err.code==='LIMIT_FILE_SIZE'?'File is too large.':'Upload failed.'});
  if(err) return res.status(400).json({error:err.message||'Upload failed.'});res.status(500).json({error:'Server error. Please try again.'});});

export default app;

if (!process.env.VERCEL) app.listen(PORT,()=>console.log(`Vajrion backend listening on http://localhost:${PORT}`));
