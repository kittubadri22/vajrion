import { verifyToken } from './security.js';
import { db } from './db.js';

export async function requireAuth(req, res, next) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return res.status(401).json({ error: 'Authentication required' });
  try {
    const p = verifyToken(h.slice(7));
    const user = await db.prepare('SELECT id,username,name,email,phone,role,police_station_id,verified,verified_at FROM users WHERE id=?').get(p.sub);
    if (!user) return res.status(401).json({ error: 'Session is no longer valid' });
    if (['POLICE', 'IO', 'FORENSIC'].includes(user.role) && user.verified !== 1) {
      return res.status(403).json({ error: 'Your officer account is awaiting Admin verification.' });
    }
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Session expired. Please sign in again.' });
  }
}

export function allowRoles(...roles) {
  return (req, res, next) => roles.includes(req.user.role)
    ? next()
    : res.status(403).json({ error: 'This action is not available for your role.' });
}

export async function getCase(caseRef) {
  return db.prepare(`SELECT c.*,f.fir_number,f.citizen_id,f.police_station_id,f.created_by,f.incident_type,f.incident_date,f.incident_time,f.incident_location,f.description,f.submitted_at,f.status AS fir_status,u.name citizen_name,u.email citizen_email,u.phone citizen_phone,ps.name station_name,ps.address station_address,io.name io_name,io.email io_email FROM cases c JOIN firs f ON f.id=c.fir_id JOIN users u ON u.id=f.citizen_id JOIN police_stations ps ON ps.id=f.police_station_id LEFT JOIN users io ON io.id=c.assigned_io_id WHERE c.case_id=? OR c.id=?`).get(caseRef, Number(caseRef) || -1);
}

export async function canViewCase(user, c) {
  if (!c) return false;
  if (user.role === 'ADMIN' || user.role === 'COMMISSIONER') return true;
  if (user.role === 'CITIZEN') return user.id === c.citizen_id;
  if (user.role === 'POLICE') return user.police_station_id === c.police_station_id;
  if (user.role === 'IO') {
    if (user.id === c.assigned_io_id) return true;
    return !!(await db.prepare('SELECT 1 FROM case_officer_access WHERE case_id=? AND officer_id=? AND revoked_at IS NULL').get(c.id, user.id));
  }
  if (user.role === 'FORENSIC') return !!(await db.prepare('SELECT 1 FROM case_officer_access WHERE case_id=? AND officer_id=? AND revoked_at IS NULL').get(c.id, user.id));
  return false;
}

export function canEditCase(user, c) {
  if (c?.current_status === 'CASE_CLOSED') return false;
  if (user.role === 'ADMIN') return true;
  if (user.role === 'POLICE') return user.police_station_id === c.police_station_id;
  if (user.role === 'IO') return user.id === c.assigned_io_id;
  return false;
}

export async function canUploadEvidence(user, c) {
  if (user.role === 'ADMIN') return true;
  if (user.role === 'IO') return user.id === c.assigned_io_id;
  if (user.role === 'FORENSIC') return canViewCase(user, c);
  return false;
}

export function canGrantAccess(user, c) {
  if (user.role === 'ADMIN') return true;
  if (user.role === 'IO') return user.id === c.assigned_io_id;
  if (user.role === 'POLICE') return user.police_station_id === c.police_station_id;
  return false;
}
