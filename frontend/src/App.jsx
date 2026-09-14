import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ShieldCheck, UserRound, Building2, FileText, Clock3, CheckCircle2, AlertTriangle,
  Search, Plus, LogOut, RefreshCw, ChevronRight, Upload, Eye, ShieldAlert,
  UsersRound, Bell, Gavel, CalendarDays, Scale, Link2, UserPlus, Trash2,
  X, Download, FileCheck2, CircleUserRound, BarChart3, UserCheck, Lock
} from 'lucide-react';

const API = (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '');
const STATUS_OPTIONS = [
  ['FIR_REGISTERED', 'FIR Registered'],
  ['INVESTIGATION_NOT_STARTED', 'Investigation Not Started'],
  ['INVESTIGATION_IN_PROGRESS', 'Investigation In Progress'],
  ['EVIDENCE_COLLECTION', 'Evidence Collection'],
  ['SUSPECT_IDENTIFIED', 'Suspect Identified'],
  ['CHARGE_SHEET_PREPARATION', 'Charge Sheet Preparation'],
  ['INVESTIGATION_COMPLETED', 'Investigation Completed'],
  ['CASE_CLOSED', 'Case Closed'],
];


function App() {
  const [token, setToken] = useState(() => localStorage.getItem('securedocs_token'));
  const [user, setUser] = useState(() => safeJson(localStorage.getItem('securedocs_user')));
  const [login, setLogin] = useState({ identifier: '', password: '' });
  const [showSignup, setShowSignup] = useState(false);
  const [view, setView] = useState('dashboard');
  const [cases, setCases] = useState([]);
  const [stats, setStats] = useState({ total: 0, active: 0, completed: 0, documents: 0, notifications: 0 });
  const [notifications, setNotifications] = useState([]);
  const [selectedCase, setSelectedCase] = useState(null);
  const [selectedEvidence, setSelectedEvidence] = useState(null);
  const [notice, setNotice] = useState(null);
  const [busy, setBusy] = useState(false);
  const [search, setSearch] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const notify = useCallback((message, type = 'success') => {
    setNotice({ message, type });
    window.setTimeout(() => setNotice(null), 3500);
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('securedocs_token');
    localStorage.removeItem('securedocs_user');
    setToken(null); setUser(null); setCases([]); setSelectedCase(null); setView('dashboard');
  }, []);

  const request = useCallback(async (path, options = {}) => {
    const headers = new Headers(options.headers || {});
    if (token) headers.set('Authorization', `Bearer ${token}`);
    if (!(options.body instanceof FormData) && options.body !== undefined) headers.set('Content-Type', 'application/json');
    const res = await fetch(`${API}${path}`, { ...options, headers });
    const raw = await res.text();
    let data = {};
    try { data = raw ? JSON.parse(raw) : {}; } catch { data = { raw }; }
    if (res.status === 401) { logout(); throw new Error('Your session expired. Please sign in again.'); }
    if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
    return data;
  }, [token, logout]);
  const requestBlob = useCallback(async (path) => {
    const headers = new Headers();
    if (token) headers.set('Authorization', `Bearer ${token}`);
    const res = await fetch(`${API}${path}`, { headers });
    if (res.status === 401) { logout(); throw new Error('Your session expired. Please sign in again.'); }
    if (!res.ok) { let message = `Request failed (${res.status})`; try { const data = await res.json(); message = data.error || message; } catch {} throw new Error(message); }
    return res.blob();
  }, [token, logout]);

  const load = useCallback(async () => {
    if (!token) return;
    setBusy(true);
    try {
      const [cs, st, ns] = await Promise.all([
        request('/firs'), request('/dashboard/stats'), request('/notifications')
      ]);
      setCases(cs.firs || []); setStats(st || {}); setNotifications(ns.notifications || []);
    } catch (e) { notify(e.message, 'error'); }
    finally { setBusy(false); }
  }, [token, request, notify]);

  useEffect(() => { load(); }, [load]);

  // Keep dashboards synchronized when another authorized user creates or updates a case.
  useEffect(() => {
    if (!token) return;
    const timer = setInterval(() => { load(); }, 8000);
    return () => clearInterval(timer);
  }, [token, load]);

  const loginNow = async (e) => {
    e.preventDefault(); setBusy(true);
    try {
      const res = await fetch(`${API}/auth/login`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(login) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Login failed');
      localStorage.setItem('securedocs_token', data.token);
      localStorage.setItem('securedocs_user', JSON.stringify(data.user));
      setToken(data.token); setUser(data.user); setView('dashboard');
      notify('Signed in successfully');
    } catch (e) { notify(e.message, 'error'); }
    finally { setBusy(false); }
  };

  const openCase = async (caseId) => {
    setBusy(true);
    try { const data = await request(`/cases/${caseId}`); setSelectedCase(data); }
    catch (e) { notify(e.message, 'error'); }
    finally { setBusy(false); }
  };

  const markRead = async (id) => { try { await request(`/notifications/${id}/read`, { method:'PATCH' }); load(); } catch(e) { notify(e.message,'error'); } };

  const filteredCases = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return cases;
    return cases.filter(c => [c.fir_number,c.case_id,c.citizen_name,c.citizen_email,c.incident_type,c.current_status].some(v => String(v||'').toLowerCase().includes(q)));
  }, [cases, search]);

  if (!token) return showSignup ? <SignupPage onBack={()=>setShowSignup(false)} onCreated={(identifier)=>{setShowSignup(false);setLogin({identifier,password:''});notify('Account created. You can now sign in.');}} busy={busy} setBusy={setBusy} /> : <LoginPage login={login} setLogin={setLogin} loginNow={loginNow} busy={busy} notify={notice} onSignup={()=>setShowSignup(true)} />;

  const role = user?.role || 'CITIZEN';
  const roleLabel = role === 'POLICE' ? 'Police Station Officer' : role === 'IO' ? 'Investigation Officer' : role === 'FORENSIC' ? 'Forensic Officer' : role === 'COMMISSIONER' ? 'Commissioner / DGP' : role === 'ADMIN' ? 'Administrator' : 'Citizen';

  return <div className="app-shell">
    <header className="topbar">
      <div className="brand">
        <div className="brand-icon"><img src="/vajrion-logo.jpeg" alt="Vajrion logo" /></div>
        <div><div className="brand-title">Vajrion</div><div className="brand-subtitle">FIR, Case & Digital Evidence Management</div></div>
      </div>
      <div className="topbar-right">
        <div className="live"><span/> Backend Connected</div>
        <div className="user-pill"><CircleUserRound size={16}/><span>{user?.name}</span><em>{roleLabel}</em></div>
        <button className="soft-btn" title="Refresh" onClick={load} disabled={busy}><RefreshCw size={17}/></button>
        <button className="logout-btn" onClick={logout}><LogOut size={16}/> Sign out</button>
      </div>
    </header>

    <div className="layout">
      <Sidebar role={role} view={view} setView={setView} notifications={stats.notifications || 0} user={user} onPassword={()=>setShowPassword(true)}/>
      <main className="content">
        {notice && <Toast notice={notice}/>} 
        <PageHeader roleLabel={roleLabel} role={role}/>
        {view === 'dashboard' && <Dashboard role={role} stats={stats} cases={filteredCases} search={search} setSearch={setSearch} openCase={openCase} />}
        {view === 'cases' && <CaseList cases={filteredCases} search={search} setSearch={setSearch} openCase={openCase} role={role}/>} 
        {view === 'create-fir' && (role === 'POLICE' || role === 'ADMIN') && <CreateFIR request={request} notify={notify} busy={busy} user={user} onDone={async()=>{setView('cases');await load();}}/>}
        {view === 'notifications' && <Notifications items={notifications} markRead={markRead} openCase={openCase}/>} 
        {view === 'audit' && role === 'ADMIN' && <Audit request={request} notify={notify}/>} 
        {view === 'admin' && role === 'ADMIN' && <AdminSummary request={request} notify={notify}/>} 
        {view === 'dashboard' && role === 'IO' && <div className="dashboard-extra"><AccessHint text="Open a case and use Officer Access to grant a verified Investigation Officer from your station access by email."/></div>}
      </main>
    </div>

    {selectedCase && <CaseModal data={selectedCase} user={user} role={role} request={request} requestBlob={requestBlob} notify={notify} onClose={()=>setSelectedCase(null)} onRefresh={()=>openCase(selectedCase.case.case_id)} onEvidence={setSelectedEvidence}/>} 
    {selectedEvidence && <EvidenceModal data={selectedEvidence} onClose={()=>setSelectedEvidence(null)} />}
    {showPassword && <ChangePasswordModal request={request} notify={notify} onClose={()=>setShowPassword(false)} onChanged={()=>{setShowPassword(false);logout();}} />}
  </div>;
}

function Sidebar({ role, view, setView, notifications, user, onPassword }) {
  const items = [
    ['dashboard','Dashboard',BarChart3], ['cases', role==='CITIZEN'?'My Cases':'All Cases',FileText],
    ...(role==='POLICE'||role==='ADMIN' ? [['create-fir','Create FIR',Plus]] : []),
    ['notifications','Notifications',Bell],
    ...(role==='ADMIN' ? [['audit','Audit Ledger',Link2]] : []),
    ...(role==='ADMIN' ? [['admin','Admin Overview',ShieldCheck]] : []),
  ];
  const designation = role==='POLICE' ? 'Police Station Officer' : role==='IO' ? 'Investigation Officer' : role==='FORENSIC' ? 'Forensic Officer' : role==='COMMISSIONER' ? 'Commissioner / DGP' : role==='ADMIN' ? 'Administrator' : null;
  return <aside className="sidebar">
    <div className="sidebar-section"><div className="section-caption">WORKSPACE</div>{items.map(([id,label,Icon])=><button key={id} onClick={()=>setView(id)} className={view===id?'nav active':'nav'}><Icon size={18}/><span>{label}</span>{id==='notifications'&&notifications>0&&<b>{notifications}</b>}</button>)}</div>
    <div className="sidebar-card"><div className="mini-shield"><ShieldCheck size={18}/></div><strong>Vajrion Security</strong><span>JWT access control, case-level permissions and SHA-256 evidence verification.</span></div>
    <div className="sidebar-profile"><div className="profile-avatar"><CircleUserRound size={18}/></div><div className="profile-info"><strong>{user?.name || 'User'}</strong>{designation && <><span>{designation}</span><small>{user?.area || user?.station_name || '—'}</small></>}</div></div>{role==='CITIZEN'&&<button className="profile-action" onClick={onPassword}><Lock size={14}/> Change password</button>}
    <div className="sidebar-foot">Local prototype · SIH Vajrion</div>
  </aside>;
}

function PageHeader({roleLabel,role}){ return <div className="page-header"><div><div className="crumb">VAJRION / {role}</div><h1>{roleLabel} Dashboard</h1><p>Manage FIRs, case progress, timelines, evidence and controlled access.</p></div><div className="header-status"><ShieldCheck size={16}/><span>Protected workspace</span></div></div>; }

function Dashboard({role,stats,cases,search,setSearch,openCase}){ const actionCases=cases.filter(c=>Number(c.action_required)===1); return <>
  {role==='COMMISSIONER'&&<div className="panel action-required-panel"><div className="panel-head"><div><h2>Action Required</h2><p>Cases with no recorded progress update for 15 days or more.</p></div><AlertTriangle size={20}/></div>{!actionCases.length?<EmptyState text="No cases require immediate action."/>:<div className="action-required-list">{actionCases.slice(0,8).map(c=><button key={c.case_id} className="action-required-row" onClick={()=>openCase(c.case_id)}><div><strong>{c.case_id}</strong><span>{c.fir_number} · {c.station_name} · Last progress {formatDate(c.last_progress_at)}</span></div><em>ACTION REQUIRED</em><ChevronRight size={17}/></button>)}</div>}</div>}
  <div className="metrics">
    <Metric icon={FileText} label={role==='CITIZEN'?'My FIRs':'Total Cases'} value={stats.total||0}/>
    <Metric icon={Clock3} label="Active Cases" value={stats.active||0}/>
    <Metric icon={CheckCircle2} label="Completed" value={stats.completed||0}/>
    <Metric icon={FileCheck2} label="Evidence Records" value={stats.documents||0}/>
  </div>
  <div className="panel">
    <div className="panel-head"><div><h2>{role==='CITIZEN'?'My Cases':'Recent Cases'}</h2><p>Live data from the Vajrion database.</p></div><SearchBox value={search} onChange={setSearch}/></div>
    <CaseTable rows={cases.slice(0,8)} openCase={openCase} role={role}/>
  </div>
</>; }
function CaseList({cases,search,setSearch,openCase,role}){ return <div className="panel"><div className="panel-head"><div><h2>{role==='CITIZEN'?'My Cases':'Case Registry'}</h2><p>Search FIR number, Case ID, citizen, incident type or status.</p></div><SearchBox value={search} onChange={setSearch}/></div><CaseTable rows={cases} openCase={openCase} role={role}/></div>; }
function CaseTable({rows,openCase,role}){ if(!rows.length)return <EmptyState text={role==='CITIZEN'?'No FIRs have been linked to this account yet.':'No cases found.'}/>; return <div className="table-wrap"><table><thead><tr><th>Case</th><th>Citizen</th><th>Police Station</th><th>Status</th><th>Progress</th><th>Registration</th><th/></tr></thead><tbody>{rows.map(c=><tr key={c.case_id}><td><strong className="case-id">{c.case_id}</strong><span className="cell-secondary">{c.fir_number}</span></td><td>{c.citizen_name||'Private to citizen'}<span className="cell-secondary">{c.incident_type||''}</span></td><td>{c.station_name}</td><td><StatusBadge status={c.current_status||c.status}/></td><td><Progress value={c.progress_percent||0}/></td><td>{formatDate(c.case_registration_date||c.submitted_at)}</td><td><button className="outline-btn" onClick={()=>openCase(c.case_id)}>View <ChevronRight size={14}/></button></td></tr>)}</tbody></table></div>; }
function SearchBox({value,onChange}){ return <div className="search-box"><Search size={16}/><input value={value} onChange={e=>onChange(e.target.value)} placeholder="Search cases..."/></div>; }
function Metric({icon:Icon,label,value}){return <div className="metric"><div className="metric-icon"><Icon size={18}/></div><div><span>{label}</span><strong>{value}</strong></div></div>;}
function StatusBadge({status}){const label=String(status||'').replaceAll('_',' ');return <span className={`status ${String(status).includes('COMPLETED')||status==='CASE_CLOSED'?'good':''}`}>{label}</span>}
function Progress({value}){return <div className="progress"><div className="progress-track"><div style={{width:`${Math.min(100,Math.max(0,value))}%`}}/></div><span>{value}%</span></div>}
function EmptyState({text}){return <div className="empty"><FileText size={24}/><strong>{text}</strong></div>}
function AccessHint({text}){return <div className="hint"><UserPlus size={18}/><span>{text}</span></div>}

function CreateFIR({request,notify,busy,onDone,user}){
  const [stations,setStations]=useState([]); const [form,setForm]=useState({citizenName:'',citizenEmail:'',citizenPhone:'',incidentType:'',incidentDate:new Date().toISOString().slice(0,10),incidentTime:'',incidentLocation:'',description:'',policeStationId:user?.police_station_id?String(user.police_station_id):''});
  useEffect(()=>{request('/police-stations').then(d=>setStations(d.stations||[])).catch(e=>notify(e.message,'error'));},[request,notify]);
  useEffect(()=>{if(user?.role==='POLICE'&&user.police_station_id)setForm(f=>({...f,policeStationId:String(user.police_station_id)}));},[user]);
  const change=(k,v)=>setForm(f=>({...f,[k]:v}));
  const submit=async e=>{e.preventDefault();try{const r=await request('/firs',{method:'POST',body:JSON.stringify(form)});const access=r.citizenAccess;const msg=access?.temporaryPassword?`FIR ${r.firNo} created. Citizen access enabled for ${access.email}. Temporary password: ${access.temporaryPassword}`:`FIR ${r.firNo} created. Citizen access is linked to ${access?.email||form.citizenEmail}.`;notify(msg,'info');onDone(r);}catch(e){notify(e.message,'error');}};
  return <div className="panel form-panel"><div className="panel-head"><div><h2>Register New FIR</h2><p>Enter citizen and incident information. The citizen is linked to the FIR by email; a default FIR copy is created for the case.</p></div><FileText size={22}/></div><form className="form-grid" onSubmit={submit}>
    <Field label="Citizen name" value={form.citizenName} onChange={v=>change('citizenName',v)} required/><Field label="Citizen email" type="email" value={form.citizenEmail} onChange={v=>change('citizenEmail',v)} required/><Field label="Citizen phone (optional)" value={form.citizenPhone} onChange={v=>change('citizenPhone',v)}/>
    {user?.role==='POLICE' ? <label className="field-label">Police station<input value={stations.find(s=>String(s.id)===String(form.policeStationId))?.name || user?.station_name || user?.area || ''} readOnly /></label> : <Select label="Police station" value={form.policeStationId} onChange={v=>change('policeStationId',v)} options={stations.map(s=>[s.id,s.name])} required/>}
    <Field label="Incident type" value={form.incidentType} onChange={v=>change('incidentType',v)} required/><Field label="Incident date" type="date" value={form.incidentDate} onChange={v=>change('incidentDate',v)} required/><Field label="Incident time" type="time" value={form.incidentTime} onChange={v=>change('incidentTime',v)}/><Field label="Incident location" value={form.incidentLocation} onChange={v=>change('incidentLocation',v)} required/>
        <div className="full"><label className="field-label">Description<textarea value={form.description} onChange={e=>change('description',e.target.value)} rows="5" placeholder="Describe what was reported..." required/></label></div>
    <div className="full form-actions"><button className="primary-btn" disabled={busy}><Plus size={17}/> Create FIR & Case</button><span>FIR copy and audit/timeline data are stored in SQLite.</span></div>
  </form></div>;
}
function Field({label,value,onChange,type='text',required=false}){return <label className="field-label">{label}<input type={type} value={value||''} onChange={e=>onChange(e.target.value)} required={required}/></label>}
function Select({label,value,onChange,options,required=false}){return <label className="field-label">{label}<select value={value||''} onChange={e=>onChange(e.target.value)} required={required}><option value="">Select…</option>{options.map(([v,l])=><option key={v} value={v}>{l}</option>)}</select></label>}

function Notifications({items,markRead,openCase}){return <div className="panel"><div className="panel-head"><div><h2>Notifications</h2><p>Updates and requests linked to your cases.</p></div><Bell size={22}/></div><div className="notification-list">{!items.length?<EmptyState text="No notifications."/>:items.map(n=><div className={`notification ${n.is_read?'read':''}`} key={n.id}><div className="notification-icon"><Bell size={16}/></div><div className="notification-body"><strong>{n.title}</strong><p>{n.message}</p><span>{formatDate(n.created_at)}</span></div><div className="notification-actions">{n.case_id&&<button className="outline-btn" onClick={()=>openCase(n.case_id)}>Open case</button>}{!n.is_read&&<button className="text-btn" onClick={()=>markRead(n.id)}>Mark read</button>}</div></div>)}</div></div>}

function Audit({request,notify}){const [rows,setRows]=useState([]),[status,setStatus]=useState(null);useEffect(()=>{Promise.all([request('/audit'),request('/audit/verify-chain')]).then(([a,v])=>{setRows(a.audit||[]);setStatus(v)}).catch(e=>notify(e.message,'error'));},[request,notify]);return <div className="panel"><div className="panel-head"><div><h2>Audit Ledger</h2><p>Hash-linked activity history for accountable case operations.</p></div><div className={`chain-status ${status?.valid?'ok':'bad'}`}>{status?.valid?<CheckCircle2 size={16}/>:<AlertTriangle size={16}/>} {status?.valid?`Chain verified (${status.count})`:'Chain requires review'}</div></div><div className="audit-list">{rows.map(r=><div className="audit-row" key={r.id}><div className="audit-mark"><Link2 size={15}/></div><div><strong>{r.action.replaceAll('_',' ')}</strong><span>{r.actor_name||'System'} · {r.case_id||'System'} · {formatDate(r.created_at)}</span></div><code>{String(r.current_hash||'').slice(0,18)}…</code></div>)}</div></div>}

function AdminSummary({request,notify}){
  const [stats,setStats]=useState({});
  const [officers,setOfficers]=useState([]);
  const [stations,setStations]=useState([]);
  const [form,setForm]=useState({name:'',email:'',username:'',phone:'',role:'IO',policeStationId:'',password:''});
  const [creating,setCreating]=useState(false);
  const loadAdmin=async()=>{try{const [s,o,ps]=await Promise.all([request('/admin/summary'),request('/admin/officers'),request('/police-stations')]);setStats(s);setOfficers(o.officers||[]);setStations(ps.stations||[]);}catch(e){notify(e.message,'error')}};
  useEffect(()=>{loadAdmin()},[]);
  const createOfficer=async e=>{e.preventDefault();setCreating(true);try{const r=await request('/admin/officers',{method:'POST',body:JSON.stringify(form)});notify(`Officer account created for ${form.email}. Admin verification is required.`);setForm({name:'',email:'',username:'',phone:'',role:'IO',policeStationId:'',password:''});await loadAdmin();}catch(e){notify(e.message,'error')}finally{setCreating(false)}};
  const verify=async(id,verified)=>{try{await request(`/admin/officers/${id}/verify`,{method:'PATCH',body:JSON.stringify({verified})});notify(verified?'Officer verified.':'Officer access revoked.');await loadAdmin();}catch(e){notify(e.message,'error')}};
  return <div>
    <div className="admin-grid"><div className="admin-card"><Building2 size={20}/><strong>{stats.stations||0} police stations</strong><span>Stations represented in the system.</span></div><div className="admin-card"><UsersRound size={20}/><strong>{stats.users||0} users</strong><span>{stats.citizens||0} citizens · {stats.police||0} police · {stats.ios||0} investigation officers · {stats.forensics||0} forensic officers.</span></div><div className="admin-card"><ShieldAlert size={20}/><strong>{stats.documents||0} evidence records</strong><span>Evidence binaries are stored in SQLite with SHA-256 hashes.</span></div><div className="admin-card"><BarChart3 size={20}/><strong>{stats.cases||0} cases</strong><span>{stats.firs||0} FIRs · {stats.proceedings||0} court proceedings · {stats.audit||0} audit events.</span></div></div>
    <div className="panel admin-panel"><div className="panel-head"><div><h2>Register & verify officers</h2><p>New Police, Investigation and Forensic Officer accounts remain locked until an Admin verifies them.</p></div><UserCheck size={20}/></div>
      <form className="admin-officer-form" onSubmit={createOfficer}>
        <input placeholder="Officer full name" value={form.name} onChange={e=>setForm({...form,name:e.target.value})} required/>
        <input type="email" placeholder="Officer email" value={form.email} onChange={e=>setForm({...form,email:e.target.value})} required/>
        <input placeholder="Username" value={form.username} onChange={e=>setForm({...form,username:e.target.value})} required/>
        <input placeholder="Phone (optional)" value={form.phone} onChange={e=>setForm({...form,phone:e.target.value})}/>
        <select value={form.role} onChange={e=>setForm({...form,role:e.target.value})}><option value="IO">Investigation Officer</option><option value="POLICE">Police Station Officer</option><option value="FORENSIC">Forensic Officer</option></select>
        <select value={form.policeStationId} onChange={e=>setForm({...form,policeStationId:e.target.value})} required><option value="">Select police station</option>{stations.map(s=><option key={s.id} value={s.id}>{s.name}</option>)}</select>
        <input type="password" minLength="8" placeholder="Strong password" value={form.password} onChange={e=>setForm({...form,password:e.target.value})} required/>
        <button className="primary-btn" disabled={creating}><UserPlus size={15}/>{creating?'Creating…':'Create officer'}</button>
      </form>
      <div className="officer-note">Strong password: 8+ characters with uppercase, lowercase, number and special character. Workflow: Admin creates account → Admin verifies → officer can sign in → main IO can grant case-specific access by email.</div>
      <div className="officer-table-wrap"><table><thead><tr><th>Officer</th><th>Email</th><th>Role</th><th>Police Station</th><th>Status</th><th>Action</th></tr></thead><tbody>{!officers.length?<tr><td colSpan="6">No officers found.</td></tr>:officers.map(o=><tr key={o.id}><td><strong>{o.name}</strong><span className="cell-secondary">{o.username}</span></td><td>{o.email}</td><td>{o.role==='IO'?'Investigation Officer':o.role==='FORENSIC'?'Forensic Officer':'Police Station Officer'}</td><td>{o.station_name||'—'}</td><td><span className={`status ${o.verified?'good':'pending'}`}>{o.verified?'Verified':'Pending verification'}</span></td><td>{o.verified?<button className="text-btn danger-text" onClick={()=>verify(o.id,false)}>Revoke verification</button>:<button className="primary-mini" onClick={()=>verify(o.id,true)}><UserCheck size={13}/> Verify officer</button>}</td></tr>)}</tbody></table></div>
    </div>
    <div className="panel admin-panel"><div className="panel-head"><div><h2>Admin control coverage</h2><p>All major Vajrion entities are persisted in the database.</p></div><ShieldCheck size={20}/></div><div className="admin-checks"><span>✓ FIR copy stored with FIR</span><span>✓ Case ID & registration date</span><span>✓ Police station</span><span>✓ Status & progress</span><span>✓ Important dates</span><span>✓ Current + previous lawyers</span><span>✓ Court proceedings</span><span>✓ Notifications</span><span>✓ Evidence IDs + files</span><span>✓ Officer verification + case access</span><span>✓ Audit hash chain</span></div></div>
  </div>;
}
function CaseModal({data,user,role,request,requestBlob,notify,onClose,onRefresh,onEvidence}){
  const c=data.case; const [progress,setProgress]=useState({progressPercent:c.progress_percent,status:c.current_status});
  const [timeline,setTimeline]=useState({eventType:'INVESTIGATION_UPDATE',message:'',visibility:'CITIZEN_VISIBLE'});
  const [accessEmail,setAccessEmail]=useState(''); const [accessLevel,setAccessLevel]=useState('VIEW_CASE_DOCUMENTS');
  const [verifiedOfficers,setVerifiedOfficers]=useState([]); const [selectedIoId,setSelectedIoId]=useState('');
  const [doc,setDoc]=useState({name:'',documentType:'Investigation Evidence',description:'',citizenVisible:true}); const [file,setFile]=useState(null);
  const [lawyer,setLawyer]=useState({lawyerName:'',barRegistration:'',phone:'',email:'',startedAt:new Date().toISOString().slice(0,10),notes:''});
  const [date,setDate]=useState({label:'',dateValue:new Date().toISOString().slice(0,10),notes:''});
  const [proceeding,setProceeding]=useState({proceedingDate:new Date().toISOString().slice(0,10),courtName:'',stage:'',outcome:'',nextHearingDate:'',notes:''});
  const canEdit=role==='ADMIN'||(role==='POLICE'&&user?.police_station_id===c.police_station_id)||(role==='IO'&&user?.id===c.assigned_io_id);
  const canGrant=(role==='ADMIN')||(role==='POLICE'&&user?.police_station_id===c.police_station_id)||(role==='IO'&&user?.id===c.assigned_io_id);
  const canRequestClosure=role==='POLICE'&&user?.id===c.created_by&&c.current_status!=='CASE_CLOSED';
  const canUpload=(role==='ADMIN')||(role==='IO'&&canEdit)||(role==='FORENSIC');
  useEffect(()=>{ if(role==='POLICE'||role==='ADMIN'){ request('/officers').then(r=>setVerifiedOfficers(r.officers||[])).catch(()=>{}); } },[role,request]);
  const updateProgress=async()=>{try{await request(`/cases/${c.case_id}/progress`,{method:'PATCH',body:JSON.stringify(progress)});notify('Case progress updated');onRefresh();}catch(e){notify(e.message,'error')}};
  const addTimeline=async()=>{try{await request(`/cases/${c.case_id}/timeline`,{method:'POST',body:JSON.stringify(timeline)});setTimeline(t=>({...t,message:''}));notify('Timeline entry added');onRefresh();}catch(e){notify(e.message,'error')}};
  const uploadEvidence=async()=>{if(!file)return notify('Choose a file first','error');const fd=new FormData();fd.append('file',file);fd.append('name',doc.name||file.name);fd.append('documentType',doc.documentType);fd.append('description',doc.description);fd.append('citizenVisible',String(doc.citizenVisible));try{await request(`/cases/${c.case_id}/documents`,{method:'POST',body:fd});notify('Evidence stored in the database');setFile(null);onRefresh();}catch(e){notify(e.message,'error')}};
  const share=async()=>{const email=accessEmail.trim();if(!email)return notify('Enter or select a verified officer email','error');try{await request(`/cases/${c.case_id}/access`,{method:'POST',body:JSON.stringify({email,accessLevel})});notify('Case access granted to the officer');setAccessEmail('');onRefresh();}catch(e){notify(e.message,'error')}};
  const assignIo=async()=>{if(!selectedIoId)return notify('Select a verified Investigation Officer','error');try{await request(`/cases/${c.case_id}/assign-io`,{method:'POST',body:JSON.stringify({officerId:Number(selectedIoId)})});notify('Investigation Officer assigned');setSelectedIoId('');onRefresh();}catch(e){notify(e.message,'error')}};
  const addLawyer=async()=>{try{await request(`/cases/${c.case_id}/lawyers`,{method:'POST',body:JSON.stringify(lawyer)});notify('Lawyer history updated');onRefresh();}catch(e){notify(e.message,'error')}};
  const addDate=async()=>{try{await request(`/cases/${c.case_id}/important-dates`,{method:'POST',body:JSON.stringify(date)});notify('Important date added');onRefresh();}catch(e){notify(e.message,'error')}};
  const addProceeding=async()=>{try{await request(`/cases/${c.case_id}/proceedings`,{method:'POST',body:JSON.stringify(proceeding)});notify('Court proceeding added');onRefresh();}catch(e){notify(e.message,'error')}};
  const completion=async()=>{try{await request(`/cases/${c.case_id}/completion-request`,{method:'POST',body:JSON.stringify({message:`The investigation for ${c.case_id} is complete. Please review the case and approve closure if you agree.`})});notify('Case closure request sent to the citizen');onRefresh();}catch(e){notify(e.message,'error')}};
  const respondClosure=async(id,decision)=>{try{await request(`/completion-requests/${id}/respond`,{method:'POST',body:JSON.stringify({decision})});notify(decision==='APPROVE'?'Case closed after citizen approval':'Case remains open — closure rejected');onRefresh();}catch(e){notify(e.message,'error')}};
  return <div className="modal-backdrop"><div className="case-modal">
    <div className="modal-head"><div><div className="crumb">CASE DETAILS</div><h2>{c.case_id}</h2><p>{c.fir_number} · {c.station_name}</p></div><button className="close-btn" onClick={onClose}><X size={20}/></button></div>
    <div className="case-overview-grid">
      <Info label="FIR number" value={c.fir_number}/><Info label="Case registration" value={formatDate(c.case_registration_date||c.submitted_at)}/><Info label="Police station" value={c.station_name}/><Info label="Current status" value={String(c.current_status).replaceAll('_',' ')}/>
      <Info label="Progress" value={<Progress value={c.progress_percent}/>}/><Info label="Incident" value={c.incident_type}/><Info label="Current lawyer" value={(data.lawyers||[]).find(x=>x.is_current)?.lawyer_name||'Not assigned'}/><Info label="Evidence IDs" value={data.documents?.length||0}/>
    </div>
    <div className="case-tabs">
      <Section title="FIR & Registration" icon={FileText}><div className="details-grid"><Info label="Citizen" value={c.citizen_name}/><Info label="Citizen email" value={c.citizen_email}/><Info label="Phone" value={c.citizen_phone}/><Info label="Incident date" value={`${c.incident_date} ${c.incident_time||''}`}/><Info label="Location" value={c.incident_location}/></div><div className="description-box">{c.description}</div><div className="inline-row"><span className="hash-note"><ShieldCheck size={15}/> FIR copy is attached to this FIR in the database (not to a specific user)</span><button className="outline-btn" onClick={()=>openFirCopy(request,c,notify)}><Eye size={14}/> View FIR Copy</button></div></Section>
      {(role==='POLICE'||role==='ADMIN') && <Section title="Investigation Officer Assignment" icon={UserCheck}><div className="assign-box"><div><strong>Assign the primary Investigation Officer</strong><span>Only Admin-verified Investigation Officers are listed. Police Station Officers see officers from their station.</span></div><div className="inline-form"><select value={selectedIoId} onChange={e=>setSelectedIoId(e.target.value)}><option value="">Select verified Investigation Officer</option>{verifiedOfficers.filter(o=>o.role==='IO').filter(o=>role!=='POLICE'||o.police_station_id===user?.police_station_id).map(o=><option key={o.id} value={o.id}>{o.name} · {o.email}</option>)}</select><button className="primary-btn" onClick={assignIo}><UserCheck size={15}/> Assign IO</button></div></div></Section>}
      {canEdit && <Section title="Update Case Progress" icon={Clock3}><div className="inline-form"><input type="number" min="0" max="100" value={progress.progressPercent} onChange={e=>setProgress({...progress,progressPercent:Number(e.target.value)})}/><select value={progress.status} onChange={e=>setProgress({...progress,status:e.target.value})}>{STATUS_OPTIONS.filter(([v])=>v!=='CASE_CLOSED').map(([v,l])=><option key={v} value={v}>{l}</option>)}</select><button className="primary-btn" onClick={updateProgress}>Save progress</button>{canRequestClosure&&progress.progressPercent===100&&<button className="outline-btn" onClick={completion}>Request case closure</button>}</div></Section>}
      {(role==='CITIZEN') && data.completion?.filter(x=>x.status==='PENDING').map(r=><div className="completion-card" key={r.id}><Bell size={18}/><div><strong>Case closure request</strong><p>{r.message}</p><small>The case will close only if you approve.</small></div><div className="completion-actions"><button className="primary-btn" onClick={()=>respondClosure(r.id,'APPROVE')}>Approve & close case</button><button className="outline-btn" onClick={()=>respondClosure(r.id,'REJECT')}>Reject</button></div></div>)}
      <Section title="Case Timeline" icon={Clock3}><div className="timeline">{(data.timeline||[]).map(t=><div className="timeline-item" key={t.id}><div className="timeline-dot"/><div><strong>{String(t.event_type).replaceAll('_',' ')}</strong><p>{t.message}</p><span>{formatDate(t.created_at)} · {t.actor_name||'System'}</span></div></div>)}</div>{canEdit&&<div className="timeline-add"><input placeholder="Event type" value={timeline.eventType} onChange={e=>setTimeline({...timeline,eventType:e.target.value})}/><input placeholder="Timeline message" value={timeline.message} onChange={e=>setTimeline({...timeline,message:e.target.value})}/><select value={timeline.visibility} onChange={e=>setTimeline({...timeline,visibility:e.target.value})}><option value="CITIZEN_VISIBLE">Citizen visible</option><option value="POLICE_ONLY">Police only</option></select><button className="outline-btn" onClick={addTimeline}>Add update</button></div>}</Section>
      <Section title="Evidence Documents" icon={FileCheck2}><div className="evidence-list">{!data.documents?.length?<EmptyState text="No evidence has been uploaded yet."/>:data.documents.map(d=><div className="evidence-row" key={d.id}><div className="evidence-id"><ShieldCheck size={17}/><div><strong>{d.evidence_id}</strong><span>{d.name} · {d.document_type}</span></div></div><div className="evidence-meta"><span>{formatBytes(d.file_size)}</span><code>{String(d.sha256_hash).slice(0,18)}…</code></div><button className="outline-btn" onClick={async()=>{try{const r=await request(`/documents/${d.id}`);const blob=await requestBlob(`/documents/${d.id}/content`);const contentUrl=URL.createObjectURL(blob);const textContent=r.document.mime_type?.startsWith('text/')?await blob.text():'';onEvidence({...r.document,contentUrl,textContent})}catch(e){notify(e.message,'error')}}}><Eye size={14}/> View evidence</button></div>)}</div>
        {canUpload&&<div className="upload-box"><div className="upload-title"><Upload size={17}/> {role==='FORENSIC'?'Upload forensic report':'Upload investigation evidence'}</div><div className="mini-grid"><input placeholder="Document name" value={doc.name} onChange={e=>setDoc({...doc,name:e.target.value})}/><input placeholder="Document type" value={doc.documentType} onChange={e=>setDoc({...doc,documentType:e.target.value})}/><input placeholder="Description" value={doc.description} onChange={e=>setDoc({...doc,description:e.target.value})}/><input type="file" accept=".pdf,.txt,.csv,.jpg,.jpeg,.png,.mp3,.wav,.m4a,.aac,.mp4,.mov,.webm,.avi,audio/*,video/*" onChange={e=>setFile(e.target.files?.[0]||null)}/></div><label className="check"><input type="checkbox" checked={doc.citizenVisible} onChange={e=>setDoc({...doc,citizenVisible:e.target.checked})}/> Make this evidence visible to citizen</label><button className="primary-btn" onClick={uploadEvidence}><Upload size={15}/> Store evidence</button></div>}
      </Section>
      <Section title="Officer Access" icon={UsersRound}><div className="access-list">{(data.access||[]).map(a=><div className="access-row" key={a.id}><UserRound size={16}/><div><strong>{a.officer_name}</strong><span>{a.officer_email} · {a.station_name||'—'}</span></div><em>{a.access_level==='VIEW_CASE_DOCUMENTS'?'Case + documents':'Case only'}</em><small>Granted by {a.granted_by_name} · {formatDate(a.granted_at)}</small>{canGrant&&<button className="icon-danger" onClick={async()=>{try{await request(`/cases/${c.case_id}/access/${a.id}`,{method:'DELETE'});notify('Access revoked');onRefresh()}catch(e){notify(e.message,'error')}}}><Trash2 size={15}/></button>}</div>)}{canGrant&&<div className="share-box"><strong>Grant verified officer access by email</strong><div className="inline-form"><input type="email" placeholder="officer@example.com" value={accessEmail} onChange={e=>setAccessEmail(e.target.value)}/><select value={accessLevel} onChange={e=>setAccessLevel(e.target.value)}><option value="VIEW_CASE">View case</option><option value="VIEW_CASE_DOCUMENTS">View case + documents</option></select><button className="primary-btn" onClick={share}><UserPlus size={15}/> Grant access</button></div><small>Only Admin-verified officers can be shared. Police Station Officers can share verified Investigation or Forensic Officers; the main Investigation Officer can share the assigned case with another verified officer. Access is limited to this case.</small></div>}</div></Section>
      <div className="two-col-sections">
        <Section title="Important Dates" icon={CalendarDays}><div className="compact-list">{(data.importantDates||[]).map(x=><div key={x.id}><strong>{x.label}</strong><span>{x.date_value}</span><small>{x.notes||''}</small></div>)}</div>{canEdit&&<div className="stack-form"><input placeholder="Date label" value={date.label} onChange={e=>setDate({...date,label:e.target.value})}/><input type="date" value={date.dateValue} onChange={e=>setDate({...date,dateValue:e.target.value})}/><input placeholder="Notes" value={date.notes} onChange={e=>setDate({...date,notes:e.target.value})}/><button className="outline-btn" onClick={addDate}>Add important date</button></div>}</Section>
        <Section title="Lawyer / Counsel History" icon={Scale}><div className="compact-list">{(data.lawyers||[]).map(x=><div key={x.id}><strong>{x.lawyer_name}{x.is_current?' · Current':''}</strong><span>{x.started_at} {x.ended_at?`→ ${x.ended_at}`:''}</span><small>{x.email||''} {x.bar_registration?`· ${x.bar_registration}`:''}</small></div>)}</div>{canEdit&&<div className="stack-form"><input placeholder="Lawyer name" value={lawyer.lawyerName} onChange={e=>setLawyer({...lawyer,lawyerName:e.target.value})}/><input placeholder="Bar registration" value={lawyer.barRegistration} onChange={e=>setLawyer({...lawyer,barRegistration:e.target.value})}/><input placeholder="Email" value={lawyer.email} onChange={e=>setLawyer({...lawyer,email:e.target.value})}/><input type="date" value={lawyer.startedAt} onChange={e=>setLawyer({...lawyer,startedAt:e.target.value})}/><button className="outline-btn" onClick={addLawyer}>Set current lawyer</button></div>}</Section>
      </div>
      <Section title="Court Proceedings" icon={Gavel}><div className="compact-list">{(data.proceedings||[]).map(x=><div key={x.id}><strong>{x.proceeding_id} · {x.court_name}</strong><span>{x.proceeding_date} · {x.stage}</span><small>{x.outcome||''} {x.next_hearing_date?`· Next: ${x.next_hearing_date}`:''} {x.notes?`· ${x.notes}`:''}</small></div>)}</div>{canEdit&&<div className="mini-grid court-form"><input type="date" value={proceeding.proceedingDate} onChange={e=>setProceeding({...proceeding,proceedingDate:e.target.value})}/><input placeholder="Court name" value={proceeding.courtName} onChange={e=>setProceeding({...proceeding,courtName:e.target.value})}/><input placeholder="Stage" value={proceeding.stage} onChange={e=>setProceeding({...proceeding,stage:e.target.value})}/><input placeholder="Outcome" value={proceeding.outcome} onChange={e=>setProceeding({...proceeding,outcome:e.target.value})}/><input type="date" value={proceeding.nextHearingDate} onChange={e=>setProceeding({...proceeding,nextHearingDate:e.target.value})}/><input placeholder="Notes" value={proceeding.notes} onChange={e=>setProceeding({...proceeding,notes:e.target.value})}/><button className="outline-btn" onClick={addProceeding}>Add court proceeding</button></div>}</Section>
      <Section title="FIR / Case Notifications" icon={Bell}>{data.completion?.length?<div className="compact-list">{data.completion.map(r=><div key={r.id}><strong>{r.status}</strong><span>{r.message}</span><small>{formatDate(r.sent_at)}</small></div>)}</div>:<EmptyState text="No completion requests yet."/>}</Section>
    </div>
  </div></div>;
}
function Section({title,icon:Icon,children}){return <section className="case-section"><div className="section-title"><Icon size={17}/><h3>{title}</h3></div>{children}</section>}
function Info({label,value}){return <div className="info"><span>{label}</span><strong>{value??'—'}</strong></div>}
function CaseDetailModal({}){return null}
function Toast({notice}){return <div className={`toast ${notice.type}`}>{notice.type==='error'?<AlertTriangle size={16}/>:<CheckCircle2 size={16}/>}<span>{notice.message}</span></div>}

function EvidenceModal({data,onClose}){
  useEffect(()=>()=>{if(data.contentUrl) URL.revokeObjectURL(data.contentUrl);},[data.contentUrl]);
  const mime=data.mime_type||''; const isText=mime.startsWith('text/'); const isImg=mime==='image/jpeg'||mime==='image/png'; const isPdf=mime==='application/pdf'; const isAudio=mime.startsWith('audio/'); const isVideo=mime.startsWith('video/');
  const download=()=>{const a=document.createElement('a');a.href=data.contentUrl;a.download=data.file_name;a.click();};
  const text=isText?data.textContent||'':'';
  const src=data.contentUrl;
  return <div className="modal-backdrop"><div className="evidence-modal"><div className="modal-head"><div><div className="crumb">EVIDENCE VIEW</div><h2>{data.evidence_id}</h2><p>{data.name} · {data.file_name} · SHA-256 {data.sha256_hash}</p></div><button className="close-btn" onClick={onClose}><X size={20}/></button></div><div className="evidence-viewer">{isText&&<pre>{text}</pre>}{isImg&&<img src={src} alt={data.name}/>} {isPdf&&<iframe title={data.name} src={src}/>} {isAudio&&<audio controls src={src} className="media-player"/>} {isVideo&&<video controls src={src} className="media-player video-player"/>} {!isText&&!isImg&&!isPdf&&!isAudio&&!isVideo&&<div className="viewer-empty"><FileText size={28}/><strong>Preview is not available for this file type.</strong><p>The evidence itself is securely stored in the database and can be downloaded.</p></div>}</div><div className="viewer-footer"><span><ShieldCheck size={15}/> Integrity hash recorded</span><button className="primary-btn" onClick={download}><Download size={15}/> Download evidence</button></div></div></div>;
}

async function openFirCopy(request,c,notify){try{const r=await request(`/cases/${c.case_id}/fir-copy`);const w=window.open('','_blank','width=850,height=700');if(!w)return;w.document.write(`<html><head><title>${c.fir_number}</title><style>body{font-family:Arial;padding:40px;line-height:1.6;color:#172033}pre{white-space:pre-wrap;font-family:Arial}</style></head><body><h1>Vajrion FIR Copy</h1><p><b>${c.fir_number}</b> · ${c.case_id}</p><pre>${escapeHtml(r.copy.content)}</pre></body></html>`);w.document.close();}catch(e){notify(e.message,'error');}}
function escapeHtml(s){return String(s).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');}
function ChangePasswordModal({request,notify,onClose,onChanged}){
  const [form,setForm]=useState({currentPassword:'',newPassword:'',confirm:''});
  const [saving,setSaving]=useState(false);
  const submit=async e=>{e.preventDefault();if(form.newPassword!==form.confirm)return notify('New passwords do not match.','error');setSaving(true);try{await request('/auth/password',{method:'PATCH',body:JSON.stringify({currentPassword:form.currentPassword,newPassword:form.newPassword})});notify('Password changed. Please sign in again.');onChanged();}catch(e){notify(e.message,'error')}finally{setSaving(false)}};
  return <div className="modal-backdrop"><div className="password-modal"><div className="modal-head"><div><div className="crumb">ACCOUNT SECURITY</div><h2>Change password</h2><p>Choose a strong password with uppercase, lowercase, number and special character.</p></div><button className="close-btn" onClick={onClose}><X size={20}/></button></div><form className="password-form" onSubmit={submit}><label className="field-label">Current password<input type="password" value={form.currentPassword} onChange={e=>setForm({...form,currentPassword:e.target.value})} required/></label><label className="field-label">New password<input type="password" value={form.newPassword} onChange={e=>setForm({...form,newPassword:e.target.value})} required/></label><label className="field-label">Confirm new password<input type="password" value={form.confirm} onChange={e=>setForm({...form,confirm:e.target.value})} required/></label><div className="form-actions"><button type="button" className="outline-btn" onClick={onClose}>Cancel</button><button className="primary-btn" disabled={saving}>{saving?'Updating…':'Update password'}</button></div></form></div></div>;
}

function LoginPage({login,setLogin,loginNow,busy,notify,onSignup}){return <div className="login-screen"><div className="login-layout"><div className="login-intro"><div className="brand large"><div className="brand-logo-wrap"><img className="brand-logo" src="/vajrion-logo.jpeg" alt="Vajrion logo" /></div><div><div className="brand-title">Vajrion</div><div className="brand-subtitle">Secure FIR & Evidence Management</div></div></div><div className="login-copy"><span className="eyebrow">SMART INDIA HACKATHON · SIH</span><h1>One secure workspace for the full case lifecycle.</h1><p>Register an FIR, track case progress, preserve evidence, collaborate by case, and maintain an accountable audit trail.</p><div className="feature-grid"><Feature icon={ShieldCheck} title="Protected access"/><Feature icon={FileCheck2} title="Evidence integrity"/><Feature icon={Clock3} title="Case timeline"/><Feature icon={UsersRound} title="Case sharing"/></div></div></div><div className="login-card"><div className="login-head"><div className="login-badge"><LockIcon/></div><div><h2>Sign in</h2><p>Citizens can create an account. Officer accounts are issued by Admin.</p></div></div>{notify&&<Toast notice={notify}/>}<div className="login-guidance"><ShieldCheck size={16}/><span>Use the credentials issued to you. Citizens can create an account below; officer accounts are created and verified by Admin.</span></div><form onSubmit={loginNow} className="login-form"><label className="field-label">Username or email<input value={login.identifier} onChange={e=>setLogin({...login,identifier:e.target.value})} autoComplete="username" required/></label><label className="field-label">Password<input type="password" value={login.password} onChange={e=>setLogin({...login,password:e.target.value})} autoComplete="current-password" required/></label><button className="primary-btn wide" disabled={busy}><ShieldCheck size={17}/>{busy?'Signing in…':'Enter Vajrion'}</button></form><button className="signup-link" onClick={onSignup}>New citizen? Create an account</button><div className="login-note">API: {API}</div></div></div></div>}

function SignupPage({onBack,onCreated,busy,setBusy}){
  const [form,setForm]=useState({name:'',email:'',phone:'',username:'',password:'',confirm:''});
  const [error,setError]=useState('');
  const submit=async e=>{e.preventDefault();setError('');if(form.password!==form.confirm){setError('Passwords do not match.');return;}setBusy(true);try{const res=await fetch(`${API}/auth/signup`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:form.name,email:form.email,phone:form.phone,username:form.username,password:form.password})});const data=await res.json();if(!res.ok)throw new Error(data.error||'Unable to create account');onCreated(data.user?.email||form.email);}catch(e){setError(e.message)}finally{setBusy(false)}};
  return <div className="login-screen"><div className="signup-card"><div className="signup-head"><div className="login-badge"><UserRound size={20}/></div><div><div className="crumb">CITIZEN REGISTRATION</div><h2>Create your Vajrion account</h2><p>Citizen signup is available from the public login page. Police and investigation officer accounts are created by Admin.</p></div></div>{error&&<div className="form-error">{error}</div>}<form className="signup-form" onSubmit={submit}><div className="form-grid"><Field label="Full name" value={form.name} onChange={v=>setForm({...form,name:v})} required/><Field label="Email" type="email" value={form.email} onChange={v=>setForm({...form,email:v})} required/><Field label="Phone (optional)" value={form.phone} onChange={v=>setForm({...form,phone:v})}/><Field label="Username" value={form.username} onChange={v=>setForm({...form,username:v})} required/><Field label="Strong password" type="password" value={form.password} onChange={v=>setForm({...form,password:v})} required/><Field label="Confirm password" type="password" value={form.confirm} onChange={v=>setForm({...form,confirm:v})} required/></div><p className="password-hint">Use at least 8 characters with uppercase, lowercase, number and special character.</p><div className="signup-actions"><button type="button" className="outline-btn" onClick={onBack}>Back to sign in</button><button className="primary-btn" disabled={busy}><UserPlus size={16}/>{busy?'Creating…':'Create citizen account'}</button></div></form></div></div>}
function LockIcon(){return <ShieldCheck size={20}/>}
function Feature({icon:Icon,title}){return <div className="feature"><Icon size={17}/><span>{title}</span></div>}
function formatDate(v){if(!v)return '—';const d=new Date(v.includes('T')?v:v.replace(' ','T'));return Number.isNaN(d.getTime())?String(v):d.toLocaleString([], {dateStyle:'medium',timeStyle:'short'});}
function formatBytes(n){if(!n)return '0 B';const u=['B','KB','MB'];let x=n,i=0;while(x>=1024&&i<u.length-1){x/=1024;i++;}return `${x.toFixed(i?1:0)} ${u[i]}`;}
function safeJson(s){try{return s?JSON.parse(s):null}catch{return null;}}

export default App;
