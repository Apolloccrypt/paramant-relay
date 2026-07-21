'use strict';
/* ── CSP-safe event delegation (replaces inline on* handlers) ──────────────
   Elements declare data-click / data-change / data-input = "actionName", plus
   optional data-* args. A single set of document listeners dispatches to the
   registry (bottom of file), so script-src can drop 'unsafe-inline'. Registered
   BEFORE the menu close-on-click listener so toggleMenu's
   stopImmediatePropagation() wins over it. */
const ACTIONS = { click: {}, change: {}, input: {} };
function act(type, name, fn) { ACTIONS[type][name] = fn; }
function _delegate(type) {
  const attr = 'data-' + type;
  return function (ev) {
    const el = ev.target.closest('[' + attr + ']');
    if (!el) return;
    const fn = ACTIONS[type][el.getAttribute(attr)];
    if (fn) fn(el, ev);
  };
}
document.addEventListener('click', _delegate('click'));
document.addEventListener('change', _delegate('change'));
document.addEventListener('input', _delegate('input'));

/* ── State ───────────────────────────────────────────────────────────────── */
let SESSION = sessionStorage.getItem('adm_session') || '';
let LOADED = {};
let REFRESH = {};
let openMenu = null;

/* ── Helpers ─────────────────────────────────────────────────────────────── */
function esc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
// Event-type display. Older mis-stored records had the type/user swapped (event_type
// held an object), so fall back to user_id when event_type is not a plain string.
function evType(e){return typeof e.event_type==='string'?e.event_type:(typeof e.user_id==='string'?e.user_id:'—');}
// For old swapped records the real user + metadata sat inside the event_type object.
function evUser(e){return (e.event_type&&typeof e.event_type==='object')?String(e.event_type.user_id||e.event_type.account||'—'):String(e.user_id||'');}
function evMeta(e){return (e.event_type&&typeof e.event_type==='object')?e.event_type:(e.metadata||{});}
function fmt(ts){if(!ts)return '—';const d=new Date(ts);return d.toLocaleDateString('nl-NL',{month:'short',day:'numeric'})+' '+d.toLocaleTimeString('nl-NL',{hour:'2-digit',minute:'2-digit'})}
function toast(msg,type=''){const el=document.createElement('div');el.className='toast'+(type?' '+type:'');el.textContent=msg;el.setAttribute('role','status');document.body.appendChild(el);requestAnimationFrame(()=>requestAnimationFrame(()=>el.classList.add('show')));setTimeout(()=>{el.classList.remove('show');setTimeout(()=>el.remove(),250);},3200);}
function showErr(msg){const e=document.getElementById('l-err');e.textContent=msg;e.style.display='block'}

async function api(path,opts={}){
  const r=await fetch('/admin/api'+path,{...opts,headers:{'X-Session':SESSION,'Content-Type':'application/json',...(opts.headers||{})}});
  const ct=r.headers.get('content-type')||'';
  const data=ct.includes('json')?await r.json().catch(()=>null):null;
  return{ok:r.ok,status:r.status,data};
}

/* ── Auth ────────────────────────────────────────────────────────────────── */
async function doLogin(){
  const token=document.getElementById('l-token').value.trim();
  const totp=document.getElementById('l-totp').value.replace(/\D/g,'');
  if(!token){showErr('Admin token required');return}
  if(totp.length!==6){showErr('TOTP must be 6 digits');return}
  const btn=document.getElementById('l-btn');
  btn.disabled=true;btn.textContent='Signing in…';
  document.getElementById('l-err').style.display='none';
  const r=await fetch('/admin/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,totp})});
  const d=await r.json().catch(()=>({}));
  if(!r.ok||!d.session){
    showErr(d.error||'Login failed — check token and TOTP');
    btn.disabled=false;btn.textContent='Sign in';return;
  }
  SESSION=d.session;
  sessionStorage.setItem('adm_session',SESSION);
  document.getElementById('view-login').style.display='none';
  document.getElementById('view-dashboard').style.display='flex';
  const hash=location.hash.replace('#','');
  switchTab(['overview','users','audit','billing','relay'].includes(hash)?hash:'overview');
}

async function doLogout(){
  await api('/auth/logout',{method:'POST'}).catch(()=>{});
  SESSION='';sessionStorage.removeItem('adm_session');
  LOADED={};Object.values(REFRESH).forEach(clearInterval);REFRESH={};
  document.getElementById('view-dashboard').style.display='none';
  document.getElementById('view-login').style.display='flex';
  document.getElementById('l-token').value='';
  document.getElementById('l-totp').value='';
}

/* ── Tab switching ───────────────────────────────────────────────────────── */
function switchTab(tab){
  document.querySelectorAll('.panel').forEach(p=>{p.classList.remove('on');p.setAttribute('aria-hidden','true');});
  document.querySelectorAll('.tabs button').forEach(b=>{
    const active=b.dataset.tab===tab;
    b.classList.toggle('on',active);
    b.setAttribute('aria-selected',active?'true':'false');
    b.setAttribute('tabindex',active?'0':'-1');
  });
  const panel=document.getElementById('tab-'+tab);
  panel.classList.add('on');
  panel.removeAttribute('aria-hidden');
  location.hash='#'+tab;
  srAnnounce('Loading '+tab+' tab');
  if(!LOADED[tab]){LOADED[tab]=true;loadTab(tab);}
}

function srAnnounce(msg){const el=document.getElementById('sr-live');if(el)el.textContent=msg;}

function loadTab(tab){
  if(tab==='overview')loadOverview();
  else if(tab==='users')loadUsers();
  else if(tab==='audit')loadAudit();
  else if(tab==='billing')loadBilling();
  else if(tab==='relay')loadRelay();
}

/* ── Overview ────────────────────────────────────────────────────────────── */
async function loadOverview(){
  const el=document.getElementById('tab-overview');
  el.innerHTML='<div class="empty"><span class="sp-icon"></span>Loading…</div>';
  const r=await api('/admin/overview');
  if(!r.ok){el.innerHTML='<div class="empty">Error loading overview</div>';return}
  const d=r.data;
  const st=d.stats||{};
  const dist=d.plan_distribution||{};
  const total=Object.values(dist).reduce((a,b)=>a+b,0)||1;
  el.innerHTML=
    '<div class="sg">'+
      statCard('Signups today',st.signups_today??0)+
      statCard('Active sessions',st.active_sessions??0)+
      statCard('Pro upgrades today',st.pro_upgrades_today??0)+
      statCard('MRR (EUR)','€'+((st.revenue_mrr||0)/100).toFixed(0))+
    '</div>'+
    (d.alerts&&d.alerts.length?'<div class="card"><div class="card-hdr">Alerts</div>'+d.alerts.map(a=>'<div class="banner info">'+esc(a)+'</div>').join('')+'</div>':'')+
    '<div class="g2">'+
      '<div class="card"><div class="card-hdr">Recent activity <small>last 10 events</small></div>'+
        '<div class="al">'+
          (d.recent_activity&&d.recent_activity.length?
            d.recent_activity.map(e=>'<div class="ai"><span class="t">'+fmt(e.ts).split(' ').slice(-1)[0]+'</span><span class="e">'+esc(evType(e))+'</span><span class="u">'+esc(evUser(e).slice(0,20))+'</span></div>').join(''):
            '<div class="empty">No events yet</div>')+
        '</div>'+
      '</div>'+
      '<div class="card"><div class="card-hdr">Plan distribution</div>'+
        planBars(dist,total)+
      '</div>'+
    '</div>';
  clearInterval(REFRESH.overview);
  REFRESH.overview=setInterval(()=>{LOADED.overview=false;loadOverview();},30000);
}

function statCard(lbl,val){return '<div class="sc"><div class="sc-lbl">'+lbl+'</div><div class="sc-val">'+esc(val)+'</div></div>'}

function planBars(dist,total){
  return ['community','pro','enterprise','trial'].map(p=>{
    const n=dist[p]||0;
    return '<div class="pb"><span class="pl">'+p+'</span><div class="tr"><div class="fi" style="width:'+(n/total*100).toFixed(1)+'%"></div></div><span class="cn">'+n+'</span></div>';
  }).join('');
}

/* ── Users ───────────────────────────────────────────────────────────────── */
let allUsers=[],userPagination={page:1,page_size:50,total_items:0,total_pages:1,has_next:false,has_prev:false};
async function loadUsers(page,pageSize){
  const el=document.getElementById('tab-users');
  if(page!==undefined)userPagination.page=page;
  if(pageSize!==undefined)userPagination.page_size=pageSize;
  el.innerHTML='<div class="empty"><span class="sp-icon"></span>Loading users…</div>';
  const r=await api('/admin/users?page='+userPagination.page+'&page_size='+userPagination.page_size);
  if(!r.ok){el.innerHTML='<div class="empty">Error loading users</div>';return}
  allUsers=r.data.users||[];
  const counts=r.data.counts||{};
  if(r.data.pagination)Object.assign(userPagination,r.data.pagination);
  renderUsers(el,allUsers,counts);
}

function renderUsers(el,users,counts){
  const pg=userPagination;
  el.innerHTML=
    '<div class="card"><div class="card-hdr">Users <small>'+counts.total+' total · '+counts.active+' active · page '+pg.page+'/'+pg.total_pages+'</small>'+
      '<button class="btn" data-click="showNewKeyModal">+ New key</button>'+
    '</div>'+
    '<div class="fb">'+
      '<label for="u-search" class="sr-only">Search users</label>'+
      '<input id="u-search" placeholder="Search email or label…" data-input="filterUsers" style="width:220px">'+
      '<select id="u-plan" aria-label="Filter by plan" data-change="filterUsers"><option value="">All plans</option><option>community</option><option>pro</option><option>enterprise</option><option>trial</option></select>'+
      '<select id="u-totp" aria-label="Filter by TOTP" data-change="filterUsers"><option value="">Any TOTP</option><option value="active">Active</option><option value="pending">Pending</option><option value="none">None</option></select>'+
      '<select id="u-status" aria-label="Filter by status" data-change="filterUsers"><option value="">All status</option><option value="active">Active</option><option value="revoked">Revoked</option></select>'+
    '</div>'+
    '<div id="u-table-wrap">'+usersTable(users)+'</div>'+
    '<div class="pag" aria-label="Pagination">'+
      '<button data-click="usersPage" data-page="'+(pg.page-1)+'" '+(pg.has_prev?'':'disabled')+' aria-label="Previous page">&#8592; Prev</button>'+
      '<span class="pag-info">Page '+pg.page+' of '+pg.total_pages+' ('+pg.total_items+' users)</span>'+
      '<button data-click="usersPage" data-page="'+(pg.page+1)+'" '+(pg.has_next?'':'disabled')+' aria-label="Next page">Next &#8594;</button>'+
      '<select aria-label="Rows per page" data-change="usersPageSize">'+
        '<option value="25" '+(pg.page_size==25?'selected':'')+'>25/page</option>'+
        '<option value="50" '+(pg.page_size==50?'selected':'')+'>50/page</option>'+
        '<option value="100" '+(pg.page_size==100?'selected':'')+'>100/page</option>'+
        '<option value="200" '+(pg.page_size==200?'selected':'')+'>200/page</option>'+
      '</select>'+
    '</div>'+
    '</div>';
}

function filterUsers(){
  const q=(document.getElementById('u-search').value||'').toLowerCase();
  const plan=document.getElementById('u-plan').value;
  const totp=document.getElementById('u-totp').value;
  const status=document.getElementById('u-status').value;
  let filtered=allUsers;
  if(q)filtered=filtered.filter(u=>(u.email||'').toLowerCase().includes(q)||(u.label||'').toLowerCase().includes(q)||(u.usage_purpose||'').toLowerCase().includes(q));
  if(plan)filtered=filtered.filter(u=>(u.plan||'community')===plan);
  if(totp)filtered=filtered.filter(u=>u.totp_status===totp);
  if(status==='active')filtered=filtered.filter(u=>u.active);
  else if(status==='revoked')filtered=filtered.filter(u=>!u.active);
  document.getElementById('u-table-wrap').innerHTML=usersTable(filtered);
}

// Usage-purpose survey answer (dashboard question). 'organisation' and
// 'client_management' are the sales-relevant ones, so they get the accent.
const PURPOSE_LABELS={personal:'Personal use',organisation:'Organisation',client_management:'Manages for clients',research_journalism:'Research/journalism',skipped:'Skipped'};
function purposeLine(u){
  if(!u.usage_purpose)return '';
  const hot=u.usage_purpose==='organisation'||u.usage_purpose==='client_management';
  return '<div class="mono" style="font-size:11px;color:'+(hot?'#0B3A6A;font-weight:600':'#475569')+'" title="Usage purpose ('+esc(u.usage_purpose_at?u.usage_purpose_at.split('T')[0]:'')+')">use: '+esc(PURPOSE_LABELS[u.usage_purpose]||u.usage_purpose)+'</div>';
}
function usersTable(users){
  if(!users.length)return '<div class="empty">No users match filters</div>';
  return '<table class="tbl cards" role="table" aria-label="Users list"><caption class="sr-only">List of Paramant users</caption><thead><tr role="row"><th scope="col">Email / Label</th><th scope="col">Plan</th><th scope="col">TOTP</th><th scope="col">Status</th><th scope="col">Created</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead><tbody>'+
    users.map((u,i)=>{
      const ki=esc(u.key_id||u.key),em=esc(u.email||''),pl=esc(u.plan||'community');
      const hasE=!!u.email,hasTotp=hasE&&u.totp_status!=='none',isRevoked=!u.active;
      return '<tr>'+
        '<td data-label="User"><div>'+esc(u.email||'—')+'</div>'+(u.label?'<div class="mono" style="font-size:11px;color:#475569">'+esc(u.label)+'</div>':'')+
        purposeLine(u)+'</td>'+
        '<td data-label="Plan"><span class="badge '+esc(u.plan||'community')+'">'+esc(u.plan||'community')+'</span>'+(u.parasign?' <span class="chip active" title="ParaSign /v1 API enabled">ParaSign</span>':'')+
          '<div class="mono" style="font-size:10px;color:#475569" title="Per-product tiers">sign:'+esc(u.plan_parasign||'—')+' · send:'+esc(u.plan_parasend||'—')+'</div></td>'+ /*MARK:parasign_badge*/
        '<td data-label="TOTP">'+totpBadge(u)+'</td>'+
        '<td data-label="Status"><span class="chip '+(u.active?'active':'revoked')+'">'+(u.active?'active':'revoked')+'</span></td>'+
        '<td data-label="Created" class="mono" style="font-size:11px;color:#475569">'+(u.created?u.created.split('T')[0]:'—')+'</td>'+
        '<td class="actions"><div class="amw">'+
          '<button class="amb" aria-haspopup="menu" aria-expanded="false" data-click="toggleMenu" data-menu="m'+i+'">···</button>'+
          '<div class="am" role="menu" id="m'+i+'" data-key="'+ki+'" data-email="'+em+'" data-plan="'+pl+'" data-label="'+esc(u.label||'')+'" data-created="'+esc(u.created||'')+'" data-totp-req="'+(u.totp_required?'true':'false')+'" data-parasign="'+(u.parasign?'true':'false')+'" data-pp-sign="'+esc(u.plan_parasign||'')+'" data-pp-send="'+esc(u.plan_parasend||'')+'">'+ /*MARK:parasign_dataset*/
            '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="details">View details</button>'+
            '<div class="ag-lbl">Email</div>'+
            '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="welcome"'+(hasE?'':' disabled')+'>Send welcome</button>'+
            '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="setup"'+(hasE?'':' disabled')+'>Send TOTP setup link</button>'+
            '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="reset-totp"'+(hasTotp?'':' disabled')+'>Send TOTP reset</button>'+
            '<div class="ag-lbl">Account</div>'+
            '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="plan">Change plan</button>'+
            '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="revoke-sessions">Revoke sessions</button>'+
            '<div class="ag-lbl">Security</div>'+
            '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="force-totp">'+(u.totp_required?'Remove TOTP requirement':'Require TOTP')+'</button>'+
            '<div class="ag-lbl">ParaSign API</div>'+
            '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="parasign-toggle">'+(u.parasign?'Disable ParaSign API':'Enable ParaSign API')+'</button>'+
            '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="parasign-onboard"'+(hasE?'':' disabled')+'>Send ParaSign onboarding</button>'+
'<div class="ag-lbl danger">Destructive</div>'+ /*MARK:parasign_menu*/
            '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="disable" class="danger"'+(isRevoked?' disabled':'')+'>Disable key</button>'+
            '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="delete" class="danger">Deactivate account</button>'+
          '</div>'+
        '</div></td>'+
      '</tr>';
    }).join('')+'</tbody></table>';
}

function toggleMenu(e,id){
  e.stopImmediatePropagation();
  const btn=e.currentTarget||e.target;
  const m=document.getElementById(id);
  const wasOpen=m.classList.contains('open');
  if(openMenu){openMenu.classList.remove('open');const ob=openMenu.previousElementSibling;if(ob)ob.setAttribute('aria-expanded','false');}
  if(!wasOpen){
    m.classList.add('open');openMenu=m;
    btn.setAttribute('aria-expanded','true');
    const first=m.querySelector('[role=menuitem]');if(first)first.focus();
  } else {openMenu=null;btn.setAttribute('aria-expanded','false');}
}
document.addEventListener('click',()=>{if(openMenu){openMenu.classList.remove('open');const ob=openMenu.previousElementSibling;if(ob)ob.setAttribute('aria-expanded','false');openMenu=null;}});
document.addEventListener('keydown',e=>{
  // Tab arrow key navigation
  if(['Tab','ArrowLeft','ArrowRight','Home','End'].includes(e.key)){
    const focused=document.activeElement;
    if(focused&&focused.getAttribute('role')==='tab'){
      const tabs=Array.from(document.querySelectorAll('[role=tab]'));
      const idx=tabs.indexOf(focused);
      if(e.key==='ArrowRight'||e.key==='Tab'){if(idx<tabs.length-1){e.preventDefault();tabs[idx+1].focus();tabs[idx+1].click();}}
      if(e.key==='ArrowLeft'){if(idx>0){e.preventDefault();tabs[idx-1].focus();tabs[idx-1].click();}}
      if(e.key==='Home'){e.preventDefault();tabs[0].focus();tabs[0].click();}
      if(e.key==='End'){e.preventDefault();tabs[tabs.length-1].focus();tabs[tabs.length-1].click();}
    }
  }
  // Escape closes open menu
  if(e.key==='Escape'&&openMenu){
    const btn=openMenu.previousElementSibling;
    openMenu.classList.remove('open');openMenu=null;
    if(btn){btn.setAttribute('aria-expanded','false');btn.focus();}
  }
  // Menu item arrow navigation
  if((e.key==='ArrowDown'||e.key==='ArrowUp')&&openMenu){
    const items=Array.from(openMenu.querySelectorAll('[role=menuitem]'));
    const ci=items.indexOf(document.activeElement);
    if(e.key==='ArrowDown'){e.preventDefault();items[(ci+1)%items.length].focus();}
    if(e.key==='ArrowUp'){e.preventDefault();items[(ci-1+items.length)%items.length].focus();}
  }
});

function uAction(action,btn){
  const m=btn.closest('.am');
  const key=m.dataset.key,email=m.dataset.email,plan=m.dataset.plan;
  if(openMenu){openMenu.classList.remove('open');const ob=openMenu.previousElementSibling;if(ob)ob.setAttribute('aria-expanded','false');openMenu=null;}
  switch(action){
    case 'details': openUserDetailsModal(key); break;
    case 'force-totp': openForceTotpModal(key,email,m.dataset.totpReq==='true'); break;
    case 'welcome': openEmailPreviewModal('welcome',key,email); break;
    case 'setup':   openEmailPreviewModal('setup',key,email); break;
    case 'reset-totp': openEmailPreviewModal('reset-confirm',key,email); break;
    case 'plan':    openChangePlanModal(key,email,plan,m.dataset.ppSign,m.dataset.ppSend); break;
    case 'revoke-sessions':
      if(!confirm('Revoke all sessions for '+(email||key.slice(0,20)+'…')+'?'))return;
      api('/admin/revoke-sessions',{method:'POST',body:JSON.stringify({key})}).then(r=>{
        toast(r.ok?'Sessions revoked ('+(r.data?.revoked||0)+')':'Failed: '+(r.data?.error||'unknown'),r.ok?'ok':'err');
      });
      break;
    case 'parasign-toggle': {
      const enabled=m.dataset.parasign!=='true';
      api('/admin/set-parasign',{method:'POST',body:JSON.stringify({key,enabled})}).then(r=>{
        toast(r.ok?('ParaSign '+(enabled?'enabled':'disabled')):'Failed: '+(r.data?.error||'unknown'),r.ok?'ok':'err');
        if(r.ok){LOADED.users=false;loadUsers();}
      });
      break;
    }
    case 'parasign-onboard':
      if(!confirm('Send ParaSign onboarding email to '+(email||key.slice(0,20)+'…')+'?'))return;
      api('/admin/send-parasign-onboarding',{method:'POST',body:JSON.stringify({key})}).then(r=>{
        toast(r.ok?'ParaSign onboarding sent':'Failed: '+(r.data?.error||'unknown'),r.ok?'ok':'err');
      });
      break;
    case 'disable': openDisableKeyModal(key,email); break; /*MARK:parasign_action*/
    case 'delete':  openDeleteAccountModal(key,email); break;
  }
}
function showNewKeyModal(){
  const o=document.createElement('div');
  o.style.cssText='position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(11,58,106,.4);z-index:100;display:flex;align-items:center;justify-content:center;padding:24px';
  o.innerHTML='<div style="background:#F8FAFC;border:1.5px solid rgba(11,58,106,.12);padding:28px;max-width:480px;width:100%">'+
    '<div style="font-family:\'IBM Plex Mono\',monospace;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:#475569;margin-bottom:16px">Create new API key</div>'+
    '<label class="l-lbl">Label</label><input id="nk-l" class="l-inp" placeholder="acme-corp"><br>'+
    '<label class="l-lbl">Plan</label><select id="nk-p" class="l-inp"><option value="community">community</option><option value="pro" selected>pro</option><option value="enterprise">enterprise</option><option value="trial">trial</option></select><br>'+
    '<label class="l-lbl">Email (optional)</label><input id="nk-e" class="l-inp" type="email" placeholder="client@example.com"><br>'+
    '<div style="display:flex;gap:10px;margin-top:8px">'+
    '<button data-click="doCreateKey" class="btn" style="flex:1">Create key</button>'+
    '<button data-click="closeCreateKey" class="btn out">Cancel</button>'+
    '</div><div id="nk-res" style="margin-top:12px;font-size:12px;font-family:\'IBM Plex Mono\',monospace"></div></div>';
  o.dataset.modal='1';
  o.addEventListener('click',e=>{if(e.target===o)o.remove();});
  document.body.appendChild(o);
}

async function doCreateKey(){
  const label=document.getElementById('nk-l').value.trim();
  const plan=document.getElementById('nk-p').value;
  const email=document.getElementById('nk-e').value.trim();
  if(!label){toast('Label required','err');return}
  const r=await api('/keys/all',{method:'POST',body:JSON.stringify({label,plan,email})});
  const res=document.getElementById('nk-res');
  if(r.ok&&r.data?.created?.length){
    const key=r.data.created[0]?.key||'(see response)';
    res.innerHTML='<div style="background:#fff;border:1px solid rgba(11,58,106,.12);padding:12px;word-break:break-all;color:#0B3A6A">'+esc(key)+'</div>'+
      '<div style="color:#059669;margin-top:6px">Key created. Save it — shown once.</div>';
    LOADED.users=false;
  }else{
    res.innerHTML='<div style="color:#dc2626">Failed: '+esc(r.data?.failed?.[0]?.error||r.data?.error||'unknown')+'</div>';
  }
}

/* ── Audit ───────────────────────────────────────────────────────────────── */
async function loadAudit(){
  const el=document.getElementById('tab-audit');
  el.innerHTML='<div class="empty"><span class="sp-icon"></span>Loading audit log…</div>';
  renderAuditShell(el);
  fetchAudit();
}

function renderAuditShell(el){
  el.innerHTML='<div class="card"><div class="card-hdr">Audit log</div>'+
    '<div class="fb">'+
      '<select id="a-event"><option value="">All events</option>'+
        ['signup','login','logout','setup_totp','activate_totp','revoke_session','plan_changed','delete_account'].map(e=>'<option>'+e+'</option>').join('')+
      '</select>'+
      '<input id="a-user" placeholder="User key prefix…" style="width:200px">'+
      '<select id="a-since"><option value="">All time</option><option value="1">Last hour</option><option value="24">Last 24h</option><option value="168">Last 7d</option></select>'+
      '<div class="sp"></div>'+
      '<button class="btn out" data-click="exportAuditCSV">Export CSV</button>'+
      '<button class="btn" data-click="fetchAudit">Refresh</button>'+
    '</div>'+
    '<div id="a-results"><div class="empty"><span class="sp-icon"></span>Loading…</div></div>'+
    '</div>';
}

async function fetchAudit(){
  const event=document.getElementById('a-event')?.value||'';
  const user=document.getElementById('a-user')?.value||'';
  const hours=parseInt(document.getElementById('a-since')?.value||0);
  const params=new URLSearchParams();
  if(event)params.set('event',event);
  if(user)params.set('user',user);
  if(hours)params.set('since',new Date(Date.now()-hours*3600000).toISOString());
  const r=await api('/admin/audit?'+params);
  const el=document.getElementById('a-results');
  if(!el)return;
  if(!r.ok){el.innerHTML='<div class="empty">Error loading audit log</div>';return}
  const events=r.data.events||[];
  if(!events.length){el.innerHTML='<div class="empty">No audit events match filters</div>';return}
  el.innerHTML='<table class="tbl"><thead><tr><th>Timestamp</th><th>Event</th><th>User</th><th>Details</th></tr></thead><tbody>'+
    events.map(e=>'<tr>'+
      '<td class="mono" style="font-size:11px;white-space:nowrap">'+esc(e.ts?new Date(e.ts).toISOString().replace('T',' ').slice(0,19):'—')+'</td>'+
      '<td><span class="chip active">'+esc(evType(e))+'</span></td>'+
      '<td class="mono" style="font-size:11px;color:#475569">'+esc(evUser(e).slice(0,20))+'</td>'+
      '<td><details><summary style="cursor:pointer;font-size:11px;color:#475569">show</summary><pre style="font-size:10px;font-family:\'IBM Plex Mono\',monospace;margin-top:4px;color:#0B3A6A;white-space:pre-wrap">'+esc(JSON.stringify(evMeta(e),null,2))+'</pre></details></td>'+
    '</tr>').join('')+'</tbody></table>';
}

function exportAuditCSV(){
  const rows=document.querySelectorAll('#a-results tr');
  if(!rows.length)return;
  let csv='timestamp,event,user_id,metadata\n';
  rows.forEach(r=>{
    const cells=r.querySelectorAll('td');
    if(cells.length)csv+=[cells[0],cells[1],cells[2],''].map((c,i)=>'"'+(c?.textContent?.trim()||'').replace(/"/g,'""')+'"').join(',')+'\n';
  });
  const a=document.createElement('a');
  a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv);
  a.download='paramant-audit-'+new Date().toISOString().slice(0,10)+'.csv';
  a.click();
}

/* ── Billing ─────────────────────────────────────────────────────────────── */
async function loadBilling(){
  const el=document.getElementById('tab-billing');
  el.innerHTML='<div class="empty"><span class="sp-icon"></span>Loading…</div>';
  const r=await api('/admin/billing');
  if(!r.ok){el.innerHTML='<div class="empty">Error loading billing</div>';return}
  const d=r.data;
  const dist=d.plan_distribution||{};
  const total=Object.values(dist).reduce((a,b)=>a+b,0)||1;
  el.innerHTML=
    '<div class="banner stub" role="status"><strong>Beta billing</strong> &mdash; Payment processing (Mollie) is in integration. Customers are manually invoiced. Data shown is stub only.'+'</div>'+
      '<div class="card"><div class="card-hdr">Recent plan changes <small>'+( d.recent_checkouts?.length||0)+' events</small></div>'+
        (d.recent_checkouts&&d.recent_checkouts.length?
          '<table class="tbl"><thead><tr><th>Time</th><th>User</th><th>Event</th></tr></thead><tbody>'+
          d.recent_checkouts.map(e=>'<tr>'+
            '<td class="mono" style="font-size:11px">'+esc(e.ts?new Date(e.ts).toISOString().slice(0,10):'—')+'</td>'+
            '<td class="mono" style="font-size:11px;color:#475569">'+esc((e.user_id||'').slice(0,16))+'</td>'+
            '<td>'+esc(evType(e))+'</td>'+
          '</tr>').join('')+'</tbody></table>':
          '<div class="empty">No plan changes recorded yet</div>')+
      '</div>'+
    '</div>';
}

/* ── Relay ───────────────────────────────────────────────────────────────── */
async function loadRelay(){
  const el=document.getElementById('tab-relay');
  el.innerHTML='<div class="empty"><span class="sp-icon"></span>Loading relay data…</div>';
  renderRelayShell(el);
  fetchRelay();
  clearInterval(REFRESH.relay);
  REFRESH.relay=setInterval(fetchRelay,10000);
}

function renderRelayShell(el){
  el.innerHTML=
    '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">'+
      '<div style="font-family:\'IBM Plex Mono\',monospace;font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:#475569">Relay health — auto-refreshes every 10s</div>'+
      '<button class="btn out" data-click="fetchRelay">Refresh now</button>'+
    '</div>'+
    '<div id="r-strip" class="rs"><div class="ri loading"><div class="ri-name">health</div><div class="ri-det">loading…</div></div><div class="ri loading"><div class="ri-name">legal</div><div class="ri-det">loading…</div></div><div class="ri loading"><div class="ri-name">finance</div><div class="ri-det">loading…</div></div><div class="ri loading"><div class="ri-name">iot</div><div class="ri-det">loading…</div></div></div>'+
    '<div id="r-cards" class="g2"></div>';
}

async function fetchRelay(){
  const r=await api('/admin/relay-detail');
  if(!r.ok)return;
  const sectors=r.data.sectors||{};
  const strip=document.getElementById('r-strip');
  if(strip)strip.innerHTML=Object.entries(sectors).map(([name,s])=>{
    const ok=!s.error;
    return '<div class="ri'+(ok?'':' offline')+'">'+
      '<div class="ri-name">'+esc(name)+'</div>'+
      '<div class="ri-det">'+(ok?'v'+esc(s.version||'?')+' · up '+Math.floor((s.uptime_s||0)/3600)+'h':esc(s.error))+'</div>'+
    '</div>';
  }).join('');
  const cards=document.getElementById('r-cards');
  if(cards)cards.innerHTML=Object.entries(sectors).map(([name,s])=>{
    if(s.error)return '<div class="card"><div class="card-hdr">'+esc(name)+' <small style="color:#dc2626">offline</small></div><div class="empty">'+esc(s.error)+'</div></div>';
    const st=s.stats||{};
    return '<div class="card"><div class="card-hdr">'+esc(name)+' relay<small>v'+esc(s.version||'?')+'</small></div>'+
      '<table class="tbl"><tbody>'+
        [['Uptime',Math.floor((s.uptime_s||0)/3600)+'h '+Math.floor(((s.uptime_s||0)%3600)/60)+'m'],
         ['Protocol',s.protocol||'—'],
         ['Blobs in flight',s.blobs||0],
         ['Inbound processed',st.inbound||0],
         ['Burned',st.burned||0],
         ['Webhooks sent',st.webhooks_sent||0],
        ].map(([k,v])=>'<tr><td style="color:#475569;font-size:12px">'+esc(k)+'</td><td class="mono">'+esc(v)+'</td></tr>').join('')+
      '</tbody></table></div>';
  }).join('');
}

/* ── Modal helpers ───────────────────────────────────────────────────────── */
let _ms={};
function closeModal(id){const el=document.getElementById(id);if(el)el.style.display='none';}
function openModal(id){const el=document.getElementById(id);if(el)el.style.display='flex';}
function epTab(tab,btn){
  document.querySelectorAll('.ep-tab').forEach(b=>b.classList.remove('on'));btn.classList.add('on');
  const t=document.getElementById('ep-text'),h=document.getElementById('ep-html');
  if(tab==='text'){t.style.display='';h.style.display='none';}else{t.style.display='none';h.style.display='';}
}
async function openEmailPreviewModal(type,key,email){
  const epMap={'welcome':'/admin/send-welcome','setup':'/admin/resend-setup','reset-confirm':'/admin/reset-totp'};
  _ms.email={type,key,email,ep:epMap[type]};
  document.getElementById('mo-email-title').textContent='Preview: '+type+(email?' → '+email:'');
  document.getElementById('ep-subj').textContent='Loading…';
  document.getElementById('ep-text').textContent='';
  document.getElementById('ep-html').removeAttribute('srcdoc');
  document.getElementById('ep-send-btn').disabled=true;
  openModal('mo-email');
  const r=await api('/admin/preview-email',{method:'POST',body:JSON.stringify({type,key})});
  if(!r.ok){document.getElementById('ep-subj').textContent='Preview failed: '+(r.data?.error||'unknown');return;}
  const d=r.data;
  document.getElementById('ep-subj').textContent=d.subject||'';
  document.getElementById('ep-text').textContent=d.text||'';
  document.getElementById('ep-html').srcdoc=d.html||'';
  document.getElementById('ep-send-btn').disabled=false;
  document.getElementById('ep-send-btn').onclick=doSendEmail;
}
async function doSendEmail(){
  const {type,key,email,ep}=_ms.email||{};if(!ep)return;
  document.getElementById('ep-send-btn').disabled=true;document.getElementById('ep-send-btn').textContent='Sending…';
  const body={key};
  if(type==='reset-confirm')body.mode='request';
  if(type==='setup'){body.user_id=key;body.email=email;}
  const r=await api(ep,{method:'POST',body:JSON.stringify(body)});
  closeModal('mo-email');document.getElementById('ep-send-btn').textContent='Send email →';
  toast(r.ok?'Email sent':'Send failed: '+(r.data?.error||'unknown'),r.ok?'ok':'err');
}
// Per-product tier ladders. MUST mirror relay/lib/entitlements.js
// (PARASIGN_TIERS / PARASEND_TIERS); the relay re-validates, this only shapes UI.
const PP_TIERS={parasign:['free','pro','business','enterprise'],parasend:['community','pro','enterprise']};
function ppFillTiers(){
  const p=document.getElementById('pp-product').value;
  document.getElementById('pp-tier').innerHTML=(PP_TIERS[p]||[]).map(t=>'<option value="'+t+'">'+t+'</option>').join('');
}
function ppProductChange(){
  ppFillTiers();
  const p=document.getElementById('pp-product').value;
  const cur=p==='parasign'?(_ms.plan&&_ms.plan.ppSign):(_ms.plan&&_ms.plan.ppSend);
  if(cur&&(PP_TIERS[p]||[]).includes(cur))document.getElementById('pp-tier').value=cur;
}
function openChangePlanModal(key,email,currentPlan,ppSign,ppSend){
  _ms.plan={key,email,ppSign:ppSign||'',ppSend:ppSend||''};
  document.getElementById('cp-current').textContent=currentPlan||'community';
  document.getElementById('cp-plan').value=currentPlan||'community';
  document.getElementById('pp-current').textContent='ParaSign: '+(ppSign||'—')+'  ·  ParaSend: '+(ppSend||'—');
  document.getElementById('plan-entitlement-readback').textContent='No mutation measured yet.';
  document.getElementById('pp-product').value='parasign';
  document.getElementById('pp-notify').checked=false;
  ppFillTiers();
  // Preselect the tier dropdown to the product's CURRENT tier so the operator
  // sees where it stands before moving it.
  const cur=document.getElementById('pp-product').value==='parasign'?ppSign:ppSend;
  if(cur&&(PP_TIERS.parasign.includes(cur)||PP_TIERS.parasend.includes(cur)))document.getElementById('pp-tier').value=cur;
  openModal('mo-plan');setTimeout(()=>document.getElementById('cp-plan').focus(),50);
}
function showEntitlementReadback(d){
  const mismatches=new Map((d?.verification_failed||[]).map(x=>[x.sector+':'+x.product,x]));
  const rows=Object.entries(d?.entitlements_by_sector||{}).map(([s,r])=>{
    if(!r?.ok)return s+': READ FAILED';
    const e=r.entitlements||{};
    const bad=['parasign','parasend'].map(p=>mismatches.get(s+':'+p)).filter(Boolean).map(x=>' expected '+x.product+'='+x.expected).join(',');
    return s+': ParaSign '+(e.parasign?.tier||'-')+' / ParaSend '+(e.parasend?.tier||'-')+(bad?' | MISMATCH'+bad:'');
  });
  document.getElementById('plan-entitlement-readback').textContent=rows.length?rows.join('\n'):'Read-back unavailable.';
}
async function doChangePlan(){
  const {key}=_ms.plan||{};if(!key)return;
  const new_plan=document.getElementById('cp-plan').value;
  const notify=document.getElementById('cp-notify').checked;
  document.getElementById('cp-btn').disabled=true;
  const r=await api('/admin/change-plan',{method:'POST',body:JSON.stringify({key,new_plan,notify})});
  document.getElementById('cp-btn').disabled=false;showEntitlementReadback(r.data);
  const failed=(r.data?.failed_sectors||[]).map(x=>x.sector).join(', ');
  toast(r.data?.ok?'Plan → '+new_plan+' · measured on all sectors':'WARNING partial failure'+(failed?': '+failed:''),r.data?.ok?'ok':'warn');
  if(r.data?.ok){LOADED.users=false;loadUsers();}
}
async function doSetProductPlan(){
  const {key}=_ms.plan||{};if(!key)return;
  const product=document.getElementById('pp-product').value;
  const tier=document.getElementById('pp-tier').value;
  const notify=document.getElementById('pp-notify').checked;
  const btn=document.getElementById('pp-btn');btn.disabled=true;
  const r=await api('/admin/set-product-plan',{method:'POST',body:JSON.stringify({key,product,tier,notify})});
  btn.disabled=false;
  const label=(product==='parasign'?'ParaSign':'ParaSend')+' → '+tier;
  showEntitlementReadback(r.data);
  const failed=(r.data?.failed_sectors||[]).map(x=>x.sector).join(', ');
  toast(r.data?.ok?label+' · measured on all sectors':'WARNING partial failure'+(failed?': '+failed:''),r.data?.ok?'ok':'warn');
  if(r.data?.ok){LOADED.users=false;loadUsers();}
}
function openDisableKeyModal(key,email){
  _ms.disable={key,email};
  document.getElementById('dk-reason').value='';document.getElementById('dk-notify').checked=false;
  openModal('mo-disable');setTimeout(()=>document.getElementById('dk-reason').focus(),50);
}
async function doDisableKey(){
  const {key}=_ms.disable||{};if(!key)return;
  const reason=document.getElementById('dk-reason').value.trim()||'not specified';
  const notify=document.getElementById('dk-notify').checked;
  document.getElementById('dk-btn').disabled=true;
  const r=await api('/admin/disable-key',{method:'POST',body:JSON.stringify({key,reason,notify})});
  closeModal('mo-disable');document.getElementById('dk-btn').disabled=false;
  toast(r.ok?'Key disabled':'Failed: '+(r.data?.error||'unknown'),r.ok?'ok':'err');
  if(r.ok){LOADED.users=false;loadUsers();}
}
function openDeleteAccountModal(key,email){
  _ms.del={key,email};
  document.getElementById('da-confirm').value='';document.getElementById('da-btn').disabled=true;
  document.getElementById('da-notify').checked=true;
  document.getElementById('da-target').textContent=key;
  // Enriched context from the triggering menu's dataset (set by the row template)
  var _mm = document.querySelector('.am[data-key="'+key.replace(/"/g,'')+'"]');
  var _dLabel = _mm && _mm.dataset.label || '';
  var _dPlan = _mm && _mm.dataset.plan || 'community';
  var _dCreated = _mm && _mm.dataset.created || '';
  document.getElementById('da-email').textContent = email || '(no email on file)';
  document.getElementById('da-label').textContent = _dLabel || '(no label)';
  var _planEl = document.getElementById('da-plan');
  _planEl.textContent = _dPlan; _planEl.className = 'badge '+_dPlan;
  document.getElementById('da-created').textContent = _dCreated ? (_dCreated.split('T')[0]+' ('+ _relTime(_dCreated) +')') : '—';
  var _recent = _dCreated && (Date.now() - new Date(_dCreated).getTime()) < 24*3600*1000;
  document.getElementById('da-recent-warn').style.display = _recent ? 'block' : 'none';
  openModal('mo-delete');setTimeout(()=>document.getElementById('da-confirm').focus(),50);
}
function _relTime(iso){
  if(!iso) return '';
  var ms = Date.now() - new Date(iso).getTime();
  if(ms < 60000) return 'just now';
  if(ms < 3600000) return Math.round(ms/60000)+' min ago';
  if(ms < 86400000) return Math.round(ms/3600000)+' h ago';
  return Math.round(ms/86400000)+' d ago';
}
async function doDeleteAccount(){
  const {key}=_ms.del||{};if(!key)return;
  if(document.getElementById('da-confirm').value!=='DEACTIVATE')return;
  const notify=document.getElementById('da-notify').checked;
  document.getElementById('da-btn').disabled=true;
  const r=await api('/admin/delete-account',{method:'POST',body:JSON.stringify({key,confirm:'DELETE',notify})});
  closeModal('mo-delete');
  toast(r.ok?'Account deactivated':'Failed: '+(r.data?.error||'unknown'),r.ok?'ok':'err');
  if(r.ok){LOADED.users=false;setTimeout(loadUsers,800);}
}
async function openUserDetailsModal(key){
  openModal('mo-details');
  document.getElementById('mo-details-body').innerHTML='<div class="empty"><span class="sp-icon"></span>Loading…</div>';
  const r=await api('/admin/user-details/'+key);
  if(!r.ok){document.getElementById('mo-details-body').innerHTML='<div class="empty">Error: '+(r.data?.error||'unknown')+'</div>';return;}
  const d=r.data;
  const ppSign=esc(d.plan_parasign||'—'),ppSend=esc(d.plan_parasend||'—');
  const apiChip=d.parasign?'<span class="chip active">enabled</span>':'<span class="chip none">off</span>';
  document.getElementById('mo-details-body').innerHTML=
    '<div class="g2" style="margin-bottom:16px">'+
      '<div><div class="sc-lbl">Email</div><div class="mono" style="font-size:12px">'+esc(d.email||'—')+'</div></div>'+
      '<div><div class="sc-lbl">Plan (unified)</div><span class="badge '+(d.plan||'community')+'">'+(d.plan||'community')+'</span></div>'+
      '<div><div class="sc-lbl">ParaSign tier</div><span class="badge '+ppSign+'">'+ppSign+'</span></div>'+
      '<div><div class="sc-lbl">ParaSend tier</div><span class="badge '+ppSend+'">'+ppSend+'</span></div>'+
      '<div><div class="sc-lbl">ParaSign /v1 API</div>'+apiChip+'</div>'+
      '<div><div class="sc-lbl">TOTP</div><span class="chip '+(d.totp_status||'none')+'">'+(d.totp_status||'none')+'</span></div>'+
      '<div><div class="sc-lbl">Sessions</div><div class="sc-val" style="font-size:20px">'+(d.active_sessions||0)+'</div></div>'+
      '<div><div class="sc-lbl">Status</div><span class="chip '+(d.active?'active':'revoked')+'">'+(d.active?'active':'revoked')+'</span></div>'+
      '<div><div class="sc-lbl">Created</div><div class="mono" style="font-size:11px">'+(d.created?d.created.split('T')[0]:'—')+'</div></div>'+
    '</div>'+
    '<div class="card-hdr" style="margin-bottom:8px">Recent audit</div>'+
    '<div class="al">'+(d.audit_events&&d.audit_events.length?
      d.audit_events.slice(0,10).map(e=>'<div class="ai"><span class="t" style="font-size:10px">'+(e.ts?new Date(e.ts).toISOString().slice(11,19):'—')+'</span><span class="e" style="font-size:11px">'+esc(evType(e))+'</span></div>').join(''):
      '<div class="empty" style="padding:12px">No events</div>')+
    '</div>';
}

/* ── Init ────────────────────────────────────────────────────────────────── */
document.getElementById('l-totp').addEventListener('input',function(){this.value=this.value.replace(/\D/g,'')});
document.getElementById('l-token').addEventListener('keydown',e=>{if(e.key==='Enter')document.getElementById('l-totp').focus()});
document.getElementById('l-totp').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin()});

if(SESSION){
  api('/auth/check').then(r=>{
    if(r.ok){
      document.getElementById('view-login').style.display='none';
      document.getElementById('view-dashboard').style.display='flex';
      const hash=location.hash.replace('#','');
      switchTab(['overview','users','audit','billing','relay'].includes(hash)?hash:'overview');
    }else{
      SESSION='';sessionStorage.removeItem('adm_session');
    }
  }).catch(()=>{SESSION='';sessionStorage.removeItem('adm_session');});
}

function totpBadge(u){
  const req=u.totp_required,st=u.totp_status;
  if(req&&st!=='active')return '<span class="chip required-missing">⚠ required</span>';
  if(req&&st==='active')return '<span class="chip required-ok">🔒 active</span>';
  return '<span class="chip '+esc(st)+'">'+esc(st)+'</span>';
}
function openForceTotpModal(key,email,currentlyRequired){
  _ms.forceTotp={key,email,removing:currentlyRequired};
  document.getElementById('mo-force-totp-title').textContent=(currentlyRequired?'Remove TOTP requirement':'Require TOTP')+(email?' — '+email:'');
  document.getElementById('mo-force-totp-body').innerHTML=currentlyRequired
    ?'<p style="font-size:13px;color:#475569;margin:0">Remove the TOTP requirement. The user can log in without TOTP, or keep using their existing authenticator.</p>'
    :'<p style="font-size:13px;color:#475569;margin:0 0 10px">Forces this user to set up TOTP before their next login.</p><ul style="font-size:13px;color:#475569;margin:0 0 14px;padding-left:18px"><li>Active sessions will be revoked immediately</li><li>A setup email will be sent automatically</li><li>Login is blocked until setup is complete</li></ul><div class="mc"><label>Reason (optional, for audit log)</label><input type="text" id="ft-reason" placeholder="e.g. policy enforcement"></div>';
  const btn=document.getElementById('ft-btn');
  btn.textContent=currentlyRequired?'Remove requirement':'Require TOTP';
  btn.className='btn '+(currentlyRequired?'':'pri');
  btn.disabled=false;
  openModal('mo-force-totp');
  if(!currentlyRequired)setTimeout(()=>document.getElementById('ft-reason')?.focus(),50);
}
async function doForceTotpRequirement(){
  const{key,removing}=_ms.forceTotp||{};if(!key)return;
  const required=!removing;
  const reason=required?(document.getElementById('ft-reason')?.value.trim()||''):'';
  const btn=document.getElementById('ft-btn');btn.disabled=true;
  const r=await api('/admin/force-totp',{method:'POST',body:JSON.stringify({key,required,reason:reason||undefined})});
  closeModal('mo-force-totp');btn.disabled=false;
  if(r.ok){
    const d=r.data;
    const msg=required?'TOTP required. Sessions revoked: '+(d.sessions_revoked||0)+(d.setup_email_sent?'. Setup email sent.':'.'):'TOTP requirement removed.';
    toast(msg,'ok');LOADED.users=false;setTimeout(loadUsers,500);
  } else { toast('Failed: '+(r.data?.error||'unknown'),'err'); }
}


/* ── Action registry (bottom: all referenced functions are defined above) ──── */
act('click', 'doLogin', () => doLogin());
act('click', 'doLogout', () => doLogout());
act('click', 'switchTab', (el) => switchTab(el.dataset.tab));
act('click', 'closeModal', (el) => closeModal(el.dataset.modal));
act('click', 'epTab', (el) => epTab(el.dataset.arg, el));
act('click', 'doSendEmail', () => doSendEmail());
act('click', 'doChangePlan', () => doChangePlan());
act('click', 'doSetProductPlan', () => doSetProductPlan());
act('change', 'ppProductChange', () => ppProductChange());
act('click', 'doDisableKey', () => doDisableKey());
act('click', 'doDeleteAccount', () => doDeleteAccount());
act('click', 'doForceTotpRequirement', () => doForceTotpRequirement());
act('click', 'doCreateKey', () => doCreateKey());
act('click', 'showNewKeyModal', () => showNewKeyModal());
act('click', 'exportAuditCSV', () => exportAuditCSV());
act('click', 'fetchAudit', () => fetchAudit());
act('click', 'fetchRelay', () => fetchRelay());
act('click', 'uAction', (el) => uAction(el.dataset.uact, el));
act('click', 'toggleMenu', (el, ev) => toggleMenu(ev, el.dataset.menu));
act('click', 'usersPage', (el) => loadUsers(parseInt(el.dataset.page, 10)));
act('click', 'closeCreateKey', (el) => { const m = el.closest('[data-modal]'); if (m) m.remove(); });
act('change', 'filterUsers', () => filterUsers());
act('input', 'filterUsers', () => filterUsers());
act('change', 'usersPageSize', (el) => loadUsers(1, parseInt(el.value, 10)));
act('input', 'confirmDelete', (el) => { const b = document.getElementById('da-btn'); if (b) b.disabled = el.value !== 'DEACTIVATE'; });
