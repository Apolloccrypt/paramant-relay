'use strict';

/* ── State ───────────────────────────────────────────────────────────────── */
let SESSION = sessionStorage.getItem('adm_session') || '';
let LOADED = {};
let REFRESH = {};
let openMenu = null;

/* ── Helpers ─────────────────────────────────────────────────────────────── */
function esc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function fmt(ts){if(!ts)return '-';const d=new Date(ts);return d.toLocaleDateString('nl-NL',{month:'short',day:'numeric'})+' '+d.toLocaleTimeString('nl-NL',{hour:'2-digit',minute:'2-digit'})}
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
  if(!token){showErr('Beheertoken is verplicht');return}
  if(totp.length!==6){showErr('De TOTP-code moet 6 cijfers hebben');return}
  const btn=document.getElementById('l-btn');
  btn.disabled=true;btn.textContent='Bezig met inloggen…';
  document.getElementById('l-err').style.display='none';
  const r=await fetch('/admin/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,totp})});
  const d=await r.json().catch(()=>({}));
  if(!r.ok||!d.session){
    showErr(d.error||'Inloggen mislukt. Controleer het token en de TOTP-code.');
    btn.disabled=false;btn.textContent='Inloggen';return;
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
  srAnnounce('Tabblad '+(TAB_NAMES[tab]||tab)+' wordt geladen');
  if(!LOADED[tab]){LOADED[tab]=true;loadTab(tab);}
}

const TAB_NAMES={overview:'overzicht',users:'gebruikers',audit:'audit',billing:'betalingen',relay:'relay'};
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
  el.innerHTML='<div class="empty"><span class="sp-icon"></span>Laden…</div>';
  const r=await api('/admin/overview');
  if(!r.ok){el.innerHTML='<div class="empty">Het overzicht kon niet worden geladen</div>';return}
  const d=r.data;
  const st=d.stats||{};
  const dist=d.plan_distribution||{};
  const total=Object.values(dist).reduce((a,b)=>a+b,0)||1;
  el.innerHTML=
    '<div class="sg">'+
      statCard('Aanmeldingen vandaag',st.signups_today??0)+
      statCard('Actieve sessies',st.active_sessions??0)+
      statCard('Upgrades naar pro vandaag',st.pro_upgrades_today??0)+
      statCard('MRR (EUR)','€'+((st.revenue_mrr||0)/100).toFixed(0))+
    '</div>'+
    (d.alerts&&d.alerts.length?'<div class="card"><div class="card-hdr">Meldingen</div>'+d.alerts.map(a=>'<div class="banner info">'+esc(a)+'</div>').join('')+'</div>':'')+
    '<div class="g2">'+
      '<div class="card"><div class="card-hdr">Recente activiteit <small>laatste 10 gebeurtenissen</small></div>'+
        '<div class="al">'+
          (d.recent_activity&&d.recent_activity.length?
            d.recent_activity.map(e=>'<div class="ai"><span class="t">'+fmt(e.ts).split(' ').slice(-1)[0]+'</span><span class="e">'+esc(e.event_type||'-')+'</span><span class="u">'+esc((e.user_id||'').slice(0,20))+'</span></div>').join(''):
            '<div class="empty">Nog geen gebeurtenissen</div>')+
        '</div>'+
      '</div>'+
      '<div class="card"><div class="card-hdr">Verdeling over abonnementen</div>'+
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
  el.innerHTML='<div class="empty"><span class="sp-icon"></span>Gebruikers worden geladen…</div>';
  const r=await api('/admin/users?page='+userPagination.page+'&page_size='+userPagination.page_size);
  if(!r.ok){el.innerHTML='<div class="empty">De gebruikers konden niet worden geladen</div>';return}
  allUsers=r.data.users||[];
  const counts=r.data.counts||{};
  if(r.data.pagination)Object.assign(userPagination,r.data.pagination);
  renderUsers(el,allUsers,counts);
}

function renderUsers(el,users,counts){
  const pg=userPagination;
  el.innerHTML=
    '<div class="card"><div class="card-hdr">Gebruikers <small>'+counts.total+' totaal · '+counts.active+' actief · pagina '+pg.page+'/'+pg.total_pages+'</small>'+
      '<button class="btn" data-click="showNewKeyModal">+ Nieuwe sleutel</button>'+
    '</div>'+
    '<div class="fb">'+
      '<label for="u-search" class="sr-only">Gebruikers zoeken</label>'+
      '<input id="u-search" placeholder="Zoek op e-mail of label…" data-input="filterUsers" style="width:220px">'+
      '<select id="u-plan" aria-label="Filteren op abonnement" data-change="filterUsers"><option value="">Alle abonnementen</option><option>community</option><option>pro</option><option>enterprise</option><option>trial</option></select>'+
      '<select id="u-totp" aria-label="Filteren op TOTP" data-change="filterUsers"><option value="">Elke TOTP-stand</option><option value="active">Actief</option><option value="pending">In afwachting</option><option value="none">Geen</option></select>'+
      '<select id="u-status" aria-label="Filteren op status" data-change="filterUsers"><option value="">Elke status</option><option value="active">Actief</option><option value="revoked">Ingetrokken</option></select>'+
    '</div>'+
    '<div id="u-table-wrap">'+usersTable(users)+'</div>'+
    '<div class="pag" aria-label="Paginering">'+
      '<button data-click="usersPage" data-page="'+(pg.page-1)+'" '+(pg.has_prev?'':'disabled')+' aria-label="Vorige pagina">&#8592; Vorige</button>'+
      '<span class="pag-info">Pagina '+pg.page+' van '+pg.total_pages+' ('+pg.total_items+' gebruikers)</span>'+
      '<button data-click="usersPage" data-page="'+(pg.page+1)+'" '+(pg.has_next?'':'disabled')+' aria-label="Volgende pagina">Volgende &#8594;</button>'+
      '<select aria-label="Rijen per pagina" data-change="usersPageSize">'+
        '<option value="25" '+(pg.page_size==25?'selected':'')+'>25 per pagina</option>'+
        '<option value="50" '+(pg.page_size==50?'selected':'')+'>50 per pagina</option>'+
        '<option value="100" '+(pg.page_size==100?'selected':'')+'>100 per pagina</option>'+
        '<option value="200" '+(pg.page_size==200?'selected':'')+'>200 per pagina</option>'+
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
const PURPOSE_LABELS={personal:'Persoonlijk gebruik',organisation:'Organisatie',client_management:'Beheert voor klanten',research_journalism:'Onderzoek/journalistiek',skipped:'Overgeslagen'};
function purposeLine(u){
  if(!u.usage_purpose)return '';
  const hot=u.usage_purpose==='organisation'||u.usage_purpose==='client_management';
  return '<div class="mono" style="font-size:11px;color:'+(hot?'var(--ochre);font-weight:600':'var(--ink-dim)')+'" title="Doel van gebruik ('+esc(u.usage_purpose_at?u.usage_purpose_at.split('T')[0]:'')+')">gebruik: '+esc(PURPOSE_LABELS[u.usage_purpose]||u.usage_purpose)+'</div>';
}
function usersTable(users){
  if(!users.length)return '<div class="empty">Geen gebruikers die aan de filters voldoen</div>';
  return '<table class="tbl" role="table" aria-label="Lijst met gebruikers"><caption class="sr-only">Lijst met gebruikers van Paramant</caption><thead><tr role="row"><th scope="col">E-mail / label</th><th scope="col">Abonnement</th><th scope="col">TOTP</th><th scope="col">Status</th><th scope="col">Aangemaakt</th><th scope="col"><span class="sr-only">Acties</span></th></tr></thead><tbody>'+
    users.map((u,i)=>{
      const ki=esc(u.key_id||u.key),em=esc(u.email||''),pl=esc(u.plan||'community');
      const hasE=!!u.email,hasTotp=hasE&&u.totp_status!=='none',isRevoked=!u.active;
      return '<tr>'+
        '<td><div>'+esc(u.email||'-')+'</div>'+(u.label?'<div class="mono" style="font-size:11px;color:#475569">'+esc(u.label)+'</div>':'')+
        purposeLine(u)+'</td>'+
        '<td><span class="badge '+esc(u.plan||'community')+'">'+esc(u.plan||'community')+'</span></td>'+
        '<td>'+totpBadge(u)+'</td>'+
        '<td><span class="chip '+(u.active?'active':'revoked')+'">'+(u.active?'actief':'ingetrokken')+'</span></td>'+
        '<td class="mono" style="font-size:11px;color:#475569">'+(u.created?u.created.split('T')[0]:'-')+'</td>'+
        '<td><div class="amw">'+
          '<button class="amb" aria-haspopup="menu" aria-expanded="false" data-click="toggleMenu" data-menu="m'+i+'">···</button>'+
          '<div class="am" role="menu" id="m'+i+'" data-key="'+ki+'" data-email="'+em+'" data-plan="'+pl+'" data-label="'+esc(u.label||'')+'" data-created="'+esc(u.created||'')+'" data-totp-req="'+(u.totp_required?'true':'false')+'">'+
            '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="details">Gegevens bekijken</button>'+
            '<div class="ag-lbl">E-mail</div>'+
            '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="welcome"'+(hasE?'':' disabled')+'>Welkomstmail sturen</button>'+
            '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="setup"'+(hasE?'':' disabled')+'>Link voor TOTP-instelling sturen</button>'+
            '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="reset-totp"'+(hasTotp?'':' disabled')+'>TOTP-reset sturen</button>'+
            '<div class="ag-lbl">Account</div>'+
            '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="plan">Abonnement wijzigen</button>'+
            '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="revoke-sessions">Sessies intrekken</button>'+
            '<div class="ag-lbl">Beveiliging</div>'+
            '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="force-totp">'+(u.totp_required?'TOTP-verplichting opheffen':'TOTP verplicht stellen')+'</button>'+
'<div class="ag-lbl danger">Onomkeerbaar</div>'+
            '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="disable" class="danger"'+(isRevoked?' disabled':'')+'>Sleutel uitschakelen</button>'+
            '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="delete" class="danger">Account deactiveren</button>'+
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
    case 'plan':    openChangePlanModal(key,email,plan); break;
    case 'revoke-sessions':
      if(!confirm('Alle sessies van '+(email||key.slice(0,20)+'…')+' intrekken?'))return;
      api('/admin/revoke-sessions',{method:'POST',body:JSON.stringify({key})}).then(r=>{
        toast(r.ok?'Sessies ingetrokken ('+(r.data?.revoked||0)+')':'Mislukt: '+(r.data?.error||'onbekend'),r.ok?'ok':'err');
      });
      break;
    case 'disable': openDisableKeyModal(key,email); break;
    case 'delete':  openDeleteAccountModal(key,email); break;
  }
}
function showNewKeyModal(){
  const o=document.createElement('div');
  o.style.cssText='position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(12, 15, 17, .72);z-index:100;display:flex;align-items:center;justify-content:center;padding:24px';
  o.innerHTML='<div style="background:var(--bone-2);border:1.5px solid var(--line);padding:28px;max-width:480px;width:100%;color:var(--ink)">'+
    '<div style="font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--ink-dim);margin-bottom:16px">Nieuwe API-sleutel maken</div>'+
    '<label class="l-lbl">Label</label><input id="nk-l" class="l-inp" placeholder="acme-corp"><br>'+
    '<label class="l-lbl">Abonnement</label><select id="nk-p" class="l-inp"><option value="community">community</option><option value="pro" selected>pro</option><option value="enterprise">enterprise</option><option value="trial">trial</option></select><br>'+
    '<label class="l-lbl">E-mail (optioneel)</label><input id="nk-e" class="l-inp" type="email" placeholder="client@example.com"><br>'+
    '<div style="display:flex;gap:10px;margin-top:8px">'+
    '<button data-click="doCreateKey" class="btn" style="flex:1">Sleutel maken</button>'+
    '<button onclick="this.closest(\'[data-modal]\').remove()" class="btn out">Annuleren</button>'+
    '</div><div id="nk-res" style="margin-top:12px;font-size:12px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace"></div></div>';
  o.dataset.modal='1';
  o.addEventListener('click',e=>{if(e.target===o)o.remove();});
  document.body.appendChild(o);
}

async function doCreateKey(){
  const label=document.getElementById('nk-l').value.trim();
  const plan=document.getElementById('nk-p').value;
  const email=document.getElementById('nk-e').value.trim();
  if(!label){toast('Label is verplicht','err');return}
  const r=await api('/keys/all',{method:'POST',body:JSON.stringify({label,plan,email})});
  const res=document.getElementById('nk-res');
  if(r.ok&&r.data?.created?.length){
    const key=r.data.created[0]?.key||'(zie het antwoord)';
    res.innerHTML='<div style="background:var(--card-2);border:1px solid var(--line);padding:12px;word-break:break-all;color:var(--ochre)">'+esc(key)+'</div>'+
      '<div style="color:#059669;margin-top:6px">Sleutel gemaakt. Bewaar hem nu: u ziet hem maar één keer.</div>';
    LOADED.users=false;
  }else{
    res.innerHTML='<div style="color:var(--brick-ink)">Mislukt: '+esc(r.data?.failed?.[0]?.error||r.data?.error||'onbekend')+'</div>';
  }
}

/* ── Audit ───────────────────────────────────────────────────────────────── */
async function loadAudit(){
  const el=document.getElementById('tab-audit');
  el.innerHTML='<div class="empty"><span class="sp-icon"></span>Auditlog wordt geladen…</div>';
  renderAuditShell(el);
  fetchAudit();
}

function renderAuditShell(el){
  el.innerHTML='<div class="card"><div class="card-hdr">Auditlog</div>'+
    '<div class="fb">'+
      '<select id="a-event" aria-label="Filteren op gebeurtenis"><option value="">Alle gebeurtenissen</option>'+
        ['signup','login','logout','setup_totp','activate_totp','revoke_session','plan_changed','delete_account'].map(e=>'<option>'+e+'</option>').join('')+
      '</select>'+
      '<input id="a-user" placeholder="Begin van de gebruikerssleutel…" style="width:200px">'+
      '<select id="a-since" aria-label="Periode"><option value="">Altijd</option><option value="1">Laatste uur</option><option value="24">Laatste 24 uur</option><option value="168">Laatste 7 dagen</option></select>'+
      '<div class="sp"></div>'+
      '<button class="btn out" data-click="exportAuditCSV">CSV exporteren</button>'+
      '<button class="btn" data-click="fetchAudit">Vernieuwen</button>'+
    '</div>'+
    '<div id="a-results"><div class="empty"><span class="sp-icon"></span>Laden…</div></div>'+
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
  if(!r.ok){el.innerHTML='<div class="empty">De auditlog kon niet worden geladen</div>';return}
  const events=r.data.events||[];
  if(!events.length){el.innerHTML='<div class="empty">Geen auditgebeurtenissen die aan de filters voldoen</div>';return}
  el.innerHTML='<table class="tbl"><thead><tr><th>Tijdstip</th><th>Gebeurtenis</th><th>Gebruiker</th><th>Details</th></tr></thead><tbody>'+
    events.map(e=>'<tr>'+
      '<td class="mono" style="font-size:11px;white-space:nowrap">'+esc(e.ts?new Date(e.ts).toISOString().replace('T',' ').slice(0,19):'-')+'</td>'+
      '<td><span class="chip active">'+esc(e.event_type||'-')+'</span></td>'+
      '<td class="mono" style="font-size:11px;color:#475569">'+esc((e.user_id||'').slice(0,20))+'</td>'+
      '<td><details><summary style="cursor:pointer;font-size:11px;color:var(--ink-dim)">tonen</summary><pre style="font-size:10px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin-top:4px;color:var(--ink-2);white-space:pre-wrap">'+esc(JSON.stringify(e.metadata||{},null,2))+'</pre></details></td>'+
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
  el.innerHTML='<div class="empty"><span class="sp-icon"></span>Laden…</div>';
  const r=await api('/admin/billing');
  if(!r.ok){el.innerHTML='<div class="empty">De betalingen konden niet worden geladen</div>';return}
  const d=r.data;
  const dist=d.plan_distribution||{};
  const total=Object.values(dist).reduce((a,b)=>a+b,0)||1;
  el.innerHTML=
    /* The same line, and the same correction, as admin/public/app.js. Every
       clause of what stood here was false by September 2026: relay.js POST
       /v2/billing/checkout calls mollie.createPayment against api.mollie.com
       unconditionally, and the webhook issues a numbered invoice
       (lib/invoice.js, PS-YYYY-NNNN) or a credit note (lib/credit-note.js,
       CN-YYYY-NNNN) on its own. Nobody is invoiced by hand and the tab is not
       a fixture. This screen is served by nothing (nginx sends /admin/ to the
       admin container), and it is corrected rather than deleted because
       tests/ui-truthfulness.test.mjs reads it by name, and because a wrong
       copy left lying next to a right one is how the wrong one comes back. */
    '<div class="banner info" role="status"><strong>Betalingen</strong> Mollie-betalingen zijn live: één betaling per termijn, geen doorlopend abonnement en geen automatische incasso. Een genummerde factuur of creditnota wordt automatisch gemaakt vanuit de betaalwebhook. Dit tabblad toont de verdeling over abonnementen en de wijzigingen die een beheerder maakte, geen betalingen of omzet.</div>'+
      '<div class="card"><div class="card-hdr">Recente wijzigingen van abonnement <small>'+( d.recent_checkouts?.length||0)+' gebeurtenissen</small></div>'+
        (d.recent_checkouts&&d.recent_checkouts.length?
          '<table class="tbl"><thead><tr><th>Tijd</th><th>Gebruiker</th><th>Gebeurtenis</th></tr></thead><tbody>'+
          d.recent_checkouts.map(e=>'<tr>'+
            '<td class="mono" style="font-size:11px">'+esc(e.ts?new Date(e.ts).toISOString().slice(0,10):'-')+'</td>'+
            '<td class="mono" style="font-size:11px;color:#475569">'+esc((e.user_id||'').slice(0,16))+'</td>'+
            '<td>'+esc(e.event_type||'-')+'</td>'+
          '</tr>').join('')+'</tbody></table>':
          '<div class="empty">Nog geen wijzigingen van abonnement vastgelegd</div>')+
      '</div>'+
      renderCouponsShell()+
    '</div>';
  fetchCoupons();
}

/* ── Coupons ─────────────────────────────────────────────────────────────
   Gift codes: a term given away, never a sale. relay/lib/coupon.js holds the
   rules; this is the window on them. Two things belong on the screen and
   nothing else does: how to make one, and how many seats of each are gone.
   There is deliberately no edit. Raising the cap on a code people are already
   redeeming against, or changing what it grants under them, is how two
   customers get different answers for the same code. Withdraw it and make
   another. */
function renderCouponsShell(){
  return '<div class="card"><div class="card-hdr">Cadeaucodes <small>een gegeven termijn, geen betaling, geen factuur</small></div>'+
    '<div class="fb">'+
      '<input id="c-code" placeholder="CODE" aria-label="Code" style="width:160px;text-transform:uppercase">'+
      '<input id="c-max" type="number" min="1" value="100" style="width:90px" title="Maximaal aantal keer inwisselen" aria-label="Maximaal aantal keer inwisselen">'+
      '<input id="c-days" type="number" min="1" value="90" style="width:90px" title="Aantal dagen" aria-label="Aantal dagen">'+
      '<input id="c-until" type="date" style="width:150px" title="Geldig tot" aria-label="Geldig tot">'+
      '<div class="sp"></div>'+
      '<button class="btn" data-click="doCreateCoupon">Code maken</button>'+
      '<button class="btn out" data-click="fetchCoupons">Vernieuwen</button>'+
    '</div>'+
    '<div id="c-msg" style="font-size:12px;margin-bottom:8px"></div>'+
    '<div id="c-results"><div class="empty"><span class="sp-icon"></span>Laden…</div></div>'+
  '</div>';
}

async function fetchCoupons(){
  const el=document.getElementById('c-results');
  if(!el)return;
  const r=await api('/admin/coupons');
  if(!r.ok){el.innerHTML='<div class="empty">De cadeaucodes konden niet worden geladen</div>';return}
  const list=(r.data&&r.data.coupons)||[];
  if(!list.length){el.innerHTML='<div class="empty">Nog geen cadeaucodes</div>';return}
  el.innerHTML='<table class="tbl"><thead><tr><th>Code</th><th>Geeft</th><th>Gebruikt</th><th>Geldig tot</th><th>Status</th><th></th></tr></thead><tbody>'+
    list.map(c=>'<tr>'+
      '<td class="mono">'+esc(c.code)+'</td>'+
      '<td style="font-size:12px">'+esc(c.describes||'')+'</td>'+
      '<td class="mono">'+esc(c.used+' / '+c.max_redemptions)+'</td>'+
      '<td style="font-size:12px">'+esc(c.valid_until?c.valid_until.slice(0,10):'geen einddatum')+'</td>'+
      '<td>'+(c.revoked_at?'<span class="chip">ingetrokken</span>':(c.remaining>0?'<span class="chip active">open</span>':'<span class="chip">op</span>'))+'</td>'+
      '<td>'+(c.revoked_at?'':'<button class="btn out" data-click="doRevokeCoupon" data-code="'+esc(c.code)+'">Intrekken</button>')+'</td>'+
    '</tr>').join('')+'</tbody></table>';
}

async function doCreateCoupon(){
  const code=(document.getElementById('c-code')?.value||'').trim().toUpperCase();
  const max=parseInt(document.getElementById('c-max')?.value||'0',10);
  const days=parseInt(document.getElementById('c-days')?.value||'0',10);
  const until=document.getElementById('c-until')?.value||'';
  const msg=document.getElementById('c-msg');
  if(!code){if(msg){msg.style.color='var(--brick-ink)';msg.textContent='Vul een code in.';}return}
  /* Both products on Pro is the campaign this shipped for. The relay validates
     every field again; nothing here is trusted. */
  const body={code:code,max_redemptions:max,grants:[
    {product:'parasign',tier:'pro',days:days},
    {product:'parasend',tier:'pro',days:days},
  ]};
  if(until)body.valid_until=until+'T23:59:59Z';
  const r=await api('/admin/coupons',{method:'POST',body:JSON.stringify(body)});
  if(msg){
    msg.style.color=r.ok?'#059669':'var(--brick-ink)';
    msg.textContent=r.ok
      ?(code+' gemaakt: '+((r.data&&r.data.coupon&&r.data.coupon.describes)||'')+', '+max+' keer in te wisselen.')
      :('Mislukt: '+((r.data&&r.data.error)||'onbekend'));
  }
  if(r.ok){document.getElementById('c-code').value='';fetchCoupons();}
}

async function doRevokeCoupon(el){
  const code=el&&el.dataset?el.dataset.code:'';
  if(!code)return;
  const r=await api('/admin/coupons/'+encodeURIComponent(code),{method:'DELETE'});
  const msg=document.getElementById('c-msg');
  if(msg){
    msg.style.color=r.ok?'#059669':'var(--brick-ink)';
    msg.textContent=r.ok
      ?(code+' ingetrokken. Wie de code al inwisselde, houdt de termijn.')
      :('Mislukt: '+((r.data&&r.data.error)||'onbekend'));
  }
  if(r.ok)fetchCoupons();
}

/* ── Relay ───────────────────────────────────────────────────────────────── */
async function loadRelay(){
  const el=document.getElementById('tab-relay');
  el.innerHTML='<div class="empty"><span class="sp-icon"></span>Relaygegevens worden geladen…</div>';
  renderRelayShell(el);
  fetchRelay();
  clearInterval(REFRESH.relay);
  REFRESH.relay=setInterval(fetchRelay,10000);
}

function renderRelayShell(el){
  el.innerHTML=
    '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">'+
      '<div style="font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:#475569">Stand van de relays, ververst elke 10 s</div>'+
      '<button class="btn out" data-click="fetchRelay">Nu vernieuwen</button>'+
    '</div>'+
    '<div id="r-strip" class="rs"><div class="ri loading"><div class="ri-name">health</div><div class="ri-det">laden…</div></div><div class="ri loading"><div class="ri-name">legal</div><div class="ri-det">laden…</div></div><div class="ri loading"><div class="ri-name">finance</div><div class="ri-det">laden…</div></div><div class="ri loading"><div class="ri-name">iot</div><div class="ri-det">laden…</div></div></div>'+
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
      '<div class="ri-det">'+(ok?'v'+esc(s.version||'?')+' · draait '+Math.floor((s.uptime_s||0)/3600)+' u':esc(s.error))+'</div>'+
    '</div>';
  }).join('');
  const cards=document.getElementById('r-cards');
  if(cards)cards.innerHTML=Object.entries(sectors).map(([name,s])=>{
    if(s.error)return '<div class="card"><div class="card-hdr">'+esc(name)+' <small style="color:var(--brick-ink)">offline</small></div><div class="empty">'+esc(s.error)+'</div></div>';
    const st=s.stats||{};
    return '<div class="card"><div class="card-hdr">'+esc(name)+' relay<small>v'+esc(s.version||'?')+'</small></div>'+
      '<table class="tbl"><tbody>'+
        [['Draait',Math.floor((s.uptime_s||0)/3600)+' u '+Math.floor(((s.uptime_s||0)%3600)/60)+' min'],
         ['Protocol',s.protocol||'-'],
         ['Blobs onderweg',s.blobs||0],
         ['Inkomend verwerkt',st.inbound||0],
         ['Vernietigd',st.burned||0],
         ['Webhooks verstuurd',st.webhooks_sent||0],
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
const EMAIL_TYPES={'welcome':'welkomstmail','setup':'TOTP-instelling','reset-confirm':'TOTP-reset'};
async function openEmailPreviewModal(type,key,email){
  const epMap={'welcome':'/admin/send-welcome','setup':'/admin/resend-setup','reset-confirm':'/admin/reset-totp'};
  _ms.email={type,key,email,ep:epMap[type]};
  document.getElementById('mo-email-title').textContent='Voorbeeld: '+(EMAIL_TYPES[type]||type)+(email?' → '+email:'');
  document.getElementById('ep-subj').textContent='Laden…';
  document.getElementById('ep-text').textContent='';
  document.getElementById('ep-html').removeAttribute('srcdoc');
  document.getElementById('ep-send-btn').disabled=true;
  openModal('mo-email');
  const r=await api('/admin/preview-email',{method:'POST',body:JSON.stringify({type,key})});
  if(!r.ok){document.getElementById('ep-subj').textContent='Voorbeeld mislukt: '+(r.data?.error||'onbekend');return;}
  const d=r.data;
  document.getElementById('ep-subj').textContent=d.subject||'';
  document.getElementById('ep-text').textContent=d.text||'';
  document.getElementById('ep-html').srcdoc=d.html||'';
  document.getElementById('ep-send-btn').disabled=false;
  document.getElementById('ep-send-btn').onclick=doSendEmail;
}
async function doSendEmail(){
  const {type,key,email,ep}=_ms.email||{};if(!ep)return;
  document.getElementById('ep-send-btn').disabled=true;document.getElementById('ep-send-btn').textContent='Bezig met versturen…';
  const body={key};
  if(type==='reset-confirm')body.mode='request';
  if(type==='setup'){body.user_id=key;body.email=email;}
  const r=await api(ep,{method:'POST',body:JSON.stringify(body)});
  closeModal('mo-email');document.getElementById('ep-send-btn').textContent='E-mail versturen →';
  toast(r.ok?'E-mail verstuurd':'Versturen mislukt: '+(r.data?.error||'onbekend'),r.ok?'ok':'err');
}
function openChangePlanModal(key,email,currentPlan){
  _ms.plan={key,email};
  document.getElementById('cp-current').textContent=currentPlan||'community';
  document.getElementById('cp-plan').value=currentPlan||'community';
  openModal('mo-plan');setTimeout(()=>document.getElementById('cp-plan').focus(),50);
}
async function doChangePlan(){
  const {key}=_ms.plan||{};if(!key)return;
  const new_plan=document.getElementById('cp-plan').value;
  const notify=document.getElementById('cp-notify').checked;
  document.getElementById('cp-btn').disabled=true;
  const r=await api('/admin/change-plan',{method:'POST',body:JSON.stringify({key,new_plan,notify})});
  closeModal('mo-plan');document.getElementById('cp-btn').disabled=false;
  toast(r.ok?'Abonnement → '+new_plan:'Mislukt: '+(r.data?.error||'onbekend'),r.ok?'ok':'err');
  if(r.ok){LOADED.users=false;loadUsers();}
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
  toast(r.ok?'Sleutel uitgeschakeld':'Mislukt: '+(r.data?.error||'onbekend'),r.ok?'ok':'err');
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
  document.getElementById('da-email').textContent = email || '(geen e-mailadres bekend)';
  document.getElementById('da-label').textContent = _dLabel || '(geen label)';
  var _planEl = document.getElementById('da-plan');
  _planEl.textContent = _dPlan; _planEl.className = 'badge '+_dPlan;
  document.getElementById('da-created').textContent = _dCreated ? (_dCreated.split('T')[0]+' ('+ _relTime(_dCreated) +')') : '-';
  var _recent = _dCreated && (Date.now() - new Date(_dCreated).getTime()) < 24*3600*1000;
  document.getElementById('da-recent-warn').style.display = _recent ? 'block' : 'none';
  openModal('mo-delete');setTimeout(()=>document.getElementById('da-confirm').focus(),50);
}
function _relTime(iso){
  if(!iso) return '';
  var ms = Date.now() - new Date(iso).getTime();
  if(ms < 60000) return 'zojuist';
  if(ms < 3600000) return Math.round(ms/60000)+' min geleden';
  if(ms < 86400000) return Math.round(ms/3600000)+' uur geleden';
  return Math.round(ms/86400000)+' dagen geleden';
}
async function doDeleteAccount(){
  const {key}=_ms.del||{};if(!key)return;
  if(document.getElementById('da-confirm').value!=='DEACTIVATE')return;
  const notify=document.getElementById('da-notify').checked;
  document.getElementById('da-btn').disabled=true;
  const r=await api('/admin/delete-account',{method:'POST',body:JSON.stringify({key,confirm:'DELETE',notify})});
  closeModal('mo-delete');
  toast(r.ok?'Account gedeactiveerd':'Mislukt: '+(r.data?.error||'onbekend'),r.ok?'ok':'err');
  if(r.ok){LOADED.users=false;setTimeout(loadUsers,800);}
}
async function openUserDetailsModal(key){
  openModal('mo-details');
  document.getElementById('mo-details-body').innerHTML='<div class="empty"><span class="sp-icon"></span>Laden…</div>';
  const r=await api('/admin/user-details/'+key);
  if(!r.ok){document.getElementById('mo-details-body').innerHTML='<div class="empty">Fout: '+(r.data?.error||'onbekend')+'</div>';return;}
  const d=r.data;
  document.getElementById('mo-details-body').innerHTML=
    '<div class="g2" style="margin-bottom:16px">'+
      '<div><div class="sc-lbl">E-mail</div><div class="mono" style="font-size:12px">'+(d.email||'-')+'</div></div>'+
      '<div><div class="sc-lbl">Abonnement</div><span class="badge '+(d.plan||'community')+'">'+(d.plan||'community')+'</span></div>'+
      '<div><div class="sc-lbl">TOTP</div><span class="chip '+(d.totp_status||'none')+'">'+(TOTP_NAMES[d.totp_status||'none']||d.totp_status)+'</span></div>'+
      '<div><div class="sc-lbl">Sessies</div><div class="sc-val" style="font-size:20px">'+(d.active_sessions||0)+'</div></div>'+
      '<div><div class="sc-lbl">Status</div><span class="chip '+(d.active?'active':'revoked')+'">'+(d.active?'actief':'ingetrokken')+'</span></div>'+
      '<div><div class="sc-lbl">Aangemaakt</div><div class="mono" style="font-size:11px">'+(d.created?d.created.split('T')[0]:'-')+'</div></div>'+
    '</div>'+
    '<div class="card-hdr" style="margin-bottom:8px">Recente audit</div>'+
    '<div class="al">'+(d.audit_events&&d.audit_events.length?
      d.audit_events.slice(0,10).map(e=>'<div class="ai"><span class="t" style="font-size:10px">'+(e.ts?new Date(e.ts).toISOString().slice(11,19):'-')+'</span><span class="e" style="font-size:11px">'+esc(e.event_type||'-')+'</span></div>').join(''):
      '<div class="empty" style="padding:12px">Geen gebeurtenissen</div>')+
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

const TOTP_NAMES={active:'actief',pending:'in afwachting',none:'geen'};
function totpBadge(u){
  const req=u.totp_required,st=u.totp_status;
  if(req&&st!=='active')return '<span class="chip required-missing">verplicht, ontbreekt</span>';
  if(req&&st==='active')return '<span class="chip required-ok">verplicht, actief</span>';
  return '<span class="chip '+esc(st)+'">'+esc(TOTP_NAMES[st]||st)+'</span>';
}
function openForceTotpModal(key,email,currentlyRequired){
  _ms.forceTotp={key,email,removing:currentlyRequired};
  document.getElementById('mo-force-totp-title').textContent=(currentlyRequired?'TOTP-verplichting opheffen':'TOTP verplicht stellen')+(email?': '+email:'');
  document.getElementById('mo-force-totp-body').innerHTML=currentlyRequired
    ?'<p style="font-size:13px;color:#475569;margin:0">De TOTP-verplichting vervalt. De gebruiker kan inloggen zonder TOTP, of zijn bestaande authenticator blijven gebruiken.</p>'
    :'<p style="font-size:13px;color:#475569;margin:0 0 10px">Deze gebruiker moet TOTP instellen voor de volgende keer inloggen.</p><ul style="font-size:13px;color:#475569;margin:0 0 14px;padding-left:18px"><li>Actieve sessies worden direct ingetrokken</li><li>Er gaat automatisch een e-mail met de instelling uit</li><li>Inloggen is geblokkeerd tot de instelling klaar is</li></ul><div class="mc"><label>Reden (optioneel, voor de auditlog)</label><input type="text" id="ft-reason" placeholder="bijv. beleid"></div>';
  const btn=document.getElementById('ft-btn');
  btn.textContent=currentlyRequired?'Verplichting opheffen':'TOTP verplicht stellen';
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
    const msg=required?'TOTP is verplicht. Sessies ingetrokken: '+(d.sessions_revoked||0)+(d.setup_email_sent?'. E-mail met de instelling verstuurd.':'.'):'TOTP-verplichting opgeheven.';
    toast(msg,'ok');LOADED.users=false;setTimeout(loadUsers,500);
  } else { toast('Mislukt: '+(r.data?.error||'onbekend'),'err'); }
}


act('click','doLogin',()=>doLogin());act('click','doLogout',()=>doLogout());
act('click','switchTab',(el)=>switchTab(el.dataset.tab));
act('click','closeModal',(el)=>closeModal(el.dataset.modal));
act('click','epTab',(el)=>epTab(el.dataset.arg,el));
act('click','doSendEmail',()=>doSendEmail());act('click','doChangePlan',()=>doChangePlan());
act('click','doDisableKey',()=>doDisableKey());act('click','doDeleteAccount',()=>doDeleteAccount());
act('click','doForceTotpRequirement',()=>doForceTotpRequirement());act('click','doCreateKey',()=>doCreateKey());
act('click','doCreateCoupon',()=>doCreateCoupon());act('click','doRevokeCoupon',(el)=>doRevokeCoupon(el));act('click','fetchCoupons',()=>fetchCoupons());
act('click','showNewKeyModal',()=>showNewKeyModal());act('click','exportAuditCSV',()=>exportAuditCSV());
act('click','fetchAudit',()=>fetchAudit());act('click','fetchRelay',()=>fetchRelay());
act('click','uAction',(el)=>uAction(el.dataset.uact,el));
act('click','toggleMenu',(el,ev)=>toggleMenu(ev,el.dataset.menu));
act('click','usersPage',(el)=>loadUsers(parseInt(el.dataset.page,10)));
act('click','closeCreateKey',(el)=>{const m=el.closest('[data-modal]');if(m)m.remove();});
act('change','filterUsers',()=>filterUsers());act('input','filterUsers',()=>filterUsers());
act('change','usersPageSize',(el)=>loadUsers(1,parseInt(el.value,10)));
act('input','confirmDelete',(el)=>{const b=document.getElementById('da-btn');if(b)b.disabled=el.value!=='DEACTIVATE';});
