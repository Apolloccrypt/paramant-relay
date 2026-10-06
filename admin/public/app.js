'use strict';
/* Het beheerscherm van Paramant, voor één eigenaar, op telefoon en desktop.
   Wat erop staat beantwoordt drie vragen: brandt er iets, verdien ik iets, en
   wie deed wat. De server (admin/server.js met lib/beheer.js) vertaalt de ruwe
   opslag al naar zinnen en getallen; dit bestand zet ze neer en maakt elk getal
   klikbaar naar de details. Een volle sleutel komt hier nooit binnen: rijen
   dragen de kid (k_<hex>) als handvat en de sleutel gemaskeerd.

   CSP-veilige event delegation: elementen dragen data-click / data-change /
   data-input = "actienaam"; één set listeners op document roept het register
   onderaan aan, zodat script-src zonder 'unsafe-inline' kan. Geregistreerd
   VOOR de listener die het menu sluit, zodat toggleMenu's
   stopImmediatePropagation() wint. */
const ACTIONS = { click: {}, change: {}, input: {} };
function act(type, name, fn) { ACTIONS[type][name] = fn; }
function _delegate(type) {
  const attr = 'data-' + type;
  return function (ev) {
    const el = ev.target && ev.target.closest ? ev.target.closest('[' + attr + ']') : null;
    if (!el) return;
    const fn = ACTIONS[type][el.getAttribute(attr)];
    if (fn) fn(el, ev);
  };
}
document.addEventListener('click', _delegate('click'));
document.addEventListener('change', _delegate('change'));
document.addEventListener('input', _delegate('input'));

/* ── Toestand ────────────────────────────────────────────────────────────── */
let SESSION = sessionStorage.getItem('adm_session') || '';
let LOADED = {};
let REFRESH = {};
let openMenu = null;
const TABS = ['overview', 'users', 'audit', 'billing', 'relay'];

/* ── Hulpjes ─────────────────────────────────────────────────────────────── */
function esc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function toast(msg,type=''){const el=document.createElement('div');el.className='toast'+(type?' '+type:'');el.textContent=msg;el.setAttribute('role','status');document.body.appendChild(el);requestAnimationFrame(()=>requestAnimationFrame(()=>el.classList.add('show')));setTimeout(()=>{el.classList.remove('show');setTimeout(()=>el.remove(),250);},3600);}
function showErr(msg){const e=document.getElementById('l-err');e.textContent=msg;e.style.display='block'}
function srAnnounce(msg){const el=document.getElementById('sr-live');if(el)el.textContent=msg;}
function loading(t){return '<div class="empty"><span class="sp-icon"></span>'+esc(t||'Laden…')+'</div>'}

async function api(path,opts={}){
  const r=await fetch('/admin/api'+path,{...opts,headers:{'X-Session':SESSION,'Content-Type':'application/json',...(opts.headers||{})}});
  const ct=(r.headers&&r.headers.get&&r.headers.get('content-type'))||'';
  const data=ct.includes('json')?await r.json().catch(()=>null):null;
  if(r.status===401&&SESSION&&!String(path).startsWith('/auth/')){sessionExpired();}
  return{ok:r.ok,status:r.status,data};
}
// Netwerkfout wordt een gewone weigering, zodat een tab nooit stil blijft hangen.
async function apiSafe(path,opts){try{return await api(path,opts||{});}catch{return{ok:false,status:0,data:null};}}

function toMs(ts){if(ts==null||ts==='')return 0;if(typeof ts==='number')return ts;const n=Number(ts);if(String(ts).trim()!==''&&Number.isFinite(n))return n;const p=Date.parse(ts);return Number.isFinite(p)?p:0;}
const MONTHS=['jan','feb','mrt','apr','mei','jun','jul','aug','sep','okt','nov','dec'];
function absTime(ms){if(!ms)return '-';const d=new Date(ms);const now=new Date();const t=String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0');const same=d.toDateString()===now.toDateString();const y=new Date(now);y.setDate(now.getDate()-1);if(same)return 'vandaag '+t;if(d.toDateString()===y.toDateString())return 'gisteren '+t;return d.getDate()+' '+MONTHS[d.getMonth()]+(d.getFullYear()!==now.getFullYear()?' '+d.getFullYear():'')+' '+t;}
function absDate(v){const ms=toMs(v);if(!ms)return '-';const d=new Date(ms);return d.getDate()+' '+MONTHS[d.getMonth()]+' '+d.getFullYear();}
function relTime(ms){if(!ms)return '';const s=Math.round((Date.now()-ms)/1000);const fut=s<0;const a=Math.abs(s);let t;
  if(a<45)t='zojuist';else if(a<3600)t=Math.round(a/60)+' min';else if(a<86400)t=Math.round(a/3600)+' uur';else if(a<86400*45)t=Math.round(a/86400)+(Math.round(a/86400)===1?' dag':' dagen');else t=Math.round(a/(86400*30))+' maanden';
  if(t==='zojuist')return t;return fut?'over '+t:t+' geleden';}
function whenCell(ms){return '<div class="when"><b>'+esc(absTime(ms))+'</b><span>'+esc(relTime(ms))+'</span></div>'}
function euro(c){if(c==null||!Number.isFinite(Number(c)))return 'niet gemeten';c=Math.round(Number(c));const neg=c<0;const a=Math.abs(c);return (neg?'-':'')+'€ '+String(Math.floor(a/100)).replace(/\B(?=(\d{3})+(?!\d))/g,'.')+','+String(a%100).padStart(2,'0');}
function amount(v,cur){if(v==null||v==='')return '-';const n=Number(v);if(!Number.isFinite(n))return esc(v);return euro(Math.round(n*100))+(cur&&cur!=='EUR'?' '+cur:'');}
function upTime(s){if(!Number.isFinite(s))return 'looptijd onbekend';const d=Math.floor(s/86400),h=Math.floor((s%86400)/3600),m=Math.floor((s%3600)/60);return (d?d+' d ':'')+(d||h?h+' u ':'')+m+' min in de lucht';}
const TIER_NL={free:'Community',community:'Community',pro:'Firm',business:'Business',enterprise:'Enterprise',trial:'Proef'};
function tierNL(t){return TIER_NL[t]||t||'-';}
function isPaidTier(t){return !!t&&!['free','community'].includes(t);}
function planLine(name,tier,until){const ms=toMs(until);let tail='';if(ms){tail=ms>Date.now()?' <span>tot '+esc(absDate(ms))+'</span>':' <span>afgelopen '+esc(absDate(ms))+'</span>';}
  return '<div class="plan-line">'+name+': <b>'+esc(tierNL(tier))+'</b>'+tail+'</div>';}
function sectorNL(s){return {main:'Main',health:'Health',legal:'Legal',finance:'Finance',iot:'IoT'}[s]||s;}
const LEVEL_NL={goed:'In orde',let_op:'Let op',kapot:'Kapot',niet_gemeten:'Niet gemeten',info:'Ter info'};
function stTag(level){return '<span class="st '+esc(level)+'">'+esc(LEVEL_NL[level]||level)+'</span>';}
const KEY_NL={admin_ip:'IP-adres beheerder (ingekort)',ip:'IP-adres (ingekort)',email:'E-mail',from:'Van',to:'Naar',product:'Product',tier:'Plan',reason:'Reden',notify:'Klant gemaild',count:'Aantal',mode:'Manier',before:'Was verplicht',after:'Nu verplicht',code:'Code',max:'Maximaal',via:'Via',envelope:'Ondertekenverzoek',party:'Ondertekenaar',cancel_at:'Stopt op',plan:'Plan',age_sec:'Seconden na aanvraag',key_prefix:'Sleutel',backup_file:'Bestand',command:'Opdracht',args:'Invoer',error:'Fout',admin_id:'Door',stored:'Teller was',presented:'Teller kreeg',cred:'Passkey',envelopes_voided:'Verzoeken ingetrokken',ua:'Browser',ts:'Tijd',event:'Gebeurtenis',detail:'Detail',changed:'Gewijzigd'};
function valNL(v){if(v===true)return 'ja';if(v===false)return 'nee';if(v==null||v==='')return '-';if(typeof v==='object')return JSON.stringify(v);return String(v);}
function kvList(obj){const e=Object.entries(obj||{});if(!e.length)return '<div class="mut">Geen details opgeslagen.</div>';return '<dl class="kv">'+e.map(([k,v])=>'<dt>'+esc(KEY_NL[k]||k.replace(/_/g,' '))+'</dt><dd>'+esc(valNL(v))+'</dd>').join('')+'</dl>';}

/* ── Inloggen ────────────────────────────────────────────────────────────── */
async function doLogin(){
  const token=document.getElementById('l-token').value.trim();
  const totp=document.getElementById('l-totp').value.replace(/\D/g,'');
  if(!token){showErr('Vul je beheertoken in.');return}
  if(totp.length!==6){showErr('De code uit je app heeft zes cijfers.');return}
  const btn=document.getElementById('l-btn');
  btn.disabled=true;btn.textContent='Bezig met inloggen…';
  document.getElementById('l-err').style.display='none';
  let r,d={};
  try{r=await fetch('/admin/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,totp})});d=await r.json().catch(()=>({}));}catch{r={ok:false};}
  if(!r.ok||!d.session){
    showErr(r.status===429?'Te vaak geprobeerd. Wacht een minuut en probeer het opnieuw.':'Inloggen lukte niet. Klopt het token, en is de code nog geldig?');
    btn.disabled=false;btn.textContent='Inloggen';return;
  }
  SESSION=d.session;
  sessionStorage.setItem('adm_session',SESSION);
  showDashboard();
}
function showDashboard(){
  document.getElementById('view-login').style.display='none';
  document.getElementById('view-dashboard').style.display='flex';
  const hash=location.hash.replace('#','');
  switchTab(TABS.includes(hash)?hash:'overview');
}
function sessionExpired(){
  SESSION='';sessionStorage.removeItem('adm_session');
  LOADED={};Object.values(REFRESH).forEach(clearInterval);REFRESH={};
  document.getElementById('view-dashboard').style.display='none';
  document.getElementById('view-login').style.display='flex';
  const b=document.getElementById('l-btn');if(b){b.disabled=false;b.textContent='Inloggen';}
  showErr('Je sessie is verlopen. Log opnieuw in.');
}
async function doLogout(){
  await api('/auth/logout',{method:'POST'}).catch(()=>{});
  SESSION='';sessionStorage.removeItem('adm_session');
  LOADED={};Object.values(REFRESH).forEach(clearInterval);REFRESH={};
  document.getElementById('view-dashboard').style.display='none';
  document.getElementById('view-login').style.display='flex';
  document.getElementById('l-token').value='';
  document.getElementById('l-totp').value='';
  const b=document.getElementById('l-btn');if(b){b.disabled=false;b.textContent='Inloggen';}
}

/* ── Tabbladen ───────────────────────────────────────────────────────────── */
const TAB_NL={overview:'Overzicht',users:'Klanten',audit:'Audit',billing:'Betalingen',relay:'Relays'};
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
  srAnnounce(TAB_NL[tab]+' laden');
  const more=document.querySelector&&document.querySelector('.more');if(more)more.removeAttribute('open');
  if(!LOADED[tab]){LOADED[tab]=true;loadTab(tab);}
}
function loadTab(tab){
  if(tab==='overview')loadOverview();
  else if(tab==='users')loadUsers();
  else if(tab==='audit')loadAudit();
  else if(tab==='billing')loadBilling();
  else if(tab==='relay')loadRelay();
}
// Van een getal naar zijn details: tab openen en zo nodig een filter zetten.
let PENDING_AUDIT=null;
function goTo(el){
  const tab=el.dataset.tab;
  if(tab==='audit'&&(el.dataset.event||el.dataset.q!==undefined||el.dataset.since)){
    PENDING_AUDIT={event:el.dataset.event||'',q:el.dataset.q||'',since:el.dataset.since||''};
    if(LOADED.audit){applyPendingAudit();fetchAudit();}
  }
  if(tab)switchTab(tab);
  if(el.dataset.focus){setTimeout(()=>{const t=document.getElementById(el.dataset.focus);if(t&&t.scrollIntoView)t.scrollIntoView({behavior:'smooth',block:'start'});},400);}
}

/* ── Overzicht ───────────────────────────────────────────────────────────── */
let OV_PREV={};
async function loadOverview(){
  const el=document.getElementById('tab-overview');
  if(!el.innerHTML)el.innerHTML=loading('Overzicht laden…');
  const r=await apiSafe('/admin/overview');
  if(!r.ok){el.innerHTML='<div class="empty">Het overzicht kwam niet terug. <button class="lnk" data-click="reloadTab" data-tab="overview">Opnieuw proberen</button></div>';return}
  renderOverview(el,r.data||{});
  clearInterval(REFRESH.overview);
  REFRESH.overview=setInterval(()=>{if(document.getElementById('tab-overview').classList.contains('on'))apiSafe('/admin/overview').then(x=>{if(x.ok)renderOverview(el,x.data||{});});},30000);
}
function statCard(id,lbl,val,sub,attrs){
  return '<button class="sc" id="'+id+'" data-click="goTo" '+(attrs||'')+'><div class="sc-lbl">'+esc(lbl)+'</div><div class="sc-val">'+esc(val)+'</div>'+(sub?'<div class="sc-sub">'+esc(sub)+'</div>':'')+'</button>';
}
function monthName(ym){if(!ym)return 'deze maand';const m=Number(String(ym).slice(5,7));return ['januari','februari','maart','april','mei','juni','juli','augustus','september','oktober','november','december'][m-1]||ym;}
function renderOverview(el,d){
  const st=d.stats||{},cu=d.customers||{},rev=d.revenue,probs=d.problems||[];
  const order={kapot:0,niet_gemeten:1,let_op:2,goed:3};
  const worst=probs.slice().sort((a,b)=>order[a.level]-order[b.level])[0];
  const bad=probs.filter(p=>p.level!=='goed');
  let sign;
  if(!worst)sign='<div class="sign niet_gemeten">Er kwam geen enkele meting terug.</div>';
  else if(worst.level==='goed')sign='<div class="sign goed">Alles in orde. Alle relays antwoorden en er staat niets open.</div>';
  else sign='<div class="sign '+esc(worst.level==='kapot'?'kapot':worst.level==='let_op'?'':'niet_gemeten')+'">'+esc((worst.level==='kapot'?'Er is iets kapot: ':worst.level==='let_op'?'Let op: ':'Niet gemeten: ')+worst.title)+(bad.length>1?' (en nog '+(bad.length-1)+')':'')+'</div>';
  const vals={
    'ov-klanten':String(cu.total??'-'),
    'ov-betalend':cu.paying==null?'niet gemeten':String(cu.paying),
    'ov-omzet':rev?euro(rev.net_cents):'niet gemeten',
    'ov-signups':String(st.signups_today??0),
  };
  el.innerHTML=
    '<h1 class="h1">Overzicht</h1><p class="lead">Wat je nu moet weten. Tik op een getal voor de details.</p>'+sign+
    '<div class="sg">'+
      statCard('ov-klanten','Klanten',vals['ov-klanten'],(cu.active??'-')+' actief, '+(cu.on_paid_plan??'-')+' op een betaald plan','data-tab="users"')+
      statCard('ov-betalend','Betalende klanten',vals['ov-betalend'],'met een betaalde periode die nu loopt','data-tab="billing" data-focus="b-terms"')+
      statCard('ov-omzet','Omzet '+monthName(rev&&rev.month),vals['ov-omzet'],rev?('MRR '+euro(rev.mrr_cents)+' per maand, netto'):'documenten niet te lezen','data-tab="billing"')+
      statCard('ov-signups','Aanmeldingen vandaag',vals['ov-signups'],(st.active_sessions??0)+' klantsessies open','data-tab="users"')+
    '</div>'+
    '<div class="g2">'+
      '<div class="card"><div class="card-hdr">Openstaande punten <small>'+(bad.length?bad.length+' vraagt aandacht':'niets open')+'</small></div>'+
        probs.map(p=>'<button class="pr '+esc(p.level)+'" data-click="openProblem" data-id="'+esc(p.id)+'" data-tab="'+esc(p.tab||'')+'"><div><b>'+esc(p.title)+'</b><span class="t">'+esc(p.text)+'</span></div>'+stTag(p.level)+'</button>').join('')+
      '</div>'+
      '<div class="card"><div class="card-hdr">Relays <small><button class="lnk" data-click="goTo" data-tab="relay">alles over de relays</button></small></div>'+
        '<div class="rs" style="grid-template-columns:1fr 1fr">'+(d.relays||[]).map(r=>
          '<button class="ri'+(r.ok?'':' offline')+'" data-click="openRelay" data-sector="'+esc(r.sector)+'"><div class="ri-name">'+esc(r.sector)+'</div><div class="ri-det">'+(r.ok?'v'+esc(r.version||'?')+' · '+esc(upTime(r.uptime_s)):'antwoordt niet: '+esc(r.error||''))+'</div></button>').join('')+'</div>'+
      '</div>'+
    '</div>'+
    '<div class="g2">'+
      '<div class="card"><div class="card-hdr">Laatste aanmeldingen <small><button class="lnk" data-click="goTo" data-tab="users">alle klanten</button></small></div>'+
        ((d.recent_signups||[]).length?'<ul class="ls">'+d.recent_signups.map(u=>'<li><div>'+(u.kid?'<button class="lnk" data-click="openKlant" data-kid="'+esc(u.kid)+'">'+esc(u.name)+'</button>':esc(u.name))+'<div class="mut" style="font-size:13px">ParaSign '+esc(tierNL(u.plan_parasign))+' · ParaSend '+esc(tierNL(u.plan_parasend))+'</div></div><div class="r">'+whenCell(toMs(u.created))+'</div></li>').join('')+'</ul>':'<div class="empty">Nog geen klanten.</div>')+
      '</div>'+
      '<div class="card"><div class="card-hdr">Laatste betalingen <small><button class="lnk" data-click="goTo" data-tab="billing">alle betalingen</button></small></div>'+
        (d.recent_payments==null?'<div class="empty">De betaaldocumenten waren niet te lezen.</div>':d.recent_payments.length?'<ul class="ls">'+d.recent_payments.map(p=>'<li><div>'+(p.kid?'<button class="lnk" data-click="openKlant" data-kid="'+esc(p.kid)+'">'+esc(p.customer||'Klant')+'</button>':esc(p.customer||'Klant'))+'<div class="mut" style="font-size:13px">'+esc(p.status_nl)+'</div></div><div class="r"><b>'+amount(p.amount_gross,p.currency)+'</b><div class="mut" style="font-size:13px">'+esc(absDate(p.date))+'</div></div></li>').join('')+'</ul>':'<div class="empty">Nog geen betalingen ontvangen.</div>')+
      '</div>'+
    '</div>'+
    '<div class="g2">'+
      '<div class="card"><div class="card-hdr">Laatst gebeurd <small><button class="lnk" data-click="goTo" data-tab="audit">hele audit</button></small></div>'+
        ((d.recent_activity||[]).length?'<ul class="ls">'+d.recent_activity.slice(0,8).map(a=>'<li><div><b style="font-weight:500">'+esc(a.label)+'</b><div class="mut" style="font-size:13px">'+esc(a.who)+(a.summary?' · '+esc(a.summary):'')+'</div></div><div class="r mut" style="font-size:13px">'+esc(relTime(a.ts))+'</div></li>').join('')+'</ul>':'<div class="empty">Nog niets gebeurd.</div>')+
      '</div>'+
      '<div class="card"><div class="card-hdr">Plannen <small>actieve accounts, per account</small></div>'+planBars(d.plan_distribution||{})+'</div>'+
    '</div>';
  // Een getal dat sinds de vorige keer veranderde licht even op: zo zie je wat er nieuw is.
  for(const [id,v] of Object.entries(vals)){if(OV_PREV[id]!==undefined&&OV_PREV[id]!==v){const c=document.getElementById(id);if(c)c.classList.add('flash');}}
  OV_PREV=vals;
}
function planBars(dist){
  const total=Object.values(dist).reduce((a,b)=>a+b,0)||1;
  return ['community','pro','business','enterprise','trial'].filter(p=>p in dist||p!=='trial').map(p=>{
    const n=dist[p]||0;
    return '<div class="pb" style="display:flex;align-items:center;gap:10px;margin-bottom:8px"><span style="width:96px">'+esc(tierNL(p))+'</span><div style="flex:1;height:8px;background:var(--line-2);border-radius:4px;overflow:hidden"><div style="height:100%;background:var(--ink);width:'+(n/total*100).toFixed(1)+'%"></div></div><span style="width:28px;text-align:right">'+n+'</span></div>';
  }).join('');
}
function openProblem(el){
  const id=el.dataset.id;
  if(id==='mails'||id==='http429'){openFailures(id);return}
  if(el.dataset.tab)switchTab(el.dataset.tab);
}
async function openFailures(focus){
  const body=document.getElementById('mo-info-body');
  document.getElementById('mo-info-title').textContent=focus==='mails'?'Mislukte mails':'Te veel verzoeken (429)';
  body.innerHTML=loading();openModal('mo-info');
  const r=await apiSafe('/admin/overview/failures');
  if(!r.ok){body.innerHTML='<div class="empty">Kwam niet terug.</div>';return}
  const list=focus==='mails'?(r.data.mails||[]):(r.data.http429||[]);
  const intro=focus==='mails'
    ?'<p class="lead">De laatste twintig mails die de beheerkant niet kwijt kon, met de reden van de verzender. Adressen worden niet bewaard.</p>'
    :'<p class="lead">De laatste twintig keer dat deze dienst "te veel verzoeken" antwoordde. Het pad is ingekort tot zijn vaste delen.</p>';
  body.innerHTML=intro+(list.length?'<table class="tbl cards"><thead><tr><th>Wanneer</th>'+(focus==='mails'?'<th>Kenmerk</th><th>Reden</th>':'<th>Verzoek</th>')+'</tr></thead><tbody>'+list.map(x=>'<tr><td data-label="Wanneer">'+whenCell(x.ts)+'</td>'+(focus==='mails'?'<td data-label="Kenmerk" class="mono" title="Vingerafdruk van het onderwerp; het onderwerp zelf wordt niet bewaard">'+esc(x.subject_fp||'-')+'</td><td data-label="Reden">'+esc((x.reason||'onbekend')+(x.provider?' via '+x.provider:''))+'</td>':'<td data-label="Verzoek" class="mono">'+esc(x.method+' '+x.path)+'</td>')+'</tr>').join('')+'</tbody></table>':'<div class="empty">Niets gevonden in de laatste drie dagen.</div>');
}

/* ── Klanten ─────────────────────────────────────────────────────────────── */
let allUsers=[],userCounts={},userQuery='',userPagination={page:1,page_size:50,total_items:0,total_pages:1,has_next:false,has_prev:false};
async function loadUsers(page,pageSize){
  const el=document.getElementById('tab-users');
  if(page!==undefined)userPagination.page=page;
  if(pageSize!==undefined)userPagination.page_size=pageSize;
  if(!document.getElementById('u-table-wrap'))el.innerHTML=loading('Klanten laden…');
  const r=await apiSafe('/admin/users?page='+userPagination.page+'&page_size='+userPagination.page_size+(userQuery?'&q='+encodeURIComponent(userQuery):''));
  if(!r.ok){el.innerHTML='<div class="empty">De klantenlijst kwam niet terug. <button class="lnk" data-click="reloadTab" data-tab="users">Opnieuw proberen</button></div>';return}
  allUsers=r.data.users||[];
  userCounts=r.data.counts||{};
  if(r.data.pagination)Object.assign(userPagination,r.data.pagination);
  renderUsers(el);
}
function renderUsers(el){
  const pg=userPagination,counts=userCounts;
  const prev={q:document.getElementById('u-search')?.value||userQuery,plan:document.getElementById('u-plan')?.value||'',totp:document.getElementById('u-totp')?.value||'',status:document.getElementById('u-status')?.value||''};
  el.innerHTML=
    '<div class="card"><div class="card-hdr">Klanten <small>'+(counts.total??0)+' totaal · '+(counts.active??0)+' actief</small>'+
      '<button class="btn out" data-click="showNewKeyModal">Nieuwe sleutel</button>'+
    '</div>'+
    '<div class="fb">'+
      '<label for="u-search" class="sr-only">Zoek een klant</label>'+
      '<input id="u-search" type="search" placeholder="Zoek op e-mailadres of label" data-input="filterUsers" style="min-width:260px" value="'+esc(prev.q)+'" autocomplete="off" autocapitalize="off">'+
      '<select id="u-plan" aria-label="Plan" data-change="filterUsers"><option value="">Elk plan</option><option value="community">Community</option><option value="pro">Firm</option><option value="business">Business</option><option value="enterprise">Enterprise</option></select>'+
      '<select id="u-totp" aria-label="Tweestapsverificatie" data-change="filterUsers"><option value="">Tweestaps: alles</option><option value="active">Tweestaps aan</option><option value="pending">Ingesteld, niet bevestigd</option><option value="none">Tweestaps uit</option></select>'+
      '<select id="u-status" aria-label="Status" data-change="filterUsers"><option value="">Elke status</option><option value="active">Actief</option><option value="revoked">Ingetrokken</option></select>'+
    '</div>'+
    '<div id="u-table-wrap"></div>'+
    '<div class="pag" aria-label="Pagina’s">'+
      '<button data-click="usersPage" data-page="'+(pg.page-1)+'" '+(pg.has_prev?'':'disabled')+'>Vorige</button>'+
      '<span class="pag-info">Pagina '+pg.page+' van '+pg.total_pages+' ('+pg.total_items+' klanten)</span>'+
      '<button data-click="usersPage" data-page="'+(pg.page+1)+'" '+(pg.has_next?'':'disabled')+'>Volgende</button>'+
      '<select aria-label="Rijen per pagina" data-change="usersPageSize">'+[25,50,100,200].map(n=>'<option value="'+n+'" '+(pg.page_size==n?'selected':'')+'>'+n+' per pagina</option>').join('')+'</select>'+
    '</div>'+
    '</div>';
  for(const k of ['plan','totp','status']){const s=document.getElementById('u-'+k);if(s)s.value=prev[k];}
  filterUsers(true);
}
let _userSearchT=null;
function filterUsers(noServer){
  const q=(document.getElementById('u-search')?.value||'').trim().toLowerCase();
  const plan=document.getElementById('u-plan')?.value||'';
  const totp=document.getElementById('u-totp')?.value||'';
  const status=document.getElementById('u-status')?.value||'';
  let filtered=allUsers;
  if(q)filtered=filtered.filter(u=>[u.email,u.label,u.usage_purpose,u.key_id].some(v=>String(v||'').toLowerCase().includes(q)));
  if(plan)filtered=filtered.filter(u=>(u.plan||'community')===plan);
  if(totp)filtered=filtered.filter(u=>u.totp_status===totp);
  if(status==='active')filtered=filtered.filter(u=>u.active);
  else if(status==='revoked')filtered=filtered.filter(u=>!u.active);
  const w=document.getElementById('u-table-wrap');if(w)w.innerHTML=usersTable(filtered);
  // Staan er meer klanten dan op deze pagina, dan zoekt de server ook mee.
  if(noServer!==true&&(userPagination.total_pages>1||userQuery)&&q!==userQuery){
    clearTimeout(_userSearchT);
    _userSearchT=setTimeout(()=>{userQuery=q;loadUsers(1);},350);
  }
}
const PURPOSE_LABELS={personal:'Privégebruik',organisation:'Voor een organisatie',client_management:'Beheert voor klanten',research_journalism:'Onderzoek of journalistiek',skipped:'Niet ingevuld'};
function totpBadge(u){
  const req=u.totp_required,st=u.totp_status;
  if(req&&st!=='active')return '<span class="chip required-missing">Verplicht, nog niet ingesteld</span>';
  if(req&&st==='active')return '<span class="chip required-ok">Aan (verplicht)</span>';
  return '<span class="chip '+esc(st)+'">'+({active:'Aan',pending:'Ingesteld, niet bevestigd',none:'Uit'}[st]||esc(st))+'</span>';
}
function usersTable(users){
  if(!users.length)return '<div class="empty">Geen klant gevonden met deze zoekopdracht.</div>';
  return '<table class="tbl cards" aria-label="Klanten"><thead><tr><th>Klant</th><th>Plan per product</th><th>Laatste activiteit</th><th>Gebruik deze maand</th><th>Status</th><th><span class="sr-only">Acties</span></th></tr></thead><tbody>'+
    users.map((u,i)=>{
      const ki=esc(u.key_id||u.key),em=esc(u.email||''),pl=esc(u.plan||'community');
      const hasE=!!u.email,hasTotp=hasE&&u.totp_status!=='none',isRevoked=!u.active;
      const la=u.last_activity;
      const use=u.usage_month;
      return '<tr>'+
        '<td data-label="Klant" class="who">'+(u.key_id?'<button class="lnk" data-click="openKlant" data-kid="'+esc(u.key_id)+'"><b>'+esc(u.email||u.label||'Zonder e-mailadres')+'</b></button>':'<b>'+esc(u.email||'-')+'</b>')+
          (u.label&&u.email?'<div class="mut" style="font-size:13px">'+esc(u.label)+'</div>':'')+
          (u.usage_purpose?'<div class="mut" style="font-size:13px">'+esc(PURPOSE_LABELS[u.usage_purpose]||u.usage_purpose)+'</div>':'')+'</td>'+
        '<td data-label="Plan">'+planLine('ParaSign',u.plan_parasign,u.paid_until_parasign)+planLine('ParaSend',u.plan_parasend,u.paid_until_parasend)+
          (u.parasign?'<div class="mut" style="font-size:13px">ParaSign-API aan'+(u.parasign_keys?', '+u.parasign_keys+' sleutel'+(u.parasign_keys===1?'':'s'):'')+'</div>':'')+'</td>'+
        '<td data-label="Laatste activiteit">'+(la?'<div class="when"><b>'+esc(relTime(la.ts))+'</b><span>'+esc(la.label)+'</span></div>':'<span class="mut">Nog niets</span>')+'</td>'+
        '<td data-label="Gebruik">'+(use?'<span style="white-space:nowrap">'+esc(use.transfers??'-')+' verzonden</span><br><span style="white-space:nowrap">'+esc(use.signs??'-')+' getekend</span>':'<span class="mut">niet gemeten</span>')+'</td>'+
        '<td data-label="Status"><div class="chip '+(u.active?'active':'revoked')+'">'+(u.active?'Actief':'Ingetrokken')+'</div><div style="font-size:13px">Tweestaps: '+totpBadge(u)+'</div><div class="mut" style="font-size:13px">sinds '+esc(absDate(u.created))+'</div></td>'+
        '<td class="actions"><div class="amw">'+
          '<button class="amb" aria-haspopup="menu" aria-expanded="false" aria-label="Acties voor '+esc(u.email||u.label||'klant')+'" data-click="toggleMenu" data-menu="m'+i+'">···</button>'+
          menuHtml('m'+i,u,{ki,em,pl,hasE,hasTotp,isRevoked})+
        '</div></td>'+
      '</tr>';
    }).join('')+'</tbody></table>';
}
function menuHtml(id,u,o,inline){
  return '<div class="am'+(inline?' open klant-acts':'')+'" role="menu" id="'+id+'" data-key="'+o.ki+'" data-email="'+o.em+'" data-plan="'+o.pl+'" data-label="'+esc(u.label||'')+'" data-created="'+esc(u.created||'')+'" data-totp-req="'+(u.totp_required?'true':'false')+'" data-parasign="'+(u.parasign?'true':'false')+'" data-pp-sign="'+esc(u.plan_parasign||'')+'" data-pp-send="'+esc(u.plan_parasend||'')+'">'+
    (inline?'':'<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="details">Alles over deze klant</button>')+
    '<div class="ag-lbl">Mail</div>'+
    '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="welcome"'+(o.hasE?'':' disabled')+'>Welkomstmail sturen</button>'+
    '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="setup"'+(o.hasE?'':' disabled')+'>Link voor authenticator-app sturen</button>'+
    '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="reset-totp"'+(o.hasTotp?'':' disabled')+'>Tweestaps resetten</button>'+
    '<div class="ag-lbl">Account</div>'+
    '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="plan">Plan wijzigen</button>'+
    '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="revoke-sessions">Overal uitloggen</button>'+
    '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="force-totp">'+(u.totp_required?'Tweestaps niet meer verplichten':'Tweestaps verplicht maken')+'</button>'+
    '<div class="ag-lbl">ParaSign-API</div>'+
    '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="parasign-toggle">'+(u.parasign?'ParaSign-API uitzetten':'ParaSign-API aanzetten')+'</button>'+
    '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="parasign-onboard"'+(o.hasE?'':' disabled')+'>ParaSign-startmail sturen</button>'+
    '<div class="ag-lbl">Onomkeerbaar</div>'+
    '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="disable" class="danger"'+(o.isRevoked?' disabled':'')+'>Sleutel uitzetten</button>'+
    '<button role="menuitem" tabindex="-1" data-click="uAction" data-uact="delete" class="danger">Account deactiveren</button>'+
  '</div>';
}

function toggleMenu(e,id){
  e.stopImmediatePropagation();
  const m=document.getElementById(id);
  // De klik is gedelegeerd, dus e.currentTarget is het document en heeft geen
  // setAttribute (ADMIN-07-G). De knop van het menu staat er direct voor.
  const btn=(m&&m.previousElementSibling&&m.previousElementSibling.setAttribute)?m.previousElementSibling:{setAttribute(){}};
  const wasOpen=m.classList.contains('open');
  closeOpenMenu();
  if(!wasOpen){
    m.classList.add('open');openMenu=m;
    btn.setAttribute('aria-expanded','true');
    const first=m.querySelector('[role=menuitem]:not([disabled])');if(first)first.focus();
  }
}
function closeOpenMenu(){if(openMenu){openMenu.classList.remove('open');const ob=openMenu.previousElementSibling;if(ob&&ob.setAttribute)ob.setAttribute('aria-expanded','false');openMenu=null;}}
document.addEventListener('click',()=>closeOpenMenu());
document.addEventListener('keydown',e=>{
  if(['ArrowLeft','ArrowRight','Home','End'].includes(e.key)){
    const focused=document.activeElement;
    if(focused&&focused.getAttribute&&focused.getAttribute('role')==='tab'){
      const tabs=Array.from(document.querySelectorAll('[role=tab]'));
      const idx=tabs.indexOf(focused);
      let n=null;
      if(e.key==='ArrowRight'&&idx<tabs.length-1)n=tabs[idx+1];
      if(e.key==='ArrowLeft'&&idx>0)n=tabs[idx-1];
      if(e.key==='Home')n=tabs[0];
      if(e.key==='End')n=tabs[tabs.length-1];
      if(n){e.preventDefault();n.focus();n.click();}
    }
  }
  if(e.key==='Escape'){
    if(openMenu){const btn=openMenu.previousElementSibling;closeOpenMenu();if(btn&&btn.focus)btn.focus();return}
    const mo=Array.from(document.querySelectorAll('.mo')).filter(m=>m.style.display==='flex').pop();
    if(mo)closeModal(mo.id);
  }
  if((e.key==='ArrowDown'||e.key==='ArrowUp')&&openMenu){
    const items=Array.from(openMenu.querySelectorAll('[role=menuitem]:not([disabled])'));
    const ci=items.indexOf(document.activeElement);
    if(e.key==='ArrowDown'){e.preventDefault();items[(ci+1)%items.length].focus();}
    if(e.key==='ArrowUp'){e.preventDefault();items[(ci-1+items.length)%items.length].focus();}
  }
});

function uAction(action,btn){
  const m=btn.closest('.am');
  const key=m.dataset.key,email=m.dataset.email,plan=m.dataset.plan;
  const who=email||'deze klant';
  closeOpenMenu();
  switch(action){
    case 'details': openUserDetailsModal(key); break;
    case 'force-totp': openForceTotpModal(key,email,m.dataset.totpReq==='true'); break;
    case 'welcome': openEmailPreviewModal('welcome',key,email); break;
    case 'setup':   openEmailPreviewModal('setup',key,email); break;
    case 'reset-totp': openEmailPreviewModal('reset-confirm',key,email); break;
    case 'plan':    openChangePlanModal(key,email,plan,m.dataset.ppSign,m.dataset.ppSend); break;
    case 'revoke-sessions':
      if(!confirm(who+' overal uitloggen? Alle open sessies stoppen meteen.'))return;
      api('/admin/revoke-sessions',{method:'POST',body:JSON.stringify({key})}).then(r=>{
        toast(r.ok?'Uitgelogd op '+(r.data?.revoked||0)+' plek(ken)':'Mislukt: '+(r.data?.error||'onbekend'),r.ok?'ok':'err');
      });
      break;
    case 'parasign-toggle': {
      const enabled=m.dataset.parasign!=='true';
      if(!confirm('ParaSign-API '+(enabled?'aanzetten':'uitzetten')+' voor '+who+'?'))return;
      api('/admin/set-parasign',{method:'POST',body:JSON.stringify({key,enabled})}).then(r=>{
        toast(r.ok?('ParaSign-API '+(enabled?'aangezet':'uitgezet')):'Mislukt: '+(r.data?.error||'onbekend'),r.ok?'ok':'err');
        if(r.ok){LOADED.users=false;loadUsers();refreshKlant(key);}
      });
      break;
    }
    case 'parasign-onboard':
      if(!confirm('ParaSign-startmail sturen naar '+who+'?'))return;
      api('/admin/send-parasign-onboarding',{method:'POST',body:JSON.stringify({key})}).then(r=>{
        toast(r.ok?'ParaSign-startmail verstuurd':'Mislukt: '+(r.data?.error||'onbekend'),r.ok?'ok':'err');
      });
      break;
    case 'disable': openDisableKeyModal(key,email); break;
    case 'delete':  openDeleteAccountModal(key,email,m); break;
  }
}
function showNewKeyModal(){
  const o=document.createElement('div');
  o.className='mo';o.style.display='flex';
  o.innerHTML='<div class="mb"><div class="mh"><span class="mt">Nieuwe sleutel</span><button class="close-mo" data-click="closeCreateKey" aria-label="Sluiten">&times;</button></div><div class="mbody">'+
    '<div class="mc"><label for="nk-l">Label</label><input id="nk-l" type="text" placeholder="bijvoorbeeld bakkerij-jansen"></div>'+
    '<div class="mc"><label for="nk-p">Plan</label><select id="nk-p"><option value="community">Community</option><option value="pro" selected>Firm</option><option value="business">Business</option><option value="enterprise">Enterprise</option></select></div>'+
    '<div class="mc"><label for="nk-e">E-mailadres (mag leeg)</label><input id="nk-e" type="text" inputmode="email" autocapitalize="off" placeholder="klant@voorbeeld.nl"></div>'+
    '<div id="nk-res" style="margin-top:12px"></div></div>'+
    '<div class="mfoot"><button data-click="closeCreateKey" class="btn">Sluiten</button><button data-click="doCreateKey" class="btn pri">Sleutel maken</button></div></div>';
  o.dataset.modal='1';
  o.addEventListener('click',e=>{if(e.target===o)o.remove();});
  document.body.appendChild(o);
}
async function doCreateKey(){
  const label=document.getElementById('nk-l').value.trim();
  const plan=document.getElementById('nk-p').value;
  const email=document.getElementById('nk-e').value.trim();
  if(!label){toast('Geef de sleutel een label','err');return}
  const r=await api('/keys/all',{method:'POST',body:JSON.stringify({label,plan,email})});
  const res=document.getElementById('nk-res');
  if(r.ok&&r.data?.created?.length){
    const key=r.data.created[0]?.key||'(zie antwoord)';
    res.innerHTML='<div class="mono" style="background:var(--bg-2);border:1px solid var(--line);padding:12px;word-break:break-all;border-radius:4px">'+esc(key)+'</div>'+
      '<div style="color:var(--ok);margin-top:8px;font-weight:600">Sleutel aangemaakt. Bewaar hem nu: hij wordt maar één keer getoond.</div>';
    LOADED.users=false;
  }else{
    res.innerHTML='<div style="color:var(--bad)">Mislukt: '+esc(r.data?.failed?.[0]?.error||r.data?.error||'onbekend')+'</div>';
  }
}

/* ── De infopagina van één klant ─────────────────────────────────────────── */
let KLANT_OPEN=null;
function openKlant(el){openUserDetailsModal(el.dataset.kid);}
function refreshKlant(key){if(KLANT_OPEN&&KLANT_OPEN===key&&document.getElementById('mo-details').style.display==='flex')openUserDetailsModal(key);}
async function openUserDetailsModal(key){
  KLANT_OPEN=key;
  openModal('mo-details');
  document.getElementById('mo-details-title').textContent='Klant';
  const body=document.getElementById('mo-details-body');
  body.innerHTML=loading();
  const r=await apiSafe('/admin/user-details/'+encodeURIComponent(key));
  if(!r.ok){body.innerHTML='<div class="empty">Deze klant kwam niet terug ('+esc(r.data?.error||('status '+r.status))+').</div>';return;}
  const d=r.data;
  document.getElementById('mo-details-title').textContent=d.email||d.label||'Klant zonder e-mailadres';
  const totpNL={active:'aan',pending:'ingesteld, niet bevestigd',none:'uit'}[d.totp_status]||d.totp_status;
  const u={label:d.label,created:d.created,totp_required:d.totp_required,parasign:d.parasign,plan_parasign:d.plan_parasign,plan_parasend:d.plan_parasend};
  const o={ki:esc(d.key_id||key),em:esc(d.email||''),pl:esc(d.plan||'community'),hasE:!!d.email,hasTotp:!!d.email&&d.totp_status!=='none',isRevoked:!d.active};
  const use=d.usage,env=d.envelopes,pays=d.payments,aud=d.audit||[];
  body.innerHTML=
    '<div class="g2">'+
      '<div><h3 style="font-size:16px;margin-bottom:6px">Account</h3><dl class="kv">'+
        '<dt>E-mail</dt><dd>'+esc(d.email||'-')+'</dd>'+
        '<dt>Label</dt><dd>'+esc(d.label||'-')+'</dd>'+
        '<dt>Status</dt><dd>'+(d.active?'<span class="chip active">Actief</span>':'<span class="chip revoked">Ingetrokken</span>')+'</dd>'+
        '<dt>Klant sinds</dt><dd>'+esc(absDate(d.created))+' ('+esc(relTime(toMs(d.created)))+')</dd>'+
        '<dt>Tweestaps</dt><dd>Tweestapsverificatie '+esc(totpNL)+'</dd>'+
        '<dt>Sessies open</dt><dd>'+esc(d.active_sessions||0)+'</dd>'+
        (d.usage_purpose?'<dt>Gebruikt het voor</dt><dd>'+esc(PURPOSE_LABELS[d.usage_purpose]||d.usage_purpose)+'</dd>':'')+
      '</dl></div>'+
      '<div><h3 style="font-size:16px;margin-bottom:6px">Plannen</h3><dl class="kv">'+
        '<dt>ParaSign</dt><dd><b>'+esc(tierNL(d.plan_parasign))+'</b>'+(d.paid_until_parasign?' · betaald tot '+esc(absDate(d.paid_until_parasign)):(isPaidTier(d.plan_parasign)?' · zonder einddatum':''))+'</dd>'+
        '<dt>ParaSend</dt><dd><b>'+esc(tierNL(d.plan_parasend))+'</b>'+(d.paid_until_parasend?' · betaald tot '+esc(absDate(d.paid_until_parasend)):(isPaidTier(d.plan_parasend)?' · zonder einddatum':''))+'</dd>'+
        '<dt>Verlengt vanzelf</dt><dd>'+(d.auto_renews?'ja, Mollie incasseert opnieuw':'nee')+'</dd>'+
        '<dt>ParaSign-API</dt><dd>'+(d.parasign?'aan':'uit')+'</dd>'+
        '<dt>Oude plannaam</dt><dd>'+esc(d.plan||'community')+'</dd>'+
      '</dl></div>'+
    '</div>'+
    '<div class="sec"><h3>Acties</h3>'+menuHtml('klant-acts',u,o,true)+'</div>'+
    '<div class="sec"><h3>Gebruik deze maand <small>'+esc(use?.month||'')+'</small></h3>'+
      (use?'<dl class="kv"><dt>Verzonden</dt><dd>'+esc(use.transfers??'-')+(use.limits&&use.limits.transfers_month!=null?' van '+esc(use.limits.transfers_month):'')+'</dd><dt>Getekend</dt><dd>'+esc(use.signs??'-')+(use.limits&&use.limits.signs_month!=null?' van '+esc(use.limits.signs_month):'')+'</dd></dl>':'<div class="mut">Niet gemeten: de relay gaf geen telling.</div>')+'</div>'+
    '<div class="sec"><h3>Sleutels <small>gemaskeerd, de volle sleutel blijft op de server</small></h3>'+
      ((d.keys||[]).length?'<ul class="ls">'+d.keys.map(k=>'<li><div><b style="font-weight:500">'+esc(k.kind)+'</b>'+(k.label?' · '+esc(k.label):'')+'<div class="mono mut">'+esc(k.key_masked)+'</div></div><div class="r">'+(k.active?'<span class="chip active">Actief</span>':'<span class="chip revoked">Uit</span>')+(k.primary?'<div class="mut" style="font-size:13px">hoofdsleutel</div>':'')+'</div></li>').join('')+'</ul>':'<div class="mono">'+esc(d.key_masked||'')+'</div>')+'</div>'+
    '<div class="sec"><h3>Ondertekenverzoeken <small>'+(env?esc(env.total)+' in totaal':'')+'</small></h3>'+
      (env==null?'<div class="mut">Niet gemeten.</div>':env.recent.length?'<ul class="ls">'+env.recent.map(e=>'<li><div>'+esc(e.status_nl)+'<div class="mut" style="font-size:13px">'+esc(e.signed)+' van '+esc(e.parties)+' getekend</div></div><div class="r mut" style="font-size:13px">'+esc(absDate(e.created))+'</div></li>').join('')+'</ul>':'<div class="mut">Nog geen ondertekenverzoeken verstuurd.</div>')+'</div>'+
    '<div class="sec"><h3>Betalingen</h3>'+
      (pays==null?'<div class="mut">Niet gemeten.</div>':pays.length?'<ul class="ls">'+pays.map(p=>'<li><div>'+esc(p.kind_nl)+' '+esc(p.number)+'<div class="mut" style="font-size:13px">'+esc(p.status_nl)+'</div></div><div class="r"><b>'+amount(p.amount_gross,p.currency)+'</b><div class="mut" style="font-size:13px">'+esc(absDate(p.date))+'</div></div></li>').join('')+'</ul>':'<div class="mut">Nog nooit betaald.</div>')+'</div>'+
    '<div class="sec"><h3>Audit van deze klant <small>'+(d.email?'<button class="lnk" data-click="auditFor" data-q="'+esc(d.email)+'">alles in de audit</button>':'')+'</small></h3>'+
      (aud.length?'<ul class="ls">'+aud.slice(0,15).map(a=>'<li><div><b style="font-weight:500">'+esc(a.label)+'</b>'+(a.summary?'<div class="mut" style="font-size:13px">'+esc(a.summary)+'</div>':'')+'</div><div class="r">'+whenCell(a.ts)+'</div></li>').join('')+'</ul>':'<div class="mut">Nog niets vastgelegd.</div>')+'</div>';
}
function auditFor(el){closeModal('mo-details');goTo({dataset:{tab:'audit',q:el.dataset.q,event:'',since:''}});}

/* ── Audit ───────────────────────────────────────────────────────────────── */
let AUDIT_ROWS=[],AUDIT_LABELS={};
async function loadAudit(){
  const el=document.getElementById('tab-audit');
  renderAuditShell(el);
  applyPendingAudit();
  fetchAudit();
}
function renderAuditShell(el){
  el.innerHTML='<div class="card"><div class="card-hdr">Audit <small>wie deed wat, nieuwste boven</small></div>'+
    '<div class="fb">'+
      '<label for="a-event" class="sr-only">Gebeurtenis</label><select id="a-event" data-change="fetchAudit"><option value="">Alle gebeurtenissen</option></select>'+
      '<label for="a-q" class="sr-only">Zoek op e-mailadres</label><input id="a-q" type="search" placeholder="Zoek op e-mailadres of woord" data-input="auditSearch" class="wide" autocomplete="off" autocapitalize="off">'+
      '<label for="a-since" class="sr-only">Periode</label><select id="a-since" data-change="fetchAudit"><option value="">Altijd</option><option value="1">Laatste uur</option><option value="24">Laatste 24 uur</option><option value="168">Laatste 7 dagen</option><option value="720">Laatste 30 dagen</option></select>'+
      '<div class="sp"></div>'+
      '<button class="btn out" data-click="exportAuditCSV">CSV downloaden</button>'+
      '<button class="btn out" data-click="fetchAudit">Vernieuwen</button>'+
    '</div>'+
    '<div id="a-count" class="mut" style="font-size:14px;margin-bottom:6px"></div>'+
    '<div id="a-results">'+loading()+'</div>'+
    '</div>';
}
function applyPendingAudit(){
  if(!PENDING_AUDIT)return;
  const p=PENDING_AUDIT;PENDING_AUDIT=null;
  const ev=document.getElementById('a-event'),q=document.getElementById('a-q'),s=document.getElementById('a-since');
  if(ev){if(p.event&&!Array.from(ev.options||[]).some(o=>o.value===p.event))ev.insertAdjacentHTML('beforeend','<option value="'+esc(p.event)+'">'+esc(p.event)+'</option>');ev.value=p.event;}
  if(q)q.value=p.q;if(s)s.value=p.since;
}
let _auditT=null;
function auditSearch(){clearTimeout(_auditT);_auditT=setTimeout(fetchAudit,300);}
async function fetchAudit(){
  const event=document.getElementById('a-event')?.value||'';
  const q=(document.getElementById('a-q')?.value||'').trim();
  const hours=parseInt(document.getElementById('a-since')?.value||0);
  const params=new URLSearchParams();
  params.set('limit','500');
  if(event)params.set('event',event);
  if(q)params.set('q',q);
  if(hours)params.set('since',new Date(Date.now()-hours*3600000).toISOString());
  const r=await apiSafe('/admin/audit?'+params);
  const el=document.getElementById('a-results');
  if(!el)return;
  if(!r.ok){el.innerHTML='<div class="empty">De audit kwam niet terug. <button class="lnk" data-click="fetchAudit">Opnieuw proberen</button></div>';return}
  const events=r.data.events||[];
  AUDIT_LABELS=r.data.event_labels||{};
  // Het filter biedt alleen gebeurtenissen die echt voorkomen (ADMIN-27-F).
  const sel=document.getElementById('a-event');
  if(sel&&Array.isArray(r.data.event_types)){
    const cur=sel.value;
    sel.innerHTML='<option value="">Alle gebeurtenissen</option>'+r.data.event_types.map(t=>'<option value="'+esc(t)+'"'+(t===cur?' selected':'')+'>'+esc(AUDIT_LABELS[t]||t)+'</option>').join('');
  }
  AUDIT_ROWS=events;
  const cnt=document.getElementById('a-count');
  if(cnt)cnt.textContent=events.length?(events.length+(r.data.total>events.length?' van '+r.data.total:'')+' gebeurtenis'+(events.length===1?'':'sen')):'';
  if(!events.length){el.innerHTML='<div class="empty">Niets gevonden met deze filters.</div>';return}
  el.innerHTML='<div class="tbl-wrap"><table class="tbl cards compact"><thead><tr><th>Wanneer</th><th>Gebeurtenis</th><th>Wie</th><th>Wat</th><th>Details</th></tr></thead><tbody>'+
    events.map(e=>'<tr>'+
      '<td data-label="Wanneer" class="c-when">'+whenCell(e.ts)+'</td>'+
      '<td data-label="Gebeurtenis" class="c-ev"><b style="font-weight:600">'+esc(e.label||e.event_type)+'</b></td>'+
      '<td data-label="Wie" class="who c-who"><div>'+(e.kid?'<button class="lnk" data-click="openKlant" data-kid="'+esc(e.kid)+'">'+esc(e.who)+'</button>':'<b>'+esc(e.who)+'</b>')+
        (e.key_masked?'<details class="key"><summary>sleutel</summary><span class="mono">'+esc(e.key_masked)+'</span></details>':'')+'</div></td>'+
      '<td data-label="Wat" class="c-what">'+(e.summary?esc(e.summary):'<span class="mut">-</span>')+'</td>'+
      '<td data-label="Details" class="full"><details class="det"><summary>Toon details</summary>'+kvList(e.metadata)+'<div class="mut mono" style="font-size:12px;margin-top:4px">'+esc(e.event_type)+'</div></details></td>'+
    '</tr>').join('')+'</tbody></table></div>';
}
// CSV voor een Nederlandse Excel: puntkomma, UTF-8 met BOM, elke kolom gevuld.
// Een cel die met = + - @ (of tab/CR) begint, opent Excel als formule; die krijgt
// een apostrof ervoor. Gewone getallen blijven getallen (relay/lib/csv-safe.js).
function csvSafe(v){const s=String(v==null?'':v);return /^[=+\-@\t\r]/.test(s)&&!/^[-+]?\d+(?:[.,]\d+)*$/.test(s)?"'"+s:s;}
function csvCell(v){return '"'+csvSafe(v).replace(/[\r\n]+/g,' ').replace(/"/g,'""')+'"';}
function exportAuditCSV(){
  if(!AUDIT_ROWS.length){toast('Er staat niets om te downloaden','warn');return}
  const head=['tijd_utc','tijd_lokaal','gebeurtenis','code','wie','sleutel','wat','details'];
  const lines=[head.map(csvCell).join(';')];
  for(const e of AUDIT_ROWS){
    const meta=e.metadata&&Object.keys(e.metadata).length?JSON.stringify(e.metadata):'(geen details)';
    lines.push([e.iso||new Date(e.ts).toISOString(),absTime(e.ts),e.label||e.event_type,e.event_type,e.who||'onbekend',e.key_masked||'(geen sleutel)',e.summary||'(geen samenvatting)',meta].map(csvCell).join(';'));
  }
  const csv='﻿'+lines.join('\r\n')+'\r\n';
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8'}));
  a.download='paramant-audit-'+new Date().toISOString().slice(0,10)+'.csv';
  document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove();},1000);
}

/* ── Betalingen ──────────────────────────────────────────────────────────── */
function docTable(rows,empty){
  if(!rows)return '<div class="empty">De betaaldocumenten waren niet te lezen. Niet gemeten, dus ook geen nul.</div>';
  if(!rows.length)return '<div class="empty">'+esc(empty)+'</div>';
  return '<div class="tbl-wrap"><table class="tbl cards"><thead><tr><th>Datum</th><th>Klant</th><th>Wat</th><th class="num">Bedrag</th><th>Status</th><th>Nummer</th></tr></thead><tbody>'+
    rows.map(p=>'<tr><td data-label="Datum">'+esc(absDate(p.date))+'</td>'+
      '<td data-label="Klant">'+(p.kid?'<button class="lnk" data-click="openKlant" data-kid="'+esc(p.kid)+'">'+esc(p.customer||'Klant')+'</button>':esc(p.customer||'-'))+'</td>'+
      '<td data-label="Wat">'+esc(p.description||p.kind_nl)+'</td>'+
      '<td data-label="Bedrag" class="num"><b>'+amount(p.amount_gross,p.currency)+'</b><div class="mut" style="font-size:13px">'+amount(p.amount_net,p.currency)+' zonder btw</div></td>'+
      '<td data-label="Status"><span class="badge '+({loopt:'ok',betaald:'ok',terugbetaald:'bad',deels_terug:'warn',verlopen:''}[p.status]||'')+'">'+esc(p.status_nl)+'</span></td>'+
      '<td data-label="Nummer" class="mono">'+esc(p.kind_nl)+' '+esc(p.number)+'</td></tr>').join('')+'</tbody></table></div>';
}
async function loadBilling(){
  const el=document.getElementById('tab-billing');
  el.innerHTML=loading();
  const r=await apiSafe('/admin/billing');
  if(!r.ok){el.innerHTML='<div class="empty">De betalingen kwamen niet terug. <button class="lnk" data-click="reloadTab" data-tab="billing">Opnieuw proberen</button></div>';return}
  const d=r.data||{};
  const rev=d.revenue,subs=d.subscriptions||[],terms=d.terms||[];
  const running=terms.filter(t=>t.running);
  /* Hier stond tot september 2026 een banner over een billing-bèta: Mollie nog
     niet aangesloten, met de hand factureren, verzonnen cijfers. Dat klopte
     toen al niet meer: relay.js POST /v2/billing/checkout roept
     mollie.createPayment altijd aan en de webhook geeft zelf een genummerde
     factuur (lib/invoice.js, PS-JJJJ-NNNN) of creditnota (lib/credit-note.js,
     CN-JJJJ-NNNN) uit. BILLING_MODE staat leeg in productie, en dat zet alleen
     de automatische verlenging uit. De zin hieronder zegt dat, en past zich
     aan zodra er wel verlengingen lopen. */
  el.innerHTML=
    '<h1 class="h1">Betalingen</h1>'+
    '<div class="banner" role="status">'+(subs.length
      ?'Betalingen lopen echt via Mollie. Er lopen '+subs.length+' automatische verlenging'+(subs.length===1?'':'en')+'. Bij elke betaling maakt de webhook zelf een genummerde factuur of creditnota.'
      :'Betalingen lopen echt via Mollie: één betaling per termijn, geen abonnement en geen automatische incasso. Bij elke betaling maakt de webhook zelf een genummerde factuur of creditnota.')+'</div>'+
    (d.collection_failed?'<div class="sign">Let op: '+esc(d.collection_failed)+' automatische incasso'+(d.collection_failed===1?'':'s')+' mislukt. De klant is gemaild.</div>':'')+
    '<div class="sg">'+
      statCard('b-omzet','Omzet '+monthName(rev&&rev.this_month&&rev.this_month.month),rev?euro(rev.this_month.net_cents):'niet gemeten',rev?(rev.this_month.documents+' document'+(rev.this_month.documents===1?'':'en')+', '+euro(rev.this_month.gross_cents)+' met btw'):'','data-tab="billing" data-focus="b-payments"')+
      statCard('b-vorige','Omzet '+monthName(rev&&rev.last_month&&rev.last_month.month),rev?euro(rev.last_month.net_cents):'niet gemeten',rev?euro(rev.last_month.gross_cents)+' met btw':'','data-tab="billing" data-focus="b-payments"')+
      statCard('b-mrr','Per maand (MRR)',rev?euro(rev.mrr_cents):'niet gemeten',rev?'netto, uit '+rev.mrr_basis+' lopende betaalde periode'+(rev.mrr_basis===1?'':'s'):'','data-tab="billing" data-focus="b-terms"')+
      statCard('b-betalend','Betalende klanten',rev?String(rev.paying_accounts):'niet gemeten',running.length+(running.length===1?' betaald plan loopt nu':' betaalde plannen lopen nu'),'data-tab="billing" data-focus="b-terms"')+
    '</div>'+
    '<div class="card" id="b-payments"><div class="card-hdr">Betalingen en facturen <small>nieuwste boven</small></div>'+docTable(d.payments||(d.documents===undefined?[]:null),'Nog geen betalingen ontvangen.')+'</div>'+
    '<div class="card" id="b-refunds"><div class="card-hdr">Terugboekingen <small>creditnota’s</small></div>'+docTable(d.refunds||(d.documents===undefined?[]:null),'Nog nooit iets terugbetaald.')+'</div>'+
    '<div class="card" id="b-terms"><div class="card-hdr">Lopende plannen en verlengingen</div>'+
      (subs.length?'<h3 style="font-size:15px;margin:4px 0 8px">Automatische verlengingen</h3><ul class="ls">'+subs.map(s=>'<li><div>'+(s.kid?'<button class="lnk" data-click="openKlant" data-kid="'+esc(s.kid)+'">'+esc(s.who)+'</button>':esc(s.who))+'<div class="mut" style="font-size:13px">'+esc(s.line)+(s.interval?' · elke '+esc(s.interval):'')+'</div></div><div class="r">'+(s.amount?'<b>'+esc(s.amount)+'</b>':'')+'<div class="mut" style="font-size:13px">'+esc(s.status_nl)+'</div></div></li>').join('')+'</ul>':'')+
      (terms.length?'<div class="tbl-wrap"><table class="tbl cards"><thead><tr><th>Klant</th><th>Product</th><th>Plan</th><th>Status</th></tr></thead><tbody>'+terms.slice(0,100).map(t=>'<tr><td data-label="Klant">'+(t.kid?'<button class="lnk" data-click="openKlant" data-kid="'+esc(t.kid)+'">'+esc(t.who)+'</button>':esc(t.who))+'</td><td data-label="Product">'+(t.product==='parasign'?'ParaSign':'ParaSend')+'</td><td data-label="Plan">'+esc(tierNL(t.tier))+'</td><td data-label="Status"><span class="badge '+(t.running?'ok':'')+'">'+esc(t.status_nl)+'</span></td></tr>').join('')+'</tbody></table></div>':'<div class="empty">Geen betaald plan met een einddatum.</div>')+
    '</div>'+
    '<div class="card"><div class="card-hdr">Plannen die je zelf zette <small>'+((d.recent_checkouts||[]).length)+' wijziging'+((d.recent_checkouts||[]).length===1?'':'en')+', zonder betaling</small></div>'+
      ((d.recent_checkouts||[]).length?'<ul class="ls">'+d.recent_checkouts.map(e=>'<li><div>'+(e.kid?'<button class="lnk" data-click="openKlant" data-kid="'+esc(e.kid)+'">'+esc(e.who||'Klant')+'</button>':esc(e.who||e.user_id||'-'))+'<div class="mut" style="font-size:13px">'+esc(e.label||e.event_type)+(e.summary?': '+esc(e.summary):'')+'</div></div><div class="r">'+whenCell(toMs(e.ts))+'</div></li>').join('')+'</ul>':'<div class="empty">Nog geen plan met de hand gezet.</div>')+
    '</div>'+
    renderCouponsShell();
  fetchCoupons();
}

/* ── Cadeaucodes ─────────────────────────────────────────────────────────────
   Een code geeft iemand een termijn, en er gaat geen geld over: de regels staan
   in relay/lib/coupon.js, /admin/coupons in admin/server.js brengt de X-Session
   van dit paneel naar de relay, en dit is het venster op beide.

   Er is bewust geen wijzigknop. De grens verhogen op een code die al gebruikt
   wordt, of veranderen wat hij geeft, is hoe twee klanten verschillende
   antwoorden krijgen op dezelfde code. Intrekken en een nieuwe maken; wat al
   gegeven is wordt nooit teruggenomen. */
const COUPON_ERRORS={
  code_exists:'Die code bestaat al. Trek de oude in of kies een andere naam.',
  bad_code:'Een code is 3 tot 32 tekens: letters, cijfers en streepjes.',
  bad_valid_until:'Die einddatum is geen datum. Kies er een uit de kalender, of laat het veld leeg voor geen einddatum.',
  bad_max_redemptions:'Het maximum moet een heel getal tussen 1 en 100000 zijn.',
  bad_days:'Het aantal dagen moet een heel getal tussen 1 en 3650 zijn.',
  unknown_code:'Die code bestaat niet meer.',
  coupons_unavailable:'De opslag voor codes is niet bereikbaar, er is niets veranderd. Probeer het zo opnieuw.',
  no_redis:'De opslag voor codes is niet bereikbaar, er is niets veranderd. Probeer het zo opnieuw.',
  rate_limited:'Te veel wijzigingen achter elkaar. Wacht een minuut.',
};
function couponError(r){
  const err=(r&&r.data&&r.data.error)||'';
  if(COUPON_ERRORS[err])return COUPON_ERRORS[err];
  if(!r||r.status===0)return 'De relay was niet bereikbaar, er is niets veranderd.';
  if(r.status===502||r.status===503||r.status===504)return 'De relay was niet bereikbaar, er is niets veranderd.';
  if(r.status===401||r.status===403)return 'Je sessie is verlopen. Log opnieuw in.';
  return 'Er ging iets mis en er is niets veranderd.';
}
async function couponApi(path,opts){
  try{return await api(path,opts||{});}catch{return{ok:false,status:0,data:null};}
}
function couponMsg(text,ok){
  const msg=document.getElementById('c-msg');
  if(!msg)return;
  msg.style.color=ok?'var(--ok)':'var(--bad)';
  msg.textContent=text;
}
// Wat een code geeft, in het Nederlands, uit de grants zelf.
function describeGrants(c){
  const g=Array.isArray(c&&c.grants)?c.grants:[];
  if(!g.length)return (c&&c.describes)||'';
  const days=g[0].days;
  const prods=g.map(x=>(x.product==='parasign'?'ParaSign':'ParaSend')+' '+tierNL(x.tier)).join(' en ');
  return (days?days+' dagen ':'')+prods;
}
function renderCouponsShell(){
  return '<div class="card" id="b-coupons"><div class="card-hdr">Cadeaucodes <small>geeft een termijn, zonder betaling en zonder factuur</small></div>'+
    '<div class="fb">'+
      '<label class="sr-only" for="c-code">Code</label><input id="c-code" placeholder="CODE" style="width:170px;text-transform:uppercase" autocapitalize="characters" aria-label="Code">'+
      '<label class="sr-only" for="c-max">Hoe vaak te gebruiken</label><input id="c-max" type="number" min="1" value="100" style="width:120px" title="Hoe vaak te gebruiken" aria-label="Hoe vaak te gebruiken">'+
      '<label class="sr-only" for="c-days">Dagen</label><input id="c-days" type="number" min="1" value="90" style="width:100px" title="Aantal dagen" aria-label="Aantal dagen">'+
      '<label class="sr-only" for="c-until">Geldig tot</label><input id="c-until" type="date" style="width:170px" title="Geldig tot" aria-label="Geldig tot">'+
      '<div class="sp"></div>'+
      '<button class="btn" data-click="doCreateCoupon">Code maken</button>'+
      '<button class="btn out" data-click="fetchCoupons">Vernieuwen</button>'+
    '</div>'+
    '<div class="mut" style="font-size:13px;margin:-6px 0 10px">Code · hoe vaak te gebruiken · dagen Firm (versturen en ondertekenen) · geldig tot (leeg is geen einddatum)</div>'+
    '<div id="c-msg" role="status" style="margin-bottom:8px;font-weight:500"></div>'+
    '<div id="c-results">'+loading()+'</div>'+
  '</div>';
}
async function fetchCoupons(){
  const el=document.getElementById('c-results');
  if(!el)return;
  const r=await couponApi('/admin/coupons');
  if(!r.ok){el.innerHTML='<div class="empty">'+esc(couponError(r))+'</div>';return}
  const list=(r.data&&r.data.coupons)||[];
  if(!list.length){el.innerHTML='<div class="empty">Nog geen cadeaucodes.</div>';return}
  el.innerHTML='<div class="tbl-wrap"><table class="tbl cards"><thead><tr><th>Code</th><th>Geeft</th><th>Gebruikt</th><th>Geldig tot</th><th>Status</th><th></th></tr></thead><tbody>'+
    list.map(c=>'<tr>'+
      '<td data-label="Code" class="mono">'+esc(c.code)+'</td>'+
      '<td data-label="Geeft">'+esc(describeGrants(c))+'</td>'+
      '<td data-label="Gebruikt">'+esc(c.used+' van '+c.max_redemptions)+'</td>'+
      '<td data-label="Geldig tot">'+esc(c.valid_until?absDate(c.valid_until):'geen einddatum')+'</td>'+
      '<td data-label="Status">'+(c.revoked_at?'<span class="chip revoked">ingetrokken</span>':(c.remaining>0?'<span class="chip active">open</span>':'<span class="chip none">op</span>'))+'</td>'+
      '<td class="actions">'+(c.revoked_at?'':'<button class="btn out" data-click="doRevokeCoupon" data-code="'+esc(c.code)+'">Intrekken</button>')+'</td>'+
    '</tr>').join('')+'</tbody></table></div>';
}
async function doCreateCoupon(){
  const code=(document.getElementById('c-code')?.value||'').trim().toUpperCase();
  const max=parseInt(document.getElementById('c-max')?.value||'0',10);
  const days=parseInt(document.getElementById('c-days')?.value||'0',10);
  const until=(document.getElementById('c-until')?.value||'').trim();
  if(!code){couponMsg('Vul eerst een code in.',false);return}
  if(!/^[A-Z0-9-]{3,32}$/.test(code)){couponMsg(COUPON_ERRORS.bad_code,false);return}
  if(!(max>=1)){couponMsg(COUPON_ERRORS.bad_max_redemptions,false);return}
  if(!(days>=1)){couponMsg(COUPON_ERRORS.bad_days,false);return}
  // Een lege datum is geen einddatum. Een datum die geen datum is wordt hier
  // geweigerd, dezelfde regel als coupon.js validateValidUntil.
  if(until&&Number.isNaN(Date.parse(until+'T23:59:59Z'))){couponMsg(COUPON_ERRORS.bad_valid_until,false);return}
  /* Beide producten op Pro is de campagne waarvoor dit kwam. De relay keurt elk
     veld opnieuw; niets van hier wordt vertrouwd. */
  const body={code:code,max_redemptions:max,grants:[
    {product:'parasign',tier:'pro',days:days},
    {product:'parasend',tier:'pro',days:days},
  ]};
  if(until)body.valid_until=until+'T23:59:59Z';
  couponMsg('Bezig…',true);
  const r=await couponApi('/admin/coupons',{method:'POST',body:JSON.stringify(body)});
  if(r.ok){
    couponMsg('Code '+code+' aangemaakt: '+describeGrants((r.data&&r.data.coupon)||{grants:body.grants})+', '+max+' keer te gebruiken.',true);
    const inp=document.getElementById('c-code');if(inp)inp.value='';
    fetchCoupons();
  }else{
    couponMsg(couponError(r),false);
  }
}
async function doRevokeCoupon(el){
  const code=el&&el.dataset?el.dataset.code:'';
  if(!code)return;
  const r=await couponApi('/admin/coupons/'+encodeURIComponent(code),{method:'DELETE'});
  if(r.ok){
    couponMsg('Code '+code+' ingetrokken. Wie hem al gebruikte, houdt zijn termijn.',true);
    fetchCoupons();
  }else{
    couponMsg(couponError(r),false);
  }
}

/* ── Relays ──────────────────────────────────────────────────────────────── */
async function loadRelay(){
  const el=document.getElementById('tab-relay');
  el.innerHTML=
    '<div class="card-hdr" style="margin-bottom:6px"><span class="h1" style="margin:0">Relays</span><button class="btn out" data-click="fetchRelay">Nu vernieuwen</button></div>'+
    '<p class="lead">Ververst elke tien seconden. Tik op een relay voor alles over die relay.</p>'+
    '<div id="r-strip" class="rs">'+['main','health','legal','finance','iot'].map(s=>'<div class="ri loading"><div class="ri-name">'+s+'</div><div class="ri-det">laden…</div></div>').join('')+'</div>'+
    '<div id="r-cards" class="g2"></div>';
  fetchRelay();
  clearInterval(REFRESH.relay);
  REFRESH.relay=setInterval(()=>{if(document.getElementById('tab-relay').classList.contains('on'))fetchRelay();},10000);
}
async function fetchRelay(){
  const r=await apiSafe('/admin/relay-detail');
  if(!r.ok)return;
  const sectors=r.data.sectors||{};
  const ct=Object.fromEntries((r.data.ct||[]).map(c=>[c.sector,c]));
  const strip=document.getElementById('r-strip');
  if(strip)strip.innerHTML=Object.entries(sectors).map(([name,s])=>{
    const ok=!s.error;
    return '<button class="ri'+(ok?'':' offline')+'" data-click="openRelay" data-sector="'+esc(name)+'">'+
      '<div class="ri-name">'+esc(sectorNL(name))+'</div>'+
      '<div class="ri-det">'+(ok?'v'+esc(s.version||'?')+' · '+esc(upTime(s.uptime_s)):'antwoordt niet: '+esc(s.error))+'</div>'+
    '</button>';
  }).join('');
  const cards=document.getElementById('r-cards');
  if(cards)cards.innerHTML=Object.entries(sectors).map(([name,s])=>{
    if(s.error)return '<div class="card"><div class="card-hdr"><span>'+esc(sectorNL(name))+'</span>'+stTag('kapot')+'</div><div class="empty">Antwoordt niet: '+esc(s.error)+'</div></div>';
    const st=s.stats||{},m=s.metrics||{},c=ct[name];
    return '<div class="card"><div class="card-hdr"><button class="lnk" data-click="openRelay" data-sector="'+esc(name)+'" style="font-weight:700">'+esc(sectorNL(name))+'</button>'+stTag(c&&c.forked?'kapot':'goed')+'</div>'+
      '<dl class="kv">'+
        [['Versie','v'+(s.version||'?')],['In de lucht',upTime(s.uptime_s).replace(' in de lucht','')],['Bestanden onderweg',s.blobs||0],['Ontvangen sinds start',st.inbound||0],['Opgehaald en vernietigd',st.burned||0],['Webhooks verstuurd',st.webhooks_sent||0],
         ['Transparantielogboek',m.ct_log!=null?m.ct_log+' regels'+(c&&c.growth_24h!=null?', +'+c.growth_24h+' in 24 uur':''):'niet gemeten'],
         ['Fouten sinds start',m.errors_total!=null?m.errors_total:'niet gemeten']].map(([k,v])=>'<dt>'+esc(k)+'</dt><dd>'+esc(v)+'</dd>').join('')+
      '</dl></div>';
  }).join('');
}
async function openRelay(el){
  const s=el.dataset.sector;
  document.getElementById('mo-relay-title').textContent='Relay '+sectorNL(s);
  const body=document.getElementById('mo-relay-body');
  body.innerHTML=loading();openModal('mo-relay');
  const r=await apiSafe('/admin/relay-info/'+encodeURIComponent(s));
  if(!r.ok){body.innerHTML='<div class="empty">Kwam niet terug.</div>';return}
  const d=r.data,h=d.health||{},m=d.metrics||{},ct=d.ct;
  const mbv=(b)=>b==null?'-':(Math.round(b/1048576*10)/10)+' MB';
  const deepLevel=d.deep?({green:'goed',yellow:'let_op',red:'kapot'}[d.deep.overall]||'niet_gemeten'):'niet_gemeten';
  body.innerHTML=
    '<div class="sign '+(d.ok?'goed':'kapot')+'">'+(d.ok?'Antwoordt, versie '+esc(h.version||'?')+', '+esc(upTime(m.uptime_s)):'Antwoordt niet: '+esc(d.error||''))+'</div>'+
    '<div class="g2">'+
      '<div><h3 style="font-size:16px;margin-bottom:6px">Gezondheid</h3><dl class="kv">'+
        '<dt>Sector</dt><dd>'+esc(h.sector||s)+'</dd><dt>Editie</dt><dd>'+esc(h.edition||'-')+'</dd>'+
        '<dt>Actieve sleutels</dt><dd>'+esc(h.active_keys??'-')+(h.key_limit?' van '+esc(h.key_limit):'')+'</dd>'+
        '<dt>Bestanden onderweg</dt><dd>'+esc(h.blobs_in_flight??h.blobs??'-')+'</dd>'+
        '<dt>Webhooks</dt><dd>'+esc(h.webhooks??'-')+'</dd>'+
        (h.license_expires?'<dt>Licentie tot</dt><dd>'+esc(absDate(h.license_expires))+'</dd>':'')+
      '</dl></div>'+
      '<div><h3 style="font-size:16px;margin-bottom:6px">Meetwaarden</h3><dl class="kv">'+
        '<dt>Verzoeken sinds start</dt><dd>'+esc(m.requests_total??'-')+'</dd>'+
        '<dt>Fouten sinds start</dt><dd>'+esc(m.errors_total??'-')+'</dd>'+
        '<dt>Geheugen (heap)</dt><dd>'+esc(mbv(m.heap_bytes))+'</dd>'+
        '<dt>Geheugen (RSS)</dt><dd>'+esc(m.ram_rss_mb!=null?m.ram_rss_mb+' MB':'-')+'</dd>'+
        '<dt>Vrije plekken voor bestanden</dt><dd>'+esc(m.ram_slots_available??'-')+(m.ram_blobs_max!=null?' van '+esc(m.ram_blobs_max):'')+'</dd>'+
      '</dl></div>'+
    '</div>'+
    '<div class="sec"><h3>Transparantielogboek</h3>'+(ct?'<dl class="kv"><dt>Omvang</dt><dd>'+esc(ct.size)+' regels</dd><dt>Groei laatste 24 uur</dt><dd>'+(ct.growth_24h==null?'wordt vanaf nu gemeten':'+'+esc(ct.growth_24h))+'</dd><dt>Op schijf bewaard</dt><dd>'+(ct.persisted==null?'-':ct.persisted?'ja':'nee, alleen in het geheugen')+'</dd><dt>Gesplitst</dt><dd>'+(ct.forked?'ja, de relay tekent niet meer':'nee')+'</dd></dl>':'<div class="mut">Niet gemeten.</div>')+'</div>'+
    '<div class="sec"><h3>Diepe controle '+stTag(deepLevel)+'</h3>'+(d.deep?'<ul class="ls">'+(d.deep.checks||[]).map(c=>'<li><div><b style="font-weight:500">'+esc(c.name)+'</b><div class="mut" style="font-size:13px">'+esc(c.detail||'')+'</div></div><div class="r">'+stTag({green:'goed',yellow:'let_op',red:'kapot',info:'info'}[c.status]||'niet_gemeten')+'</div></li>').join('')+'</ul>':'<div class="mut">De relay gaf geen uitslag.</div>')+'</div>';
}

/* ── Vensters ────────────────────────────────────────────────────────────── */
let _ms={};
function closeModal(id){const el=document.getElementById(id);if(el)el.style.display='none';if(id==='mo-details')KLANT_OPEN=null;}
function openModal(id){const el=document.getElementById(id);if(el)el.style.display='flex';}
function epTab(tab,btn){
  document.querySelectorAll('.ep-tab').forEach(b=>b.classList.remove('on'));btn.classList.add('on');
  const t=document.getElementById('ep-text'),h=document.getElementById('ep-html');
  if(tab==='text'){t.style.display='';h.style.display='none';}else{t.style.display='none';h.style.display='';}
}
const MAIL_NL={'welcome':'Welkomstmail','setup':'Link voor de authenticator-app','reset-confirm':'Reset van tweestaps'};
async function openEmailPreviewModal(type,key,email){
  const epMap={'welcome':'/admin/send-welcome','setup':'/admin/resend-setup','reset-confirm':'/admin/reset-totp'};
  _ms.email={type,key,email,ep:epMap[type]};
  document.getElementById('mo-email-title').textContent=MAIL_NL[type]+(email?' aan '+email:'');
  document.getElementById('ep-subj').textContent='Laden…';
  document.getElementById('ep-text').textContent='';
  document.getElementById('ep-html').removeAttribute('srcdoc');
  document.getElementById('ep-send-btn').disabled=true;
  openModal('mo-email');
  const r=await api('/admin/preview-email',{method:'POST',body:JSON.stringify({type,key})});
  if(!r.ok){document.getElementById('ep-subj').textContent='Voorbeeld lukte niet: '+(r.data?.error||'onbekend');return;}
  const d=r.data;
  document.getElementById('ep-subj').textContent='Onderwerp: '+(d.subject||'');
  document.getElementById('ep-text').textContent=d.text||'';
  document.getElementById('ep-html').srcdoc=d.html||'';
  document.getElementById('ep-send-btn').disabled=false;
}
async function doSendEmail(){
  const {type,key,email,ep}=_ms.email||{};if(!ep)return;
  const b=document.getElementById('ep-send-btn');b.disabled=true;b.textContent='Versturen…';
  const body={key};
  if(type==='reset-confirm')body.mode='request';
  if(type==='setup'){body.user_id=key;body.email=email;}
  const r=await api(ep,{method:'POST',body:JSON.stringify(body)});
  closeModal('mo-email');b.textContent='Mail versturen';
  toast(r.ok?'Mail verstuurd':'Versturen mislukt: '+(r.data?.error||'onbekend'),r.ok?'ok':'err');
}
// Planladders per product. MOETEN gelijk blijven aan relay/lib/entitlements.js
// (PARASIGN_TIERS / PARASEND_TIERS); de relay keurt opnieuw, dit vormt alleen het scherm.
const PP_TIERS={parasign:['free','pro','business','enterprise'],parasend:['community','pro','enterprise']};
function ppFillTiers(){
  const p=document.getElementById('pp-product').value;
  document.getElementById('pp-tier').innerHTML=(PP_TIERS[p]||[]).map(t=>'<option value="'+t+'">'+tierNL(t)+'</option>').join('');
}
function ppProductChange(){
  ppFillTiers();
  const p=document.getElementById('pp-product').value;
  const cur=p==='parasign'?(_ms.plan&&_ms.plan.ppSign):(_ms.plan&&_ms.plan.ppSend);
  if(cur&&(PP_TIERS[p]||[]).includes(cur))document.getElementById('pp-tier').value=cur;
}
function openChangePlanModal(key,email,currentPlan,ppSign,ppSend){
  _ms.plan={key,email,ppSign:ppSign||'',ppSend:ppSend||''};
  document.getElementById('mo-plan-title').textContent='Plan wijzigen'+(email?' voor '+email:'');
  document.getElementById('cp-current').textContent=currentPlan||'community';
  document.getElementById('cp-plan').value=currentPlan||'community';
  document.getElementById('pp-current').textContent='ParaSign '+tierNL(ppSign)+'  ·  ParaSend '+tierNL(ppSend);
  document.getElementById('plan-entitlement-readback').textContent='Nog niets gewijzigd.';
  document.getElementById('pp-product').value='parasign';
  document.getElementById('pp-notify').checked=false;
  ppFillTiers();
  if(ppSign&&PP_TIERS.parasign.includes(ppSign))document.getElementById('pp-tier').value=ppSign;
  openModal('mo-plan');setTimeout(()=>document.getElementById('pp-product').focus(),50);
}
function showEntitlementReadback(d){
  const mismatches=new Map((d?.verification_failed||[]).map(x=>[x.sector+':'+x.product,x]));
  const rows=Object.entries(d?.entitlements_by_sector||{}).map(([s,r])=>{
    if(!r?.ok)return s+': NIET GELEZEN';
    const e=r.entitlements||{};
    const bad=['parasign','parasend'].map(p=>mismatches.get(s+':'+p)).filter(Boolean).map(x=>' verwacht '+x.product+'='+x.expected).join(',');
    return s+': ParaSign '+(e.parasign?.tier||'-')+' / ParaSend '+(e.parasend?.tier||'-')+(bad?' | KLOPT NIET'+bad:'');
  });
  document.getElementById('plan-entitlement-readback').textContent=rows.length?rows.join('\n'):'Niet terug te lezen.';
}
async function doChangePlan(){
  const {key,email}=_ms.plan||{};if(!key)return;
  const new_plan=document.getElementById('cp-plan').value;
  if(!confirm('Beide producten van '+(email||'deze klant')+' op '+new_plan+' zetten?'))return;
  const notify=document.getElementById('cp-notify').checked;
  document.getElementById('cp-btn').disabled=true;
  const r=await apiSafe('/admin/change-plan',{method:'POST',body:JSON.stringify({key,new_plan,notify})});
  document.getElementById('cp-btn').disabled=false;showEntitlementReadback(r.data);
  const failed=(r.data?.failed_sectors||[]).map(x=>x.sector).join(', ');
  toast(r.data?.ok?'Plan nu '+new_plan+', gecontroleerd op alle relays':'Niet overal gelukt'+(failed?': '+failed:''),r.data?.ok?'ok':'warn');
  if(r.data?.ok){LOADED.users=false;loadUsers();refreshKlant(key);}
}
async function doSetProductPlan(){
  const {key,email}=_ms.plan||{};if(!key)return;
  const product=document.getElementById('pp-product').value;
  const tier=document.getElementById('pp-tier').value;
  const label=(product==='parasign'?'ParaSign':'ParaSend')+' naar '+tierNL(tier);
  if(!confirm(label+' zetten voor '+(email||'deze klant')+'?'))return;
  const notify=document.getElementById('pp-notify').checked;
  const btn=document.getElementById('pp-btn');btn.disabled=true;
  let r=await apiSafe('/admin/set-product-plan',{method:'POST',body:JSON.stringify({key,product,tier,notify})});
  // Een weigering is geen gedeeltelijke mislukking: elke relay zei nee en er
  // bewoog niets. Een lopend plan verlagen is een aparte, bewuste stap die de
  // einddatum houdt.
  if(r.data?.error==='lower_than_running'){
    if(!confirm('Deze klant heeft een hoger plan dat nog loopt.\n\nDe lopende termijn verlagen naar '+tierNL(tier)+' en de einddatum houden?')){btn.disabled=false;toast('Niets veranderd','warn');return;}
    r=await apiSafe('/admin/set-product-plan',{method:'POST',body:JSON.stringify({key,product,tier,notify,downgrade:true})});
  }
  btn.disabled=false;
  showEntitlementReadback(r.data);
  const failed=(r.data?.failed_sectors||[]).map(x=>x.sector).join(', ');
  toast(r.data?.ok?label+', gecontroleerd op alle relays':'Niet overal gelukt'+(failed?': '+failed:''),r.data?.ok?'ok':'warn');
  if(r.data?.ok){LOADED.users=false;loadUsers();refreshKlant(key);}
}
function openDisableKeyModal(key,email){
  _ms.disable={key,email};
  document.getElementById('mo-disable-title').textContent='Sleutel uitzetten'+(email?' van '+email:'');
  document.getElementById('dk-reason').value='';document.getElementById('dk-notify').checked=false;
  openModal('mo-disable');setTimeout(()=>document.getElementById('dk-reason').focus(),50);
}
async function doDisableKey(){
  const {key}=_ms.disable||{};if(!key)return;
  const reason=document.getElementById('dk-reason').value.trim()||'not specified';
  const notify=document.getElementById('dk-notify').checked;
  document.getElementById('dk-btn').disabled=true;
  const r=await apiSafe('/admin/disable-key',{method:'POST',body:JSON.stringify({key,reason,notify})});
  closeModal('mo-disable');document.getElementById('dk-btn').disabled=false;
  toast(r.ok?'Sleutel uitgezet':'Mislukt: '+(r.data?.error||'onbekend'),r.ok?'ok':'err');
  if(r.ok){LOADED.users=false;loadUsers();refreshKlant(key);}
}
function openDeleteAccountModal(key,email,menu){
  _ms.del={key,email};
  document.getElementById('da-confirm').value='';document.getElementById('da-btn').disabled=true;
  document.getElementById('da-notify').checked=true;
  const u=allUsers.find(x=>x.key_id===key)||{};
  document.getElementById('da-target').textContent=u.key||key;
  const ds=(menu&&menu.dataset)||{};
  const label=ds.label||'',plan=ds.plan||'community',created=ds.created||'';
  document.getElementById('da-email').textContent=email||'(geen e-mailadres bekend)';
  document.getElementById('da-label').textContent=label||'(geen label)';
  const planEl=document.getElementById('da-plan');planEl.textContent=plan;
  document.getElementById('da-created').textContent=created?(absDate(created)+' ('+relTime(toMs(created))+')'):'-';
  const recent=created&&(Date.now()-toMs(created))<24*3600*1000;
  document.getElementById('da-recent-warn').style.display=recent?'block':'none';
  openModal('mo-delete');setTimeout(()=>document.getElementById('da-confirm').focus(),50);
}
async function doDeleteAccount(){
  const {key}=_ms.del||{};if(!key)return;
  if(document.getElementById('da-confirm').value.trim().toUpperCase()!=='DEACTIVATE')return;
  const notify=document.getElementById('da-notify').checked;
  document.getElementById('da-btn').disabled=true;
  const r=await apiSafe('/admin/delete-account',{method:'POST',body:JSON.stringify({key,confirm:'DELETE',notify})});
  closeModal('mo-delete');closeModal('mo-details');
  toast(r.ok?'Account gedeactiveerd':'Mislukt: '+(r.data?.error||'onbekend'),r.ok?'ok':'err');
  if(r.ok){LOADED.users=false;setTimeout(loadUsers,800);}
}
function openForceTotpModal(key,email,currentlyRequired){
  _ms.forceTotp={key,email,removing:currentlyRequired};
  document.getElementById('mo-force-totp-title').textContent=(currentlyRequired?'Tweestaps niet meer verplichten':'Tweestaps verplicht maken')+(email?' voor '+email:'');
  document.getElementById('mo-force-totp-body').innerHTML=currentlyRequired
    ?'<p style="margin:0">De klant kan weer inloggen zonder authenticator-app, of blijft de bestaande gewoon gebruiken.</p>'
    :'<p style="margin:0 0 10px">De klant moet een authenticator-app instellen voor de volgende keer inloggen.</p><ul style="margin:0 0 14px;padding-left:20px"><li>Open sessies stoppen meteen</li><li>Er gaat vanzelf een mail met de instellink</li><li>Inloggen kan pas weer na het instellen</li></ul><div class="mc"><label for="ft-reason">Reden (mag leeg, komt in de audit)</label><input type="text" id="ft-reason" placeholder="bijvoorbeeld beleid"></div>';
  const btn=document.getElementById('ft-btn');
  btn.textContent=currentlyRequired?'Niet meer verplichten':'Verplicht maken';
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
  const r=await apiSafe('/admin/force-totp',{method:'POST',body:JSON.stringify({key,required,reason:reason||undefined})});
  closeModal('mo-force-totp');btn.disabled=false;
  if(r.ok){
    const d=r.data;
    const msg=required?'Tweestaps is nu verplicht. Sessies gestopt: '+(d.sessions_revoked||0)+(d.setup_email_sent?'. Instelmail verstuurd.':'.'):'Tweestaps is niet meer verplicht.';
    toast(msg,'ok');LOADED.users=false;setTimeout(loadUsers,500);refreshKlant(key);
  } else { toast('Mislukt: '+(r.data?.error||'onbekend'),'err'); }
}

/* ── Start ───────────────────────────────────────────────────────────────── */
document.getElementById('l-totp').addEventListener('input',function(){this.value=this.value.replace(/\D/g,'')});
document.getElementById('l-token').addEventListener('keydown',e=>{if(e.key==='Enter')document.getElementById('l-totp').focus()});
document.getElementById('l-totp').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin()});

if(SESSION){
  api('/auth/check').then(r=>{
    if(r.ok)showDashboard();
    else{SESSION='';sessionStorage.removeItem('adm_session');}
  }).catch(()=>{SESSION='';sessionStorage.removeItem('adm_session');});
}

/* ── Actieregister (onderaan: alle functies staan hierboven) ──────────────── */
act('click', 'doLogin', () => doLogin());
act('click', 'doLogout', () => doLogout());
act('click', 'switchTab', (el) => switchTab(el.dataset.tab));
act('click', 'goTo', (el) => goTo(el));
act('click', 'reloadTab', (el) => { LOADED[el.dataset.tab] = false; loadTab(el.dataset.tab); });
act('click', 'openProblem', (el) => openProblem(el));
act('click', 'openKlant', (el, ev) => { if (ev && ev.stopPropagation) ev.stopPropagation(); openKlant(el); });
act('click', 'openRelay', (el) => openRelay(el));
act('click', 'auditFor', (el) => auditFor(el));
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
act('change', 'fetchAudit', () => fetchAudit());
act('input', 'auditSearch', () => auditSearch());
act('click', 'doCreateCoupon', () => doCreateCoupon());
act('click', 'doRevokeCoupon', (el) => doRevokeCoupon(el));
act('click', 'fetchCoupons', () => fetchCoupons());
act('click', 'fetchRelay', () => fetchRelay());
act('click', 'uAction', (el) => uAction(el.dataset.uact, el));
act('click', 'toggleMenu', (el, ev) => toggleMenu(ev, el.dataset.menu));
act('click', 'usersPage', (el) => loadUsers(parseInt(el.dataset.page, 10)));
act('click', 'closeCreateKey', (el) => { const m = el.closest('[data-modal]'); if (m) m.remove(); });
act('change', 'filterUsers', () => filterUsers());
act('input', 'filterUsers', () => filterUsers());
act('change', 'usersPageSize', (el) => loadUsers(1, parseInt(el.value, 10)));
act('input', 'confirmDelete', (el) => { const b = document.getElementById('da-btn'); if (b) b.disabled = el.value.trim().toUpperCase() !== 'DEACTIVATE'; });
