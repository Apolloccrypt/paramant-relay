'use strict';

// The relay whose log this page shows. It is health.paramant.app because that
// is the relay the web app on this site actually sends through: parashare.page.js
// starts at the health sector and discoverRelay() prefers it, and co-sign.js and
// sign-flow.js name it outright. Every relay keeps its own log, so this page is
// showing one of several and the copy in ct-log.html says which by name.
// tests/ui-truthfulness.test.mjs reads the host out of this line and fails if the
// page describes a different log than the one it fetches.
const RELAY = 'https://health.paramant.app';
const PAGE_SIZE = 20;
let allEntries = [], page = 0, filtered = [], typeFilter = 'all';

function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

async function load() {
  try {
    // The log endpoint pages from the FRONT (from=0). Learn the size first and
    // fetch the TAIL, otherwise a long-running relay shows its oldest thousand
    // entries as if they were the latest (the "everything says 01 jun" bug).
    const [sizeRes, hRes] = await Promise.all([
      fetch(RELAY + '/v2/ct/log?limit=1'),
      fetch(RELAY + '/health', {signal: AbortSignal.timeout(4000)}).catch(() => null)
    ]);
    const sizeD = await sizeRes.json();
    const total = sizeD.size || 0;
    const from  = Math.max(0, total - 1000);
    const ctRes = await fetch(RELAY + '/v2/ct/log?from=' + from + '&limit=1000');
    const d = await ctRes.json();
    allEntries = (d.entries || []).slice().reverse();
    filtered   = allEntries;

    var keyRegCount   = allEntries.filter(function(e){ return !e.type || e.type === 'key_reg'; }).length;
    var transferCount = allEntries.filter(function(e){ return e.type === 'transfer' || e.type === 'pubkey'; }).length;
    // The kind that dominates this log and had no counter of its own, so the
    // three numbers under the table came nowhere near the total and nothing on
    // the page said where the difference went. relay.js writes one of these
    // every time one of our containers boots and announces itself.
    var relayRegCount = allEntries.filter(function(e){ return e.type === 'relay_reg'; }).length;
    var logSize = d.size != null ? d.size : allEntries.length;
    document.getElementById('stat-total').textContent = logSize;
    // The composition sentence names the same number the counter shows. It is
    // filled in here rather than typed into ct-log.html so it can never go
    // stale; if this never runs the sentence keeps its own word "vermeldingen" and
    // still reads correctly, which is why the fallback is not "n/a".
    var compEl = document.getElementById('composition-count');
    if (compEl && logSize) compEl.textContent = logSize + ' vermeldingen';
    document.getElementById('stat-count').textContent = keyRegCount;
    document.getElementById('stat-transfers').textContent = transferCount;
    var relayRegEl = document.getElementById('stat-relayreg');
    if (relayRegEl) relayRegEl.textContent = relayRegCount;
    const root = d.root || '';
    document.getElementById('stat-root').textContent =
      root && root !== '0'.repeat(64) ? root.slice(0,16)+'…' : 'n/a';

    if (hRes && hRes.ok) {
      const h = await hRes.json();
      const el = document.getElementById('stat-relay');
      el.textContent = 'online v' + (h.version || '?');
      el.className = 'val green';
    } else {
      const el = document.getElementById('stat-relay');
      el.textContent = 'offline';
      el.className = 'val offline';
    }

    if (allEntries.length > 0) {
      const ts = allEntries[0].ts;
      document.getElementById('stat-last').textContent = ts
        ? new Date(ts).toLocaleString('nl-NL', {hour:'2-digit',minute:'2-digit',second:'2-digit',day:'2-digit',month:'short'})
        : 'n/a';
    }

    // Update notice: check if persistent (file-backed) by seeing if log survived restart
    if (d.size > 0) {
      document.getElementById('persistence-notice').style.display = '';
    }

    render();
  } catch(e) {
    document.getElementById('entries').innerHTML =
      '<div class="loading">Het log kon niet worden geladen: ' + esc(e.message) + '</div>';
  }
}

function render() {
  const start = page * PAGE_SIZE;
  const slice = filtered.slice(start, start + PAGE_SIZE);
  const total = filtered.length;

  document.getElementById('page-info').textContent =
    total === 0 ? 'geen resultaten' : (start+1) + ' tot ' + Math.min(start+PAGE_SIZE, total) + ' van ' + total;
  document.getElementById('prev-btn').disabled = page === 0;
  document.getElementById('next-btn').disabled = start + PAGE_SIZE >= total;

  if (slice.length === 0) {
    document.getElementById('entries').innerHTML =
      '<div class="empty-state">'
      + '<h3>' + (allEntries.length === 0 ? 'Het log is leeg' : 'Geen resultaten') + '</h3>'
      + '<p>' + (allEntries.length === 0
          ? 'Nog geen registraties van publieke sleutels. Het CT-log legt elke registratie van een apparaat vast als vermelding die niet meer te wijzigen is. Nieuwe vermeldingen verschijnen hier direct.'
          : 'Geen vermeldingen die bij uw filter passen.')
      + '</p></div>';
    return;
  }

  document.getElementById('entries').innerHTML = slice.map(function(e, i) {
    var gi  = start + i;
    // e.index comes straight from /v2/ct/log, which derives it from the
    // entry's position in the log, so it is the same number /v2/ct/proof takes.
    // The fallback is for a relay too old to send the field at all.
    var idx = e.index !== undefined ? e.index : (filtered.length - 1 - gi);
    var ts  = e.ts;
    var time = ts
      ? new Date(ts).toLocaleString('nl-NL', {hour:'2-digit',minute:'2-digit',second:'2-digit',day:'2-digit',month:'short'})
      : 'n/a';
    var leaf   = trunc(e.leaf_hash   || e.hash || '');
    var tree   = trunc(e.tree_hash   || e.merkle_root || '');
    var proofHtml = '';
    if (e.proof && e.proof.length) {
      proofHtml = '<div class="drow"><span class="dkey">Merkle-bewijs</span>'
        + '<span class="dval"><div class="proof-chain">'
        + e.proof.map(function(h){return '<span class="proof-hash">'+esc(h.slice(0,16))+'…</span>';}).join('')
        + '</div></span></div>';
    }
    return '<div class="entry" data-click="toggle" data-arg="'+gi+'">'
      + '<div class="idx">'+esc(String(idx))+'</div>'
      + '<div class="hash leaf">'+esc(leaf)+'</div>'
      + '<div class="hash">'+esc(tree)+'</div>'
      + '<div class="ts">'+esc(time)+'</div>'
      + '</div>'
      + '<div class="entry-detail" id="d-'+gi+'">'
      + (e.type ? '<div class="drow"><span class="dkey">Type</span><span class="dval">'+esc(e.type)+'</span></div>' : '')
      + '<div class="drow"><span class="dkey">Leaf-hash</span><span class="dval">'+esc(e.leaf_hash||'n/a')+'</span></div>'
      + '<div class="drow"><span class="dkey">Tree-hash</span><span class="dval">'+esc(e.tree_hash||'n/a')+'</span></div>'
      + (e.from_earlier_tree ? '<div class="drow"><span class="dkey">Opgeslagen tree-hash (uit een eerdere boom)</span><span class="dval">'+esc(e.stored_tree_hash||'n/a')+'</span></div>' : '')
      + '<div class="drow"><span class="dkey">Index</span><span class="dval">'+esc(String(idx))+'</span></div>'
      + '<div class="drow"><span class="dkey">Tijdstip</span><span class="dval">'+(ts ? esc(new Date(ts).toISOString()) : 'n/a')+'</span></div>'
      + proofHtml
      + '</div>';
  }).join('');
}

function trunc(h) { return h ? h.slice(0,20)+'…' : 'n/a'; }

function toggle(i) {
  var el = document.getElementById('d-'+i);
  if (el) el.style.display = el.style.display === 'block' ? 'none' : 'block';
}

function filterEntries() {
  var q = document.getElementById('search').value.trim().toLowerCase();
  var base = typeFilter === 'relay_reg'
    ? allEntries.filter(function(e){ return e.type === 'relay_reg'; })
    : typeFilter === 'transfer'
    ? allEntries.filter(function(e){ return e.type === 'transfer' || e.type === 'pubkey'; })
    : allEntries;
  filtered = q ? base.filter(function(e) {
    return (e.leaf_hash||'').includes(q) || (e.tree_hash||'').includes(q)
        || String(e.index||'').includes(q);
  }) : base;
  page = 0;
  render();
}

function setTypeFilter(type) {
  typeFilter = type;
  ['all','relay_reg','transfer'].forEach(function(t) {
    var btn = document.getElementById('tf-'+t);
    if (btn) btn.className = 'tf' + (t === type ? ' active' : '');
  });
  filterEntries();
}

function changePage(dir) {
  page = Math.max(0, page + dir);
  render();
  window.scrollTo(0, 0);
}

function clearVerify() {
  document.getElementById('verify-result').style.display = 'none';
}

// The verdict box. A row in the list is only what the relay sent; "verified"
// is said only after js/ct-log-verify.js has checked the pinned key, the signed
// tree head and the inclusion proof in this browser (see that file for why).
var VT = {
  key: {t: 'Sleutel van de relay is de sleutel die deze site vastzet', n: 'Geen vastgezette sleutel voor deze relay; niet gecontroleerd', f: 'Sleutel klopt niet'},
  sth: {t: 'Ondertekende boomstand (STH) klopt onder die sleutel', n: 'Ondertekende boomstand kon niet worden opgehaald', f: 'Handtekening over de boomstand klopt niet'},
  inclusion: {t: 'Inclusiebewijs leidt van deze vermelding naar de ondertekende wortel', n: 'Inclusiebewijs kon niet worden opgehaald', f: 'Inclusiebewijs klopt niet'},
  consistency: {t: 'Boom is een uitbreiding van de stand die deze browser eerder zag', n: 'Geen eerdere boomstand in deze browser, dus groei niet gecontroleerd. Bij een volgend bezoek wel.', f: 'Boom is geen uitbreiding van de stand die deze browser eerder zag'}
};
var verifyRun = 0;

function verifyHash() {
  var q = document.getElementById('verify-input').value.trim().toLowerCase();
  var el = document.getElementById('verify-result');
  if (!q || q.length < 8) { el.style.display='none'; return; }

  var match = allEntries.find(function(e) {
    return (e.leaf_hash||'').startsWith(q) || (e.tree_hash||'').startsWith(q);
  });

  el.style.display = 'block';
  el.removeAttribute('data-verdict');
  if (!match) {
    el.className = 'verify-result notfound';
    el.innerHTML = '<strong>✗ Niet gevonden in het log</strong><br>'
      + '<span class="verify-why">Deze hash komt niet voor in het deel van het log dat nu is geladen (de laatste duizend vermeldingen).</span>';
    return;
  }

  var isLeaf = (match.leaf_hash||'').startsWith(q);
  var idx = String(match.index);
  var details = '<pre>'
    + 'Gevonden veld : ' + esc(isLeaf ? 'leaf_hash' : 'tree_hash') + '\n'
    + 'Index         : ' + esc(idx) + '\n'
    + 'Leaf-hash     : ' + esc(match.leaf_hash||'n/a') + '\n'
    + 'Tree-hash     : ' + esc(match.tree_hash||'n/a') + '\n'
    + 'Tijdstip      : ' + (match.ts ? esc(new Date(match.ts).toISOString()) : 'n/a')
    + '</pre>';
  el.className = 'verify-result listed';
  var run = ++verifyRun;
  if (!isLeaf) {
    el.setAttribute('data-verdict', 'unchecked');
    el.innerHTML = '<strong>' + esc('Gevonden in de lijst op index {i}, niet cryptografisch bevestigd'.replace('{i}', idx)) + '</strong><br><span class="verify-why">Dit is een tree-hash. Alleen een leaf-hash wordt hier tegen de ondertekende boom gecontroleerd.</span>' + details;
    return;
  }
  el.innerHTML = '<strong>' + esc('Gevonden in de lijst op index {i}. Cryptografische controle loopt…'.replace('{i}', idx)) + '</strong>' + details;
  import('/js/ct-log-verify.js?v=1').then(function(m) {
    return m.verifyEntry({ relay: RELAY, index: match.index, leafHash: match.leaf_hash });
  }).then(function(res) {
    if (run !== verifyRun) return;
    var head = res.verdict === 'verified' ? '✓ Geverifieerd: index {i} staat in de door deze relay ondertekende boom'
      : res.verdict === 'failed' ? '✗ Controle mislukt: het antwoord van de relay klopt niet' : 'Gevonden in de lijst op index {i}, niet cryptografisch bevestigd';
    el.className = 'verify-result ' + (res.verdict === 'verified' ? 'found' : res.verdict === 'failed' ? 'notfound' : 'listed');
    var list = '<ul class="verify-steps">' + res.steps.map(function(s) {
      var k = s.ok === true ? 't' : s.ok === false ? 'f' : 'n';
      return '<li data-step="' + esc(s.id) + '" data-ok="' + k + '">' + (k === 't' ? '✓ ' : k === 'f' ? '✗ ' : '– ') + esc(VT[s.id][k]) + '</li>';
    }).join('') + '</ul>';
    el.innerHTML = '<strong>' + esc(head.replace('{i}', idx)) + '</strong>' + list
      + '<span class="verify-why">Wat dit niet bewijst: dat anderen dezelfde boom zien. Er is nog geen onafhankelijke bewaarder van de boomstanden.</span>' + details;
    el.setAttribute('data-verdict', res.verdict);
  }).catch(function() {
    if (run !== verifyRun) return;
    el.innerHTML = '<strong>' + esc('Gevonden in de lijst op index {i}, niet cryptografisch bevestigd'.replace('{i}', idx)) + '</strong>' + details;
    el.setAttribute('data-verdict', 'unchecked');
  });
}

// ── Tab switching ─────────────────────────────────────────────────────────────
function switchTab(tab) {
  document.getElementById('pane-log').style.display    = tab === 'log'    ? '' : 'none';
  document.getElementById('pane-relays').style.display = tab === 'relays' ? '' : 'none';
  document.getElementById('tab-log').classList.toggle('active',    tab === 'log');
  document.getElementById('tab-relays').classList.toggle('active', tab === 'relays');
  if (tab === 'relays') loadRelays();
}

// ── Relay registry ────────────────────────────────────────────────────────────
let relaysLoaded = false;

async function loadRelays() {
  if (relaysLoaded) return;
  relaysLoaded = true;
  var el = document.getElementById('relay-entries');
  try {
    var r = await fetch(RELAY + '/v2/relays');
    var d = await r.json();
    var relays = d.relays || [];

    document.getElementById('rstat-count').textContent = relays.length || '0';
    var sectors = [...new Set(relays.map(function(r){return r.sector;}))];
    document.getElementById('rstat-sectors').textContent = sectors.join(', ') || 'n/a';
    var latest = relays.reduce(function(a,b){ return (b.last_seen > a) ? b.last_seen : a; }, '');
    document.getElementById('rstat-last').textContent = latest
      ? new Date(latest).toLocaleString('nl-NL', {hour:'2-digit',minute:'2-digit',day:'2-digit',month:'short'})
      : 'n/a';

    if (relays.length === 0) {
      el.innerHTML = '<div class="empty-state">'
        + '<h3>Nog geen relays geregistreerd</h3>'
        + '<p>Relays registreren zichzelf bij het opstarten via <code>POST /v2/relays/register</code>, met een payload die is ondertekend met ML-DSA-65. '
        + 'Stel <code>RELAY_SELF_URL</code> en <code>RELAY_PRIMARY_URL</code> in de omgeving van de relay in om automatische registratie aan te zetten.</p></div>';
      return;
    }

    el.innerHTML = relays.map(function(relay) {
      var since = relay.verified_since
        ? new Date(relay.verified_since).toLocaleString('nl-NL', {hour:'2-digit',minute:'2-digit',day:'2-digit',month:'short',year:'2-digit'})
        : 'n/a';
      var last = relay.last_seen
        ? new Date(relay.last_seen).toLocaleString('nl-NL', {hour:'2-digit',minute:'2-digit',day:'2-digit',month:'short',year:'2-digit'})
        : 'n/a';
      var urlShort = esc(relay.url.replace(/^https?:\/\//, ''));
      return '<div class="relay-row">'
        + '<div class="url" title="' + esc(relay.url) + '">' + urlShort + '</div>'
        + '<div class="cell green">' + esc(relay.sector || 'n/a') + '</div>'
        + '<div class="cell">v' + esc(relay.version || '?') + '</div>'
        + '<div class="cell">' + esc(relay.edition || 'community') + '</div>'
        + '<div class="cell dim" title="Index in het CT-log ' + esc(String(relay.ct_index ?? '')) + '">' + since + '</div>'
        + '<div class="cell dim">' + last + '</div>'
        + '</div>';
    }).join('');
  } catch (e) {
    el.innerHTML = '<div class="loading">Het relayregister kon niet worden geladen: ' + esc(e.message) + '</div>';
  }
}

load();
setInterval(load, 30000);


act('click','changePage',(el)=>changePage(parseInt(el.dataset.arg,10)));
act('click','filterEntries',()=>filterEntries());act('input','filterEntries',()=>filterEntries());
act('click','setTypeFilter',(el)=>setTypeFilter(el.dataset.arg));
act('click','switchTab',(el)=>switchTab(el.dataset.tab));
act('click','toggle',(el)=>toggle(el.dataset.arg));
act('click','verifyHash',()=>verifyHash());act('input','clearVerify',()=>clearVerify());

