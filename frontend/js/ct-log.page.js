'use strict';

const RELAY = 'https://health.paramant.app';
const PAGE_SIZE = 20;
let allEntries = [], page = 0, filtered = [], typeFilter = 'all';

function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

async function load() {
  try {
    const [ctRes, hRes] = await Promise.all([
      fetch(RELAY + '/v2/ct/log?limit=1000'),
      fetch(RELAY + '/health', {signal: AbortSignal.timeout(4000)}).catch(() => null)
    ]);
    const d = await ctRes.json();
    allEntries = (d.entries || []).slice().reverse();
    filtered   = allEntries;

    var keyRegCount   = allEntries.filter(function(e){ return !e.type || e.type === 'key_reg'; }).length;
    var transferCount = allEntries.filter(function(e){ return e.type === 'transfer' || e.type === 'pubkey'; }).length;
    document.getElementById('stat-total').textContent = d.size != null ? d.size : allEntries.length;
    document.getElementById('stat-count').textContent = keyRegCount;
    document.getElementById('stat-transfers').textContent = transferCount;
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
        ? new Date(ts).toLocaleString('en-GB', {hour:'2-digit',minute:'2-digit',second:'2-digit',day:'2-digit',month:'short'})
        : 'n/a';
    }

    // Update notice: check if persistent (file-backed) by seeing if log survived restart
    if (d.size > 0) {
      document.getElementById('persistence-notice').style.display = '';
    }

    render();
  } catch(e) {
    document.getElementById('entries').innerHTML =
      '<div class="loading">Error loading log: ' + esc(e.message) + '</div>';
  }
}

function render() {
  const start = page * PAGE_SIZE;
  const slice = filtered.slice(start, start + PAGE_SIZE);
  const total = filtered.length;

  document.getElementById('page-info').textContent =
    total === 0 ? 'no results' : (start+1) + '–' + Math.min(start+PAGE_SIZE, total) + ' of ' + total;
  document.getElementById('prev-btn').disabled = page === 0;
  document.getElementById('next-btn').disabled = start + PAGE_SIZE >= total;

  if (slice.length === 0) {
    document.getElementById('entries').innerHTML =
      '<div class="empty-state">'
      + '<div class="big">📋</div>'
      + '<h3>' + (allEntries.length === 0 ? 'Log is empty' : 'No results') + '</h3>'
      + '<p>' + (allEntries.length === 0
          ? 'No public key registrations yet. The CT log records every device registration as an immutable entry. Entries appear here in real time.'
          : 'No entries match your filter.')
      + '</p></div>';
    return;
  }

  document.getElementById('entries').innerHTML = slice.map(function(e, i) {
    var gi  = start + i;
    var idx = e.index !== undefined ? e.index : (filtered.length - 1 - gi);
    var ts  = e.ts;
    var time = ts
      ? new Date(ts).toLocaleString('en-GB', {hour:'2-digit',minute:'2-digit',second:'2-digit',day:'2-digit',month:'short'})
      : 'n/a';
    var leaf   = trunc(e.leaf_hash   || e.hash || '');
    var tree   = trunc(e.tree_hash   || e.merkle_root || '');
    var device = trunc(e.device_hash || e.pubkey_hash  || '');
    var proofHtml = '';
    if (e.proof && e.proof.length) {
      proofHtml = '<div class="drow"><span class="dkey">Merkle proof</span>'
        + '<span class="dval"><div class="proof-chain">'
        + e.proof.map(function(h){return '<span class="proof-hash">'+esc(h.slice(0,16))+'…</span>';}).join('')
        + '</div></span></div>';
    }
    return '<div class="entry" data-click="toggle" data-arg="'+gi+'">'
      + '<div class="idx">'+esc(String(idx))+'</div>'
      + '<div class="hash leaf">'+esc(leaf)+'</div>'
      + '<div class="hash">'+esc(tree)+'</div>'
      + '<div class="hash">'+esc(device)+'</div>'
      + '<div class="ts">'+esc(time)+'</div>'
      + '</div>'
      + '<div class="entry-detail" id="d-'+gi+'">'
      + (e.type ? '<div class="drow"><span class="dkey">Type</span><span class="dval">'+esc(e.type)+'</span></div>' : '')
      + '<div class="drow"><span class="dkey">Leaf hash</span><span class="dval">'+esc(e.leaf_hash||'n/a')+'</span></div>'
      + '<div class="drow"><span class="dkey">Tree hash</span><span class="dval">'+esc(e.tree_hash||'n/a')+'</span></div>'
      + '<div class="drow"><span class="dkey">Device hash</span><span class="dval">'+esc(e.device_hash||'n/a')+'</span></div>'
      + '<div class="drow"><span class="dkey">Index</span><span class="dval">'+esc(String(idx))+'</span></div>'
      + '<div class="drow"><span class="dkey">Timestamp</span><span class="dval">'+(ts ? esc(new Date(ts).toISOString()) : 'n/a')+'</span></div>'
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
        || (e.device_hash||'').includes(q) || String(e.index||'').includes(q);
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

function verifyHash() {
  var q = document.getElementById('verify-input').value.trim().toLowerCase();
  var el = document.getElementById('verify-result');
  if (!q || q.length < 8) { el.style.display='none'; return; }

  var match = allEntries.find(function(e) {
    return (e.leaf_hash||'').startsWith(q) || (e.device_hash||'').startsWith(q)
        || (e.tree_hash||'').startsWith(q);
  });

  el.style.display = 'block';
  if (!match) {
    el.className = 'verify-result notfound';
    el.innerHTML = '<strong>✗ Not found in log</strong><br>'
      + '<span style="color:#999;font-size:11px">This hash has no matching entry in the current log window. '
      + 'If the log was recently reset, older entries may no longer be present.</span>';
    return;
  }

  el.className = 'verify-result found';
  var field = (match.leaf_hash||'').startsWith(q) ? 'leaf_hash'
             : (match.device_hash||'').startsWith(q) ? 'device_hash' : 'tree_hash';
  el.innerHTML = '<strong>✓ Verified: found at index ' + esc(String(match.index)) + '</strong>'
    + '<pre>'
    + 'Matched field : ' + esc(field) + '\n'
    + 'Index         : ' + esc(String(match.index)) + '\n'
    + 'Leaf hash     : ' + esc(match.leaf_hash||'n/a') + '\n'
    + 'Tree hash     : ' + esc(match.tree_hash||'n/a') + '\n'
    + 'Device hash   : ' + esc(match.device_hash||'n/a') + '\n'
    + 'Timestamp     : ' + (match.ts ? esc(new Date(match.ts).toISOString()) : 'n/a') + '\n'
    + (match.proof && match.proof.length ? 'Merkle proof  : ' + esc(match.proof.join(' → ')) : '')
    + '</pre>';
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
      ? new Date(latest).toLocaleString('en-GB', {hour:'2-digit',minute:'2-digit',day:'2-digit',month:'short'})
      : 'n/a';

    if (relays.length === 0) {
      el.innerHTML = '<div class="empty-state"><div class="big">📡</div>'
        + '<h3>No relays registered yet</h3>'
        + '<p>Relays register themselves at startup via <code>POST /v2/relays/register</code> using an ML-DSA-65 signed payload. '
        + 'Set <code>RELAY_SELF_URL</code> and <code>RELAY_PRIMARY_URL</code> in the relay environment to enable auto-registration.</p></div>';
      return;
    }

    el.innerHTML = relays.map(function(relay) {
      var since = relay.verified_since
        ? new Date(relay.verified_since).toLocaleString('en-GB', {hour:'2-digit',minute:'2-digit',day:'2-digit',month:'short',year:'2-digit'})
        : 'n/a';
      var last = relay.last_seen
        ? new Date(relay.last_seen).toLocaleString('en-GB', {hour:'2-digit',minute:'2-digit',day:'2-digit',month:'short',year:'2-digit'})
        : 'n/a';
      var urlShort = esc(relay.url.replace(/^https?:\/\//, ''));
      return '<div class="relay-row">'
        + '<div class="url" title="' + esc(relay.url) + '">' + urlShort + '</div>'
        + '<div class="cell green">' + esc(relay.sector || 'n/a') + '</div>'
        + '<div class="cell">v' + esc(relay.version || '?') + '</div>'
        + '<div class="cell">' + esc(relay.edition || 'community') + '</div>'
        + '<div class="cell dim" title="CT log index ' + esc(String(relay.ct_index ?? '')) + '">' + since + '</div>'
        + '<div class="cell dim">' + last + '</div>'
        + '</div>';
    }).join('');
  } catch (e) {
    el.innerHTML = '<div class="loading">Error loading relay registry: ' + esc(e.message) + '</div>';
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

