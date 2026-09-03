'use strict';

const RELAY_WS  = 'wss://relay.paramant.app';
const RELAY_SECTORS = {
  health:  'https://health.paramant.app',
  legal:   'https://legal.paramant.app',
  finance: 'https://finance.paramant.app',
  iot:     'https://iot.paramant.app',
};
let RELAY_API = RELAY_SECTORS.health; // updated after key validation

let apiKey = '', keyValid = false, selectedFile = null, selectedFiles = [];
// The credential this page really runs on. `sessionAuth` is a pst_ session
// token: fifteen minutes, scoped by the relay to the five routes a transfer
// walks, and minted per browser session. `apiKey` above is now only ever the
// manual way out, for a self-hosted relay with no /api/user/parasend/token.
// Exactly one of the two is set; relayAuthHeaders() is the one place that
// decides which header goes on a request.
let sessionAuth = '', sessionAuthExp = 0, sessionAuthPending = null;
// Sector discovery is its own question, kept apart from keyValid: a key can be
// perfectly good while not one of the four sectors answers. relayReady says a
// sector was found; relayError carries the reason it was not.
let relayReady = false, relayError = '';
// The receiver-pubkey poll lives next to the socket, and reopenSession has to
// be able to stop it: a second poll on a dead token would keep asking forever.
let pubkeyPoll = null;
// nginx puts /api/user/ in the relay_auth zone (burst 5). One fetch for the
// session token, and at most one retry, 2 s later, when that fetch is throttled.
const KEY_RETRY_MS = 2000;
// Where the token comes from. The admin mints it against the account this
// browser is signed in as; the page never sees the account key.
const TOKEN_URL = '/api/user/parasend/token';
// Refresh a minute before the relay would stop honouring it. A sender who
// spends twenty minutes choosing a 4 GB file and comparing a fingerprint must
// not hit an expiry at the upload, which is the one step that cannot be
// cheaply retried.
const TOKEN_MARGIN_MS = 60000;
let sessionToken = '', ws = null;
let receiverPubs = null;
// Which of the two stands the page is in. 'live' is the handshake this page was
// built for: both online, a code compared, nothing stored. 'link' is the stand
// added for the sender whose receiver is not at a desk right now -- the file is
// sealed in this browser, parked on the relay under a one-time download token,
// and the key travels in the URL fragment where no server ever sees it.
let sendMode = 'live';
// The per-plan link lifetimes, straight from tiers.js by way of GET
// /v2/check-key. Never written into the page by hand: see the comment on the
// chooser in parashare.html.
let planTtlByPlan = null, planTtlMs = 0;
// The links this browser session has minted, newest last. Page-local on
// purpose: the relay keeps no list of a sender's outstanding links, and
// pretending otherwise would be a claim this build cannot keep.
const sentLinks = [];

// ── Helpers ──
function $(id) { return document.getElementById(id); }
// The same apology the signer gives, from the same file, so sending and signing
// cannot drift into two different sentences. This page is a classic script and
// cannot import, so js/error-message.js is loaded above it as a plain script and
// hangs its namespace off the global. The fallback string exists for the case
// where that tag is missing; it is never the normal path.
function failureText(where, e) {
  var errors = window.paramantErrors;
  if (errors) return errors.reportFailure(where, e).message;
  console.error('[paramant] ' + where, e);
  return 'Something went wrong on our side. Try again in a minute; if it keeps happening, ' +
         'mail privacy@paramant.app with the time and what you did.';
}
function showStep(id) {
  document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
  $(id).classList.add('active');
  globeOnStepChange(id);
  // The 5-stage stepper describes the sender's journey. Hide it for the
  // receiver-only download path (step-tb-download); show + advance otherwise.
  // The stepper is the LIVE journey: share the link, compare the code, encrypt.
  // The receiver-only download path never walks it, and neither does the
  // Send-a-link stand, which has no share-and-compare stage to be at. Showing it
  // there would put a sender on "3 . Compare" in a flow with nothing to compare.
  var stepper = $('ps-stepper');
  if (stepper) stepper.style.display = (id === 'step-tb-download' || sendMode === 'link') ? 'none' : '';
  var stepperKey = ({
    'step-setup': 'setup',
    'step-waiting': 'share',
    'step-encrypting': 'encrypt',
    'step-done': 'done'
  })[id];
  if (stepperKey) setStepperStage(stepperKey);
}

// Stepper: highlight current stage, mark earlier stages as done.
var STEPPER_ORDER = ['setup', 'share', 'verify', 'encrypt', 'done'];
function setStepperStage(key) {
  var idx = STEPPER_ORDER.indexOf(key);
  if (idx < 0) return;
  var nodes = document.querySelectorAll('#ps-stepper .ps-step');
  nodes.forEach(function(n, i) {
    n.classList.remove('active');
    n.classList.remove('done');
    if (i < idx) n.classList.add('done');
    else if (i === idx) n.classList.add('active');
  });
}

// Show the full API-key card. Two callers: the "Change" link in the slim row,
// and the way out on the error banner, which is the path a self-hoster whose
// deployment cannot mint a session token takes.
function expandApiKeyCard() {
  var s = $('step-setup');
  if (s) s.classList.add('manual-key');
  setKeyError(false);
  // Asking for the box means taking over from the session token, so the token
  // is dropped here rather than left as a second credential the page might
  // still reach for. One credential at a time, always.
  sessionAuth = ''; sessionAuthExp = 0; sessionAuthPending = null;
  var inp = $('api-key');
  if (inp) { inp.value = ''; inp.focus(); onKeyInput(); }
  // Legacy only. This page no longer writes the key to localStorage; this
  // clears whatever a build from before that change left behind.
  try { localStorage.removeItem('paramant_api_key'); } catch (_) {}
}

// The slim row is the default state of step 1. This fills it in once the
// session key has really arrived: the mask, the label, and the green dot.
function applySlimApiKeyView(shown) {
  if (!shown) return;
  var mask = $('ps-key-mask');
  if (mask) {
    mask.textContent = shown.length > 14 ? shown.slice(0, 8) + '...' + shown.slice(-4) : shown;
    mask.hidden = false;
  }
  var label = $('ps-key-slim-label');
  if (label) label.textContent = 'Using your account';
  var row = $('ps-key-slim');
  if (row) { row.classList.remove('is-loading'); row.hidden = false; }
  var s = $('step-setup');
  if (s) s.classList.remove('manual-key');
  setKeyError(false);
}

// The banner. Shown only when the account key could not be loaded at all, and
// it takes the slim row with it: a row that says "using your account key" while
// there is no key would be the same lie the manual box used to tell.
// The banner keeps its own words on purpose: failureText is the sentence for
// what we did not plan for, and a key that will not load is planned, with a
// better next step than "try again in a minute". Its unplanned tail goes
// through failureText like everything else on this page.
function setKeyError(on) {
  var box = $('ps-key-error');
  if (box) box.classList.toggle('is-shown', !!on);
  var row = $('ps-key-slim');
  if (row && on) row.hidden = true;
}

// Step 2 used to answer a dropped socket with the bare word "Disconnected",
// which tells the sender nothing about the file they just handed over. Same
// treatment as the key banner: what happened, where the file is, one action.
function setLinkError(on, msg) {
  var box = $('ps-link-error');
  if (!box) return;
  if (on && msg) {
    var t = $('ps-link-error-text');
    if (t) t.textContent = msg;
  }
  box.classList.toggle('is-shown', !!on);
  setSessionCardStale(!!on);
}

// The alarm above the card said the session was gone; the card under it went on
// offering a beating beacon, "Waiting for receiver...", the dead link and a blue
// Copy link. A sender who copies that link sends his receiver to a session that
// no longer exists, and finds out nothing until the receiver says so. So the
// card is switched off with the alarm: greyed by CSS, marked aria-disabled for
// a screen reader, and the copy button really disabled, not just dimmed. The
// way back out is the alarm's own action, which sits outside the card.
function setSessionCardStale(stale) {
  var card = $('ps-session-card');
  if (card) {
    card.classList.toggle('is-stale', stale);
    card.setAttribute('aria-disabled', stale ? 'true' : 'false');
  }
  var copy = $('ps-copy-btn');
  if (copy) copy.disabled = stale;
  var link = $('session-link');
  if (link) link.setAttribute('aria-disabled', stale ? 'true' : 'false');
}

// Make a fresh session: new token, new link, new socket. The file is untouched
// in the file input, so the sender does not pick it again.
async function reopenSession() {
  setLinkError(false);
  if (pubkeyPoll) { clearInterval(pubkeyPoll); pubkeyPoll = null; }
  if (ws) { try { ws.onclose = null; ws.close(); } catch (_) {} ws = null; }
  receiverPubs = null;
  var fp = $('fp-card');
  if (fp) fp.style.display = 'none';
  $('waiting-title').textContent = 'Waiting for receiver...';
  $('waiting-dot').className = 'dot amber';
  await createSession();
}
function setStatus(id, msg, cls) {
  const el = $(id);
  el.textContent = msg;
  el.className = 'status-line' + (cls ? ' ' + cls : '');
}

// SHA-256(kyber_pub || ecdh_pub) → first 10 bytes → 5×4 hex groups
// Both parties compute independently; mismatch = relay MITM detected.
async function genFingerprint(kyberPubHex, ecdhPubHex) {
  const buf = hexToU8(kyberPubHex + (ecdhPubHex || ''));
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
  const h = [...hash.slice(0, 10)].map(b => b.toString(16).padStart(2,'0')).join('').toUpperCase();
  return `${h.slice(0,4)}-${h.slice(4,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}`;
}

function u8toHex(u8) {
  return [...u8].map(b => b.toString(16).padStart(2,'0')).join('');
}
function hexToU8(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.slice(i*2, i*2+2), 16);
  return arr;
}
function concat(...arrays) {
  const total = arrays.reduce((s,a) => s + a.length, 0);
  const out = new Uint8Array(total); let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}
function u32be(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}
function toB64(u8) {
  let s = ''; const SZ = 8192;
  for (let i = 0; i < u8.length; i += SZ) s += String.fromCharCode(...u8.slice(i,i+SZ));
  return btoa(s);
}

// The meter never stands alone: the percentage is written next to it and onto
// the track itself, so a screen reader hears the same number the eye reads.
function setEncProgress(pct) {
  const rounded = Math.max(0, Math.min(100, Math.round(Number(pct) || 0)));
  const readout = $('enc-pct');
  const track = $('enc-progress-track');
  if (readout) readout.textContent = rounded + '%';
  if (track) track.setAttribute('aria-valuenow', String(rounded));
}

async function copyLink() {
  // The confirmation belongs on the button, not in the link box: overwriting
  // the link with "Copied!" hides the thing you just asked to see.
  const button = $('ps-copy-btn');
  // A dead session hands out no links. pointer-events on the greyed card stops
  // the mouse; this stops everything else, the share box's own click handler
  // included.
  if (button && button.disabled) return;
  const url = $('session-link').textContent;
  let copied = true;
  await navigator.clipboard.writeText(url).catch(() => { copied = false; });
  if (!button) return;
  if (button._resetTimer) clearTimeout(button._resetTimer);
  button.textContent = copied ? 'Copied' : 'Copy failed';
  button.classList.toggle('is-copied', copied);
  button._resetTimer = setTimeout(() => {
    button.textContent = 'Copy link';
    button.classList.remove('is-copied');
  }, 2000);
}

// ── Fingerprint localStorage (TOFU) ──
function fpStorageKey(fp) { return 'paramant_fp_' + fp.replace(/-/g,''); }
function storeFingerprintConfirmed(fp) {
  try { localStorage.setItem(fpStorageKey(fp), JSON.stringify({ fp, ts: new Date().toISOString() })); } catch {}
}
function isFingerprintKnown(fp) {
  try { return !!localStorage.getItem(fpStorageKey(fp)); } catch { return false; }
}

// ── QR code for fingerprint ──
function renderFingerprintQR(fp) {
  const canvas = $('fp-qr');
  if (!canvas || typeof QRCode === 'undefined') return;
  try {
    QRCode.toCanvas(canvas, fp, { width: 140, margin: 1, color: { dark: '#000', light: '#fff' } });
    canvas.style.display = '';
    const lbl = $('fp-qr-label');
    if (lbl) lbl.style.display = '';
  } catch(e) { console.warn('QR render failed:', e); }
}

// ── Helpers ──
async function showReceiverConnected(kyberPub, ecdhPub) {
  receiverPubs = { kyber_pub: kyberPub, ecdh_pub: ecdhPub };
  const fp = await genFingerprint(kyberPub, ecdhPub);
  $('fp-card').style.display = '';
  $('fp-display').textContent = fp;
  $('waiting-title').textContent = 'Receiver connected';
  $('waiting-dot').className = 'dot';
  setLinkError(false);
  setStatus('waiting-status', 'Your receiver is waiting for you to compare the code');
  setStepperStage('verify');
  // TOFU: check if we've verified this fingerprint before
  if (isFingerprintKnown(fp)) {
    $('fp-seen-before').style.display = '';
    $('fp-new-device').style.display = 'none';
  } else {
    $('fp-new-device').style.display = '';
    $('fp-seen-before').style.display = 'none';
  }
  // Render QR code for easy scanning
  renderFingerprintQR(fp);
}

// ── The credential, and the one place that presents it ──────────────────────
// Every relay call on this page goes through relayFetch. Two reasons it is one
// function and not five copies: the header depends on which credential the page
// is running (a Bearer token from the session, or a hand-typed key on a
// self-host), and a token can die halfway through a long send. Spread over five
// call sites, one of them would eventually be written without the refresh.
function relayAuthHeaders(extra) {
  var h = {};
  for (var k in (extra || {})) if (Object.prototype.hasOwnProperty.call(extra, k)) h[k] = extra[k];
  if (sessionAuth) h['Authorization'] = 'Bearer ' + sessionAuth;
  else if (apiKey) h['X-Api-Key'] = apiKey;
  return h;
}

// Ask the admin for a token. The account is the one this browser is signed in
// as; there is nothing to send and nothing the page could name.
async function fetchSessionToken() {
  var r = await fetch(TOKEN_URL, { method: 'POST', credentials: 'include' });
  // nginx rate-limits /api/user/ (zone relay_auth, burst 5). A 429 here is the
  // page arriving next to its own siblings, not a broken account, so it earns
  // exactly one retry and then gives up.
  if (r.status === 429) {
    await new Promise(function (res) { setTimeout(res, KEY_RETRY_MS); });
    r = await fetch(TOKEN_URL, { method: 'POST', credentials: 'include' });
  }
  // Expected, and marked so: a browser with no session gets 401/403, and a
  // self-host that never built this endpoint answers 404. Both mean "no token
  // here", the banner is the whole answer, and neither is worth a line in the
  // console of every signed-out visitor.
  if (!r.ok) {
    var refused = new Error('session token: HTTP ' + r.status);
    refused.expected = r.status === 401 || r.status === 403 || r.status === 404;
    throw refused;
  }
  var d = await r.json();
  if (!d || !d.token) {
    var none = new Error('session token: none for this session');
    none.expected = true;
    throw none;
  }
  return d;
}

// One refresh at a time. Two uploads racing an expiry would otherwise mint two
// tokens and each keep the other's, and the loser would carry a token it had
// already replaced.
function refreshSessionAuth() {
  if (sessionAuthPending) return sessionAuthPending;
  sessionAuthPending = fetchSessionToken().then(function (d) {
    sessionAuth = d.token;
    sessionAuthExp = Date.now() + (d.expires_in_s || 0) * 1000;
    sessionAuthPending = null;
    return true;
  }).catch(function () {
    // The token is left as it was. A failed refresh is not proof the old one is
    // dead, and throwing the credential away here would turn a blip in the
    // admin into a dead page.
    sessionAuthPending = null;
    return false;
  });
  return sessionAuthPending;
}

// One relay call, with whichever credential this page is running, and exactly
// one recovery: a token that expired mid-session is replaced and the call is
// made again. Once. A 401 that survives a fresh token is a real 401.
async function relayFetch(url, opts) {
  opts = opts || {};
  // A refresh already tried and failed on this call means minting is broken
  // right now, and a 401 below is not something a second attempt will fix. Two
  // mints per call, against an endpoint nginx allows a burst of five, is how a
  // page turns one bad minute into a rate limit of its own.
  var minted = true;
  if (sessionAuth && sessionAuthExp && Date.now() > sessionAuthExp - TOKEN_MARGIN_MS) {
    minted = await refreshSessionAuth();
  }
  var send = {};
  for (var k in opts) if (Object.prototype.hasOwnProperty.call(opts, k) && k !== 'retried') send[k] = opts[k];
  send.headers = relayAuthHeaders(opts.headers);
  var r = await fetch(url, send);
  if (r.status === 401 && sessionAuth && !opts.retried && minted) {
    if (await refreshSessionAuth()) {
      var again = {};
      for (var k2 in opts) if (Object.prototype.hasOwnProperty.call(opts, k2)) again[k2] = opts[k2];
      again.retried = true;
      return relayFetch(url, again);
    }
  }
  return r;
}

// ── Relay discovery: try all sectors in parallel, pick first valid ──
// It used to fold two different failures into one null: "a sector answered and
// refused this key" and "not one sector answered". The first is about the key,
// the second is about the network, and only the first should ever disable the
// button. So the two are reported apart.
async function discoverRelay() {
  const results = await Promise.allSettled(
    Object.entries(RELAY_SECTORS).map(async ([sector, url]) => {
      const r = await relayFetch(`${url}/v2/check-key`, {
        signal: AbortSignal.timeout(5000)
      });
      const d = await r.json();
      return {
        sector, url, plan: d.plan, valid: !!d.valid,
        link_ttl_ms: d.link_ttl_ms, link_ttl_ms_by_plan: d.link_ttl_ms_by_plan,
      };
    })
  );
  const answered = results.filter(r => r.status === 'fulfilled').map(r => r.value);
  const valid = answered.filter(a => a.valid);
  return {
    // Every sector that spoke said no. That is a verdict on the key.
    rejected: answered.length > 0 && valid.length === 0,
    // Prefer health; otherwise first sector that responded
    found: valid.find(v => v.sector === 'health') || valid[0] || null
  };
}

// ── Credential validation ──
// Nothing is written to localStorage, and on the hosted relay nothing that
// reaches this page is an API key at all: the credential is a pst_ session
// token, minted per browser session and scoped by the relay to the five routes
// a transfer walks. The manual card below is the self-host path, and it is the
// only one that still holds a pgp_ key.
//
// The two paths share everything after the credential: find a sector that
// accepts the account, and report the result without holding the button
// hostage to a sector that will not answer.
async function discoverAndReport() {
  setStatus('key-status', 'Checking...');
  updateBtn();
  let d;
  try {
    d = await discoverRelay();
  } catch (e) {
    d = { answered: false, rejected: false, found: null };
  }
  if (d.found) {
    RELAY_API = d.found.url;
    relayReady = true;
    applyPlanTtls(d.found);
    const sectorLabel = d.found.sector !== 'health' ? ` · ${d.found.sector}` : '';
    setStatus('key-status', `✓ Valid, plan: ${d.found.plan}${sectorLabel}`, 'ok');
  } else if (d.rejected) {
    // A sector answered and said no. On the session path that is a verdict on
    // the account, not on anything the sender typed, so it is not called a bad
    // key: there is no key here to be bad.
    setStatus('key-status', sessionAuth ? 'This account is not active on any relay sector' : 'Invalid or revoked key', 'err');
    keyValid = false;
  } else {
    // Nothing answered. Say so where the user is looking, and let the button
    // stay live: the failure belongs at the press, with a reason attached.
    relayError = 'No relay sector answered. Check your connection and press Create secure session again.';
    setStatus('key-status', 'Could not reach a relay sector. You can still continue.', 'err');
  }
  updateBtn();
}

// The session path: a token is already in hand, so there is nothing to check
// about its shape and the sector question is the only one left.
async function useSessionToken() {
  apiKey = '';
  keyValid = true; relayReady = false; relayError = '';
  await discoverAndReport();
}

// The manual card, for a self-hosted relay with no token endpoint. Typing a key
// takes over from the session token; expandApiKeyCard has already dropped it,
// and this drops it again for the case where the box was filled another way.
async function onKeyInput() {
  sessionAuth = ''; sessionAuthExp = 0; sessionAuthPending = null;
  apiKey = $('api-key').value.trim();
  setCreateStatus('');
  // An empty box has nothing wrong with it yet. Calling it invalid is what the
  // "Change" link did the moment it cleared the field: a red-flavoured verdict
  // on a field the user had not filled in.
  if (!apiKey) {
    setStatus('key-status', 'Enter your API key to continue');
    keyValid = false; relayReady = false; relayError = ''; updateBtn(); return;
  }
  if (apiKey.length < 10 || !apiKey.startsWith('pgp_')) {
    setStatus('key-status', 'That does not look like a key. It starts with pgp_.', 'err');
    keyValid = false; relayReady = false; relayError = ''; updateBtn(); return;
  }
  keyValid = true; relayReady = false; relayError = '';
  await discoverAndReport();
}

function setCreateStatus(msg, cls) {
  const el = $('create-status');
  if (!el) return;
  el.textContent = msg || '';
  el.className = 'status-line' + (cls ? ' ' + cls : '');
}

function onFileSelect() {
  const files = $('file-input').files;
  selectedFile = files[0] || null;
  if (!files.length) { setStatus('file-status', 'No file selected'); $('vault-list').style.display='none'; updateBtn(); return; }
  if (files.length === 1) {
    setStatus('file-status', '✓ ' + files[0].name + ' (' + (files[0].size/1024/1024).toFixed(1) + ' MB)', 'ok');
    $('vault-list').style.display = 'none';
  } else {
    setStatus('file-status', '✓ ' + files.length + ' files, sent as a single package', 'ok');
    const vl = $('vault-list');
    vl.style.display = 'block';
    vl.innerHTML = [...files].map(f =>
      '<div style="font-size:10px;color:rgba(248,250,252,.65);padding:2px 0;font-family:var(--mono)">' + f.name + ' <span style="color:rgba(248,250,252,.5)">(' + (f.size/1024/1024).toFixed(1) + ' MB)</span></div>'
    ).join('');
  }
  updateBtn();
}

function updateBtn() {
  selectedFiles = $('file-input') ? [...$('file-input').files] : [];
  $('btn-create-session').disabled = !(keyValid && selectedFiles.length > 0);
}

// ── Session creation ──
async function createSession() {
  // A sector that would not answer during discovery used to leave this button
  // disabled with no explanation. Try once more here, and if it still will not
  // answer, say so out loud instead of going quiet.
  if (!relayReady) {
    setCreateStatus('Looking for a relay sector...');
    // The sector question only, not the credential question. Calling onKeyInput
    // here would re-read the manual box, and on the session path that box is
    // empty by design: the retry would throw away a working token and report a
    // missing key instead of a missing sector.
    await discoverAndReport();
    if (!relayReady) {
      // relayError is the planned sentence. Reaching here without one is a state
      // we did not plan for, so it gets the page's one sentence for that.
      setCreateStatus(relayError || failureText('relay sector discovery', new Error('no sector answered')), 'err');
      return;
    }
  }
  setCreateStatus('');
  // Generate random invite token
  const tokenBytes = crypto.getRandomValues(new Uint8Array(16));
  sessionToken = 'inv_' + u8toHex(tokenBytes).slice(0, 32);

  // Build receiver URL
  const activeSector = Object.entries(RELAY_SECTORS).find(([, u]) => u === RELAY_API)?.[0] || 'health';
  const recvUrl = `${location.origin}/ontvang?s=${encodeURIComponent(sessionToken)}&r=${activeSector}`;
  $('session-link').textContent = recvUrl;

  setLinkError(false);
  showStep('step-waiting');
  connectWebSocket();
}

// ── WebSocket signaling ──
async function connectWebSocket() {
  let wsUrl = RELAY_WS + '/v2/stream';
  try {
    // Ticket must come from the same relay host the WS connects to (relay-main)
    const wsHttpBase = RELAY_WS.replace('wss://', 'https://').replace('ws://', 'http://');
    const tr = await relayFetch(`${wsHttpBase}/v2/ws-ticket`, {method:'POST',signal:AbortSignal.timeout(5000)});
    if (tr.ok) { const td = await tr.json(); if (td.ticket) wsUrl += '?ticket=' + encodeURIComponent(td.ticket); }
  } catch {}
  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    // Join the invite room
    ws.send(JSON.stringify({ type: 'join', room: sessionToken, nick: 'sender' }));
    setLinkError(false);
    setStatus('waiting-status', 'Waiting for your receiver to open the link...');
  };

  // Poll voor receiver pubkey via ghost pipe relay
  if (pubkeyPoll) clearInterval(pubkeyPoll);
  pubkeyPoll = setInterval(async () => {
    try {
      const r = await relayFetch(`${RELAY_API}/v2/pubkey/${encodeURIComponent(sessionToken)}`, { signal: AbortSignal.timeout(3000) });
      if (r.ok) {
        const d = await r.json();
        if (d.kyber_pub && d.ecdh_pub) {
          clearInterval(pubkeyPoll); pubkeyPoll = null;
          await showReceiverConnected(d.kyber_pub, d.ecdh_pub);
        }
      }
    } catch(e) {}
  }, 2000);

  ws.onmessage = async (e) => {
    let msg;
    try { msg = JSON.parse(e.data); } catch { return; }

    try {
      if (msg.type === 'pubkey_offer' && msg.kyber_pub && msg.ecdh_pub) {
        await showReceiverConnected(msg.kyber_pub, msg.ecdh_pub);
      }

      if (msg.type === 'peer_left') {
        setStatus('waiting-status', 'Your receiver closed the link', 'err');
        setLinkError(true, 'Your receiver closed the link before you compared the code. Nothing was uploaded and your file is still here in this browser.');
      }
    } catch(err) {
      setStatus('waiting-status', failureText('receiver message', err), 'err');
    }
  };

  // Both of these used to write one word into a status line. A sender who has
  // just handed over a file needs to know that it did not go anywhere.
  ws.onerror = () => {
    if (receiverPubs) return;
    setStatus('waiting-status', 'Connection lost', 'err');
    setLinkError(true, 'The connection failed before your receiver arrived. Nothing was uploaded and your file is still here in this browser.');
  };
  ws.onclose = () => {
    if (receiverPubs) return;
    setStatus('waiting-status', 'Connection lost', 'err');
    setLinkError(true, 'The connection dropped before your receiver arrived. Nothing was uploaded and your file is still here in this browser.');
  };
}

// ── Fingerprint confirmed — encrypt & send ──
async function confirmFingerprint() {
  if (!receiverPubs) return;
  if (!document.getElementById('fp-confirm-check')?.checked) return;

  // Guard: abort if WASM crypto bridge failed to load
  if (!window._cryptoBridge?.encryptBlob) {
    setStatus('waiting-status', 'ERROR: WASM crypto module not loaded — cannot encrypt safely. Refresh and try again.', 'err');
    return;
  }

  // Store confirmed fingerprint in localStorage (TOFU)
  const confirmedFp = $('fp-display').textContent;
  if (confirmedFp && confirmedFp !== '—') storeFingerprintConfirmed(confirmedFp);

  // Tell receiver we confirmed (best-effort via WS — file transfer uses HTTP anyway)
  try { ws.send(JSON.stringify({ type: 'packet', chatHash: sessionToken, seq: 0, payload: JSON.stringify({ type: 'fingerprint_ok' }) })); } catch(e) { console.warn('WS send failed (non-fatal):', e.message); }

  showStep('step-encrypting');

  try {
    const CHUNK_PLAIN = 4.5 * 1024 * 1024;
    const META_MAGIC = new Uint8Array([0x50, 0x52, 0x53, 0x48]);
    const ttlMs = parseInt($('ttl-select').value);

    // Helper: encrypt + upload one file, returns token array
    async function encryptFile(file, fileIndex, totalFiles) {
      const totalChunks = Math.ceil(file.size / CHUNK_PLAIN) || 1;
      const fileId = u8toHex(crypto.getRandomValues(new Uint8Array(8)));
      const tokens = [];

      // Grootte-waarschuwing bij > 500MB
      if (file.size > 500 * 1024 * 1024) {
        $('enc-status').textContent = 'Large file (' + (file.size/1024/1024/1024).toFixed(2) + ' GB) — streaming mode, reading chunk by chunk...';
        await new Promise(r => setTimeout(r, 400));
      }

      for (let i = 0; i < totalChunks; i++) {
        const globalPct = Math.round(
          ((fileIndex + (i / totalChunks)) / totalFiles) * 85
        );
        $('enc-progress').style.width = globalPct + '%';
        setEncProgress(globalPct);
        const mbDone = Math.round((i * CHUNK_PLAIN) / 1024 / 1024);
        const mbTotal = Math.round(file.size / 1024 / 1024);
        $('enc-status').textContent = (totalFiles > 1 ? 'File ' + (fileIndex+1) + '/' + totalFiles + ' — ' : '') +
          'Encrypting ' + mbDone + '/' + mbTotal + ' MB (chunk ' + (i+1) + '/' + totalChunks + ')...';

        const start = Math.round(i * CHUNK_PLAIN);
        const end = Math.min(start + CHUNK_PLAIN, file.size);
        // Stream-read: alleen dit chunk in RAM, niet het hele bestand
        const chunkData = new Uint8Array(await file.slice(start, end).arrayBuffer());

        const metaJson = JSON.stringify({
          file_id: fileId, file_name: file.name,
          file_size: file.size, chunk_index: i,
          total_chunks: totalChunks, chunk_size: chunkData.length
        });
        const metaBytes = new TextEncoder().encode(metaJson);
        const payload = concat(META_MAGIC, u32be(metaBytes.length), metaBytes, chunkData);

        // ML-KEM-768 + ECDH P-256 + AES-256-GCM via Rust/WASM (crypto-bridge.js)
        const padded = await window._cryptoBridge.encryptBlob(
          payload,
          hexToU8(receiverPubs.kyber_pub),
          hexToU8(receiverPubs.ecdh_pub)
        );

        const mbUp = Math.round((i * CHUNK_PLAIN) / 1024 / 1024);
        $('enc-status').textContent = (totalFiles > 1 ? 'File ' + (fileIndex+1) + '/' + totalFiles + ' — ' : '') +
          'Uploading ' + mbUp + '/' + Math.round(file.size/1024/1024) + ' MB...';
        const hashBuf = await crypto.subtle.digest('SHA-256', padded);
        const hash = u8toHex(new Uint8Array(hashBuf));

        const ur = await relayFetch(RELAY_API + '/v2/inbound', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            hash, payload: toB64(padded), ttl_ms: ttlMs,
            // file_name omitted — filename is only in the encrypted payload (finding #4)
            meta: { device_id: 'transfer-web', chunk_index: i, total_chunks: totalChunks, file_id: fileId }
          }),
          signal: AbortSignal.timeout(120000)
        });
        const ud = await ur.json();
        // Free monthly transfer limit: keep the relay's 402 JSON on the error
        // so the catch below renders the upgrade notice instead of a raw error.
        if (window.paQuotaUpgrade && window.paQuotaUpgrade.isQuota402(ur.status, ud)) {
          const qe = new Error(ud.error); qe.quota = ud; throw qe;
        }
        if (!ud.ok) throw new Error(ud.error || 'Upload failed: ' + file.name);
        tokens.push(ud.download_token);
      }
      return { name: file.name, size: file.size, tokens };
    }

    // Upload all files
    const files = [...$('file-input').files];
    const vaultFiles = [];
    for (let fi = 0; fi < files.length; fi++) {
      vaultFiles.push(await encryptFile(files[fi], fi, files.length));
    }

    $('enc-progress').style.width = '100%';
    setEncProgress(100);
    $('enc-status').textContent = 'Notifying receiver...';

    const isVault = files.length > 1;
    await relayFetch(RELAY_API + '/v2/pubkey', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        device_id: sessionToken + '_ready',
        ecdh_pub: isVault ? JSON.stringify(vaultFiles) : vaultFiles[0].tokens.join(','),
        kyber_pub: isVault
          ? 'vault|' + files.length + '|' + ttlMs
          : files[0].name + '|' + vaultFiles[0].tokens.length + '|' + ttlMs
      })
    });

    const label = isVault
      ? files.length + ' files sent — vault ready for receiver'
      : files[0].name + ' sent securely';
    $('done-status').textContent = '✓ ' + label;
    showStep('step-done');

  } catch(e) {
    if (e && e.quota && window.paQuotaUpgrade) {
      // Quota reached is a purchase moment, not an error dump. Server JSON only.
      $('enc-status').className = 'status-line';
      $('enc-status').innerHTML = window.paQuotaUpgrade.html(e.quota);
    } else {
      $('enc-status').textContent = failureText('encrypt and upload', e);
      $('enc-status').className = 'status-line err';
    }
  }
}

// ── Send a link ──────────────────────────────────────────────────────────────
//
// WHAT THIS STAND IS FOR. An administratiekantoor wants to mail a payslip to
// somebody who is not online right now. The live handshake above cannot do it
// by design: it needs two browsers awake at the same moment. So this stand
// seals the file here, parks it on the relay under a one-time download token,
// and hands the sender one link.
//
// WHERE THE KEY GOES. Into the URL fragment, after the '#'. A fragment is never
// put on the wire by a browser, so the relay holds ciphertext it cannot open
// even though it is holding it. That is the same trick the mail extensions
// already use, and the wire format below is the one /get already reads, byte
// for byte: [u32le nameLen][name utf8][file bytes], AES-256-GCM, and the
// fragment is base64url(key32 || iv12). Reusing it rather than inventing a
// second one is what makes the receiving half of this feature already exist.
//
// WHY NOT THE LIVE STAND'S WIRE. That one is ML-KEM-768 + ECDH to the
// RECEIVER'S public key, and in this stand there is no receiver yet to have a
// public key. There is nothing to do a key exchange with, so the file is sealed
// under a symmetric key that travels beside the link instead.

// The ceiling POST /v2/inbound enforces: MAX_BLOB, 5 MB, on every ParaSend tier
// today. One link is one blob, so a file bigger than that cannot be sent this
// way and is refused here with the number, rather than at the upload with a 413.
const LINK_MAX_BLOB = 5 * 1024 * 1024;
// AES-GCM tag (16) + the 4-byte name-length header. The file name itself is
// counted per file, below.
const LINK_OVERHEAD = 20;

function b64url(u8) {
  return toB64(u8).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function u32le(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}

// "1 hour", "24 hours", "7 days". Built from the millisecond number the relay
// serves so the sentence cannot drift from tiers.js.
function humanDuration(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n) || n <= 0) return '';
  const days = n / 86400000, hours = n / 3600000, mins = n / 60000;
  // Hours win up to two days. tiers.js Pro is 86_400_000, and "1 day on Pro"
  // next to "1 hour on Community" reads as a smaller step than it is; the
  // pricing page has always sold that row as 24 hours, and the two have to
  // agree word for word or a buyer thinks they are two different limits.
  if (days >= 2 && Number.isInteger(days))   return days  + ' days';
  if (hours >= 1 && Number.isInteger(hours)) return hours + (hours === 1 ? ' hour'   : ' hours');
  if (mins >= 1)                             return Math.round(mins) + ' minutes';
  return Math.round(n / 1000) + ' seconds';
}

// The chooser's second sentence, written from the served table. Called once a
// sector has answered; until then the markup's plan-free sentence stands, which
// is true of every plan and names no time it might get wrong.
function applyPlanTtls(found) {
  planTtlMs = Number(found && found.link_ttl_ms) || 0;
  planTtlByPlan = (found && found.link_ttl_ms_by_plan) || null;
  const el = $('ps-mode-link-ttl');
  if (!el || !planTtlByPlan) return;
  const c = humanDuration(planTtlByPlan.community);
  const pr = humanDuration(planTtlByPlan.pro);
  const b = humanDuration(planTtlByPlan.business);
  if (!c || !pr || !b) return;
  // "web app" is not decoration. tests/site-claims.test.mjs block 37 holds every
  // page about a client that never sends max_views to naming that client beside
  // a single-read claim, because "up to 10 reads on Pro" is something this page
  // will never do: it asks the relay for no read count at all.
  el.textContent = 'The sealed file waits on our server for up to ' + c + ' on Community, ' +
    pr + ' on Pro and ' + b + ' on Business, and a link from this web app is wiped after the first download.';
  // The TTL picker in step 1 offers 24 hours to an account whose plan stops at
  // one, and POST /v2/inbound silently clamps it. Saying the ceiling here is
  // cheaper than letting the sender pick a number the relay will not honour.
  const note = $('ttl-status');
  if (note && planTtlMs) {
    note.textContent = 'When the link runs out we destroy the file, picked up or not. ' +
      'Your plan holds a link to ' + humanDuration(planTtlMs) + ' at most; a longer choice is shortened to that.';
  }
}

// ── The chooser ──────────────────────────────────────────────────────────────
// Both cards stay in the DOM; only what the chosen stand does not use is
// hidden. The stepper is the live journey (share, compare) and describes
// nothing the link stand walks, so it goes away rather than lying about where
// the sender is.
function setSendMode(mode) {
  sendMode = mode === 'link' ? 'link' : 'live';
  const live = $('ps-mode-live'), link = $('ps-mode-link');
  if (live) live.setAttribute('aria-checked', String(sendMode === 'live'));
  if (link) link.setAttribute('aria-checked', String(sendMode === 'link'));
  const stepper = $('ps-stepper');
  if (stepper) stepper.style.display = (sendMode === 'link') ? 'none' : '';
  // "The person you send to has to be online while you send" is the one
  // sentence on this page that the link stand makes false.
  const note = $('ps-live-note');
  if (note) {
    note.textContent = (sendMode === 'link')
      ? 'The person you send to does not have to be online. You get a link to pass on; it works once.'
      : 'The person you send to has to be online while you send; you confirm a short code together.';
  }
  const btn = $('btn-create-session');
  if (btn) btn.textContent = (sendMode === 'link') ? 'Seal the file and make a link →' : 'Create secure session →';
  setCreateStatus('');
}
function chooseModeLive() { setSendMode('live'); }
function chooseModeLink() { setSendMode('link'); }

// The one button at the bottom of step 1, dispatched on the chosen stand. The
// two flows share step 1 entirely -- same credential, same file picker, same
// expiry choice -- and part company only here.
async function startSend() {
  return (sendMode === 'link') ? createLink() : createSession();
}

// ── Seal one file and upload it ──────────────────────────────────────────────
// Returns { name, size, token, key, expires_ms }. Throws on refusal, with the
// relay's quota JSON attached when that is what happened, so the caller can
// render the upgrade notice the live stand already renders.
async function sealAndUpload(file, ttlMs) {
  const nameBytes = new TextEncoder().encode(file.name);
  if (file.size + nameBytes.length + LINK_OVERHEAD > LINK_MAX_BLOB) {
    throw new Error(file.name + ' is too big for a link. One link is one 5 MB block; ' +
      'send it with the live hand-over, which splits a file into chunks.');
  }
  const plain = concat(u32le(nameBytes.length), nameBytes, new Uint8Array(await file.arrayBuffer()));
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', key));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain));

  const hashBuf = await crypto.subtle.digest('SHA-256', ct);
  const hash = u8toHex(new Uint8Array(hashBuf));
  const ur = await relayFetch(RELAY_API + '/v2/inbound', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      hash, payload: toB64(ct), ttl_ms: ttlMs,
      // No file name and no size on the relay side: the name lives only inside
      // the sealed bytes, which is the same rule the live stand keeps.
      meta: { device_id: 'transfer-web-link' }
    }),
    signal: AbortSignal.timeout(120000)
  });
  const ud = await ur.json();
  if (window.paQuotaUpgrade && window.paQuotaUpgrade.isQuota402(ur.status, ud)) {
    const qe = new Error(ud.error); qe.quota = ud; throw qe;
  }
  if (!ud.ok) throw new Error(ud.error || 'Upload failed: ' + file.name);
  return {
    name: file.name, size: file.size, token: ud.download_token,
    // The relay's ttl_ms, not the one that was asked for: POST /v2/inbound
    // clamps to the tier, and the expiry the sender is shown has to be the one
    // the relay will actually act on.
    expires_ms: Date.now() + Number(ud.ttl_ms || ttlMs),
    key: b64url(concat(rawKey, iv)),
    state: 'waiting',
  };
}

function setSealProgress(pct) {
  const rounded = Math.max(0, Math.min(100, Math.round(Number(pct) || 0)));
  const bar = $('seal-progress');
  const readout = $('seal-pct');
  const track = $('seal-progress-track');
  if (bar) bar.style.width = rounded + '%';
  if (readout) readout.textContent = rounded + '%';
  if (track) track.setAttribute('aria-valuenow', String(rounded));
}

async function createLink() {
  if (!relayReady) {
    setCreateStatus('Looking for a relay sector...');
    await discoverAndReport();
    if (!relayReady) {
      setCreateStatus(relayError || failureText('relay sector discovery', new Error('no sector answered')), 'err');
      return;
    }
  }
  setCreateStatus('');
  const files = [...$('file-input').files];
  if (!files.length) return;
  const ttlMs = parseInt($('ttl-select').value);
  const sector = Object.entries(RELAY_SECTORS).find(([, u]) => u === RELAY_API)?.[0] || 'health';

  showStep('step-sealing');
  setSealProgress(0);
  try {
    for (let i = 0; i < files.length; i++) {
      $('seal-status').textContent = (files.length > 1 ? 'File ' + (i + 1) + '/' + files.length + ': ' : '') +
        'Sealing ' + files[i].name + ' in this browser...';
      setSealProgress(Math.round((i / files.length) * 90));
      const row = await sealAndUpload(files[i], ttlMs);
      // The sector rides in the link because an account lives on exactly one of
      // them; without it /get asks health and a legal sender's receiver is told
      // the file is burned when it is sitting on another sector.
      row.url = location.origin + '/get?t=' + encodeURIComponent(row.token) +
        '&r=' + encodeURIComponent(sector) + '#' + row.key;
      sentLinks.push(row);
    }
    setSealProgress(100);
    renderSentLinks();
    showStep('step-link');
    refreshSentLinks();
  } catch (e) {
    if (e && e.quota && window.paQuotaUpgrade) {
      $('seal-status').className = 'status-line';
      $('seal-status').innerHTML = window.paQuotaUpgrade.html(e.quota);
    } else {
      $('seal-status').textContent = failureText('seal and upload', e);
      $('seal-status').className = 'status-line err';
    }
  }
}

// ── The sent-links list ──────────────────────────────────────────────────────
// NOT a receipt list, and the page says so under it. The relay signs a delivery
// receipt on the API download path (GET /v2/outbound, fetched back from
// /v2/transfers/:id/receipt); the browser download path, GET /v2/dl/:token/get,
// signs nothing. What is left is GET /v2/dl/:token/info, which answers 200 with
// the time remaining while the link is live and 404 once it is "not found, used,
// or expired" -- one status for three outcomes. This page separates the last two
// with its own clock: a 404 before the expiry it recorded means the file was
// taken, after it means it timed out. That is an inference, and the note under
// the list calls it one.
function linkStateLabel(row) {
  if (row.state === 'delivered') return 'Downloaded, and the file is gone';
  if (row.state === 'expired')   return 'Expired, and the file is gone';
  return 'Waiting for the receiver';
}

function renderSentLinks() {
  const list = $('ps-link-list');
  if (!list) return;
  list.innerHTML = '';
  sentLinks.forEach((row, i) => {
    const li = document.createElement('li');
    li.className = 'ps-link-row';
    li.dataset.linkIndex = String(i);

    const name = document.createElement('div');
    name.className = 'ps-link-name';
    name.textContent = row.name;
    li.appendChild(name);

    const url = document.createElement('div');
    url.className = 'ps-link-url';
    url.textContent = row.url;
    li.appendChild(url);

    const meta = document.createElement('div');
    meta.className = 'ps-link-meta';
    const state = document.createElement('span');
    state.className = 'ps-link-state is-' + row.state;
    state.textContent = linkStateLabel(row);
    meta.appendChild(state);
    const exp = document.createElement('span');
    // One date format for the whole site (#424): day, month in full, year, and
    // the clock in UTC, because a one-hour link is a moment and not a day.
    exp.textContent = 'Expires ' + (window.paramantDate
      ? window.paramantDate.moment(row.expires_ms)
      : new Date(row.expires_ms).toISOString());
    meta.appendChild(exp);
    const once = document.createElement('span');
    once.textContent = 'Works once';
    meta.appendChild(once);
    li.appendChild(meta);

    const copy = document.createElement('button');
    copy.type = 'button';
    copy.className = 'ps-copy';
    copy.setAttribute('data-click', 'copySentLink');
    copy.setAttribute('data-link-index', String(i));
    copy.textContent = 'Copy link';
    li.appendChild(copy);

    list.appendChild(li);
  });
}

async function copySentLink(el) {
  const i = parseInt(el && el.getAttribute('data-link-index'), 10);
  const row = sentLinks[i];
  if (!row) return;
  let copied = true;
  await navigator.clipboard.writeText(row.url).catch(() => { copied = false; });
  if (el._resetTimer) clearTimeout(el._resetTimer);
  el.textContent = copied ? 'Copied' : 'Copy failed';
  el.classList.toggle('is-copied', copied);
  el._resetTimer = setTimeout(() => {
    el.textContent = 'Copy link';
    el.classList.remove('is-copied');
  }, 2000);
}

// No credential on this call: /v2/dl/:token/info is the receiver's half of the
// route family and takes none. Sending the session token here would be widening
// a fifteen-minute credential to a route that does not want it.
async function refreshSentLinks() {
  const btn = $('ps-link-refresh');
  if (btn) { btn.disabled = true; btn.textContent = 'Checking...'; }
  for (const row of sentLinks) {
    if (row.state !== 'waiting') continue;
    try {
      const r = await fetch(RELAY_API + '/v2/dl/' + encodeURIComponent(row.token) + '/info',
        { signal: AbortSignal.timeout(8000) });
      if (r.ok) row.state = 'waiting';
      else if (r.status === 404) row.state = (Date.now() < row.expires_ms) ? 'delivered' : 'expired';
    } catch (_) {
      // A check that did not arrive says nothing about the link. Leave the row
      // as it was rather than reporting a delivery that may not have happened.
    }
  }
  renderSentLinks();
  if (btn) { btn.disabled = false; btn.textContent = 'Check again'; }
}

function rejectFingerprint() {
  ws.close();
  showStep('step-setup');
  setStatus('key-status', 'Transfer aborted — fingerprint mismatch', 'err');
}

// ── Globe HUD ─────────────────────────────────────────────────────────────────
let globeInstance = null, globeOpen = false, globePollInterval = null;
let _gUserLat = null, _gUserLng = null;  // set after geo lookup
const RELAY_LOC = { lat: 50.1109, lng: 8.6821, label: 'Relay · Nuremberg EU/DE' };

// Keyboard shortcut
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'g') { e.preventDefault(); toggleGlobe(); }
  if (e.key === 'Escape' && globeOpen) toggleGlobe();
});

// ── Thunderbird FileLink download — URL format: ?t=T1,T2&n=NAME&c=N&r=RELAY#k=K1,K2 ──
// Keys travel in the fragment (never sent to server). Relay only sees download tokens.
async function tbDecryptChunk(blobBytes, rawKeyB64url) {
  // Decode URL-safe base64 (no padding)
  const b64 = rawKeyB64url.replace(/-/g,'+').replace(/_/g,'/');
  const padded64 = b64 + '=='.slice(0, (4 - b64.length % 4) % 4);
  const rawKey = Uint8Array.from(atob(padded64), c => c.charCodeAt(0));
  const blob = new Uint8Array(blobBytes);
  const version = blob[0];
  if (version !== 0x02) throw new Error('Unsupported packet version ' + version + ' — this link was generated by an older version');
  const nonce  = blob.slice(1, 13);
  const ctLen  = new DataView(blob.buffer, 13, 4).getUint32(0, false);
  const ct     = blob.slice(17, 17 + ctLen);
  const symKey = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
  const plain  = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, symKey, ct));
  // PRSH layout: magic(4) | metaLen(4) | metaJSON | chunkData
  if (plain[0]!==0x50||plain[1]!==0x52||plain[2]!==0x53||plain[3]!==0x48) throw new Error('Invalid decrypted payload — wrong key?');
  const metaLen = new DataView(plain.buffer, 4, 4).getUint32(0, false);
  const data = plain.slice(8 + metaLen);
  return data;
}

async function tbDownload(tokensParam, name, relay, keysParam) {
  const tokens = tokensParam.split(',');
  const keys   = keysParam.split(',');
  if (tokens.length !== keys.length) throw new Error('Token/key count mismatch in URL');
  const dlStatus = $('tb-dl-status');
  const dlBar    = $('tb-dl-bar');
  const chunks = [];
  for (let i = 0; i < tokens.length; i++) {
    dlStatus.textContent = 'Downloading chunk ' + (i+1) + ' of ' + tokens.length + '…';
    dlBar.style.width = Math.round((i / tokens.length) * 60) + '%';
    const resp = await fetch(relay + '/v2/dl/' + tokens[i] + '/get');
    if (!resp.ok) throw new Error('Download failed: HTTP ' + resp.status + ' for chunk ' + i);
    const buf = await resp.arrayBuffer();
    dlStatus.textContent = 'Decrypting chunk ' + (i+1) + '…';
    const data = await tbDecryptChunk(buf, keys[i]);
    chunks.push(data);
    dlBar.style.width = Math.round(((i+1) / tokens.length) * 90) + '%';
  }
  // Reassemble
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const assembled = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { assembled.set(c, off); off += c.length; }
  dlBar.style.width = '100%';
  dlStatus.className = 'status-line ok';
  dlStatus.textContent = 'Decrypted — saving file…';
  // Trigger browser download
  const url = URL.createObjectURL(new Blob([assembled]));
  const a = document.createElement('a');
  a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
  $('tb-dl-title').textContent = 'Downloaded.';
  $('tb-dl-sub').textContent   = 'File decrypted and saved. The key existed only in your browser.';
  $('tb-dl-dot').className     = 'dot';
}

// Auto-init globe as background on load, restore saved API key
document.addEventListener('DOMContentLoaded', () => {
  // Thunderbird FileLink download mode — check before restoring upload UI
  const sp = new URLSearchParams(location.search);
  const tbTokens = sp.get('t');
  const tbRelay  = sp.get('r');
  const tbKeys   = location.hash.startsWith('#k=') ? location.hash.slice(3) : null;
  if (tbTokens && tbKeys && tbRelay) {
    showStep('step-tb-download');
    tbDownload(tbTokens, decodeURIComponent(sp.get('n') || 'download'), decodeURIComponent(tbRelay), tbKeys)
      .catch(e => {
        $('tb-dl-status').className = 'status-line err';
        $('tb-dl-status').textContent = failureText('download', e);
        $('tb-dl-dot').className = 'dot red';
      });
    setTimeout(() => initGlobe(), 400);
    return;
  }

  loadSessionCredential();
  // Small delay so DOM is fully painted before Globe.gl reads dimensions
  setTimeout(() => initGlobe(), 400);
});

// The session is the only source of the credential, and the credential is no
// longer the account key. The page asks the admin for a pst_ session token; the
// key stays on the server. What the buyer review caught first was a second
// source of truth in localStorage, and what the security review caught after it
// was the key itself: a credential with no expiry and no scope, held for the
// life of the tab, readable by anything that got to run on the page. There is
// one source, it hands over something that expires in fifteen minutes, and it
// opens five routes.
async function loadSessionCredential() {
  try {
    const d = await fetchSessionToken();
    sessionAuth = d.token;
    sessionAuthExp = Date.now() + (d.expires_in_s || 0) * 1000;
    // The slim row shows the token, masked, and not the key: there is no key
    // here to show. The manual box stays empty, which is what makes the two
    // credentials impossible to confuse.
    applySlimApiKeyView(d.token);
    await useSessionToken();
  } catch (e) {
    setKeyError(true);
    // The banner carries the sentence either way. Only the unplanned half gets
    // reported: a 500, or a fetch that never arrived. Reporting the planned half
    // would put a console error on every signed-out page load, which is both
    // noise and a false alarm for the heartbeat that reads that console.
    if (!e || !e.expected) failureText('session token', e);
    setStatus('key-status', 'Account session could not be started', 'err');
    keyValid = false;
    updateBtn();
  }
}

function toggleGlobe() {
  const overlay = document.getElementById('globe-overlay');
  const mainEl  = document.querySelector('main');
  const navEl   = document.querySelector('nav');
  globeOpen = !globeOpen;
  if (globeOpen) {
    // Fullscreen HUD mode: hide UI, show HUD panels
    overlay.classList.add('globe-fullscreen');
    if (mainEl) mainEl.style.display = 'none';
    const _gb = document.getElementById('globe-btn'); if (_gb) _gb.style.color = '#B2FF3F';
    if (_gb) _gb.style.boxShadow = '0 0 12px rgba(178,255,63,.3)';
    if (_gb) _gb.textContent = '✕ Close';
  } else {
    // Background mode: restore UI, hide HUD panels
    overlay.classList.remove('globe-fullscreen');
    if (mainEl) mainEl.style.display = '';
    const _gb2 = document.getElementById('globe-btn'); if (_gb2) _gb2.style.color = '';
    if (_gb2) _gb2.style.boxShadow = '';
    if (_gb2) _gb2.textContent = '⬡ Globe';
    if (globePollInterval) { clearInterval(globePollInterval); globePollInterval = null; }
  }
}

function loadScript(src) {
  return new Promise((ok, fail) => {
    if (document.querySelector(`script[src="${src}"]`)) { ok(); return; }
    const s = document.createElement('script');
    s.src = src; s.onload = ok; s.onerror = fail;
    document.head.appendChild(s);
  });
}

async function initGlobe() {
  if (globeInstance) { startGlobePoll(); return; }

  // Dynamisch laden — alleen als globe geopend wordt
  try {
    await loadScript('/globe.gl.min.js');
  } catch(e) {
    document.getElementById('globe-loading').innerHTML =
      '<span style="color:#e05252">Failed to load Globe.gl — check network</span>';
    return;
  }

  // Gebruikerslocatie: gebruik relay-locatie als fallback (privacy — geen externe IP lookup)
  let userLat = RELAY_LOC.lat + 0.5, userLng = RELAY_LOC.lng - 2;
  _gUserLat = userLat; _gUserLng = userLng;
  document.getElementById('hud-loc').textContent = 'EU · DE';

  const wrap = document.getElementById('globe-canvas-wrap');

  // Globe.gl instantiëren
  globeInstance = Globe({ animateIn: true })
    .globeImageUrl('/images/globe/earth-night.jpg')
    .bumpImageUrl('/images/globe/earth-topology.png')
    .backgroundImageUrl('/images/globe/night-sky.png')
    .showAtmosphere(true)
    .atmosphereColor('#B2FF3F')
    .atmosphereAltitude(0.18)
    // HTML dots — crisp DOM elements, no pixelation at any zoom
    .htmlElementsData([
      { lat: userLat,      lng: userLng,      label: 'Your Node',          type: 'user'  },
      { lat: RELAY_LOC.lat, lng: RELAY_LOC.lng, label: RELAY_LOC.label,   type: 'relay' },
    ])
    .htmlElement(d => {
      const wrap = document.createElement('div');
      const color = d.type === 'relay' ? '#B2FF3F' : 'var(--ink-dim)';
      wrap.innerHTML = `<div title="${d.label}" style="
        width:14px;height:14px;border-radius:50%;
        background:${color};
        box-shadow:0 0 10px ${color},0 0 20px ${color}55;
        border:2px solid rgba(255,255,255,.5);
        cursor:pointer;position:relative">
        <div style="position:absolute;top:-22px;left:50%;transform:translateX(-50%);
          white-space:nowrap;font:9px/1.2 monospace;color:${color};
          background:rgba(12,12,12,.8);padding:2px 5px;
          pointer-events:none;letter-spacing:.06em">${d.label}</div>
      </div>`;
      return wrap.firstChild;
    })
    .htmlTransitionDuration(0)
    // Transfer arc gebruiker → relay
    .arcsData([
      {
        startLat: userLat, startLng: userLng,
        endLat: RELAY_LOC.lat, endLng: RELAY_LOC.lng,
        color: ['rgba(178,255,63,0)', '#B2FF3F', '#B2FF3F', 'rgba(178,255,63,0)'],
        label: 'Ghost Pipe · Encrypted Channel',
      }
    ])
    .arcColor(d => d.color)
    .arcDashLength(0.35)
    .arcDashGap(0.18)
    .arcDashAnimateTime(2200)
    .arcStroke(0.4)
    .arcAltitudeAutoScale(0.35)
    .arcLabel(d => `<div style="font:10px monospace;background:rgba(12,12,12,.9);
      border:1px solid rgba(178,255,63,.25);padding:4px 8px;color:#B2FF3F">${d.label}</div>`)
    // Pulserende ringen op knooppunten
    .ringsData([
      { lat: userLat, lng: userLng, maxR: 3, propagationSpeed: 2.5, repeatPeriod: 1200, color: () => 'rgba(178,255,63,' },
      { lat: RELAY_LOC.lat, lng: RELAY_LOC.lng, maxR: 2.5, propagationSpeed: 2, repeatPeriod: 1600, color: () => 'rgba(178,255,63,' },
    ])
    .ringColor(d => t => `${d.color()}${1 - t})`)
    .ringMaxRadius('maxR')
    .ringPropagationSpeed('propagationSpeed')
    .ringRepeatPeriod('repeatPeriod')
    (wrap);

  // Expliciete grootte na mount — Globe.gl leest offsetWidth/Height op mount moment
  // gebruik requestAnimationFrame zodat de browser de reflow heeft verwerkt
  requestAnimationFrame(() => {
    const w = wrap.offsetWidth  || window.innerWidth;
    const h = wrap.offsetHeight || window.innerHeight;
    globeInstance.width(w).height(h);
  });

  // Resize handler
  if (!window._globeResizeHandler) {
    window._globeResizeHandler = () => {
      if (!globeInstance) return;
      const wr = document.getElementById('globe-canvas-wrap');
      const w = wr.offsetWidth  || window.innerWidth;
      const h = wr.offsetHeight || window.innerHeight;
      globeInstance.width(w).height(h);
    };
    window.addEventListener('resize', window._globeResizeHandler);
  }

  // Startpositie: tussen gebruiker en relay
  globeInstance.pointOfView({ lat: (userLat + RELAY_LOC.lat) / 2, lng: (userLng + RELAY_LOC.lng) / 2, altitude: 2.0 }, 1200);

  // Toon controls info
  globeInstance.controls().autoRotate = true;
  globeInstance.controls().autoRotateSpeed = 0.35;

  // Stop autorotate bij interactie
  wrap.addEventListener('mousedown', () => { globeInstance.controls().autoRotate = false; });
  wrap.addEventListener('touchstart', () => { globeInstance.controls().autoRotate = false; });

  // Verberg loading
  document.getElementById('globe-loading').style.display = 'none';

  // Poll relay stats
  startGlobePoll();

  // Live transfer arc bijwerken als er een actieve sessie is
  updateGlobeTransfer(userLat, userLng);
}

function startGlobePoll() {
  if (globePollInterval) return;
  updateGlobeStats();
  globePollInterval = setInterval(updateGlobeStats, 8000);
}

async function updateGlobeStats() {
  // Health check
  try {
    const r = await fetch(RELAY_API + '/health', { signal: AbortSignal.timeout(4000) });
    const d = await r.json();
    const bl = document.getElementById('hud-blobs');
    if (bl) bl.textContent = (d.blobs || 0) + ' blobs';
    const up = document.getElementById('hud-uptime');
    if (up && d.uptime_s) {
      const h = Math.floor(d.uptime_s / 3600), m = Math.floor((d.uptime_s % 3600) / 60);
      up.textContent = h + 'h ' + m + 'm';
    }
  } catch(e) {}

  // Actieve sessie bijwerken
  updateSessionsPanel();
}

function updateSessionsPanel() {
  const el = document.getElementById('hud-sessions');
  if (!el) return;
  const sessions = [];

  if (sessionToken) {
    const step = document.querySelector('.step.active');
    const stepId = step ? step.id : '';
    let status = 'Idle';
    if (stepId === 'step-waiting') status = receiverPubs ? 'Receiver connected' : 'Awaiting receiver';
    else if (stepId === 'step-encrypting') status = 'Encrypting...';
    else if (stepId === 'step-done') status = 'Transfer complete';
    sessions.push({ label: 'Session · ' + sessionToken.slice(4,12) + '...', status, active: stepId !== 'step-done' });
  }

  const st = document.getElementById('hud-session-stat');
  if (st) st.textContent = sessions.length ? sessions[0].status : 'No session';

  el.innerHTML = sessions.length
    ? sessions.map(s => `<div class="hud-session">
        <span class="hud-dot${s.active ? '' : ' amber'}"></span>
        <span style="flex:1">${s.label}</span>
        <span style="color:rgba(178,255,63,.5);font-size:9px">${s.status}</span>
      </div>`).join('')
    : '<div class="hud-session"><span class="hud-dot amber"></span><span>No active session</span></div>';
}

// ── Globe state machine ───────────────────────────────────────────────────────
const _GLOBE_STATES = {
  idle:       { arcSpeed: 2800, arcColor: ['rgba(178,255,63,0)','#B2FF3F','#B2FF3F','rgba(178,255,63,0)'], ringSpeed: 1800, ringMax: 2.5, label: 'Ghost Pipe · Encrypted Channel' },
  waiting:    { arcSpeed: 1800, arcColor: ['rgba(178,255,63,0)','var(--ink-dim)','var(--ink-dim)','rgba(178,255,63,0)'], ringSpeed: 1200, ringMax: 3,   label: 'Ghost Pipe · Receiver Connected' },
  encrypting: { arcSpeed: 700,  arcColor: ['rgba(178,255,63,0)','#fff','var(--ink-dim)','rgba(178,255,63,0)'],   ringSpeed: 600,  ringMax: 4,   label: 'Ghost Pipe · Transmitting ▶' },
  done:       { arcSpeed: 2800, arcColor: ['rgba(178,255,63,0)','#B2FF3F','#B2FF3F','rgba(178,255,63,0)'], ringSpeed: 1800, ringMax: 2.5, label: 'Ghost Pipe · Transfer Complete ✓' },
};

function _globeApplyState(name) {
  if (!globeInstance || _gUserLat === null) return;
  const s = _GLOBE_STATES[name] || _GLOBE_STATES.idle;
  const uLat = _gUserLat, uLng = _gUserLng;
  const rLat = RELAY_LOC.lat, rLng = RELAY_LOC.lng;

  globeInstance
    .arcsData([{
      startLat: uLat, startLng: uLng,
      endLat: rLat, endLng: rLng,
      color: s.arcColor, label: s.label,
    }])
    .arcColor(d => d.color)
    .arcDashAnimateTime(s.arcSpeed)
    .ringsData([
      { lat: uLat, lng: uLng, maxR: s.ringMax, propagationSpeed: 2.5, repeatPeriod: s.ringSpeed, color: () => 'rgba(178,255,63,' },
      { lat: rLat, lng: rLng, maxR: s.ringMax * 0.9, propagationSpeed: 2, repeatPeriod: s.ringSpeed * 1.15, color: () => 'rgba(178,255,63,' },
    ])
    .ringColor(d => t => `${d.color()}${1 - t})`)
    .ringMaxRadius('maxR')
    .ringPropagationSpeed('propagationSpeed')
    .ringRepeatPeriod('repeatPeriod');
}

function _globeBurst() {
  if (!globeInstance || _gUserLat === null) return;
  const uLat = _gUserLat, uLng = _gUserLng;
  const rLat = RELAY_LOC.lat, rLng = RELAY_LOC.lng;
  // Big burst rings — 3 waves from relay and user
  const burstRings = [];
  for (let i = 0; i < 3; i++) {
    burstRings.push({ lat: rLat, lng: rLng, maxR: 8 + i * 4, propagationSpeed: 5 + i, repeatPeriod: 99999, color: () => 'rgba(178,255,63,' });
    burstRings.push({ lat: uLat, lng: uLng, maxR: 6 + i * 3, propagationSpeed: 4 + i, repeatPeriod: 99999, color: () => 'rgba(178,255,63,' });
  }
  globeInstance
    .ringsData(burstRings)
    .ringColor(d => t => `${d.color()}${1 - t})`)
    .ringMaxRadius('maxR')
    .ringPropagationSpeed('propagationSpeed')
    .ringRepeatPeriod('repeatPeriod');

  // Flash arc white then restore idle
  globeInstance.arcsData([{
    startLat: uLat, startLng: uLng,
    endLat: rLat, endLng: rLng,
    color: ['rgba(255,255,255,0)', '#fff', 'var(--ink-dim)', 'rgba(178,255,63,0)'],
    label: 'Ghost Pipe · Transfer Complete ✓',
  }]).arcDashAnimateTime(400);

  setTimeout(() => _globeApplyState('done'), 3200);
}

function globeOnStepChange(stepId) {
  if (!globeInstance) return;
  if (stepId === 'step-waiting')    _globeApplyState('waiting');
  else if (stepId === 'step-encrypting') _globeApplyState('encrypting');
  else if (stepId === 'step-done')  _globeBurst();
  else                              _globeApplyState('idle');
  updateSessionsPanel();
}

function updateGlobeTransfer(userLat, userLng) {
  _gUserLat = userLat; _gUserLng = userLng;
  _globeApplyState('idle');
}


act('change','fpConfirmToggle',(el)=>{const b=document.getElementById('fp-confirm-btn');if(b)b.disabled=!el.checked;});
act('change','onFileSelect',()=>onFileSelect());
act('click','confirmFingerprint',()=>confirmFingerprint());act('click','copyLink',()=>copyLink());
act('click','createSession',()=>startSend());act('click','expandApiKeyCard',()=>expandApiKeyCard());
act('click','chooseModeLive',()=>chooseModeLive());act('click','chooseModeLink',()=>chooseModeLink());
act('click','copySentLink',(el)=>copySentLink(el));act('click','refreshSentLinks',()=>refreshSentLinks());
act('click','rejectFingerprint',()=>rejectFingerprint());act('input','onKeyInput',()=>onKeyInput());
act('click','reload',()=>location.reload());
act('click','reopenSession',()=>reopenSession());
