// ParaID for logged-in users: a real wallet + requester surface (beta).
//
//  Wallet (holder): create a device holder key, get a real credential from the
//  registered Paramant Demo Authority, and answer verification requests with an
//  on-device proof. Nothing about you leaves the device except the yes/no answer.
//
//  Requester: build a predicate request ("18+?") with a fresh nonce, share it,
//  and verify the answer against the public issuer registry + revocation list.
//
// The holder key here is a real ML-DSA-65 key kept in this browser (localStorage
// for the beta; passkey-PRF hardware binding is the next step). The credential is
// signed by a registered issuer, so answers verify as "registered", not "demo".
import { ml_dsa65, sha3_256 } from '/vendor/paramant-pqc.js';

const $ = (id) => document.getElementById(id);
const te = new TextEncoder();
const hex = (u8) => Array.from(u8).map((b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (s) => new Uint8Array(s.match(/.{1,2}/g).map((b) => parseInt(b, 16)));
const b64 = (u8) => btoa(String.fromCharCode(...u8));
const b64url = (u8) => b64(u8).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64 = (s) => new Uint8Array([...atob(s)].map((c) => c.charCodeAt(0)));
const fromB64url = (s) => fromB64(s.replace(/-/g, '+').replace(/_/g, '/'));
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
const concat = (...ps) => { const t = ps.reduce((n, p) => n + p.length, 0); const o = new Uint8Array(t); let k = 0; for (const p of ps) { o.set(p, k); k += p.length; } return o; };
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const leafHash = (salt, key, value) => sha3_256(concat(salt, te.encode(key + ':' + value)));
function merklePath(leaves, target) {
  const path = []; let lvl = leaves.slice(); let pos = target;
  while (lvl.length > 1) { const nx = []; for (let i = 0; i < lvl.length; i += 2) { if (i + 1 === lvl.length) { nx.push(lvl[i]); continue; } nx.push(sha3_256(concat(lvl[i], lvl[i + 1]))); } if (pos % 2 === 0) { if (pos + 1 < lvl.length) path.push({ s: 'R', h: hex(lvl[pos + 1]) }); } else { path.push({ s: 'L', h: hex(lvl[pos - 1]) }); } pos = Math.floor(pos / 2); lvl = nx; }
  return path;
}
function rootFromPath(leaf, path) { let h = leaf; for (const st of path) h = st.s === 'R' ? sha3_256(concat(h, fromHex(st.h))) : sha3_256(concat(fromHex(st.h), h)); return h; }

// Fallback order if a credential does not carry its own fieldOrder.
const HOLDER_KEY = 'paraid.holder.v1';
const CRED_KEY = 'paraid.credential.v1';

// ── Holder key (device) ──────────────────────────────────────────────────────
function loadHolder() {
  try { const s = JSON.parse(localStorage.getItem(HOLDER_KEY)); if (s) return { publicKey: fromB64(s.pk), secretKey: fromB64(s.sk) }; } catch {}
  return null;
}
function saveHolder(kp) { localStorage.setItem(HOLDER_KEY, JSON.stringify({ pk: b64(kp.publicKey), sk: b64(kp.secretKey) })); }
function createHolder() { const kp = ml_dsa65.keygen(rand(32)); saveHolder(kp); return kp; }
function holderBinding(kp) { return b64url(sha3_256(kp.publicKey)); }

function loadCredential() { try { return JSON.parse(localStorage.getItem(CRED_KEY)); } catch { return null; } }
function saveCredential(c) { localStorage.setItem(CRED_KEY, JSON.stringify(c)); }

// ── Verify an answer (registry + revocation aware) ───────────────────────────
async function verifyAnswer(b) {
  const errors = [];
  const leaf = leafHash(fromB64url(b.disclosed.salt), b.disclosed.key, b.disclosed.value);
  if (hex(rootFromPath(leaf, b.path)) !== b.root) errors.push('answer leaf does not reach the signed root');
  const issuerPk = fromB64(b.issuerPublicKey);
  if (!ml_dsa65.verify(issuerPk, fromHex(b.root), fromB64(b.rootSig))) errors.push('issuer ML-DSA-65 signature invalid');
  if ('did:paramant:' + b64url(sha3_256(issuerPk)).slice(0, 32) !== b.issuerDid) errors.push('issuer DID not bound to key');
  const bindLeaf = leafHash(fromB64url(b.binding.salt), b.binding.key, b.binding.value);
  if (hex(rootFromPath(bindLeaf, b.bindingPath)) !== b.root) errors.push('holder-binding leaf does not reach the root');
  const holderPk = fromB64(b.holderPublicKey);
  if (b.binding.value !== b64url(sha3_256(holderPk))) errors.push('presented holder key is not the bound one');
  if (!ml_dsa65.verify(holderPk, concat(fromB64url(b.nonce), fromHex(b.root)), fromB64(b.presenterSig))) errors.push('holder signature over nonce invalid (replay?)');
  let registry = 'not checked';
  try {
    const data = await (await fetch('/v1/paraid/issuers', { cache: 'no-store' })).json();
    const iss = (data.issuers || []).find((i) => i.did === b.issuerDid);
    if (!iss) registry = 'issuer NOT registered (untrusted)';
    else if (iss.status === 'revoked') { registry = 'issuer REVOKED'; errors.push('issuer is revoked'); }
    else if ((iss.revoked_credentials || []).includes(b.root)) { registry = 'credential REVOKED by issuer'; errors.push('credential is on the revocation list'); }
    else registry = 'registered: ' + iss.label;
  } catch { registry = 'registry unreachable'; }
  return { ok: errors.length === 0, errors, registry, question: b.question, answer: b.disclosed.value };
}

// ── Wallet role ──────────────────────────────────────────────────────────────
function renderWallet() {
  const kp = loadHolder();
  const cred = loadCredential();
  $('wallet-keystate').textContent = kp ? 'Holder key on this device: ' + holderBinding(kp).slice(0, 16) + '…' : 'No holder key yet.';
  const id = loadIdentity();
  const idEl = $('wallet-idstate');
  if (idEl) idEl.innerHTML = (id && id.verified)
    ? 'Liveness passed (score ' + esc(String(id.score)) + '/100). A live person was verified as present.'
    : 'Not verified yet. Run the camera liveness check above.';
  $('wallet-credstate').innerHTML = cred
    ? 'Presence credential from a registered issuer. It proves a verified live person holds this device key. No name, age or nationality are claimed.'
    : (id && id.verified ? 'Liveness passed. Now get your presence credential.' : 'Pass the liveness check first, then get a credential.');
  $('wallet-get-cred').disabled = !(id && id.verified);
}

// Supported predicates: each maps to exactly one sealed field, so a request can
// never ask for something the credential does not carry. holds_credential reveals
// only the already-public key binding (proves a valid credential exists, no data).
// Presence-tier credentials can honestly answer only one thing today: a live,
// registered-issuer-verified human is present, bound to this device. Age and
// nationality return when the document-reading tier lands (we do not fabricate).
const PREDICATES = {
  'presence_verified|yes': { field: 'presence_verified', label: 'Is a verified live person present?' },
  'age_over_18|yes': { field: 'age_over_18', label: 'Is 18 or older?' },
  'nationality|NL': { field: 'nationality', label: 'Has Dutch nationality?' },
};
const FIELD_ORDER = ['presence_verified', 'holder_binding'];

// ── Identity: no credential is issued without a verified identity ────────────
const IDENTITY_KEY = 'paraid.identity.v1';
function loadIdentity() { try { return JSON.parse(localStorage.getItem(IDENTITY_KEY)); } catch { return null; } }
function saveIdentity(id) { localStorage.setItem(IDENTITY_KEY, JSON.stringify(id)); }
// Stand-in for a live eID flow (iDIN / DigiD / EU wallet). A real integration
// redirects to the provider and returns a signed attestation; here we fill in
// the sample identity the provider would return, clearly labelled as demo.
// Presence verification via the real screen-flash liveness check. It proves a
// live human, not which human, so the credential it unlocks is presence-level:
// no name, age or nationality are asserted (we do not fabricate those).
function readLivenessResult() {
  try {
    const r = JSON.parse(localStorage.getItem('paraid.liveness.v1'));
    if (r && r.passed && r.ts && (Date.now() - new Date(r.ts).getTime()) < 10 * 60 * 1000) return r;
  } catch (_) {}
  return null;
}

async function ensureHolderAndCred(status) {
  const id = loadIdentity();
  if (!id || !id.verified) throw new Error('Pass the liveness check first.');
  let kp = loadHolder();
  if (!kp) { kp = createHolder(); status('Holder key created on this device.'); }
  const r = await fetch('/v1/paraid/issue-demo', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ holder_binding: holderBinding(kp) }) });
  if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.error || ('issuance failed (' + r.status + ')')); }
  const { credential } = await r.json();
  saveCredential(credential);
  return { kp, credential };
}

// Build an answer bundle for a specific predicate, revealing only its one field.
// The field order travels in the credential so wallet and verifier agree.
function buildAnswer(predicateStr, nonceB64url) {
  const kp = loadHolder();
  const cred = loadCredential();
  if (!kp || !cred) throw new Error('Set up your wallet first.');
  const spec = PREDICATES[predicateStr];
  if (!spec) throw new Error('Unknown predicate.');
  if (!(spec.field in cred.fields)) throw new Error('This credential cannot answer that (it does not carry ' + spec.field + ').');
  const order = cred.fieldOrder || FIELD_ORDER;
  const salts = {}; for (const k of order) salts[k] = fromB64url(cred.salts[k]);
  const leaves = order.map((k) => leafHash(salts[k], k, cred.fields[k]));
  const nonce = fromB64url(nonceB64url);
  const presenterSig = ml_dsa65.sign(kp.secretKey, concat(nonce, fromHex(cred.root)));
  const fi = order.indexOf(spec.field), bi = order.indexOf('holder_binding');
  return {
    question: spec.label, root: cred.root, rootSig: cred.rootSig,
    issuerDid: cred.issuerDid, issuerPublicKey: cred.issuerPublicKey,
    disclosed: { key: spec.field, value: cred.fields[spec.field], salt: cred.salts[spec.field] },
    path: merklePath(leaves, fi),
    binding: { key: 'holder_binding', value: cred.fields.holder_binding, salt: cred.salts.holder_binding },
    bindingPath: merklePath(leaves, bi),
    holderPublicKey: b64(kp.publicKey), presenterSig: b64(presenterSig),
    nonce: nonceB64url,
  };
}

function initWallet() {
  // Returning from the liveness page: if it passed, record it as a real
  // presence verification (no fabricated attributes).
  const live = readLivenessResult();
  if (live) {
    const prev = loadIdentity();
    if (!prev || !prev.verified) {
      saveIdentity({ verified: true, method: 'liveness', score: live.score, tier: 'presence' });
      localStorage.removeItem(CRED_KEY);
      const s = $('wallet-id-status'); if (s) s.textContent = 'Liveness passed (score ' + live.score + '/100). You can now get a presence credential.';
    }
  }
  renderWallet();
  $('wallet-get-cred').onclick = async () => {
    const status = (m) => { $('wallet-status').textContent = m; };
    try { await ensureHolderAndCred(status); status('Credential stored. Your wallet is ready.'); renderWallet(); }
    catch (e) { status('Could not get a credential: ' + (e.message || e)); }
  };
  $('wallet-create-key').onclick = () => { createHolder(); localStorage.removeItem(CRED_KEY); renderWallet(); $('wallet-status').textContent = 'New holder key created. Get a fresh credential.'; };
  // Answer an incoming request pasted or via #request=
  $('wallet-answer-btn').onclick = () => {
    let req;
    try { req = JSON.parse(fromB64url($('wallet-req-in').value.trim().replace(/^.*#request=/, '')).reduce((s, b) => s + String.fromCharCode(b), '')); }
    catch { try { req = JSON.parse($('wallet-req-in').value); } catch { $('wallet-answer-out').textContent = 'Could not read that request.'; return; } }
    try {
      const bundle = buildAnswer(req.predicate || 'presence_verified|yes', req.nonce);
      const link = location.origin + '/paraid-app#result=' + b64url(te.encode(JSON.stringify(bundle)));
      showAnswerTransparency(req, bundle);
      $('wallet-answer-out').innerHTML = 'Answer ready. Send this back to the requester:';
      $('wallet-answer-link').value = link;
      $('wallet-answer-link').hidden = false;
    } catch (e) { $('wallet-answer-out').textContent = e.message || String(e); }
  };
  const m = location.hash.match(/#request=([A-Za-z0-9_-]+)/);
  if (m) { $('wallet-req-in').value = location.origin + '/paraid-app#request=' + m[1]; document.querySelector('[data-role="wallet"]').click(); }
}

// ── Transparency log: every step, who receives what, and why ─────────────────
const TX_WHO = {
  in: 'From the verifier',
  local: 'On your device',
  device: 'Stays on device',
  out: 'Leaves to verifier',
};
function txStep(el, who, title, what, why, data) {
  const row = document.createElement('div');
  row.className = 'tx-step';
  row.innerHTML =
    '<div class="tx-who ' + who + '">' + TX_WHO[who] + '</div>' +
    '<div class="tx-body"><p class="tx-title">' + esc(title) + '</p>' +
    '<p class="tx-what">' + esc(what) + '</p>' +
    (why ? '<p class="tx-why">Why: ' + esc(why) + '</p>' : '') +
    (data ? '<pre class="tx-data">' + esc(data) + '</pre>' : '') + '</div>';
  el.appendChild(row);
}

function showAnswerTransparency(req, bundle) {
  const cred = loadCredential();
  const el = $('wallet-tx');
  el.innerHTML = '';
  el.hidden = false;
  const legend = document.createElement('div');
  legend.className = 'tx-legend';
  legend.innerHTML = 'Colour = who gets it: <b style="color:#3a6a17">stays on device</b> &#183; <b style="color:#1746a2">from verifier</b> &#183; <b style="color:#0a1626">leaves to verifier</b> &#183; <b>computed locally</b>';
  el.appendChild(legend);

  const order = (cred && cred.fieldOrder) || FIELD_ORDER;
  const hidden = order.filter((k) => k !== bundle.disclosed.key && k !== 'holder_binding');

  txStep(el, 'in', 'The verifier asks a question', PREDICATES[req.predicate] ? PREDICATES[req.predicate].label : (req.predicate || ''), 'This is the only thing they want to know. Purpose: ' + (req.purpose || 'not stated') + '.', null);
  txStep(el, 'in', 'A fresh one-time nonce', 'nonce = ' + (req.nonce || '').slice(0, 16) + '…', 'It is random and single-use, so your answer cannot be an old one replayed.', null);
  txStep(el, 'local', 'Open exactly one sealed fact', bundle.disclosed.key + ' = ' + bundle.disclosed.value, 'The credential is a Merkle tree; only this one leaf is opened, the rest stay sealed.', null);
  txStep(el, 'local', 'Build the proof path to the signed root', bundle.path.length + ' hash steps up to the issuer-signed root', 'Proves this fact belongs to a credential the issuer signed, without revealing the other facts.', null);
  txStep(el, 'device', 'Your device secret key', 'never transmitted', 'It signs the nonce but never leaves this device, so no one can impersonate you.', null);
  txStep(el, 'local', 'Sign the nonce with your device key', 'holder signature over (nonce + root)', 'Binds the answer to this device and this exact check. Freshness + who-holds-it in one signature.', null);
  if (hidden.length) txStep(el, 'device', 'These facts stay sealed on your device', hidden.join(', '), 'They are in the credential but never opened, so the verifier never learns them.', null);
  txStep(el, 'out', 'This, and only this, leaves your device', 'to the verifier', 'The complete list of what the requester receives. Nothing else is sent, and it does not pass through Paramant.',
    '{\n  answer: "' + bundle.disclosed.key + ' = ' + bundle.disclosed.value + '",\n  issuer: "' + bundle.issuerDid.slice(0, 28) + '…",\n  key_binding + issuer_signature + holder_signature + ' + bundle.path.length + ' path hashes,\n  nonce: "' + bundle.nonce.slice(0, 14) + '…"\n}');
}

// ── Requester role ───────────────────────────────────────────────────────────
function initRequester() {
  $('req-build').onclick = () => {
    const predicate = $('req-predicate').value || 'age_over_18|yes';
    const req = { v: 1, predicate, purpose: $('req-purpose').value || '', nonce: b64url(rand(16)) };
    $('req-link').value = location.origin + '/paraid-app#request=' + b64url(te.encode(JSON.stringify(req)));
    $('req-out').hidden = false;
    sessionStorage.setItem('paraid.req.nonce', req.nonce);
  };
  $('req-verify').onclick = async () => {
    let bundle;
    try { bundle = JSON.parse(fromB64url($('req-answer-in').value.trim().replace(/^.*#result=/, '')).reduce((s, b) => s + String.fromCharCode(b), '')); }
    catch { try { bundle = JSON.parse($('req-answer-in').value); } catch { $('req-verify-out').textContent = 'Could not read that answer.'; return; } }
    const r = await verifyAnswer(bundle);
    const out = $('req-verify-out');
    out.className = 'pa-result ' + (r.ok ? 'ok' : 'err');
    out.innerHTML = r.ok
      ? '<b>&#10003; ' + esc(r.question) + ' ' + esc(String(r.answer).toUpperCase()) + '</b><br>issuer: ' + esc(r.registry)
      : '<b>&#10007; rejected</b><br>' + r.errors.map(esc).join('<br>') + '<br>issuer: ' + esc(r.registry);
    out.hidden = false;
    showVerifyTransparency(bundle, r);
  };
  const m = location.hash.match(/#result=([A-Za-z0-9_-]+)/);
  if (m) { $('req-answer-in').value = location.origin + '/paraid-app#result=' + m[1]; document.querySelector('[data-role="requester"]').click(); }
}

// Verifier-side transparency: exactly what the verifier receives, checks, and
// (importantly) does NOT learn.
function showVerifyTransparency(bundle, r) {
  const el = $('req-tx'); if (!el) return;
  el.innerHTML = ''; el.hidden = false;
  const legend = document.createElement('div');
  legend.className = 'tx-legend';
  legend.innerHTML = 'Colour = who gets it: <b style="color:#1746a2">received</b> &#183; <b>checked locally</b> &#183; <b style="color:#0a1626">one network call</b> &#183; <b style="color:#3a6a17">never learned</b>';
  el.appendChild(legend);
  txStep(el, 'in', 'You receive the answer bundle', 'answer + key binding + issuer signature + holder signature + path hashes + nonce', 'This is everything the holder sent. It did not pass through Paramant.', null);
  txStep(el, 'local', 'Recompute the Merkle root and check the issuer signature', bundle.disclosed.key + ' = ' + bundle.disclosed.value + ', root chains to an issuer-signed value', 'Proves the fact is from a credential the issuer really signed, unchanged.', null);
  txStep(el, 'local', 'Check the holder binding and the fresh nonce', 'holder key matches the credential, and signed your one-time nonce', 'Stops a stolen or replayed proof: it only works from the holder device, for this check.', null);
  txStep(el, 'out', 'One call to the public issuer registry', 'GET /v1/paraid/issuers', 'Confirms the issuer is registered and not revoked. Sends nothing about the holder, the question or the answer.', null);
  txStep(el, 'device', 'What you never learn', 'name, birthdate, document number, and everything else in the credential', 'Only the one answer and who vouched reach you. The rest stayed sealed on the holder device.', null);
}

// ── Session gate + tabs ──────────────────────────────────────────────────────
async function main() {
  let authed = false, email = '';
  try { const d = await (await fetch('/api/user/session/verify', { credentials: 'include', cache: 'no-store' })).json(); authed = !!(d && d.authenticated); email = (d && d.email) || ''; } catch {}
  if (!authed) { $('pa-gate').hidden = false; $('pa-app').hidden = true; return; }
  $('pa-gate').hidden = true; $('pa-app').hidden = false;
  if (email) $('pa-email').textContent = email;
  document.querySelectorAll('.pa-tab').forEach((t) => t.addEventListener('click', () => {
    document.querySelectorAll('.pa-tab').forEach((x) => x.classList.remove('on'));
    document.querySelectorAll('.pa-role').forEach((x) => x.hidden = true);
    t.classList.add('on'); $('pa-role-' + t.dataset.role).hidden = false;
  }));
  document.querySelectorAll('[data-selectall]').forEach((el) => el.addEventListener('click', () => el.select()));
  initWallet(); initRequester();
}
document.addEventListener('DOMContentLoaded', main);
