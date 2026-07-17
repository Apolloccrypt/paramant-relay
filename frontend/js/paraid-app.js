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

const FIELD_ORDER = ['name', 'birthdate', 'nationality', 'document_no', 'age_over_18', 'holder_binding'];
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
  $('wallet-credstate').innerHTML = cred
    ? 'Credential from <b>' + esc(cred.issuerDid.slice(0, 30)) + '…</b>, sealed facts incl. age_over_18. Registry-anchored issuer.'
    : 'No credential yet. Get one from the Paramant Demo Authority.';
  $('wallet-get-cred').disabled = false;
}

async function ensureHolderAndCred(status) {
  let kp = loadHolder();
  if (!kp) { kp = createHolder(); status('Holder key created on this device.'); }
  const r = await fetch('/v1/paraid/issue-demo', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ holder_binding: holderBinding(kp), subject: {} }) });
  if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.error || ('issuance failed (' + r.status + ')')); }
  const { credential } = await r.json();
  saveCredential(credential);
  return { kp, credential };
}

// Build an answer bundle for a predicate, from the stored credential + holder key.
function buildAnswer(question, nonceB64url) {
  const kp = loadHolder();
  const cred = loadCredential();
  if (!kp || !cred) throw new Error('Set up your wallet first.');
  const salts = {}; for (const k of FIELD_ORDER) salts[k] = fromB64url(cred.salts[k]);
  const leaves = FIELD_ORDER.map((k) => leafHash(salts[k], k, cred.fields[k]));
  const nonce = fromB64url(nonceB64url);
  const presenterSig = ml_dsa65.sign(kp.secretKey, concat(nonce, fromHex(cred.root)));
  const i = FIELD_ORDER.indexOf('age_over_18'), bi = FIELD_ORDER.indexOf('holder_binding');
  return {
    question, root: cred.root, rootSig: cred.rootSig,
    issuerDid: cred.issuerDid, issuerPublicKey: cred.issuerPublicKey,
    disclosed: { key: 'age_over_18', value: cred.fields.age_over_18, salt: cred.salts.age_over_18 },
    path: merklePath(leaves, i),
    binding: { key: 'holder_binding', value: cred.fields.holder_binding, salt: cred.salts.holder_binding },
    bindingPath: merklePath(leaves, bi),
    holderPublicKey: b64(kp.publicKey), presenterSig: b64(presenterSig),
    nonce: nonceB64url,
  };
}

function initWallet() {
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
      const bundle = buildAnswer(req.predicate || '18+?', req.nonce);
      const link = location.origin + '/paraid-app#result=' + b64url(te.encode(JSON.stringify(bundle)));
      $('wallet-answer-out').innerHTML = 'Answer ready. Send this back to the requester:';
      $('wallet-answer-link').value = link;
      $('wallet-answer-link').hidden = false;
    } catch (e) { $('wallet-answer-out').textContent = e.message || String(e); }
  };
  const m = location.hash.match(/#request=([A-Za-z0-9_-]+)/);
  if (m) { $('wallet-req-in').value = location.origin + '/paraid-app#request=' + m[1]; document.querySelector('[data-role="wallet"]').click(); }
}

// ── Requester role ───────────────────────────────────────────────────────────
function initRequester() {
  $('req-build').onclick = () => {
    const predicate = $('req-predicate').value || '18+?';
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
  };
  const m = location.hash.match(/#result=([A-Za-z0-9_-]+)/);
  if (m) { $('req-answer-in').value = location.origin + '/paraid-app#result=' + m[1]; document.querySelector('[data-role="requester"]').click(); }
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
  initWallet(); initRequester();
}
document.addEventListener('DOMContentLoaded', main);
