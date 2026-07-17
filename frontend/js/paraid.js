// ParaID beta demo: prove a predicate ("18+?") without revealing the data.
//
// The whole flow runs in this tab. The issuer seals each passport field (and the
// derived predicate) into a salted SHA3-256 leaf, signs the Merkle root with
// ML-DSA-65, and the wallet then discloses exactly ONE leaf plus its Merkle path.
// The verifier recomputes the root and checks the issuer signature offline.
// Nothing here talks to a server: the network tab stays empty by design.
import { ml_dsa65, sha3_256 } from '/vendor/paramant-pqc.js';

const $ = (id) => document.getElementById(id);
const te = new TextEncoder();
const hex = (u8) => Array.from(u8).map((b) => b.toString(16).padStart(2, '0')).join('');
const b64url = (u8) => btoa(String.fromCharCode(...u8)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
const concat = (...parts) => {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

// Leaf = SHA3-256(salt || "key:value"). The salt keeps unrevealed fields
// unguessable: without it, low-entropy values (a birthdate) could be brute-forced
// from their hash.
const leafHash = (salt, key, value) => sha3_256(concat(salt, te.encode(key + ':' + value)));

// Plain pairwise Merkle tree; an odd node is promoted unchanged.
function merkleRoot(leaves) {
  let level = leaves.slice();
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 === level.length) { next.push(level[i]); continue; }
      next.push(sha3_256(concat(level[i], level[i + 1])));
    }
    level = next;
  }
  return level[0];
}

// Sibling path for one leaf: rebuild the tree level by level and collect the
// neighbour at each step.
function merklePath(leaves, target) {
  const path = [];
  let level = leaves.slice();
  let pos = target;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 === level.length) { next.push(level[i]); continue; }
      next.push(sha3_256(concat(level[i], level[i + 1])));
    }
    if (pos % 2 === 0) {
      if (pos + 1 < level.length) path.push({ side: 'R', hash: level[pos + 1] });
    } else {
      path.push({ side: 'L', hash: level[pos - 1] });
    }
    pos = Math.floor(pos / 2);
    level = next;
  }
  return path;
}
function rootFromPath(leaf, path) {
  let h = leaf;
  for (const step of path) h = step.side === 'R' ? sha3_256(concat(h, step.hash)) : sha3_256(concat(step.hash, h));
  return h;
}

const FIELD_ORDER = ['name', 'birthdate', 'nationality', 'document_no', 'age_over_18', 'holder_binding'];
const state = { issuer: null, holder: null, credential: null, bundle: null, verifierNonce: null };

function issueDemo() {
  const kp = ml_dsa65.keygen(rand(32));
  const did = 'did:paramant:' + b64url(sha3_256(kp.publicKey)).slice(0, 32);
  // The HOLDER key: generated on this device and bound into the credential by
  // the issuer. In production it lives in the passkey-PRF vault (like ParaSign
  // signing keys), so only your biometrics can use it.
  const holder = ml_dsa65.keygen(rand(32));
  const fields = {
    name: 'A. de Vries (demo)',
    birthdate: '1994-03-02',
    nationality: 'NL',
    document_no: 'DEMO-8842671',
    // The issuer computes and seals the predicate at issuance, so the wallet can
    // later reveal "18+ = yes" WITHOUT touching the birthdate leaf.
    age_over_18: 'yes',
    // Hash of the holder public key: ties the credential to this device's key,
    // so a stolen proof bundle is useless to anyone else.
    holder_binding: b64url(sha3_256(holder.publicKey)),
  };
  const salts = {};
  const leaves = FIELD_ORDER.map((k) => {
    salts[k] = rand(16);
    return leafHash(salts[k], k, fields[k]);
  });
  const root = merkleRoot(leaves);
  const rootSig = ml_dsa65.sign(kp.secretKey, root);
  state.issuer = { did, publicKey: kp.publicKey };
  state.holder = holder;
  state.credential = { fields, salts, leaves, root, rootSig };
  state.bundle = null;
  // The verifier hands out a fresh nonce for this session: the wallet must sign
  // it into the answer, so an old bundle can never be replayed.
  state.verifierNonce = rand(16);
  { const n = $('pid-nonce'); if (n) n.textContent = hex(state.verifierNonce).slice(0, 16) + '…'; }

  $('pid-issuer-out').hidden = false;
  $('pid-issuer-did').textContent = did;
  $('pid-issuer-root').textContent = hex(root).slice(0, 32) + '…';
  $('pid-issuer-fields').innerHTML = FIELD_ORDER.map((k) =>
    '<div class="pid-row"><span>' + k + '</span><b>' + fields[k] + '</b></div>').join('');
  $('pid-answer-btn').disabled = false;
  $('pid-wallet-hint').textContent = 'Credential loaded. The verifier asks: is the holder 18 or older?';
  $('pid-verify-out').hidden = true;
  $('pid-consent').hidden = false;
}

function answerPredicate() {
  const c = state.credential;
  if (!c) return;
  const k = 'age_over_18';
  const bindKey = 'holder_binding';
  const nonce = state.verifierNonce;
  // The presenter proof: the holder key signs (nonce || root). Only the device
  // that owns the bound key can produce this, and only for THIS nonce.
  const presenterSig = ml_dsa65.sign(state.holder.secretKey, concat(nonce, c.root));
  state.bundle = {
    question: '18+?',
    disclosed: { key: k, value: c.fields[k], salt: c.salts[k] },
    path: merklePath(c.leaves, FIELD_ORDER.indexOf(k)),
    binding: { key: bindKey, value: c.fields[bindKey], salt: c.salts[bindKey] },
    bindingPath: merklePath(c.leaves, FIELD_ORDER.indexOf(bindKey)),
    holderPublicKey: state.holder.publicKey,
    presenterSig,
    root: c.root,
    rootSig: c.rootSig,
    issuerDid: state.issuer.did,
    issuerPublicKey: state.issuer.publicKey,
    nonce,
  };
  $('pid-bundle-out').hidden = false;
  $('pid-bundle-size').textContent = 'Proof bundle: 2 revealed leaves (answer + key binding) + ' +
    (state.bundle.path.length + state.bundle.bindingPath.length) +
    ' path hashes + issuer root signature + holder signature over the verifier nonce.';
  verifyBundle();
}

function verifyBundle() {
  const b = state.bundle;
  if (!b) return;
  const errors = [];
  // 1. Answer leaf chains to the signed root.
  const leaf = leafHash(b.disclosed.salt, b.disclosed.key, b.disclosed.value);
  if (hex(rootFromPath(leaf, b.path)) !== hex(b.root)) errors.push('answer leaf does not reach the signed root');
  // 2. Issuer signature over the root, and the DID is bound to that exact key.
  if (!ml_dsa65.verify(b.issuerPublicKey, b.root, b.rootSig)) errors.push('ML-DSA-65 root signature invalid');
  const boundDid = 'did:paramant:' + b64url(sha3_256(b.issuerPublicKey)).slice(0, 32);
  if (boundDid !== b.issuerDid) errors.push('issuer DID not bound to this public key');
  // 3. Holder binding: the binding leaf chains to the same root AND commits to
  //    the presented holder key.
  const bindLeaf = leafHash(b.binding.salt, b.binding.key, b.binding.value);
  if (hex(rootFromPath(bindLeaf, b.bindingPath)) !== hex(b.root)) errors.push('holder-binding leaf does not reach the signed root');
  if (b.binding.value !== b64url(sha3_256(b.holderPublicKey))) errors.push('presented holder key is not the one bound in the credential');
  // 4. Freshness: the holder signed THIS verifier nonce together with the root.
  if (!state.verifierNonce || hex(b.nonce) !== hex(state.verifierNonce)) errors.push('nonce mismatch: not answering this verification session');
  if (!ml_dsa65.verify(b.holderPublicKey, concat(b.nonce, b.root), b.presenterSig)) errors.push('holder signature over nonce invalid: possible replay');

  const out = $('pid-verify-out');
  out.hidden = false;
  if (errors.length === 0) {
    out.className = 'pid-result ok';
    out.innerHTML =
      '<p class="pid-verdict">&#10003; ' + b.question + ' <b>' + b.disclosed.value.toUpperCase() + '</b></p>' +
      '<div class="pid-row"><span>issuer</span><b class="pid-mono">' + b.issuerDid.slice(0, 34) + '…</b></div>' +
      '<div class="pid-row"><span>issuer signature</span><b>ML-DSA-65 valid</b></div>' +
      '<div class="pid-row"><span>holder</span><b>key bound &#10003; &#183; fresh nonce &#10003;</b></div>' +
      '<div class="pid-row"><span>fields received</span><b>' + b.disclosed.key + ' + key binding</b></div>' +
      '<div class="pid-row"><span>issuer registered?</span><b id="pid-reg-status">not checked</b></div>' +
      '<button type="button" class="btn home-act-ghost" id="pid-reg-btn" style="margin-top:8px;font-size:12px">Check the public issuer registry (makes 1 network request)</button>' +
      '<p class="pid-note">Why does this one check need a request? Because &ldquo;is this issuer registered <em>right now</em>?&rdquo; is a question about a shared, live list: new issuers get added and bad ones get revoked, so it cannot be answered from inside your tab. The request downloads only the public issuer list. It sends nothing about you, your document or the answer.</p>' +
      '<p class="pid-note">The verifier never saw the birthdate, name, nationality or document number. Only the sealed hashes travelled.</p>';
    const regBtn = document.getElementById('pid-reg-btn');
    if (regBtn) regBtn.addEventListener('click', checkRegistry);
  } else {
    out.className = 'pid-result err';
    out.innerHTML = '<p class="pid-verdict">&#10007; rejected</p>' + errors.map((e) => '<p class="pid-note">' + e + '</p>').join('');
  }
}

// Opt-in registry check: is this issuer DID registered with the relay operator?
// This is the ONE deliberate network request on this page, and the meter above
// will count it: that is the meter proving itself.
async function checkRegistry() {
  const s = document.getElementById('pid-reg-status');
  const btn = document.getElementById('pid-reg-btn');
  if (btn) btn.disabled = true;
  try {
    const r = await fetch('/v1/paraid/issuers', { cache: 'no-store' });
    const data = await r.json();
    const found = (data.issuers || []).find((i) => i.did === state.bundle.issuerDid);
    const activeCount = (data.issuers || []).filter((i) => i.status === 'active').length;
    const rootHex = hex(state.bundle.root);
    if (found && found.status === 'active' && (found.revoked_credentials || []).includes(rootHex)) {
      s.textContent = 'issuer is registered, but THIS credential was revoked by the issuer: reject it';
    } else if (found && found.status === 'active') {
      s.textContent = 'yes: ' + found.label + ' (anchored in the public log, credential not on the revocation list)';
    } else if (found && found.status === 'revoked') {
      s.textContent = 'REVOKED: this issuer was withdrawn, do not trust this credential';
    } else {
      s.textContent = 'no: this demo issuer only exists in your tab (' + activeCount + ' real issuer' + (activeCount === 1 ? ' is' : 's are') + ' registered)';
    }
  } catch {
    if (s) s.textContent = 'registry unreachable';
    if (btn) btn.disabled = false;
  }
}

// Live network meter: the browser's own Performance API counts every resource
// fetch after page load. We only display that number; if the demo ever caused
// a request, this counter would show it (and turn red). Airplane mode is the
// zero-trust version of the same proof.
let baselineDone = false;
function initNetMeter() {
  const countEl = $('pid-netcount');
  const meterEl = $('pid-netmeter');
  if (!countEl || !('PerformanceObserver' in window)) return;
  let count = 0;
  const obs = new PerformanceObserver((list) => {
    for (const e of list.getEntries()) {
      if (!baselineDone) continue;          // ignore initial page assets still trickling in
      count += 1;
      countEl.textContent = String(count);
      if (meterEl) meterEl.classList.add('dirty');
    }
  });
  obs.observe({ type: 'resource', buffered: false });
  // Everything loaded ~1s after load is page chrome; from then on we count.
  window.addEventListener('load', () => setTimeout(() => { baselineDone = true; }, 1000));
  if (document.readyState === 'complete') setTimeout(() => { baselineDone = true; }, 1000);
}

document.addEventListener('DOMContentLoaded', () => {
  initNetMeter();
  $('pid-issue-btn').addEventListener('click', issueDemo);
  $('pid-answer-btn').addEventListener('click', answerPredicate);
});
