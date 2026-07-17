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

const FIELD_ORDER = ['name', 'birthdate', 'nationality', 'document_no', 'age_over_18'];
const state = { issuer: null, credential: null, bundle: null };

function issueDemo() {
  const kp = ml_dsa65.keygen(rand(32));
  const did = 'did:paramant:' + b64url(sha3_256(kp.publicKey)).slice(0, 32);
  const fields = {
    name: 'M. Beer (demo)',
    birthdate: '1994-03-02',
    nationality: 'NL',
    document_no: 'DEMO-8842671',
    // The issuer computes and seals the predicate at issuance, so the wallet can
    // later reveal "18+ = yes" WITHOUT touching the birthdate leaf.
    age_over_18: 'yes',
  };
  const salts = {};
  const leaves = FIELD_ORDER.map((k) => {
    salts[k] = rand(16);
    return leafHash(salts[k], k, fields[k]);
  });
  const root = merkleRoot(leaves);
  const rootSig = ml_dsa65.sign(kp.secretKey, root);
  state.issuer = { did, publicKey: kp.publicKey };
  state.credential = { fields, salts, leaves, root, rootSig };
  state.bundle = null;

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
  const i = FIELD_ORDER.indexOf(k);
  const nonce = rand(16);
  state.bundle = {
    question: '18+?',
    disclosed: { key: k, value: c.fields[k], salt: c.salts[k] },
    path: merklePath(c.leaves, i),
    root: c.root,
    rootSig: c.rootSig,
    issuerDid: state.issuer.did,
    issuerPublicKey: state.issuer.publicKey,
    nonce,
  };
  $('pid-bundle-out').hidden = false;
  $('pid-bundle-size').textContent = 'Proof bundle: 1 revealed leaf + ' + state.bundle.path.length +
    ' path hashes + ML-DSA-65 root signature. Nonce ' + hex(nonce).slice(0, 12) + '…';
  verifyBundle();
}

function verifyBundle() {
  const b = state.bundle;
  if (!b) return;
  const errors = [];
  const leaf = leafHash(b.disclosed.salt, b.disclosed.key, b.disclosed.value);
  const root = rootFromPath(leaf, b.path);
  if (hex(root) !== hex(b.root)) errors.push('Merkle path does not reach the signed root');
  if (!ml_dsa65.verify(b.issuerPublicKey, b.root, b.rootSig)) errors.push('ML-DSA-65 root signature invalid');
  const boundDid = 'did:paramant:' + b64url(sha3_256(b.issuerPublicKey)).slice(0, 32);
  if (boundDid !== b.issuerDid) errors.push('issuer DID not bound to this public key');

  const out = $('pid-verify-out');
  out.hidden = false;
  if (errors.length === 0) {
    out.className = 'pid-result ok';
    out.innerHTML =
      '<p class="pid-verdict">&#10003; ' + b.question + ' <b>' + b.disclosed.value.toUpperCase() + '</b></p>' +
      '<div class="pid-row"><span>issuer</span><b class="pid-mono">' + b.issuerDid.slice(0, 34) + '…</b></div>' +
      '<div class="pid-row"><span>signature</span><b>ML-DSA-65 valid</b></div>' +
      '<div class="pid-row"><span>fields received</span><b>only ' + b.disclosed.key + '</b></div>' +
      '<p class="pid-note">The verifier never saw the birthdate, name, nationality or document number. Only the sealed hashes travelled.</p>';
  } else {
    out.className = 'pid-result err';
    out.innerHTML = '<p class="pid-verdict">&#10007; rejected</p>' + errors.map((e) => '<p class="pid-note">' + e + '</p>').join('');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  $('pid-issue-btn').addEventListener('click', issueDemo);
  $('pid-answer-btn').addEventListener('click', answerPredicate);
});
