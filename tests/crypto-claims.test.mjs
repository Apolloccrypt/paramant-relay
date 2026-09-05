// Every claim on the site about a cryptographic algorithm, held against the
// code that would have to perform it.
//
// Why this file exists. On 5 September 2026 an inventory of the shipped crypto
// found five untrue algorithm claims that site-claims.test.mjs and
// ui-truthfulness.test.mjs both let through: "post-quantum encryption end to
// end" on a page that also sells a path with no key exchange at all, "each
// chunk is signed with ML-DSA-65" on a sender that signs nothing, a pre-shared
// secret described as an HKDF input on a client whose HKDF takes two arguments,
// "the full NIST post-quantum suite today" on a relay that loads two
// algorithms, and "in production since 2024" in a repository whose first commit
// is 2026.
//
// Every one of those is the same shape: a page names an algorithm, or names a
// property an algorithm would give, and no test ever asked the code whether it
// does that. The two existing gates check that the names on the page are
// SPELLED the way the code spells them (ML-KEM-768 not Kyber) and that the
// COUNTS match. Neither asks what the named algorithm is actually used for, on
// which path, or whether it runs at all.
//
// So this file works the other way round. FACTS below is read out of the source
// at run time, one entry per function of the product, and nothing in it is
// typed by hand. The blocks then hold the pages against it. A block that cannot
// derive its fact from the code fails rather than passing quietly, because a
// gate that goes green when it loses its footing is worse than no gate.
//
// Node builtins only, so it runs in the "Root integration suites" job.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');
const page = (slug) => read(`frontend/${slug}.html`);

// Every .html under frontend/, subdirectories included, so a claim cannot hide
// on a page nobody thought to list. Same walk as site-claims.test.mjs.
const allPages = (dir = path.join(ROOT, 'frontend'), prefix = '') =>
  fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    if (e.isDirectory()) return ['node_modules', 'vendor', 'pkg'].includes(e.name) ? [] : allPages(path.join(dir, e.name), `${prefix}${e.name}/`);
    return e.isFile() && e.name.endsWith('.html') ? [`${prefix}${e.name.slice(0, -5)}`] : [];
  });

// What a visitor reads. Comments routinely quote the very phrasing a block
// forbids, and a comment is not a claim, so they go. Scripts and styles go for
// the same reason. Line wrapping in the source is not a sentence break, so
// whitespace collapses: a required or forbidden phrase must match whether or
// not the author happened to wrap it.
const visible = (html) => html
  .replace(/<!--[\s\S]*?-->/g, '')
  .replace(/<script\b[\s\S]*?<\/script>/gi, '')
  .replace(/<style\b[\s\S]*?<\/style>/gi, '')
  .replace(/&rsquo;/g, "'").replace(/&middot;/g, '·').replace(/&mdash;/g, '\u2014').replace(/&nbsp;/g, ' ')
  .replace(/\s+/g, ' ');

// Tags out too, for the blocks that reason about a sentence: "<code>ECDH</code>"
// has to read as one sentence with the words around it, not as three fragments.
// But a list item, a paragraph, a heading and a table cell each end a thought
// even when the author wrote no full stop, and running them together is how a
// qualifier from one bullet ends up excusing a claim in the next. So the block
// tags become sentence boundaries before the rest of the markup goes.
const BLOCK_END = /<\/(?:li|p|h[1-6]|td|th|div|dt|dd|figcaption|summary|blockquote)>|<br\s*\/?>/gi;

// The sentence a page shows in a search result, a WhatsApp preview or a chat
// unfurl lives in an attribute, not in the body, so stripping tags erases it.
// That is exactly where "post-quantum encryption end to end" sat: four copies,
// meta description, og:description, twitter:description and the JSON-LD
// WebPage node, and not one visible on the page itself. A gate that reads only
// the body would have passed the very claim this file was written for. So the
// preview text is scanned as part of what the page says.
const previews = (html) => [
  ...html.matchAll(/<meta[^>]+(?:name|property)=["'](?:description|og:description|twitter:description)["'][^>]+content=["']([^"']*)["']/gi),
  ...html.matchAll(/"description"\s*:\s*"((?:[^"\\]|\\.)*)"/g),
].map((m) => m[1].replace(/\\"/g, '"').replace(/&amp;/g, '&').replace(/&rsquo;/g, "'"));

const prose = (html) =>
  [...previews(html), visible(html).replace(BLOCK_END, '. ').replace(/<[^>]+>/g, ' ')]
    .join(' . ').replace(/\s+/g, ' ');

// A sentence, roughly. Good enough to keep a claim and its qualifier together
// and to stop a match reaching across a full stop into an unrelated promise.
const sentences = (text) => text.split(/(?<=[.!?])\s+/);

// ── FACTS: what the code actually does, per function ─────────────────────────
//
// Read at run time. Every field carries the file it came from, so a failure
// message can point at the thing that has to change.
// A comment is not code. frontend/vault.js says in a comment that ML-KEM key
// slots could be added later, and a fact derived from the raw file would read
// that as the vault having gone post-quantum. Line comments are removed only
// when they start a line, so a 'https://…' in the middle of an expression keeps
// its tail.
const noComments = (src) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^[ \t]*\/\/.*$/gm, '');

const SRC0 = {
  wasm:       read('crypto-wasm/src/lib.rs'),
  bootstrap:  read('relay/crypto/bootstrap.js'),
  kemImpl:    read('relay/crypto/impls/mlkem768.js'),
  sigImpl:    read('relay/crypto/impls/mldsa65.js'),
  share:      read('frontend/js/parashare.page.js'),
  get:        read('frontend/js/get.page.js'),
  vault:      read('frontend/vault.js'),
  ext:        read('extensions/shared/paramant-core.js'),
  relay:      read('relay/relay.js'),
  signFlow:   read('frontend/sign-flow.js'),
};
const SRC = Object.fromEntries(Object.entries(SRC0).map(([k, v]) => [k, noComments(v)]));

const nameOf = (src, file) => {
  const m = /name:\s*"([^"]+)"/.exec(src);
  assert.ok(m, `${file} no longer declares a name; this file reads the algorithm names from there`);
  return m[1];
};

const KEM = nameOf(SRC.kemImpl, 'relay/crypto/impls/mlkem768.js'); // ML-KEM-768
const SIG = nameOf(SRC.sigImpl, 'relay/crypto/impls/mldsa65.js'); // ML-DSA-65

// The hybrid, straight out of the WASM. hkdf_aes_key takes the two shared
// secrets and a salt, and nothing else: that signature is what makes the
// encryption hybrid rather than post-quantum, and it is what makes a
// pre-shared secret mixed into the derivation a description of code that does
// not exist. Both facts below are derived from it, never asserted by hand.
const HKDF_SIG = /fn hkdf_aes_key\(([^)]*)\)/.exec(SRC.wasm);
assert.ok(HKDF_SIG, 'crypto-wasm/src/lib.rs no longer has hkdf_aes_key; this file derives the shape of the key exchange from its signature');
const HKDF_ARGS = HKDF_SIG[1].split(',').map((a) => a.trim().split(':')[0].trim()).filter(Boolean);

const FACTS = {
  // Handing a file over live. The one path with a key exchange, and it is
  // hybrid: one post-quantum secret and one classical secret, concatenated
  // into HKDF-SHA256 and expanded to an AES-256-GCM key.
  liveHandover: {
    where: 'crypto-wasm/src/lib.rs',
    postQuantumPart: /MlKem768/.test(SRC.wasm) ? KEM : null,
    classicalPart: /p256::/.test(SRC.wasm) && /EphemeralSecret/.test(SRC.wasm) ? 'ECDH P-256' : null,
    kdf: /Hkdf::<Sha256>/.test(SRC.wasm) ? 'HKDF-SHA256' : null,
    cipher: /Aes256Gcm/.test(SRC.wasm) ? 'AES-256-GCM' : null,
    secretsIntoKdf: HKDF_ARGS.filter((a) => a.startsWith('ss_')),
    signsPayload: /ml_dsa_sign/.test(SRC.share),
  },
  // Sending a link. No key exchange of any kind: a fresh symmetric key made in
  // the browser and carried in the URL fragment.
  browserLink: {
    where: 'frontend/js/parashare.page.js',
    hasKeyExchange: /ML-KEM|mlKem|encryptBlob\(/.test(SRC.share) && /kem_pub/.test(SRC.share),
    cipher: /generateKey\(\s*\{\s*name:\s*'AES-GCM',\s*length:\s*256/.test(SRC.share) ? 'AES-256-GCM' : null,
    keyInFragment: /#k=/.test(SRC.share) || /'#'/.test(SRC.share),
    signsPayload: /ml_dsa_sign|mlDsaSign/.test(SRC.share),
  },
  // The two extensions. Same shape as the link: Web Crypto, symmetric only.
  extensions: {
    where: 'extensions/shared/paramant-core.js',
    cipher: /name: 'AES-GCM'/.test(SRC.ext) ? 'AES-256-GCM' : null,
    hasKeyExchange: /ML-KEM|mlkem|kem_pub/i.test(SRC.ext),
    keyInFragment: /#k=/.test(SRC.ext),
  },
  // The local vault. Symmetric, and it touches no post-quantum algorithm.
  vault: {
    where: 'frontend/vault.js',
    kdf: /name:\s*['"]PBKDF2['"]/.test(SRC.vault) ? 'PBKDF2-SHA-256' : null,
    cipher: /name:\s*['"]AES-GCM['"],\s*length:\s*256/.test(SRC.vault) ? 'AES-256-GCM' : null,
    hasPostQuantum: /ML-KEM|ML-DSA|mlkem|mldsa/i.test(SRC.vault),
  },
  // Signing a document. The one function that is purely post-quantum.
  signing: {
    where: 'relay/crypto/bootstrap.js, frontend/sign-flow.js',
    algorithm: SIG,
    pure: !/ECDH|p256|RSA|Ed25519/i.test(SRC.sigImpl),
  },
  // What the relay loads by default, against what it ships.
  suite: {
    where: 'relay/crypto/bootstrap.js',
    defaultMode: (/process\.env\.CRYPTO_MODE \|\| '(\w+)'/.exec(SRC.bootstrap) || [, ''])[1],
    loaded: (SRC.bootstrap.slice(0, SRC.bootstrap.indexOf("resolved === 'extended'")).match(/register(?:KEM|Sig)\(/g) || []).length,
    shipped: (SRC.bootstrap.match(/register(?:KEM|Sig)\(/g) || []).length,
  },
};

// ── 1 ────────────────────────────────────────────────────────────────────────
// The register on /crypto-agility is the site's own machine-readable table of
// which algorithm each client uses. Two other gates already read one row of it
// by label and treat it as the truth. So it had better be the truth: every row
// is checked against the client's own source here. This is the block that would
// have caught the Chromium and Outlook rows, which said "server-side path
// (relay encrypts)" while both extensions had been encrypting in the browser
// with AES-256-GCM for some time. A register that is wrong in the modest
// direction is still a register nothing else can be built on.
test('the per-client algorithm register matches what each client does', () => {
  const rows = (read('frontend/crypto-agility.html').match(/<tr>[\s\S]*?<\/tr>/g) || [])
    .map((r) => [...r.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/g)].map((m) => m[1].replace(/<[^>]+>/g, '').trim()))
    .filter((cells) => cells.length === 5);
  assert.ok(rows.length >= 6, 'the client register on /crypto-agility lost rows; this gate reads the five-column rows from there');

  const row = (label) => {
    const r = rows.find((cells) => cells[0] === label);
    assert.ok(r, `the client register no longer carries a row for ${label}`);
    return { kem: r[1], sig: r[2], wire: r[3], status: r[4] };
  };

  const problems = [];

  // ParaShare, the live hand-over. Hybrid KEM, and it signs nothing.
  const share = row('ParaShare (webapp)');
  const wantShareKem = `${FACTS.liveHandover.postQuantumPart} + ${FACTS.liveHandover.classicalPart}`;
  if (share.kem !== wantShareKem) problems.push(`register: ParaShare KEM is "${share.kem}"; ${FACTS.liveHandover.where} does ${wantShareKem}`);
  if (FACTS.liveHandover.signsPayload) {
    if (share.sig === 'n/a') problems.push('register: ParaShare SIG is n/a but the sender now signs; the register is behind the code');
  } else if (share.sig !== 'n/a') {
    problems.push(`register: ParaShare SIG is "${share.sig}" and ${FACTS.browserLink.where} calls no signing function`);
  }

  // The browser-encrypted link. No key exchange at all.
  const link = row('Send (browser-encrypted link)');
  if (link.kem !== 'n/a') problems.push(`register: the link path KEM is "${link.kem}"; that path does no key exchange`);
  if (link.sig !== 'n/a') problems.push(`register: the link path SIG is "${link.sig}"; that path signs nothing`);
  if (!link.wire.includes(FACTS.browserLink.cipher)) problems.push(`register: the link wire is "${link.wire}"; ${FACTS.browserLink.where} uses ${FACTS.browserLink.cipher}`);
  if (!/fragment/i.test(link.wire)) problems.push('register: the link wire must say the key travels in the URL fragment, which is the whole risk of that path');

  // The two extensions. Same shape as the link, and the register said otherwise
  // for as long as nothing read it.
  for (const label of ['Chromium extension', 'Outlook add-in']) {
    const ext = row(label);
    if (FACTS.extensions.hasKeyExchange) {
      if (ext.kem === 'n/a') problems.push(`register: ${label} KEM is n/a but ${FACTS.extensions.where} now negotiates a key`);
    } else if (ext.kem !== 'n/a') {
      problems.push(`register: ${label} KEM is "${ext.kem}"; ${FACTS.extensions.where} does no key exchange`);
    }
    if (/server-side|relay encrypts/i.test(ext.wire + ext.status)) {
      problems.push(`register: ${label} is described as a server-side path, and ${FACTS.extensions.where} encrypts with ${FACTS.extensions.cipher} in the client before it uploads`);
    }
    if (FACTS.extensions.cipher && !ext.wire.includes(FACTS.extensions.cipher)) {
      problems.push(`register: ${label} wire is "${ext.wire}"; the code uses ${FACTS.extensions.cipher}`);
    }
  }

  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// ── 2 ────────────────────────────────────────────────────────────────────────
// Hybrid is not post-quantum, and the shipped encryption is hybrid everywhere.
// hkdf_aes_key mixes exactly two shared secrets, one from ML-KEM and one from
// ECDH P-256; the other two paths have no key exchange at all. So there is no
// encryption path on this site that is purely post-quantum, and no page may
// say there is. Naming the classical half is not a weakness to hide: it is why
// breaking either one on its own buys an attacker nothing, and it is what the
// German and French agencies ask for.
//
// The rule is deliberately narrow so it stays enforceable: a sentence that
// calls ENCRYPTION post-quantum must, in that same sentence, say hybrid or name
// the classical half. Signing is exempt, because ML-DSA-65 really is pure.
test('no page calls the encryption post-quantum without saying it is hybrid', () => {
  assert.equal(FACTS.liveHandover.secretsIntoKdf.length, 2,
    `hkdf_aes_key now takes ${FACTS.liveHandover.secretsIntoKdf.length} shared secrets (${FACTS.liveHandover.secretsIntoKdf.join(', ')}); if the classical half is gone, this block is what has to change`);
  assert.ok(FACTS.liveHandover.classicalPart, 'the WASM no longer does an ECDH P-256 alongside the KEM; the encryption may have become pure post-quantum, and this block has to be rewritten deliberately');

  // "post-quantum" has to be attached to the encryption itself, not merely
  // present in the same sentence as the word: "the same encryption, the same
  // post-quantum signatures" is about signing, and signing really is pure.
  const PQ_ENCRYPTION = /post[- ]quantum[\w -]{0,12}(encryption|encrypted)|(encryption|encrypted)[\w -]{0,12}post[- ]quantum/i;
  // And the sentence has to claim it covers everything. A page may call the
  // product a post-quantum encrypted relay, because the relay does run
  // post-quantum algorithms; what it may not do is promise that every byte on
  // every path is protected by one, because the link path has no key exchange
  // at all and the live path pairs the KEM with a classical curve.
  const TOTALITY = /end[- ]to[- ]end|end to end|\bevery (file|transfer|upload|document|byte|send)\b|\ball (files|transfers|uploads|documents)\b|\balways\b|\bthroughout\b|\bat every step\b|\bfrom start to finish\b/i;

  const problems = [];
  for (const slug of allPages()) {
    for (const s of sentences(prose(page(slug)))) {
      if (!PQ_ENCRYPTION.test(s) || !TOTALITY.test(s)) continue;
      if (/\bhybrid\b/i.test(s)) continue;
      if (/\bECDH\b|\belliptic\b|\bP-256\b|\bclassical\b/i.test(s)) continue;
      problems.push(`${slug}: "${s.trim().slice(0, 180)}" promises post-quantum encryption on everything; ${FACTS.liveHandover.where} mixes ${FACTS.liveHandover.postQuantumPart} with ${FACTS.liveHandover.classicalPart}, and ${FACTS.browserLink.where} does no key exchange at all, so say hybrid or name the classical half`);
    }
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// ── 3 ────────────────────────────────────────────────────────────────────────
// Sending does not sign. The sender calls no signing function on either path,
// and the register says SIG n/a for both, yet /parashare told the sender three
// times that every chunk or block went out signed with ML-DSA-65. What is
// really signed is the relay's own work: the tree head over the transparency
// log and the delivery receipt. Attributing a signature to the file is the
// difference between "we can prove this arrived" and "we can prove you sent
// this", and only one of those is true.
test('no page says a sent file is signed while the sender signs nothing', () => {
  assert.equal(FACTS.liveHandover.signsPayload, false,
    'frontend/js/parashare.page.js now calls a signing function; if sending really signs, the pages may say so and this block has to be rewritten');
  assert.equal(FACTS.browserLink.signsPayload, false, 'the link path now signs; same');

  const problems = [];
  for (const slug of allPages()) {
    for (const s of sentences(prose(page(slug)))) {
      // A signature attributed to the thing being sent, rather than to the log
      // entry or the receipt.
      const m = /\b(each|every|per)\s+(chunk|block|packet|part)\b[^.]{0,80}\bsign/i.exec(s)
        || /\bsign(ed|s|ing)?\b[^.]{0,40}\b(each|every|per)\s+(chunk|block|packet|part)\b/i.exec(s);
      if (!m) continue;
      problems.push(`${slug}: "${s.trim().slice(0, 180)}" says a sent file is signed per chunk; ${FACTS.browserLink.where} calls no signing function on either send path`);
    }
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// ── 4 ────────────────────────────────────────────────────────────────────────
// The pre-shared secret. /security described it as an out-of-band password
// "added to HKDF input", and concluded that a fully compromised relay could not
// decrypt a PSS-protected transfer. hkdf_aes_key takes two arguments and a
// salt; there is no third input and the string "pss" appears nowhere under
// frontend/. What the relay really does with a PSS is hash it and compare it to
// a commitment, which authenticates whoever joins a session and tells the relay
// the secret in the process. Those are opposite properties, and the page sold
// the one it does not have.
test('no page claims the pre-shared secret protects the ciphertext', () => {
  const mixedIntoKdf = FACTS.liveHandover.secretsIntoKdf.some((a) => /pss|shared_secret_pre|preshared/i.test(a));
  const inClient = /\bpss\b/i.test(SRC.share) || /\bpss\b/i.test(SRC.get);

  const problems = [];
  for (const slug of allPages()) {
    const text = prose(page(slug));
    if (!/\bPSS\b|pre-shared secret/i.test(text)) continue;
    for (const s of sentences(text)) {
      if (!/\bPSS\b|pre-shared secret/i.test(s)) continue;
      if (!mixedIntoKdf && /\b(HKDF|key derivation|derivation input|mixed into)\b/i.test(s) && !/\bnot\b|\bno longer\b|\bdoes not\b/i.test(s)) {
        problems.push(`${slug}: "${s.trim().slice(0, 180)}" puts the PSS into the key derivation; hkdf_aes_key takes (${HKDF_ARGS.join(', ')}) and nothing else`);
      }
      if (/compromised relay/i.test(s) && /\bcannot\b|\bunable\b|\bimpossible\b/i.test(s) && /decrypt|read/i.test(s)) {
        problems.push(`${slug}: "${s.trim().slice(0, 180)}" says a compromised relay cannot decrypt a PSS transfer; the receiver posts the PSS in plain text to /v2/session/join, where relay.js hashes it, so the relay learns it`);
      }
      if (!inClient && /\bweb app\b|\bbrowser\b/i.test(s) && !/does not use|not use|API/i.test(s)) {
        problems.push(`${slug}: "${s.trim().slice(0, 180)}" offers the PSS to a browser user; it is a relay API feature and the word does not appear in the web app`);
      }
    }
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// ── 5 ────────────────────────────────────────────────────────────────────────
// Shipped is not loaded. bootstrap.js registers two algorithms in the default
// core mode and the rest only under CRYPTO_MODE=extended, and /v2/capabilities
// answers what is loaded, not what is on disk. site-claims.test.mjs already
// pins the two counts on /security and /crypto-agility, and that is exactly why
// "runs the full NIST post-quantum suite today" survived on the same page: it
// names no number, so a gate that reads numbers sees nothing. This block reads
// the adjective instead.
test('no page says the whole suite runs while the default mode loads two algorithms', () => {
  assert.equal(FACTS.suite.defaultMode, 'core', `bootstrap.js now defaults to ${FACTS.suite.defaultMode}; this block assumes the narrow default`);
  assert.ok(FACTS.suite.loaded < FACTS.suite.shipped,
    `bootstrap.js now loads all ${FACTS.suite.shipped} registrations by default, so a page may say the full suite runs and this block has to be retired deliberately`);

  const problems = [];
  for (const slug of allPages()) {
    for (const s of sentences(prose(page(slug)))) {
      if (!/\b(full|whole|entire|complete)\b[^.]{0,40}\b(suite|set of algorithms)\b/i.test(s)
        && !/\bsuite\b[^.]{0,20}\b(loaded|running|runs|live|in production)\b/i.test(s)) continue;
      // A sentence may say the suite ships, as long as it does not say it runs.
      if (/\bship(s|ped|ping)?\b|\bavailable\b|\bon disk\b|\bdormant\b/i.test(s) && !/\b(loaded|runs|running|live)\b/i.test(s)) continue;
      problems.push(`${slug}: "${s.trim().slice(0, 180)}" has the full suite running; ${FACTS.suite.where} loads ${FACTS.suite.loaded} of ${FACTS.suite.shipped} registrations in the default ${FACTS.suite.defaultMode} mode`);
    }
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// ── 6 ────────────────────────────────────────────────────────────────────────
// A production history that predates the product. /vs credited ML-KEM-768 with
// being "in production since 2024" in a repository whose oldest CHANGELOG entry
// is 2026 and whose first commit is April 2026. The year is read from the
// CHANGELOG rather than from git, because CI checks out at depth one and a gate
// that depends on history it may not have is a gate that quietly stops working.
test('no page dates a crypto algorithm earlier than the product exists', () => {
  const years = [...read('CHANGELOG.md').matchAll(/\b(20\d{2})-\d{2}-\d{2}\b/g)].map((m) => Number(m[1]));
  assert.ok(years.length, 'CHANGELOG.md carries no dated entries; this block reads the product\'s first year from there');
  const firstYear = Math.min(...years);

  const ALGOS = /\bML-KEM|\bML-DSA|\bSLH-DSA|\bFalcon-|\bpost[- ]quantum|\bAES-256|\bHKDF|\bSHA3\b/i;
  const problems = [];
  for (const slug of allPages()) {
    for (const s of sentences(prose(page(slug)))) {
      if (!ALGOS.test(s)) continue;
      for (const m of s.matchAll(/\b(?:since|from)\s+(20\d{2})\b/gi)) {
        if (Number(m[1]) < firstYear) {
          problems.push(`${slug}: "${s.trim().slice(0, 180)}" dates it to ${m[1]}; the oldest entry in CHANGELOG.md is ${firstYear}`);
        }
      }
    }
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// ── 7 ────────────────────────────────────────────────────────────────────────
// A primitive nobody implements. Block 3 of site-claims.test.mjs checks that
// the five pages which should name AES-256-GCM, HKDF-SHA256, SHA3-256 and
// PBKDF2 do name them. Nothing checked the other thirty-odd pages for a
// primitive the code has never contained, and a wrong cipher on a security page
// is as expensive as a missing one. The allowed list is built from the source,
// so retiring a primitive in the code retires it on the site by making every
// page that still names it fail.
//
// "AES" on its own is not on the list on purpose: on /pricing and /about it is
// the eIDAS advanced signature, not the cipher. This block anchors on the
// digit, the way the /download gate does.
test('no page names a cryptographic primitive the code does not contain', () => {
  const codebase = [SRC.wasm, SRC.relay, SRC.share, SRC.get, SRC.vault, SRC.ext, SRC.signFlow, SRC.bootstrap].join('\n');
  const CANDIDATES = [
    ['AES-128', /\bAES-128\b/i, /Aes128|AES-128|aes-128/],
    ['AES-192', /\bAES-192\b/i, /Aes192|aes-192/],
    ['RSA', /\bRSA-?\d*\b/, /\bRSA\b|rsa/],
    ['ChaCha20', /\bX?ChaCha20\b/i, /chacha/i],
    ['3DES', /\b3DES\b|\bTriple ?DES\b/i, /3des|tripledes/i],
    ['Ed25519', /\bEd25519\b/i, /ed25519/i],
    ['Curve25519', /\bCurve25519\b|\bX25519\b/i, /25519/i],
    ['SHA-1', /\bSHA-?1\b/, /sha-?1['"\s)]/i],
    ['MD5', /\bMD5\b/i, /md5/i],
    ['Kyber', /\bKyber\b/i, /kyber/i],
    ['Dilithium', /\bDilithium\b/i, /dilithium/i],
    ['BIKE', /\bBIKE\b/, /\bbike\b/i],
    ['Classic McEliece', /\bMcEliece\b/i, /mceliece/i],
  ];

  const problems = [];
  for (const [label, onPage, inCode] of CANDIDATES) {
    if (inCode.test(codebase)) continue; // the code has it, the pages may name it
    for (const slug of allPages()) {
      for (const s of sentences(prose(page(slug)))) {
        if (!onPage.test(s)) continue;
        // A sentence that names a primitive in order to say it is NOT used, or
        // that it is what someone else uses, is honest and stays.
        if (/\bnot\b|\bno longer\b|\binstead of\b|\brather than\b|\bunlike\b|\bcompetitor|\bothers\b|\breplaced\b|\bwe do not\b/i.test(s)) continue;
        problems.push(`${slug}: "${s.trim().slice(0, 160)}" names ${label}; no source file in this repository contains it`);
      }
    }
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// ── 8 ────────────────────────────────────────────────────────────────────────
// The local vault touches no post-quantum algorithm. It is PBKDF2 into
// AES-256-GCM and there is no network call in the file at all, which is what
// makes it the one function that works with no account and no server. A page
// that quietly lets the post-quantum story cover it would be selling the
// strongest claim on the site over the one function that cannot support it.
test('the vault page does not borrow the post-quantum story', () => {
  assert.equal(FACTS.vault.hasPostQuantum, false,
    'frontend/vault.js now references a post-quantum algorithm; if the vault gained one, this block has to be rewritten');
  assert.ok(FACTS.vault.kdf && FACTS.vault.cipher, 'frontend/vault.js no longer derives with PBKDF2 into AES-256-GCM; this block reads its primitives from there');

  const problems = [];
  for (const s of sentences(prose(page('vault')))) {
    if (!/post[- ]quantum|ML-KEM|ML-DSA/i.test(s)) continue;
    // Saying what the vault is not, or pointing at the functions that do use
    // post-quantum algorithms, is fine. Claiming it for this page is not.
    if (/\bnot\b|\bno\b|\bwithout\b|\belsewhere\b|\bsign(ing)?\b|\bsend(ing)?\b/i.test(s)) continue;
    problems.push(`vault: "${s.trim().slice(0, 180)}" claims a post-quantum property; ${FACTS.vault.where} uses ${FACTS.vault.kdf} into ${FACTS.vault.cipher} and nothing else`);
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});
