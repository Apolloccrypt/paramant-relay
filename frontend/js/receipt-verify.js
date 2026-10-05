// ParaSend transfer-receipt verifier. Runs entirely in the browser.
//
// A ParaSend delivery receipt is the proof that a specific encrypted transfer
// was handed over at a specific moment and then destroyed. Until now the only
// way to check one was POST /v2/verify-receipt, which asks the relay to grade
// its own homework and needs an API key. This module does the same four checks
// with the same primitives on the visitor's machine, so the receipt can be
// checked without Paramant and without a network connection.
//
// The checks mirror relay.js POST /v2/verify-receipt and relay/lib/ct-hash.js
// byte for byte. Keep them in sync.
import { sha3_256, ml_dsa65 } from '/vendor/paramant-pqc.js';
import { anchorForReceipt, anchorByFingerprint, hostOfRelayId, PUBKEY_URL } from '/js/relay-trust-anchors.js';

const LEAF_TRANSFER = 0x02; // domain separator for blob/transfer leaves
const NODE = 0x01;          // domain separator for inner Merkle nodes
const ML_DSA65_PK_BYTES = 1952;

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();

const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#x27;');

const toHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');

function hexToBytes(s) {
  const h = String(s || '');
  if (h.length % 2 !== 0 || /[^0-9a-fA-F]/.test(h)) throw new Error('not a hexadecimal value');
  const out = new Uint8Array(h.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

function fromB64(s) {
  const padded = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

function concatBytes(parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

// Byte-identical to relay.js canonicalJSON: sorted keys, no whitespace.
function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  return '{' + Object.keys(value).sort()
    .map((k) => JSON.stringify(k) + ':' + canonicalJSON(value[k])).join(',') + '}';
}

// relay/lib/ct-hash.js blobLeafHash
function blobLeafHash(blobHashHex, sector, ts) {
  const data = concatBytes([
    hexToBytes(blobHashHex),
    sha3_256(enc.encode(sector || 'relay')),
    enc.encode(String(ts)),
  ]);
  return toHex(sha3_256(concatBytes([new Uint8Array([LEAF_TRANSFER]), data])));
}

// relay/lib/ct-hash.js ctNodeHash
function nodeHash(leftHex, rightHex) {
  return toHex(sha3_256(concatBytes([
    new Uint8Array([NODE]), hexToBytes(leftHex), hexToBytes(rightHex),
  ])));
}

// ── Reading whatever the visitor drops in ───────────────────────────────────
// Receipts travel as base64url (the X-Paramant-Receipt-* handover and the body
// of POST /v2/verify-receipt), but people paste the decoded JSON just as often,
// and some tools wrap it as {"receipt": "..."}. All three are the same receipt.
export function parseReceipt(input) {
  const text = String(input || '').trim();
  if (!text) throw new Error(t('nothing'));
  let obj = null;
  if (text[0] === '{') {
    try { obj = JSON.parse(text); } catch { throw new Error(t('damagedJson')); }
    if (obj && typeof obj.receipt === 'string') return parseReceipt(obj.receipt);
  } else {
    const compact = text.replace(/\s+/g, '');
    let decoded;
    try { decoded = new TextDecoder().decode(fromB64(compact)); }
    catch { throw new Error(t('notReceipt')); }
    try { obj = JSON.parse(decoded); } catch { throw new Error(t('notReceipt')); }
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new Error(t('notReceipt'));
  }
  if (!obj.blob_hash || !obj.inclusion_proof) {
    throw new Error(t('notTransfer'));
  }
  return obj;
}

// ── The verification itself ─────────────────────────────────────────────────
// Every check runs; nothing short-circuits, so a bad receipt says everything
// that is wrong with it at once.
export function verifyReceipt(receipt, relayKeyBytes, keySource) {
  // `ok` is true, false, or null for "could not be checked here". Only an
  // outright false makes the receipt untrustworthy; a null makes it unproven.
  const checks = [];
  const add = (id, ok, label, detail) => { checks.push({ id, ok, label, detail: detail || '' }); return ok; };
  const proof = receipt.inclusion_proof || {};
  const source = (keySource && keySource.source) || (relayKeyBytes ? 'pasted' : 'none');
  const relayHost = hostOfRelayId(receipt.relay_id);

  // 1. Does the receipt point at this exact transfer?
  let leafOk = false;
  try {
    const expected = blobLeafHash(receipt.blob_hash, receipt.sector, receipt.ts);
    leafOk = expected === proof.leaf_hash;
    add('leaf', leafOk,
      leafOk ? t('leafOk')
             : t('leafBad'),
      leafOk ? '' : t('leafBadWhy'));
  } catch (e) {
    add('leaf', false, t('leafBad'), t('leafUnreadable', { err: e.message }));
  }

  // 2. Does the log entry really sit in the tree the receipt claims?
  let rootOk = false;
  try {
    let computed = proof.leaf_hash;
    for (const step of (proof.audit_path || [])) {
      computed = step.position === 'right' ? nodeHash(computed, step.hash) : nodeHash(step.hash, computed);
    }
    rootOk = !!computed && computed === proof.root;
    add('tree', rootOk,
      rootOk ? t('treeOk')
             : t('treeBad'),
      rootOk ? '' : t('treeBadWhy'));
  } catch (e) {
    add('tree', false, t('treeBad'), t('treeErr', { err: e.message }));
  }

  // 3. The relay's signature over the whole receipt.
  const { signature, ...unsigned } = receipt;
  let sigOk = false;
  let keyKnown = null;
  let fingerprint = '';
  if (!relayKeyBytes) {
    // Two different silences. "This page has never heard of that relay" is a
    // statement about us; "no key at all" is a statement about the input. Only
    // the second used to exist, and neither may read as "forged".
    if (source === 'unknown-relay') {
      add('signature', null, t('sigUnknownRelay'),
        relayHost
          ? t('sigUnknownRelayWhy', { host: relayHost })
          : t('sigNoRelay'));
    } else {
      add('signature', null, t('sigSkipped'),
        t('sigSkippedWhy'));
    }
  } else if (!signature) {
    add('signature', false, t('sigNone'),
      t('sigNoneWhy'));
  } else {
    try {
      fingerprint = toHex(sha3_256(relayKeyBytes));
      sigOk = ml_dsa65.verify(relayKeyBytes, enc.encode(canonicalJSON(unsigned)), fromB64(signature));
    } catch { sigOk = false; }
    keyKnown = anchorByFingerprint(fingerprint);
    add('signature', sigOk,
      sigOk ? t('sigOk')
            : t('sigBad'),
      sigOk ? '' : t('sigBadWhy'));
  }

  // 4. The relay's signature over the log snapshot the proof refers to.
  const sth = proof.sth || null;
  if (sth && sth.signature) {
    if (!relayKeyBytes) {
      add('sth', null, t('sthSkipped'), t('sthSkippedWhy'));
    } else {
      const { signature: sthSig, ...sthPayload } = sth;
      let sthOk = false;
      try { sthOk = ml_dsa65.verify(relayKeyBytes, enc.encode(canonicalJSON(sthPayload)), fromB64(sthSig)); } catch { sthOk = false; }
      const rootMatch = sth.sha3_root === proof.root;
      add('sth', sthOk && rootMatch,
        (sthOk && rootMatch) ? t('sthOk')
                             : t('sthBad'),
        !sthOk ? t('sthBadSig')
               : (!rootMatch ? t('sthBadRoot') : ''));
    }
  }

  const failed = checks.filter((c) => c.ok === false);
  return {
    valid: failed.length === 0,
    checkedSignature: !!relayKeyBytes,
    signatureHeld: relayKeyBytes ? sigOk : null,
    unknownRelay: source === 'unknown-relay',
    relayHost,
    keySource: source,
    checks,
    fingerprint,
    keyName: keyKnown ? ((LANG === 'nl' && keyKnown.name_nl) || keyKnown.name) : null,
    receipt,
  };
}

// Visible text in both languages. /verify is Dutch, /en/verify English; the page's <html lang> picks the set.
const LANG = ((typeof document !== 'undefined' && document.documentElement.lang) || 'nl').slice(0, 2) === 'en' ? 'en' : 'nl';
const T = {
  nl: {
    nothing: 'Er is hier nog niets om te controleren.',
    damagedJson: 'Dit lijkt op JSON, maar het is beschadigd en daardoor niet te lezen.',
    notReceipt: 'Dit is geen ontvangstbewijs. Plak de tekst van het ontvangstbewijs, of sleep het bestand hierheen.',
    notTransfer: 'Dit bestand is geen ontvangstbewijs van ParaSend. Een ontvangstbewijs noemt het bestand waar het over gaat en bevat de plek in het transparantielogboek.',
    leafOk: 'Het ontvangstbewijs gaat over dit bestand en geen ander.',
    leafBad: 'Het ontvangstbewijs past niet bij het bestand dat het noemt.',
    leafBadWhy: 'De regel in het transparantielogboek waar het naar verwijst hoort bij een ander bestand, of de vingerafdruk in het ontvangstbewijs is achteraf veranderd.',
    leafUnreadable: 'De vingerafdruk van het bestand erin was niet te lezen ({err}).',
    treeOk: 'Het staat echt in het openbare transparantielogboek.',
    treeBad: 'Het staat niet in het transparantielogboek waar het volgens zichzelf in staat.',
    treeBadWhy: 'Het logboek opnieuw berekenen vanuit de regel geeft een andere uitkomst, dus het bewijs van opname klopt niet.',
    treeErr: 'Het bewijs van opname kon niet opnieuw worden berekend ({err}).',
    sigUnknownRelay: 'De handtekening is niet gecontroleerd, omdat deze pagina deze relay niet kent.',
    sigUnknownRelayWhy: 'Volgens het ontvangstbewijs is het uitgegeven door {host}, en dat is geen van de relays die deze pagina kent. Plak de publieke sleutel van die relay om de controle af te maken.',
    sigNoRelay: 'Het ontvangstbewijs zegt niet welke relay het uitgaf, dus er is geen sleutel om het mee te vergelijken.',
    sigSkipped: 'De handtekening is niet gecontroleerd.',
    sigSkippedWhy: 'Er was geen sleutel van een server om hem mee te vergelijken. Al het andere op deze pagina is wel gecontroleerd.',
    sigNone: 'Dit ontvangstbewijs heeft helemaal geen handtekening.',
    sigNoneWhy: 'Een echt ontvangstbewijs is altijd ondertekend door de server die het bestand heeft overgedragen.',
    sigOk: 'De handtekening klopt, dus er is geen enkel teken veranderd.',
    sigBad: 'De handtekening klopt niet.',
    sigBadWhy: 'Het ontvangstbewijs is na het ondertekenen bewerkt, of het is ondertekend met een andere sleutel dan die waarmee het is gecontroleerd.',
    sthSkipped: 'De momentopname van het logboek is niet gecontroleerd.',
    sthSkippedWhy: 'Er was geen sleutel van een server om de handtekening mee te vergelijken.',
    sthOk: 'Het logboek zelf is op dat moment ook ondertekend.',
    sthBad: 'De momentopname van het logboek in het ontvangstbewijs klopt niet.',
    sthBadSig: 'De handtekening over de momentopname van het logboek klopt niet.',
    sthBadRoot: 'De momentopname beschrijft een andere stand van het logboek dan het bewijs.',
    moment: '{date} om {time} UTC',
    keyUnknownRelay: 'Volgens het ontvangstbewijs is het uitgegeven door <code class="mono">{host}</code>, een relay waarvan deze pagina geen sleutel heeft. De ondertekenaar is hier dus niet vast te stellen.',
    keyNoRelay: 'Het zegt niet welke relay het uitgaf. De ondertekenaar is hier dus niet vast te stellen.',
    keyNone: 'Er is geen ondertekenaar vast te stellen, omdat er geen sleutel was om mee te vergelijken.',
    againstNamed: 'de sleutel van {name} <code class="mono">{fp}</code>',
    againstGiven: 'de sleutel die u gaf, vingerafdruk <code class="mono">{fp}</code>',
    keyMismatch: 'Het past niet bij {against}, dus deze pagina kan niet zeggen wie het ondertekende.',
    keyNamed: 'Het is ondertekend door {name}, sleutel <code class="mono">{fp}</code>.',
    keyStranger: 'Het is ondertekend met een sleutel die deze pagina niet kent, vingerafdruk <code class="mono">{fp}</code>. Vergelijk die met de sleutel die Paramant publiceert voordat u erop vertrouwt.',
    bannerGenuine: '<div class="ps-banner ok"><strong>Dit ontvangstbewijs is echt.</strong> Het is uitgegeven door {name} en er is sindsdien geen enkel teken veranderd.</div>',
    bannerUnchanged: '<div class="ps-banner ok"><strong>Dit ontvangstbewijs is ongewijzigd.</strong> Alles past nog bij de sleutel die u gaf, en die sleutel kent deze pagina niet.</div>',
    bannerUnknownRelay: '<div class="ps-banner info"><strong>Deze pagina kent deze relay niet.</strong> Alles wat te controleren was klopt, maar volgens het ontvangstbewijs komt het van {host}, en deze pagina heeft daar geen sleutel van. Plak de publieke sleutel van die relay om de controle af te maken.</div>',
    bannerHolds: '<div class="ps-banner info"><strong>Het ontvangstbewijs klopt in zichzelf.</strong> De handtekening is niet gecontroleerd, omdat er geen sleutel van een server was.</div>',
    bannerBad: '<div class="ps-banner err"><strong>Vertrouw dit ontvangstbewijs niet.</strong> Minstens één van de controles hieronder is mislukt.</div>',
    factHanded: 'Het bestand is overgedragen op {when}.',
    factAccepted: 'De server nam het aan op {when}.',
    factHost: 'De overdracht is gedaan door <code class="mono">{host}</code>.',
    factFp: 'Het bestand waar het over gaat heeft vingerafdruk <code class="mono">{fp}</code>.',
    factBurned: 'De server vernietigde zijn kopie van het bestand bij de overdracht.',
    factKept: 'De server hield zijn kopie na deze download, omdat de verzending meer dan een download toestond.',
    factEntry: 'Het is regel {n} in een openbaar logboek dat op dat moment {size} regels telde.',
    says: 'Wat dit ontvangstbewijs zegt',
    claims: 'Wat dit ontvangstbewijs beweert',
    checkedHead: '<h3 class="rv-sub">Wat er is gecontroleerd</h3><ul class="rv-checks">',
    passed: 'Geslaagd',
    failed: 'Mislukt',
    notChecked: 'Niet gecontroleerd',
    showRaw: '<details class="rv-raw"><summary>Toon het ontvangstbewijs zoals het is geschreven</summary><pre class="mono">',
    keyUnreadable: 'Die sleutel is niet leesbaar. Een sleutel is één doorlopend blok letters en cijfers.',
    keyLength: 'Dat is geen ondertekeningssleutel van Paramant: hij is {n} bytes lang in plaats van {want}.',
    checking: '<div class="ps-banner info">Bezig met controleren op dit apparaat…</div>',
    couldNotCheck: 'Dit ontvangstbewijs kon niet worden gecontroleerd: {err}',
    loaded: '{name} geladen',
    unreadableFile: 'Dat bestand kon niet worden gelezen.',
    unnamedRelay: 'een relay die het niet noemt',
  },
  en: {
    nothing: 'There is nothing here to check yet.',
    damagedJson: 'This looks like JSON but it is damaged, so it cannot be read.',
    notReceipt: 'This is not a receipt. Paste the receipt text, or drop the receipt file.',
    notTransfer: 'This file is not a ParaSend transfer receipt. A receipt names the file it covers and carries its place in the transparency log.',
    leafOk: 'The receipt is about this file and no other.',
    leafBad: 'The receipt does not match the file it names.',
    leafBadWhy: 'The entry it points to in the transparency log belongs to a different file, or the fingerprint inside the receipt was changed afterwards.',
    leafUnreadable: 'The file fingerprint inside it could not be read ({err}).',
    treeOk: 'It really is in the public transparency log.',
    treeBad: 'It is not in the transparency log it claims to be in.',
    treeBadWhy: 'Recomputing the log from the entry gives a different result, so the proof of inclusion does not hold.',
    treeErr: 'The proof of inclusion could not be recomputed ({err}).',
    sigUnknownRelay: 'The signature was not checked, because this page does not know this relay.',
    sigUnknownRelayWhy: 'The receipt says it was issued by {host}, which is not one of the relays this page ships with. Paste that relay’s public key to finish the check.',
    sigNoRelay: 'The receipt does not say which relay issued it, so there is no key to check it against.',
    sigSkipped: 'The signature was not checked.',
    sigSkippedWhy: 'No server key was available to check it against. Everything else on this page was still checked.',
    sigNone: 'This receipt carries no signature at all.',
    sigNoneWhy: 'A genuine receipt is always signed by the server that handed the file over.',
    sigOk: 'The signature holds, so not one character has been altered.',
    sigBad: 'The signature does not hold.',
    sigBadWhy: 'Either the receipt was edited after it was signed, or it was signed by a different key than the one used to check it.',
    sthSkipped: 'The log snapshot was not checked.',
    sthSkippedWhy: 'No server key was available to check its signature against.',
    sthOk: 'The log itself was signed at that moment too.',
    sthBad: 'The log snapshot inside the receipt does not hold up.',
    sthBadSig: 'The signature over the log snapshot does not check out.',
    sthBadRoot: 'The snapshot describes a different state of the log than the proof does.',
    moment: '{date} at {time} UTC',
    keyUnknownRelay: 'It says it was issued by <code class="mono">{host}</code>, a relay this page does not ship a key for, so the signer could not be identified here.',
    keyNoRelay: 'It does not say which relay issued it, so the signer could not be identified here.',
    keyNone: 'Nobody could be identified as the signer, because no key was available to compare against.',
    againstNamed: '{name}’s key <code class="mono">{fp}</code>',
    againstGiven: 'the key you gave, fingerprint <code class="mono">{fp}</code>',
    keyMismatch: 'It does not match {against}, so this page cannot say who signed it.',
    keyNamed: 'It was signed by {name}, key <code class="mono">{fp}</code>.',
    keyStranger: 'It was signed by a key this page does not recognise, fingerprint <code class="mono">{fp}</code>. Compare that against the key Paramant publishes before you trust it.',
    bannerGenuine: '<div class="ps-banner ok"><strong>This receipt is genuine.</strong> It was issued by {name} and not one character has changed since.</div>',
    bannerUnchanged: '<div class="ps-banner ok"><strong>This receipt is unchanged.</strong> It all still matches the key you gave, and this page does not know that key.</div>',
    bannerUnknownRelay: '<div class="ps-banner info"><strong>This page does not know this relay.</strong> Everything it could check holds, but the receipt says it came from {host}, and no key for it ships with this page. Paste that relay’s public key to finish the check.</div>',
    bannerHolds: '<div class="ps-banner info"><strong>The receipt holds together.</strong> Its signature was not checked, because no server key was available.</div>',
    bannerBad: '<div class="ps-banner err"><strong>Do not trust this receipt.</strong> It failed at least one check below.</div>',
    factHanded: 'The file was handed over on {when}.',
    factAccepted: 'It was accepted by the server on {when}.',
    factHost: 'The handover was done by <code class="mono">{host}</code>.',
    factFp: 'The file it covers has fingerprint <code class="mono">{fp}</code>.',
    factBurned: 'The server destroyed its copy of the file as it was handed over.',
    factKept: 'The server kept its copy after this download, because the transfer allowed more than one download.',
    factEntry: 'It is entry {n} in a public log that held {size} entries at that moment.',
    says: 'What this receipt says',
    claims: 'What this receipt claims',
    checkedHead: '<h3 class="rv-sub">What was checked</h3><ul class="rv-checks">',
    passed: 'Passed',
    failed: 'Failed',
    notChecked: 'Not checked',
    showRaw: '<details class="rv-raw"><summary>Show the receipt as it was written</summary><pre class="mono">',
    keyUnreadable: 'That key is not readable. It is one unbroken block of letters and digits.',
    keyLength: 'That is not a Paramant signing key: it is {n} bytes long instead of {want}.',
    checking: '<div class="ps-banner info">Checking on this device…</div>',
    couldNotCheck: 'This receipt could not be checked: {err}',
    loaded: '{name} loaded',
    unreadableFile: 'That file could not be read.',
    unnamedRelay: 'a relay it does not name',
  },
};
function t(k, v) {
  let s = (T[LANG] && T[LANG][k]) || T.en[k] || k;
  if (v) for (const n of Object.keys(v)) s = s.split('{' + n + '}').join(String(v[n]));
  return s;
}

// ── Plain language ──────────────────────────────────────────────────────────
function formatMoment(value) {
  const d = value == null ? null : new Date(typeof value === 'number' ? value : String(value));
  if (!d || isNaN(d.getTime())) return null;
  const date = new Intl.DateTimeFormat(LANG === 'en' ? 'en-GB' : 'nl-NL', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' }).format(d);
  const time = new Intl.DateTimeFormat(LANG === 'en' ? 'en-GB' : 'nl-NL', { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'UTC' }).format(d);
  return t('moment', { date, time });
}

function keySentence(result) {
  const fp = result.fingerprint;
  if (!result.checkedSignature) {
    if (result.unknownRelay) {
      return result.relayHost
        ? t('keyUnknownRelay', { host: esc(result.relayHost) })
        : t('keyNoRelay');
    }
    return t('keyNone');
  }
  const short = esc(fp.slice(0, 16));
  // Past tense about the signer is only earned once the signature held. Before
  // the fix this sentence named the pinned relay as signer even when the check
  // had just failed against that very key, which asserted an identity nothing
  // had shown.
  if (result.signatureHeld !== true) {
    const against = result.keyName
      ? t('againstNamed', { name: esc(result.keyName), fp: short })
      : t('againstGiven', { fp: short });
    return t('keyMismatch', { against });
  }
  if (result.keyName) {
    return t('keyNamed', { name: esc(result.keyName), fp: short });
  }
  return t('keyStranger', { fp: short });
}

export function renderResult(result, target) {
  const r = result.receipt;
  const out = [];
  const signedFully = result.valid && result.checkedSignature;

  if (signedFully && result.keyName) {
    out.push(t('bannerGenuine', { name: esc(result.keyName) }));
  } else if (signedFully) {
    // Every check passed, but against a key this page has never seen. Saying
    // "genuine" there would launder an unknown signer into a Paramant promise.
    out.push(t('bannerUnchanged'));
  } else if (result.valid && result.unknownRelay) {
    // Every check this page could run passed; the one it could not run is the
    // signature, because the receipt names a relay we ship no key for. An
    // unknown sender and a forgery are different things and may never share a
    // banner: this is the difference between "we cannot say" and "it is fake".
    out.push(t('bannerUnknownRelay', { host: result.relayHost ? '<code class="mono">' + esc(result.relayHost) + '</code>' : t('unnamedRelay') }));
  } else if (result.valid) {
    out.push(t('bannerHolds'));
  } else {
    out.push(t('bannerBad'));
  }

  const facts = [];
  facts.push(keySentence(result));
  const when = formatMoment(r.retrieved_at);
  if (when) facts.push(t('factHanded', { when: esc(when) }));
  const issued = formatMoment(r.ts);
  if (issued && issued !== when) facts.push(t('factAccepted', { when: esc(issued) }));
  const host = result.relayHost;
  if (host) facts.push(t('factHost', { host: esc(host) }));
  facts.push(t('factFp', { fp: esc(String(r.blob_hash)) }));
  if (r.burn_confirmed === true) facts.push(t('factBurned'));
  else if (r.burn_confirmed === false) facts.push(t('factKept'));
  const proof = r.inclusion_proof || {};
  if (proof.leaf_index != null && proof.tree_size != null) {
    facts.push(t('factEntry', { n: esc(String(proof.leaf_index + 1)), size: esc(String(proof.tree_size)) }));
  }

  // A receipt that failed a check has not earned the word "says": from here on
  // its contents are a claim, and the heading has to read that way.
  out.push('<h3 class="rv-sub">' + (result.valid ? t('says') : t('claims'))
    + '</h3><ul class="rv-facts">');
  for (const f of facts) out.push('<li>' + f + '</li>');
  out.push('</ul>');

  out.push(t('checkedHead'));
  for (const c of result.checks) {
    const state = c.ok === true ? 'ok' : (c.ok === false ? 'bad' : 'skip');
    const mark = { ok: '\u2713', bad: '\u2715', skip: '\u2013' }[state];
    const words = { ok: t('passed'), bad: t('failed'), skip: t('notChecked') }[state];
    out.push('<li class="rv-' + state + '"><span class="rv-mark" aria-hidden="true">' + mark
      + '</span><span class="rv-body"><span class="rv-sr">' + words + ': </span>'
      + esc(c.label) + (c.detail ? '<span class="rv-detail">' + esc(c.detail) + '</span>' : '') + '</span></li>');
  }
  out.push('</ul>');

  out.push(t('showRaw')
    + esc(JSON.stringify(r, null, 2)) + '</pre></details>');

  target.innerHTML = out.join('');
}

// ── Page wiring ─────────────────────────────────────────────────────────────
// A pasted key wins over the pinned one, so a receipt from a relay this build
// does not ship, or from a relay that has rotated its key, stays checkable
// without a redeploy.
//
// With the field empty the key comes from the receipt's own `relay_id`, not
// from whichever anchor happens to be first. Every relay in the fleet signs
// with its own identity (relay/relay.js:5824-5829), so checking a health
// receipt against the relay.paramant.app key could only ever fail, and the page
// showed that failure as "Do not trust this receipt", calling Paramant's own
// receipt a forgery. When the receipt names a relay this page does not ship,
// the answer is "we do not know this relay", never a guess with the wrong key.
export function resolveKey(pastedKey, receipt) {
  const raw = String(pastedKey || '').replace(/\s+/g, '');
  if (raw) {
    let bytes;
    try { bytes = fromB64(raw); } catch { throw new Error(t('keyUnreadable')); }
    if (bytes.length !== ML_DSA65_PK_BYTES) {
      throw new Error(t('keyLength', { n: bytes.length, want: ML_DSA65_PK_BYTES }));
    }
    return { bytes, anchor: null, source: 'pasted' };
  }
  const anchor = anchorForReceipt(receipt);
  if (anchor) return { bytes: fromB64(anchor.key), anchor, source: 'pinned' };
  return { bytes: null, anchor: null, source: 'unknown-relay' };
}

export function initReceiptVerifier() {
  const input = $('rv-input');
  const button = $('rv-check');
  const result = $('rv-result');
  const drop = $('rv-drop');
  const file = $('rv-file');
  const keyField = $('rv-key');
  if (!input || !button || !result) return;

  const fail = (message) => {
    result.hidden = false;
    result.innerHTML = '<div class="ps-banner err"><strong>' + esc(message) + '</strong></div>';
  };

  const run = () => {
    result.hidden = false;
    result.innerHTML = t('checking');
    let receipt;
    try { receipt = parseReceipt(input.value); } catch (e) { return fail(e.message); }
    let key = null;
    try { key = resolveKey(keyField ? keyField.value : '', receipt); } catch (e) { return fail(e.message); }
    try {
      renderResult(verifyReceipt(receipt, key.bytes, key), result);
    } catch (e) {
      fail(t('couldNotCheck', { err: e.message }));
    }
  };

  button.addEventListener('click', run);

  const loadFile = async (f) => {
    if (!f) return;
    try {
      input.value = await f.text();
      if ($('rv-file-info')) $('rv-file-info').textContent = t('loaded', { name: f.name });
      run();
    } catch { fail(t('unreadableFile')); }
  };

  if (file) file.addEventListener('change', (e) => loadFile(e.target.files && e.target.files[0]));
  if (drop) {
    const stop = (e) => { e.preventDefault(); e.stopPropagation(); };
    ['dragenter', 'dragover'].forEach((n) => drop.addEventListener(n, (e) => { stop(e); drop.classList.add('rv-over'); }));
    ['dragleave', 'drop'].forEach((n) => drop.addEventListener(n, (e) => { stop(e); drop.classList.remove('rv-over'); }));
    drop.addEventListener('drop', (e) => loadFile(e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]));
  }

  const keyHint = $('rv-key-hint');
  if (keyHint) keyHint.textContent = PUBKEY_URL;
}

// The page holds two unrelated proofs. Tabs keep one URL, /verify, and
// /verify#receipt opens straight on the receipt side for a link in an email.
export function initTabs() {
  const pairs = [
    { tab: $('tab-doc'), panel: $('panel-doc'), hash: '' },
    { tab: $('tab-receipt'), panel: $('panel-receipt'), hash: '#receipt' },
  ];
  if (pairs.some((p) => !p.tab || !p.panel)) return;

  const show = (chosen) => {
    for (const p of pairs) {
      const on = p === chosen;
      p.tab.setAttribute('aria-selected', on ? 'true' : 'false');
      p.panel.hidden = !on;
    }
  };
  for (const p of pairs) p.tab.addEventListener('click', () => show(p));
  const wanted = pairs.find((p) => p.hash && p.hash === location.hash);
  show(wanted || pairs[0]);
}

// The language switch keeps whatever the address carries (#receipt, a query),
// so a reader who switches language lands on the same tab of the same proof.
export function carryLangSwitch() {
  const link = document.querySelector('.lang-switch a');
  if (!link) return;
  const base = link.getAttribute('href').split(/[?#]/)[0];
  const sync = () => { link.setAttribute('href', base + location.search + location.hash); };
  sync();
  window.addEventListener('hashchange', sync);
}

initTabs();
initReceiptVerifier();
carryLangSwitch();
