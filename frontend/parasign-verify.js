// ParaSign /verify page logic.
// The document NEVER leaves the browser: only its SHA3-256 hash is ever needed.
// v3 (parasign-doc-3) envelopes are verified ENTIRELY client-side with the same
// ML-DSA-65 + SHA3-256 primitives the signer used -- no relay, no API key, so
// the counterparty (who has no Paramant account) can verify offline. v1/v2
// envelopes carry a relay notary signature that only the relay can check, so
// they still POST to /v2/verify (which requires an API key).
import { sha3_256, ml_dsa65 } from '/vendor/paramant-pqc.js';
// The relay keys this site ships with. A multi-party receipt is only Paramant's
// when its notary key is one of these; the key printed inside the receipt is
// never trusted on its own, or any file could vouch for itself.
import { anchorByFingerprint } from '/js/relay-trust-anchors.js?v=2';

const RELAY_URL = 'https://relay.paramant.app';
// Byte-identical to relay/envelope.js SIGN_DOMAIN_DOC (recipe v3). Keep in sync.
const SIGN_DOMAIN_DOC = 'paramant/parasign/doc/v1';
let documentBuffer = null, envelope = null, isV3 = false, isMulti = false;

const $ = id => document.getElementById(id);
const toHex = u8 => Array.from(u8, b => b.toString(16).padStart(2, '0')).join('');
const esc = s => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#x27;');

// Visible text in both languages. /verify is Dutch, /en/verify English; the page's <html lang> picks the set.
const LANG = ((typeof document !== 'undefined' && document.documentElement.lang) || 'nl').slice(0, 2) === 'en' ? 'en' : 'nl';
const T = {
  nl: {
    fileSize: ' ({kb} kB)',
    notJson: 'Dit bestand is geen geldige JSON. Kies de .psign-envelop die bij het ondertekenen is gemaakt.',
    notPsign: 'Dit lijkt geen .psign-envelop (het veld algorithm ontbreekt).',
    notPsignFields: 'Dit bestand mist de velden van een ParaSign-bewijs (versie, ondertekenaar of handtekening). Kies het .psign-bestand dat bij het ondertekenen is gemaakt.',
    docUnreadable: 'Dit bestand kon niet worden gelezen. Het is mogelijk te groot voor deze browser.',
    infoAlg: 'algoritme: {v}',
    infoSigned: 'ondertekend: {v}',
    infoSigners: 'ondertekenaars: {v}',
    infoEnvMulti: 'envelop: {v}…',
    infoKeyless: 'zonder sleutel (offline)',
    infoKey: 'sleutel {v}…',
    infoEnv: 'envelop: {v}…',
    infoSignerLabel: 'ondertekenaar: {v}',
    unsupportedAlg: 'algoritme niet ondersteund: {v}',
    missingMpId: 'multiparty.envelope_id ontbreekt',
    missingSignedHash: 'de hash van het ondertekende document ontbreekt (stamped_hash of document_hash)',
    hashMismatch: 'documenthash klopt niet: dit document is niet het document dat is ondertekend',
    hashIsOriginal: 'Dit is het bestand van voor het ondertekenen. De handtekening geldt voor de ondertekende versie met de zegel erop ({name}). Kies dat bestand.',
    missingSignerPk: 'signer_public_key ontbreekt',
    missingEmailHash: 'party_email_hash ontbreekt (het ondertekende bericht is offline niet na te bouwen)',
    appearanceMismatch: 'hash van de weergave klopt niet',
    appearanceInvalid: 'de beschrijving van de zichtbare handtekening in het bestand is beschadigd',
    signerInvalid: 'handtekening van de ondertekenaar ongeldig',
    signerError: 'de handtekening of de sleutel in het .psign-bestand is beschadigd en kan niet worden gelezen',
    expired: 'envelop verlopen op {v}',
    missingEnvId: 'envelope_id ontbreekt',
    missingDocHash: 'document_hash ontbreekt',
    hashMismatchMulti: 'Dit is niet het document dat is ondertekend. De handtekeningen gelden voor het originele bestand, met SHA3-256-vingerafdruk {hash}…. Een pdf met een Paramant-stempel (voettekst "Signed with ParaSign" of een pagina "ParaSign signature certificate") is een leesbare kopie en geeft altijd deze melding. Kies het originele bestand dat ter ondertekening is aangeboden.',
    missingParties: 'partijen ontbreken',
    partyIncomplete: '{who} heeft geen volledige handtekening',
    partyWho: 'partij {i}',
    partyAt: 'de partij op plaats {n} in het bewijs',
    partyAppearance: '{who}: hash van de weergave klopt niet',
    partyAppearanceInvalid: '{who}: de beschrijving van de zichtbare handtekening is beschadigd',
    partyInvalid: '{who}: handtekening ongeldig',
    partyError: '{who}: de handtekening of de sleutel is beschadigd en kan niet worden gelezen',
    missingRelayPk: 'de ingebedde publieke sleutel van de relay ontbreekt',
    missingNotary: 'notarishandtekening ontbreekt',
    relayPkMismatch: 'hash van de publieke sleutel van de relay klopt niet',
    notaryInvalid: 'notarishandtekening ongeldig',
    notaryError: 'de notarishandtekening of de relaysleutel is beschadigd en kan niet worden gelezen',
    relayUnknown: 'De relaysleutel die dit bewijs bekrachtigt (vingerafdruk {fp}…) is geen sleutel van Paramant. Dit bewijs komt dus niet aantoonbaar van Paramant, ook al klopt het met zichzelf.',
    verifyingLocal: 'Bezig met controleren, lokaal in uw browser…',
    verifyingRelay: 'Lokaal hashen, daarna controleren via de relay…',
    verifyFailed: '<div class="ps-banner err"><span class="ps-mark" aria-hidden="true">\u2715</span>Controle mislukt: {err}</div>',
    notLinked: '<p class="ps-help">Paramant kent geen account bij deze sleutel.</p>',
    noLabel: '<em>(geen naam)</em>',
    unverified: '<em>(niet geverifieerd)</em>',
    signedBy: '<p class="ps-help"><strong>Ondertekend door {label} ({email})</strong> &middot; {algo}</p>',
    revoked: '<p class="ps-help">Deze sleutel is ingetrokken op {when}. Dit bewijs bevat geen ondertekend tijdstip, dus of er voor die datum is getekend, valt hieruit niet af te leiden. Vertrouw de handtekening alleen als u het tijdstip op een andere manier kunt aantonen.</p>',
    revokedNotary: '<p class="ps-help">Deze sleutel is ingetrokken op {when}. Het tijdstip in dit oude bewijs is door de relay ondertekend; de handtekening telt als die van voor die datum is.</p>',
    revokedBanner: '<div class="ps-banner warn"><span class="ps-mark" aria-hidden="true">!</span><strong>Sleutel ingetrokken.</strong> De handtekening klopt wiskundig, maar de sleutel is ingetrokken. Zie hieronder.</div>',
    enrolled: '<p class="ps-help">Sleutel geregistreerd op {when}.</p>',
    valid: '<div class="ps-banner ok"><span class="ps-mark" aria-hidden="true">\u2713</span><strong>Handtekening geldig.</strong> Het document komt overeen met de ondertekende hash.</div>',
    validTest: '<div class="ps-banner warn"><span class="ps-mark" aria-hidden="true">!</span><strong>Testbewijs, geen echte ondertekening.</strong> De handtekeningen kloppen, maar dit bewijs is gemaakt met een testsleutel (psk_test) en automatisch ondertekend door de sandbox van Paramant. Het heeft geen waarde als ondertekening.</div>',
    invalid: '<div class="ps-banner err"><span class="ps-mark" aria-hidden="true">\u2715</span><strong>Handtekening ONGELDIG.</strong></div>',
    notaryBy: '<p class="ps-help">Bekrachtigd door {name} (<code class="mono">{host}</code>), sleutel <code class="mono">{fp}…</code>, een vaste sleutel van deze site.</p>',
    notaryByRetired: '<p class="ps-help">Bekrachtigd door {name} (<code class="mono">{host}</code>) met een eerdere sleutel <code class="mono">{fp}…</code>, buiten gebruik sinds {when}.</p>',
    checkedKey: '<p class="ps-help">Ondertekend met de sleutel met vingerafdruk <code class="mono">{fp}</code>. Die vingerafdruk is uit de sleutel zelf berekend; vergelijk hem met de zegel op het document.</p>',
    unverifiedHead: '<p class="ps-help"><strong>Niet gecontroleerd.</strong> Het bewijs zelf koppelt deze sleutel niet aan een persoon of account. Deze gegevens staan in het bestand, maar vallen buiten de handtekening:</p><ul class="ps-unverified">',
    claimName: '<li class="ps-help">Naam: {v} (opgegeven door de ondertekenaar, niet gecontroleerd)</li>',
    claimDate: '<li class="ps-help">Datum: {v} (opgegeven door de ondertekenaar, niet gecontroleerd)</li>',
    claimFpBad: '<li class="ps-help"><strong>Let op:</strong> de vingerafdruk die in het bestand staat (<code class="mono">{v}</code>) hoort niet bij de sleutel die tekende. Iemand heeft dit bestand aangepast.</li>',
    claimNone: '<li class="ps-help">Geen naam of datum.</li>',
    partyScope: '<p class="ps-help"><strong>Voorbehoud:</strong> dit bewijs dekt één ondertekenaar (partij {i} van {n}). Of de andere partijen hebben getekend, of dat de envelop daarna is ingetrokken, staat niet in dit bestand.{counted}</p>',
    partyCounted: ' Volgens het bestand hadden toen {s} van de {n} getekend (niet gecontroleerd).',
    envOffline: '<p class="ps-help">Envelop: <code class="mono">{id}</code> &middot; offline gecontroleerd, zonder account.</p>',
    ctIndex: '<p class="ps-help">Positie in het CT-logboek: <a href="/ct-log">{idx}</a></p>',
  },
  en: {
    fileSize: ' ({kb} KB)',
    notJson: 'This file is not valid JSON. Choose the .psign envelope produced when the document was signed.',
    notPsign: 'This does not look like a .psign envelope (no algorithm field).',
    notPsignFields: 'This file lacks the fields of a ParaSign proof (version, signer or signature). Choose the .psign file that was produced when the document was signed.',
    docUnreadable: 'This file could not be read. It may be too large for this browser.',
    infoAlg: 'algorithm: {v}',
    infoSigned: 'signed_at: {v}',
    infoSigners: 'signers: {v}',
    infoEnvMulti: 'envelope: {v}…',
    infoKeyless: 'keyless (offline)',
    infoKey: 'key {v}…',
    infoEnv: 'envelope: {v}…',
    infoSignerLabel: 'signer: {v}',
    unsupportedAlg: 'unsupported algorithm: {v}',
    missingMpId: 'missing multiparty.envelope_id',
    missingSignedHash: 'missing signed document hash (stamped_hash or document_hash)',
    hashMismatch: 'document hash mismatch: this document does not match the one that was signed',
    hashIsOriginal: 'This is the file as it was before signing. The signature covers the signed version with the seal on it ({name}). Choose that file.',
    missingSignerPk: 'missing signer_public_key',
    missingEmailHash: 'missing party_email_hash (cannot reconstruct the signed message offline)',
    appearanceMismatch: 'appearance hash mismatch',
    appearanceInvalid: 'the description of the visible signature in the file is damaged',
    signerInvalid: 'signer signature invalid',
    signerError: 'the signature or the key in the .psign file is damaged and cannot be read',
    expired: 'envelope expired at {v}',
    missingEnvId: 'missing envelope_id',
    missingDocHash: 'missing document_hash',
    hashMismatchMulti: 'This is not the document that was signed. The signatures cover the original file, with SHA3-256 fingerprint {hash}…. A PDF carrying a Paramant stamp (footer "Signed with ParaSign" or a "ParaSign signature certificate" page) is a reading copy and always gives this message. Choose the original file that was put up for signing.',
    missingParties: 'missing parties',
    partyIncomplete: '{who} has no complete signature',
    partyWho: 'party {i}',
    partyAt: 'the party in position {n} of the proof',
    partyAppearance: '{who}: appearance hash mismatch',
    partyAppearanceInvalid: '{who}: the description of the visible signature is damaged',
    partyInvalid: '{who}: signature invalid',
    partyError: '{who}: the signature or the key is damaged and cannot be read',
    missingRelayPk: 'missing embedded relay public key',
    missingNotary: 'missing notary signature',
    relayPkMismatch: 'relay public key hash mismatch',
    notaryInvalid: 'notary signature invalid',
    notaryError: 'the notary signature or the relay key is damaged and cannot be read',
    relayUnknown: 'The relay key that counter-signs this proof (fingerprint {fp}…) is not a Paramant key. This proof therefore does not demonstrably come from Paramant, even though it is consistent with itself.',
    verifyingLocal: 'Verifying locally in your browser…',
    verifyingRelay: 'Hashing locally + verifying via relay…',
    verifyFailed: '<div class="ps-banner err"><span class="ps-mark" aria-hidden="true">\u2715</span>Verify failed: {err}</div>',
    notLinked: '<p class="ps-help">Paramant knows no account for this key.</p>',
    noLabel: '<em>(no label)</em>',
    unverified: '<em>(unverified)</em>',
    signedBy: '<p class="ps-help"><strong>Signed by {label} ({email})</strong> &middot; {algo}</p>',
    revoked: '<p class="ps-help">This key was revoked on {when}. This proof carries no signed time, so whether it was signed before that date cannot be told from it. Trust the signature only if you can establish the time some other way.</p>',
    revokedNotary: '<p class="ps-help">This key was revoked on {when}. The time in this older proof is signed by the relay; the signature counts if that time is before the revocation.</p>',
    revokedBanner: '<div class="ps-banner warn"><span class="ps-mark" aria-hidden="true">!</span><strong>Key revoked.</strong> The signature is mathematically correct, but the key has been revoked. See below.</div>',
    enrolled: '<p class="ps-help">Key enrolled on {when}.</p>',
    valid: '<div class="ps-banner ok"><span class="ps-mark" aria-hidden="true">\u2713</span><strong>Signature valid.</strong> Document matches the signed hash.</div>',
    validTest: '<div class="ps-banner warn"><span class="ps-mark" aria-hidden="true">!</span><strong>Test proof, not a real signature.</strong> The signatures check out, but this proof was made with a test key (psk_test) and signed automatically by the Paramant sandbox. It has no value as a signature.</div>',
    invalid: '<div class="ps-banner err"><span class="ps-mark" aria-hidden="true">\u2715</span><strong>Signature INVALID.</strong></div>',
    notaryBy: '<p class="ps-help">Counter-signed by {name} (<code class="mono">{host}</code>), key <code class="mono">{fp}…</code>, a key pinned in this site.</p>',
    notaryByRetired: '<p class="ps-help">Counter-signed by {name} (<code class="mono">{host}</code>) with an earlier key <code class="mono">{fp}…</code>, retired since {when}.</p>',
    checkedKey: '<p class="ps-help">Signed with the key whose fingerprint is <code class="mono">{fp}</code>. That fingerprint is computed from the key itself; compare it with the seal on the document.</p>',
    unverifiedHead: '<p class="ps-help"><strong>Not checked.</strong> The proof itself does not tie this key to a person or account. These details are in the file but outside the signature:</p><ul class="ps-unverified">',
    claimName: '<li class="ps-help">Name: {v} (stated by the signer, not checked)</li>',
    claimDate: '<li class="ps-help">Date: {v} (stated by the signer, not checked)</li>',
    claimFpBad: '<li class="ps-help"><strong>Warning:</strong> the fingerprint written in the file (<code class="mono">{v}</code>) does not belong to the key that signed. Someone has altered this file.</li>',
    claimNone: '<li class="ps-help">No name or date.</li>',
    partyScope: '<p class="ps-help"><strong>Caveat:</strong> this proof covers one signer (party {i} of {n}). Whether the other parties signed, or whether the envelope was withdrawn later, is not in this file.{counted}</p>',
    partyCounted: ' According to the file, {s} of the {n} had signed at that point (not checked).',
    envOffline: '<p class="ps-help">Envelope: <code class="mono">{id}</code> &middot; verified offline, no account needed.</p>',
    ctIndex: '<p class="ps-help">CT log index: <a href="/ct-log">{idx}</a></p>',
  },
};
function t(k, v) {
  let s = (T[LANG] && T[LANG][k]) || T.en[k] || k;
  if (v) for (const n of Object.keys(v)) s = s.split('{' + n + '}').join(String(v[n]));
  return s;
}

function fromB64(s) {
  const bin = atob(s);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

function hexToBytes(s) {
  const h = String(s || '');
  const out = new Uint8Array(h.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

function concatBytes(arrs) {
  let n = 0;
  for (const a of arrs) n += a.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonicalJSON(value[key])).join(',') + '}';
}

// Byte-identical to normaliseAppearance() in relay/envelope.js, key order
// included: this reproduces the bytes that were hashed into the signature, so
// any divergence surfaces as a proof that will not verify. all_pages (manifest
// v2, one mark repeated on every page) is emitted only when true, which is what
// keeps every proof made before v2 verifying unchanged.
function normaliseAppearance(value) {
  const source = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  let anyAllPages = false;
  const fields = Array.isArray(source.fields) ? source.fields.map((field) => {
    const clean = { type: String(field.type || ''), page_index: Number(field.page_index) };
    for (const name of ['x', 'y', 'w', 'h']) clean[name] = Math.round(Number(field[name]) * 1000000) / 1000000;
    if (field.all_pages === true) { clean.all_pages = true; anyAllPages = true; }
    return clean;
  }) : [];
  return { version: anyAllPages ? 2 : 1, fields };
}

function appearanceHash(value) {
  return sha3_256(new TextEncoder().encode(JSON.stringify(normaliseAppearance(value))));
}

// Reconstruct the versioned document-signing message, byte-identical to
// parasign-signer.js and relay/envelope.js.
function buildDocSignMessage(envelopeId, docHashHex, partyIndex, emailHashHex, recipeVersion, signerPublicKey, appearance) {
  const enc = new TextEncoder();
  const parts = [];
  if (Number(recipeVersion) >= 3) parts.push(enc.encode(SIGN_DOMAIN_DOC), new Uint8Array([0]));
  parts.push(
    enc.encode(String(envelopeId)),
    hexToBytes(docHashHex),
    enc.encode(String(partyIndex)),
  );
  if (Number(recipeVersion) >= 2) parts.push(hexToBytes(emailHashHex || ''));
  if (Number(recipeVersion) >= 4) parts.push(fromB64(signerPublicKey || ''));
  if (Number(recipeVersion) >= 5) parts.push(appearanceHash(appearance));
  return sha3_256(concatBytes(parts));
}

function isV3Envelope(env) {
  return !!env && (env.version === 'parasign-doc-3' || Number(env.recipe_version) >= 3);
}

// The seal fingerprint, sha3_256(pk)[0..16] as hex, exactly as sign-flow.js
// prints it on the document. '' when the key cannot be read.
function keyFingerprint(pkB64) {
  try {
    if (!pkB64) return '';
    return toHex(sha3_256(fromB64(pkB64))).slice(0, 16);
  } catch { return ''; }
}

// How a party is named in an error: its own index when it has one, otherwise
// its place in the list, never "partij null".
function partyWho(party, pos) {
  if (party && Number.isInteger(party.index)) return t('partyWho', { i: party.index });
  return t('partyAt', { n: pos + 1 });
}

// v3 verifies keyless client-side; v1/v2 need the relay (and its API key).
function update() {
  const apiKey = ($('vf-api-key').value || '').trim();
  const ready = documentBuffer && envelope && (isV3 || apiKey);
  $('vf-verify').disabled = !ready;
}

// Hide the API-key field for keyless v3 envelopes; show it for v1/v2.
function syncKeyField() {
  const block = $('vf-key-block');
  if (!block) return;
  block.hidden = isV3;
}

async function onDoc(file) {
  if (!file) return;
  try {
    documentBuffer = await file.arrayBuffer();
  } catch {
    documentBuffer = null;
    $('vf-document-info').textContent = t('docUnreadable');
    update();
    return;
  }
  $('vf-document-info').textContent = file.name + t('fileSize', { kb: LANG === 'en' ? (file.size / 1024).toFixed(1) : (file.size / 1024).toFixed(1).replace('.', ',') });
  update();
}

async function onEnv(file) {
  if (!file) return;
  try {
    let parsed;
    try {
      parsed = JSON.parse(await file.text());
    } catch {
      throw new Error(t('notJson'));
    }
    if (parsed && typeof parsed === 'object' && parsed.envelope) parsed = parsed.envelope;
    if (!parsed || typeof parsed !== 'object' || !parsed.algorithm) {
      throw new Error(t('notPsign'));
    }
    envelope = parsed;
    isMulti = envelope.type === 'parasign-envelope-receipt';
    isV3 = isMulti || isV3Envelope(envelope);
    // v1/v2 carry a nested signer and notary block. A file with neither and no
    // v3 version is not a proof at all; say so instead of asking for an API key.
    if (!isV3 && !(envelope.signer && typeof envelope.signer === 'object') && !(envelope.notary && typeof envelope.notary === 'object')) {
      throw new Error(t('notPsignFields'));
    }

    // signed_at of a v3 solo proof is outside the signature, so it is shown
    // with the result as a claim, never here as a fact.
    const info = [t('infoAlg', { v: envelope.algorithm || '?' })];
    if (isMulti && envelope.completed_at) info.push(t('infoSigned', { v: envelope.completed_at }));
    if (!isV3 && envelope.signed_at) info.push(t('infoSigned', { v: envelope.signed_at }));
    if (isMulti) {
      info.push(t('infoSigners', { v: String((envelope.parties || []).length) }));
      info.push(t('infoEnvMulti', { v: String(envelope.envelope_id || '').slice(0, 12) }));
      info.push(t('infoKeyless'));
    } else if (isV3) {
      // v3 (parasign-doc-3): signer_name and signer_pk_fingerprint are NOT in
      // the signed message, so neither is shown as the signer. The fingerprint
      // here is computed from the key that actually signs.
      const fp = keyFingerprint(envelope.signer_public_key);
      if (fp) info.push(t('infoKey', { v: fp }));
      const envId = envelope.multiparty && envelope.multiparty.envelope_id;
      if (envId) info.push(t('infoEnv', { v: String(envId).slice(0, 12) }));
      info.push(t('infoKeyless'));
    } else {
      // v1/v2: nested signer.label + notary.ct_log_index.
      if (envelope.signer && envelope.signer.label) info.push(t('infoSignerLabel', { v: envelope.signer.label }));
      const idx = (envelope.notary && envelope.notary.ct_log_index);
      if (idx != null) info.push('ct_log_index: ' + idx);
    }
    $('vf-envelope-info').textContent = info.join('  |  ');
  } catch (e) {
    $('vf-envelope-info').textContent = e.message;
    envelope = null; isV3 = false; isMulti = false;
  }
  syncKeyField();
  update();
}

// Keyless client-side verification of a v3 (parasign-doc-3) envelope. Mirrors
// relay/parasign.js verifyDocEnvelopeV3 exactly, with the same primitives - no
// relay call, no API key. Collects every failure rather than short-circuiting.
function verifyV3Client(docHashHex) {
  const errors = [];
  const env = envelope;
  if (env.algorithm && env.algorithm !== 'ML-DSA-65') errors.push(t('unsupportedAlg', { v: env.algorithm }));
  const mp = env.multiparty || {};
  if (!mp.envelope_id) errors.push(t('missingMpId'));

  // pdf/image sign the stamped document; other documents sign document_hash.
  const signedHash = env.stamped_hash || env.document_hash;
  if (!signedHash) errors.push(t('missingSignedHash'));
  if (docHashHex && signedHash && signedHash !== docHashHex) {
    // A pdf or image signs its stamped version. The file it was made from has
    // original_hash; recognise it and name the file that does verify.
    if (env.stamped_hash && env.original_hash === docHashHex) {
      errors.push(t('hashIsOriginal', { name: String(env.stamped_filename || 'signed-…') }));
    } else {
      errors.push(t('hashMismatch'));
    }
  }
  if (!env.signer_public_key) errors.push(t('missingSignerPk'));
  if (env.party_email_hash == null) {
    errors.push(t('missingEmailHash'));
  }
  const recipeVersion = Number(env.recipe_version) || 3;
  if (recipeVersion >= 5) {
    try {
      const computed = toHex(appearanceHash(env.appearance));
      if (computed !== env.appearance_hash) errors.push(t('appearanceMismatch'));
    } catch { errors.push(t('appearanceInvalid')); }
  }

  if (errors.length === 0) {
    try {
      const msg = buildDocSignMessage(
        String(mp.envelope_id),
        signedHash,
        mp.party_index != null ? mp.party_index : 0,
        env.party_email_hash || '',
        recipeVersion,
        env.signer_public_key,
        env.appearance,
      );
      const ok = ml_dsa65.verify(fromB64(env.signer_public_key), msg, fromB64(env.signature || ''));
      if (!ok) errors.push(t('signerInvalid'));
    } catch { errors.push(t('signerError')); }
  }
  if (env.expires_at && new Date(env.expires_at) < new Date()) {
    errors.push(t('expired', { v: env.expires_at }));
  }
  return { valid: errors.length === 0, errors };
}

function verifyMultiClient(docHashHex) {
  const errors = [];
  const env = envelope;
  if (env.algorithm !== 'ML-DSA-65') errors.push(t('unsupportedAlg', { v: env.algorithm }));
  if (!env.envelope_id) errors.push(t('missingEnvId'));
  if (!env.document_hash) errors.push(t('missingDocHash'));
  // The parties signed the ORIGINAL bytes. The stamped PDF that /v1 .../document
  // and co-sign hand out is a reading copy made after signing, and its hash is in
  // no signature, so it can never verify here; the message says which file to
  // use instead. (Protocol option, not taken: docs/parasign-open-api-spec.md.)
  if (env.document_hash && docHashHex !== env.document_hash) errors.push(t('hashMismatchMulti', { hash: String(env.document_hash).slice(0, 16) }));
  const recipe = Number(env.sign_recipe || env.recipe_version) || 1;
  const parties = Array.isArray(env.parties) ? env.parties : [];
  if (!parties.length) errors.push(t('missingParties'));
  parties.forEach((party, pos) => {
    const who = partyWho(party, pos);
    if (!party || party.status !== 'signed' || !party.public_key || !party.signature) {
      errors.push(t('partyIncomplete', { who }));
      return;
    }
    let visualHash = '';
    if (recipe >= 5) {
      try {
        visualHash = toHex(appearanceHash(party.appearance));
        if (visualHash !== party.appearance_hash) errors.push(t('partyAppearance', { who }));
      } catch { errors.push(t('partyAppearanceInvalid', { who })); }
    }
    try {
      const message = buildDocSignMessage(env.envelope_id, env.document_hash, party.index, party.email_hash || '', recipe, party.public_key, party.appearance);
      if (!ml_dsa65.verify(fromB64(party.public_key), message, fromB64(party.signature))) errors.push(t('partyInvalid', { who }));
    } catch { errors.push(t('partyError', { who })); }
  });
  // The notary counter-signature is checked against a relay key this site
  // ships with (js/relay-trust-anchors.js), never against the key printed in
  // the receipt: that key and its hash are written by whoever wrote the file,
  // so on their own they prove nothing. The embedded key only says WHICH pinned
  // key to use. Same rule as ParaSend receipts and scripts/heartbeat/parasign.mjs.
  const notary = env.notary || {};
  let anchor = null;
  if (!notary.relay_public_key) errors.push(t('missingRelayPk'));
  if (!env.notary_signature) errors.push(t('missingNotary'));
  if (notary.relay_public_key) {
    try {
      const embeddedHash = toHex(sha3_256(fromB64(notary.relay_public_key)));
      if (embeddedHash !== notary.relay_pk_hash) errors.push(t('relayPkMismatch'));
      const pinned = anchorByFingerprint(embeddedHash);
      // Recompute the pin's own fingerprint rather than trusting its string.
      const pinnedKey = pinned ? fromB64(pinned.key) : null;
      if (!pinned || toHex(sha3_256(pinnedKey)) !== embeddedHash) {
        errors.push(t('relayUnknown', { fp: embeddedHash.slice(0, 16) }));
      } else {
        anchor = pinned;
        const unsigned = { ...env };
        delete unsigned.notary_signature;
        const message = new TextEncoder().encode(canonicalJSON(unsigned));
        if (!ml_dsa65.verify(pinnedKey, message, fromB64(env.notary_signature || ''))) errors.push(t('notaryInvalid'));
      }
    } catch { errors.push(t('notaryError')); }
  }
  // mode/sandbox sit inside the notary signature (parasign-open-api.js
  // buildEnvelopePsign), so on a valid receipt they are facts, not claims.
  const test = env.mode === 'test' || env.sandbox === true;
  return { valid: errors.length === 0, errors, anchor, test };
}

async function verify() {
  $('vf-verify').disabled = true;
  $('vf-result').hidden = false;
  $('vf-result').innerHTML = '<div class="ps-banner info">' +
    (isV3 ? t('verifyingLocal') : t('verifyingRelay')) + '</div>';
  try {
    const docHash = sha3_256(new Uint8Array(documentBuffer)); // local
    if (isMulti) {
      await renderResult(verifyMultiClient(toHex(docHash)));
      return;
    }
    if (isV3) {
      // Fully offline: never touches the network for the crypto.
      await renderResult(verifyV3Client(toHex(docHash)));
      return;
    }
    const res = await fetch(RELAY_URL + '/v2/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Api-Key': $('vf-api-key').value.trim() },
      body: JSON.stringify({ document_hash: toHex(docHash), envelope }),
    });
    if (!res.ok && res.status !== 200) {
      const t = await res.text();
      try { console.error('[paramant] /v2/verify', res.status, t.slice(0, 200)); } catch { /* no console */ }
      $('vf-result').innerHTML = '<div class="ps-banner err">' + esc(res.status === 401 || res.status === 403
        ? (LANG === 'nl' ? 'Deze API-sleutel wordt niet geaccepteerd. Controleer de sleutel, of laat het veld leeg en controleer met het originele bestand en het .psign-bestand.' : 'This API key is not accepted. Check the key, or leave the field empty and check with the original file and the .psign file.')
        : res.status === 429
          ? (LANG === 'nl' ? 'Even te veel controles tegelijk. Probeer het over een minuut opnieuw.' : 'Too many checks at once. Try again in a minute.')
          : (LANG === 'nl' ? 'De controle kon nu niet worden uitgevoerd door een storing bij ons. Probeer het zo opnieuw.' : 'The check could not run right now because of a fault on our side. Please try again shortly.')) + '</div>';
      return;
    }
    await renderResult(await res.json());
  } catch (e) {
    $('vf-result').innerHTML = t('verifyFailed', { err: esc(e.message) });
  } finally { $('vf-verify').disabled = false; }
}

// Resolve "Signed by <label> (<email>)" via the public lookup endpoint.
// Returns { html, revoked } (html already escaped, '' if nothing found).
async function lookupSignerHtml(envelope) {
  try {
    // v1/v2 nest the key under signer.public_key; v3 (parasign-doc-3) carries it
    // flat as signer_public_key.
    const pkB64 = (envelope && envelope.signer && envelope.signer.public_key)
      || (envelope && envelope.signer_public_key);
    if (!pkB64) return { html: '', revoked: false };
    const pkBytes = fromB64(pkB64);
    const pkHash = toHex(sha3_256(pkBytes));
    const res = await fetch(RELAY_URL + '/v2/lookup-signer/' + pkHash);
    if (res.status === 404) return { html: t('notLinked'), revoked: false };
    if (!res.ok) return { html: '', revoked: false };
    const d = await res.json();
    if (!d.found) return { html: '', revoked: false };
    const label = d.label ? esc(d.label) : t('noLabel');
    const email = d.email ? esc(d.email) : t('unverified');
    const algo  = esc(d.alg || '?');
    let html = t('signedBy', { label, email, algo });
    if (d.revoked_at) {
      html += t(isV3 ? 'revoked' : 'revokedNotary', { when: esc(d.revoked_at) });
    } else if (d.enrolled_at) {
      html += t('enrolled', { when: esc(d.enrolled_at) });
    }
    return { html, revoked: !!d.revoked_at };
  } catch { return { html: '', revoked: false }; }
}

// What a valid v3 solo proof does and does not establish. Only the document
// hash, the envelope binding and the key are signed (buildDocSignMessage);
// signer_name, signer_pk_fingerprint and signed_at are free text in the file.
// This block is rendered offline, before and independent of any lookup.
function v3ScopeHtml(env) {
  const out = [];
  const fp = keyFingerprint(env.signer_public_key);
  if (fp) out.push(t('checkedKey', { fp: esc(fp) }));
  out.push(t('unverifiedHead'));
  let any = false;
  if (env.signer_name) { out.push(t('claimName', { v: esc(env.signer_name) })); any = true; }
  if (env.signed_at) { out.push(t('claimDate', { v: esc(env.signed_at) })); any = true; }
  const claimedFp = String(env.signer_pk_fingerprint || '').toLowerCase();
  if (claimedFp && fp && !fp.startsWith(claimedFp.slice(0, 16)) ) { out.push(t('claimFpBad', { v: esc(claimedFp.slice(0, 32)) })); any = true; }
  if (!any) out.push(t('claimNone'));
  out.push('</ul>');
  const mp = env.multiparty || {};
  const n = Number(mp.party_count);
  if (Number.isInteger(n) && n > 1) {
    const i = Number.isInteger(Number(mp.party_index)) ? Number(mp.party_index) + 1 : 1;
    const sc = Number(mp.signed_count);
    const counted = Number.isInteger(sc) ? t('partyCounted', { s: sc, n }) : '';
    out.push(t('partyScope', { i, n, counted }));
  }
  return out.join('');
}

async function renderResult(r) {
  const out = [];
  const banner = !r.valid ? t('invalid') : (r.test ? t('validTest') : t('valid'));
  out.push(banner);
  if (r.errors && r.errors.length) {
    out.push('<ul style="margin-top:var(--space-3)">');
    r.errors.forEach(e => out.push('<li class="ps-help">' + esc(e) + '</li>'));
    out.push('</ul>');
  }
  if (r.note) out.push('<p class="ps-help">' + esc(r.note) + '</p>');
  if (isV3) {
    const envId = isMulti ? envelope && envelope.envelope_id : envelope && envelope.multiparty && envelope.multiparty.envelope_id;
    if (envId) out.push(t('envOffline', { id: esc(String(envId)) }));
    if (r.valid && isMulti && r.anchor) {
      const a = r.anchor;
      const name = esc(LANG === 'en' ? a.name : (a.name_nl || a.name));
      const vars = { name, host: esc(a.host), fp: esc(String(a.fingerprint).slice(0, 16)), when: esc(a.retired_at || '') };
      out.push(a.retired_at ? t('notaryByRetired', vars) : t('notaryBy', vars));
    }
    if (r.valid && !isMulti) out.push(v3ScopeHtml(envelope));
  } else {
    const idx = envelope && envelope.notary && envelope.notary.ct_log_index;
    if (idx != null) out.push(t('ctIndex', { idx: esc(String(idx)) }));
  }
  // First paint without attribution so the user sees the valid/invalid badge fast.
  $('vf-result').innerHTML = out.join('');
  // Then enrich with public-key lookup (best-effort, can be 404).
  if (r.valid && !isMulti) {
    const attr = await lookupSignerHtml(envelope);
    if (attr.html) {
      // A revoked key takes the green away: the proof has no signed time, so
      // "valid if signed before the revocation" cannot be checked.
      if (attr.revoked && isV3) out[0] = t('revokedBanner');
      $('vf-result').innerHTML = out.join('') + attr.html;
    }
  }
}

$('vf-document').addEventListener('change', e => onDoc(e.target.files[0]));
$('vf-envelope').addEventListener('change', e => onEnv(e.target.files[0]));
$('vf-api-key').addEventListener('input', update);
$('vf-verify').addEventListener('click', verify);
