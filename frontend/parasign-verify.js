// ParaSign /verify page logic.
// The document NEVER leaves the browser: only its SHA3-256 hash is ever needed.
// v3 (parasign-doc-3) envelopes are verified ENTIRELY client-side with the same
// ML-DSA-65 + SHA3-256 primitives the signer used -- no relay, no API key, so
// the counterparty (who has no Paramant account) can verify offline. v1/v2
// envelopes carry a relay notary signature that only the relay can check, so
// they still POST to /v2/verify: public, no API key, but not offline.
import { sha3_256, ml_dsa65 } from '/vendor/paramant-pqc.js';
// The relay keys this site ships with. A multi-party receipt is only Paramant's
// when its notary key is one of these; the key printed inside the receipt is
// never trusted on its own, or any file could vouch for itself.
import { anchorByFingerprint } from '/js/relay-trust-anchors.js?v=2';
import { embeddedFiles, looksLikePdf } from '/js/pdf-embedded.js?v=2';

const RELAY_URL = 'https://relay.paramant.app';
// Byte-identical to relay/envelope.js SIGN_DOMAIN_DOC (recipe v3). Keep in sync.
const SIGN_DOMAIN_DOC = 'paramant/parasign/doc/v1';
let documentFile = null, envelope = null, isV3 = false, isMulti = false;

const $ = id => document.getElementById(id);
const toHex = u8 => Array.from(u8, b => b.toString(16).padStart(2, '0')).join('');
const esc = s => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#x27;');

// A moment as a reader says it: "5 oktober 2026 om 20:56", Dutch time. A
// value that is not a date is shown as it is.
function humanWhen(iso) {
  const d = new Date(String(iso || ''));
  if (Number.isNaN(d.getTime())) return String(iso || '');
  const opts = { timeZone: 'Europe/Amsterdam' };
  const loc = LANG === 'en' ? 'en-GB' : 'nl-NL';
  const day = d.toLocaleDateString(loc, { ...opts, day: 'numeric', month: 'long', year: 'numeric' });
  const time = d.toLocaleTimeString(loc, { ...opts, hour: '2-digit', minute: '2-digit' });
  return day + t('infoAt') + time;
}

// Visible text in both languages. /verify is Dutch, /en/verify English; the page's <html lang> picks the set.
const LANG = ((typeof document !== 'undefined' && document.documentElement.lang) || 'nl').slice(0, 2) === 'en' ? 'en' : 'nl';
const T = {
  nl: {
    fileSize: ' ({kb} kB)',
    notJson: 'Dit is geen bewijsbestand. Kies het .psign-bestand dat bij het ondertekenen is gemaakt.',
    notPsign: 'Dit lijkt geen .psign-bestand (het veld algorithm ontbreekt).',
    notPsignFields: 'Dit bestand mist de velden van een ParaSign-bewijs (versie, ondertekenaar of handtekening). Kies het .psign-bestand dat bij het ondertekenen is gemaakt.',
    docUnreadable: 'Dit bestand kon niet worden gelezen. Het is mogelijk te groot voor deze browser.',
    infoAlg: 'algoritme: {v}',
    infoSigned: 'getekend op {v}',
    infoSigners: '{v} ondertekenaars',
    infoSolo: 'bewijs van één ondertekenaar',
    infoKey: 'sleutel {v}…',
    techHead: 'Technische gegevens',
    infoAt: ' om ',
    infoSignerLabel: 'ondertekenaar: {v}',
    unsupportedAlg: 'algoritme niet ondersteund: {v}',
    missingMpId: 'multiparty.envelope_id ontbreekt',
    missingSignedHash: 'de hash van het ondertekende document ontbreekt (stamped_hash of document_hash)',
    embeddedOriginal: 'Het origineel zit als bijlage in deze pdf.',
    embeddedSave: 'Origineel opslaan',
    embeddedTooLarge: 'Deze pdf bevat een bijlage die uitgepakt te groot is om hier te controleren. Die bijlage is niet bekeken. Controleer met het originele bestand zelf.',
    // Review #565, M1: a pdf whose visible pages say something else, with the
    // real signed original attached, verified with the full green banner.
    embeddedValid: '<div class="ps-banner warn"><span class="ps-mark" aria-hidden="true">!</span><strong>De handtekeningen zijn geldig, voor het origineel in deze pdf.</strong> Alleen dat origineel is gecontroleerd, niet de pagina\u2019s die u nu ziet. Die kunnen in theorie afwijken. Sla het origineel op en lees dat, dan weet u zeker wat er is getekend.</div>',
    hashMismatch: 'de vingerafdruk klopt niet: dit is niet het document dat is ondertekend',
    wrongFileSolo: '<div class="ps-banner err"><span class="ps-mark" aria-hidden="true">\u2715</span><strong>Dit is niet het ondertekende bestand. {pick}</strong> De handtekening in het .psign-bestand geldt voor een ander bestand (SHA3-256-vingerafdruk {hash}…). Bij een pdf of afbeelding is dat de versie met de zegel erop, die u na het ondertekenen kreeg. Wat u koos, is niet wat er is ondertekend. Kies dat bestand en controleer opnieuw.</div>',
    partyNamesHead: 'Namen zoals de afzender ze opgaf (niet gecontroleerd; de handtekeningen zelf zijn wel gecontroleerd):',
    missingSignerPk: 'signer_public_key ontbreekt',
    missingEmailHash: 'party_email_hash ontbreekt (het ondertekende bericht is offline niet na te bouwen)',
    appearanceMismatch: 'hash van de weergave klopt niet',
    appearanceInvalid: 'de beschrijving van de zichtbare handtekening in het bestand is beschadigd',
    signerInvalid: 'handtekening van de ondertekenaar ongeldig',
    signerError: 'de handtekening of de sleutel in het .psign-bestand is beschadigd en kan niet worden gelezen',
    expired: 'envelop verlopen op {v}',
    missingEnvId: 'envelope_id ontbreekt',
    missingDocHash: 'document_hash ontbreekt',
    hashMismatchMulti: 'Dit is niet het document dat is ondertekend. De handtekeningen gelden voor het originele bestand, met SHA3-256-vingerafdruk {hash}…. De pdf met de zichtbare handtekeningen en parafen (onder elke handtekening de regel "Paramant ParaSign · PQ …") is ook niet het origineel. Kies het originele bestand dat ter ondertekening is aangeboden.',
    missingParties: 'partijen ontbreken',
    wrongFile: '<div class="ps-banner err"><span class="ps-mark" aria-hidden="true">\u2715</span><strong>Dit is niet het ondertekende bestand. Controleer met het originele bestand.</strong> Het .psign-bestand is in orde, maar de handtekeningen gelden voor een ander bestand (SHA3-256-vingerafdruk {hash}…). Wat u koos, is dus niet wat er is ondertekend. Kies het originele bestand dat ter ondertekening is aangeboden en controleer opnieuw. Bij &quot;Samen ondertekenen&quot; is dat de pdf met het zegel van de afzender, zoals de afzender die na zijn eigen handtekening kreeg; een pdf met de handtekeningen van iedereen is een leesbare kopie; die controleert hier alleen als het origineel erin is ingebed, zoals bij de complete pdf van Paramant.</div>',
    lookupFailed: '<p class="ps-help">Het opzoeken lukte nu niet; Paramant gaf geen antwoord. De controle hierboven blijft gelden. Probeer het later opnieuw.</p>',
    lookupRetry: 'Opnieuw opzoeken',
    qesNote: '<p class="ps-help">Volgens dit bewijs staat er in de pdf ook een gekwalificeerde handtekening (PAdES) van {provider}, certificaat <code class="mono">{fp}</code>{when}. Die tweede handtekening controleert deze pagina niet: open de ondertekende pdf in een PAdES-lezer, zoals Adobe Acrobat of de EU-validatiedienst DSS.</p>',
    qesWhen: ', gezet op {v}',
    pickSignedPdf: 'Kies de getekende pdf (signed-…pdf).',
    pickSignedImage: 'Kies de getekende afbeelding (signed-…).',
    pickOriginal: 'Controleer met het originele bestand.',
    soloChecked: '<div class="ps-banner info"><span class="ps-mark" aria-hidden="true">\u2713</span><strong>De handtekening klopt met dit document.</strong> Wie tekende, staat niet in de handtekening: de naam hieronder is niet gecontroleerd.</div>',
    fpTampered: '<div class="ps-banner warn"><span class="ps-mark" aria-hidden="true">!</span><strong>De handtekening klopt, maar dit bestand is aangepast.</strong> De gegevens over de ondertekenaar horen niet bij de sleutel die tekende. Vertrouw de naam in dit bestand niet.</div>',
    lookupBtn: 'Wie hoort bij deze sleutel? (vraagt het aan Paramant)',
    lookupNote: 'De controle hierboven gebeurde helemaal in uw browser. Deze knop is de enige vraag aan Paramant: welke account bij deze sleutel hoort.',
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
    relayUnknown: 'De serversleutel die dit bewijs bekrachtigt (vingerafdruk {fp}…) is geen sleutel van Paramant. Dit bewijs komt dus niet aantoonbaar van Paramant, ook al klopt het met zichzelf.',
    verifyingLocal: 'Bezig met controleren in uw browser…',
    verifyingRelay: 'Vingerafdruk maken op dit apparaat, daarna controleert onze server het bewijs…',
    verifyFailed: '<div class="ps-banner err"><span class="ps-mark" aria-hidden="true">\u2715</span>Controle mislukt: {err}</div>',
    notLinked: '<p class="ps-help">Paramant kent geen account bij deze sleutel.</p>',
    noLabel: '<em>(geen naam)</em>',
    unverified: '<em>(niet geverifieerd)</em>',
    signedBy: '<p class="ps-help"><strong>Ondertekend door {label} ({email})</strong> &middot; {algo}</p>',
    revoked: '<p class="ps-help">Deze sleutel is ingetrokken op {when}. Dit bewijs bevat geen ondertekend tijdstip, dus of er voor die datum is getekend, valt hieruit niet af te leiden. Vertrouw de handtekening alleen als u het tijdstip op een andere manier kunt aantonen.</p>',
    revokedNotary: '<p class="ps-help">Deze sleutel is ingetrokken op {when}. Het tijdstip in dit oude bewijs is door onze server ondertekend; de handtekening telt als die van voor die datum is.</p>',
    revokedBanner: '<div class="ps-banner warn"><span class="ps-mark" aria-hidden="true">!</span><strong>Sleutel ingetrokken.</strong> De handtekening klopt wiskundig, maar de sleutel is ingetrokken. Zie hieronder.</div>',
    enrolled: '<p class="ps-help">Sleutel geregistreerd op {when}.</p>',
    valid: '<div class="ps-banner ok"><span class="ps-mark" aria-hidden="true">\u2713</span><strong>Handtekening geldig.</strong> Dit is precies het document dat is ondertekend.</div>',
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
    partyScope: '<p class="ps-help"><strong>Voorbehoud:</strong> dit bewijs dekt één ondertekenaar (partij {i} van {n}). Of de andere partijen hebben getekend, of dat het verzoek daarna is ingetrokken, staat niet in dit bestand.{counted}</p>',
    partyCounted: ' Volgens het bestand hadden toen {s} van de {n} getekend (niet gecontroleerd).',
    envOffline: '<p class="ps-help">Verzoek: <code class="mono">{id}</code> &middot; offline gecontroleerd, zonder account.</p>',
    ctIndex: '<p class="ps-help">Positie in het CT-logboek: <a href="/ct-log">{idx}</a></p>',
  },
  en: {
    fileSize: ' ({kb} KB)',
    notJson: 'This is not a proof file. Choose the .psign file made when the document was signed.',
    notPsign: 'This does not look like a .psign file (no algorithm field).',
    notPsignFields: 'This file lacks the fields of a ParaSign proof (version, signer or signature). Choose the .psign file that was produced when the document was signed.',
    docUnreadable: 'This file could not be read. It may be too large for this browser.',
    infoAlg: 'algorithm: {v}',
    infoSigned: 'signed on {v}',
    infoSigners: '{v} signers',
    infoSolo: 'proof of one signer',
    infoKey: 'key {v}…',
    techHead: 'Technical details',
    infoAt: ' at ',
    infoSignerLabel: 'signer: {v}',
    unsupportedAlg: 'unsupported algorithm: {v}',
    missingMpId: 'missing multiparty.envelope_id',
    missingSignedHash: 'missing signed document hash (stamped_hash or document_hash)',
    embeddedOriginal: 'The original is attached inside this pdf.',
    embeddedSave: 'Save the original',
    embeddedTooLarge: 'This pdf has an attachment that is too large unpacked to check here. That attachment was not looked at. Check with the original file itself.',
    embeddedValid: '<div class="ps-banner warn"><span class="ps-mark" aria-hidden="true">!</span><strong>The signatures are valid, for the original inside this pdf.</strong> Only that original was checked, not the pages you see now. In theory those could differ. Save the original and read it, then you know for sure what was signed.</div>',
    hashMismatch: 'the fingerprint does not match: this is not the document that was signed',
    wrongFileSolo: '<div class="ps-banner err"><span class="ps-mark" aria-hidden="true">\u2715</span><strong>This is not the signed file. {pick}</strong> The signature in the .psign file covers a different file (SHA3-256 fingerprint {hash}…). For a PDF or image that is the version with the seal on it, which you received after signing. What you chose is not what was signed. Choose that file and check again.</div>',
    partyNamesHead: 'Names as the sender entered them (not checked; the signatures themselves were checked):',
    missingSignerPk: 'missing signer_public_key',
    missingEmailHash: 'missing party_email_hash (cannot reconstruct the signed message offline)',
    appearanceMismatch: 'appearance hash mismatch',
    appearanceInvalid: 'the description of the visible signature in the file is damaged',
    signerInvalid: 'signer signature invalid',
    signerError: 'the signature or the key in the .psign file is damaged and cannot be read',
    expired: 'envelope expired at {v}',
    missingEnvId: 'missing envelope_id',
    missingDocHash: 'missing document_hash',
    hashMismatchMulti: 'This is not the document that was signed. The signatures cover the original file, with SHA3-256 fingerprint {hash}…. The PDF with the visible signatures and initials (the line "Paramant ParaSign · PQ …" under each signature) is not the original either. Choose the original file that was put up for signing.',
    missingParties: 'missing parties',
    wrongFile: '<div class="ps-banner err"><span class="ps-mark" aria-hidden="true">\u2715</span><strong>This is not the signed file. Check with the original file.</strong> The .psign file is in order, but the signatures cover a different file (SHA3-256 fingerprint {hash}…). What you chose is therefore not what was signed. Choose the original file that was put up for signing and check again. With &quot;Sign together&quot; that is the PDF with the seal of the sender, as the sender received it after signing; a PDF that shows all signatures is a readable copy; it only checks here when the original is embedded in it, as in the complete PDF from Paramant.</div>',
    lookupFailed: '<p class="ps-help">The lookup did not work just now; Paramant did not answer. The check above still stands. Please try again later.</p>',
    lookupRetry: 'Look up again',
    qesNote: '<p class="ps-help">According to this proof, the PDF also carries a qualified signature (PAdES) from {provider}, certificate <code class="mono">{fp}</code>{when}. This page does not check that second signature: open the signed PDF in a PAdES reader, such as Adobe Acrobat or the EU validation service DSS.</p>',
    qesWhen: ', made on {v}',
    pickSignedPdf: 'Choose the signed PDF (signed-…pdf).',
    pickSignedImage: 'Choose the signed image (signed-…).',
    pickOriginal: 'Check with the original file.',
    soloChecked: '<div class="ps-banner info"><span class="ps-mark" aria-hidden="true">\u2713</span><strong>The signature matches this document.</strong> Who signed is not part of the signature: the name below has not been checked.</div>',
    fpTampered: '<div class="ps-banner warn"><span class="ps-mark" aria-hidden="true">!</span><strong>The signature is correct, but this file has been altered.</strong> The signer details do not belong to the key that signed. Do not trust the name in this file.</div>',
    lookupBtn: 'Who does this key belong to? (asks Paramant)',
    lookupNote: 'The check above happened entirely in your browser. This button is the only question to Paramant: which account this key belongs to.',
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
    relayUnknown: 'The server key that counter-signs this proof (fingerprint {fp}…) is not a Paramant key. This proof therefore does not demonstrably come from Paramant, even though it is consistent with itself.',
    verifyingLocal: 'Checking in your browser…',
    verifyingRelay: 'Taking the fingerprint on this device, then our server checks the proof…',
    verifyFailed: '<div class="ps-banner err"><span class="ps-mark" aria-hidden="true">\u2715</span>Verify failed: {err}</div>',
    notLinked: '<p class="ps-help">Paramant knows no account for this key.</p>',
    noLabel: '<em>(no label)</em>',
    unverified: '<em>(unverified)</em>',
    signedBy: '<p class="ps-help"><strong>Signed by {label} ({email})</strong> &middot; {algo}</p>',
    revoked: '<p class="ps-help">This key was revoked on {when}. This proof carries no signed time, so whether it was signed before that date cannot be told from it. Trust the signature only if you can establish the time some other way.</p>',
    revokedNotary: '<p class="ps-help">This key was revoked on {when}. The time in this older proof is signed by our server; the signature counts if that time is before the revocation.</p>',
    revokedBanner: '<div class="ps-banner warn"><span class="ps-mark" aria-hidden="true">!</span><strong>Key revoked.</strong> The signature is mathematically correct, but the key has been revoked. See below.</div>',
    enrolled: '<p class="ps-help">Key enrolled on {when}.</p>',
    valid: '<div class="ps-banner ok"><span class="ps-mark" aria-hidden="true">\u2713</span><strong>Signature valid.</strong> This is exactly the document that was signed.</div>',
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
    partyScope: '<p class="ps-help"><strong>Caveat:</strong> this proof covers one signer (party {i} of {n}). Whether the other parties signed, or whether the request was withdrawn later, is not in this file.{counted}</p>',
    partyCounted: ' According to the file, {s} of the {n} had signed at that point (not checked).',
    envOffline: '<p class="ps-help">Request: <code class="mono">{id}</code> &middot; verified offline, no account needed.</p>',
    ctIndex: '<p class="ps-help">CT log index: <a href="/en/ct-log">{idx}</a></p>',
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
  // The same checks as normaliseSigningAppearance (js/parasign-signer.js) and
  // normaliseAppearance (relay/envelope.js): a manifest the other two refuse is
  // refused here too, instead of being hashed as if it were fine (retest
  // T2-B5). Accepted input comes out byte for byte as before.
  const bad = () => { throw new Error('invalid appearance'); };
  const source = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  const declared = source.version === undefined ? null : Number(source.version);
  if (declared !== null && declared !== 1 && declared !== 2) bad();
  const input = source.fields === undefined ? [] : source.fields;
  if (!Array.isArray(input) || input.length > 8) bad();
  let anyAllPages = false;
  const fields = input.map((field) => {
    if (!field || typeof field !== 'object' || Array.isArray(field)) bad();
    const type = String(field.type || '');
    if (type !== 'seal' && type !== 'date') bad();
    const pageIndex = Number(field.page_index);
    if (!Number.isInteger(pageIndex) || pageIndex < 0 || pageIndex > 999) bad();
    const clean = { type, page_index: pageIndex };
    for (const name of ['x', 'y', 'w', 'h']) {
      const n = Number(field[name]);
      if (!Number.isFinite(n) || n < 0 || n > 1) bad();
      clean[name] = Math.round(n * 1000000) / 1000000;
    }
    if (clean.w < 0.02 || clean.h < 0.01 || clean.x + clean.w > 1.000001 || clean.y + clean.h > 1.000001) bad();
    if (field.all_pages !== undefined) {
      if (typeof field.all_pages !== 'boolean') bad();
      if (field.all_pages === true) {
        if (pageIndex !== 0 || declared !== 2) bad();
        clean.all_pages = true;
        anyAllPages = true;
      }
    }
    return clean;
  });
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

// v3 verifies keyless client-side; v1/v2 ask the relay's public /v2/verify
// (no API key since 2026-10-04; it used to ask the reader for one, T3-12).
function update() {
  const ready = documentFile && envelope;
  $('vf-verify').disabled = !ready;
}

// The note that an old v1/v2 envelope is checked by the relay.
function syncKeyField() {
  const block = $('vf-key-block');
  if (!block) return;
  block.hidden = isV3;
}

async function onDoc(file) {
  if (!file) return;
  // Kept as the File, read in slices when it is checked (hashFileInSlices):
  // reading 500 MB in one go and hashing it in one call froze the page for
  // 20 seconds (retest T3-9).
  documentFile = file;
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

    // What a reader can use at a glance: how many signed and when. The
    // algorithm, the request id and the key fingerprint are not for a reader
    // who wants to know whether his document is in order; they are in
    // "Technische gegevens" under the result (acceptance 3.1.1, 9).
    // signed_at of a v3 solo proof is outside the signature, so it is shown
    // with the result as a claim, never here as a fact.
    const info = [];
    if (isMulti) {
      info.push(t('infoSigners', { v: String((envelope.parties || []).length) }));
      if (envelope.completed_at) info.push(t('infoSigned', { v: humanWhen(envelope.completed_at) }));
    } else if (isV3) {
      // The fingerprint is computed from the key that signs, and is the one
      // thing a reader compares with the seal on the document.
      info.push(t('infoSolo'));
      const fp = keyFingerprint(envelope.signer_public_key);
      if (fp) info.push(t('infoKey', { v: fp }));
    } else {
      // v1/v2: nested signer.label; the notary signs the time.
      if (envelope.signer && envelope.signer.label) info.push(t('infoSignerLabel', { v: envelope.signer.label }));
      if (envelope.signed_at) info.push(t('infoSigned', { v: humanWhen(envelope.signed_at) }));
    }
    $('vf-envelope-info').textContent = info.join(' \u00b7 ');
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
  // original_hash and stamped_filename are not inside the signature
  // (buildDocSignMessage signs stamped_hash), so they can never make a file
  // "the original" here: anyone can edit them. Any file that is not the
  // signed one is red, without names (review #555, B2).
  const docMismatch = !!(docHashHex && signedHash && signedHash !== docHashHex);
  if (docMismatch) errors.push(t('hashMismatch'));
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

  // A wrong file next to an intact proof: the signature is still checked
  // (against the hash in the proof), so the page can say "the proof is fine,
  // this is not the signed file" in red instead of "forged".
  let sigOk = false;
  if (errors.length === 0 || (docMismatch && errors.length === 1)) {
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
      if (!ok) errors.push(t('signerInvalid')); else sigOk = true;
    } catch { errors.push(t('signerError')); }
  }
  if (env.expires_at && new Date(env.expires_at) < new Date()) {
    errors.push(t('expired', { v: env.expires_at }));
  }
  const wrongFile = docMismatch && sigOk && errors.length === 1;
  return { valid: errors.length === 0, errors, wrongFile, docHash: signedHash };
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
  const docMismatch = !!(env.document_hash && docHashHex !== env.document_hash);
  if (docMismatch) errors.push(t('hashMismatchMulti', { hash: String(env.document_hash).slice(0, 16) }));
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
  // Every signature holds and only the file differs. No signature covers the
  // stamped reading copy, and a marker in the file's bytes is not evidence
  // (anyone can paste it into any file), so every file that is not the signed
  // one is red, without party names or QES as facts (review #555, B1). The
  // proof itself is fine, so it is not called forged either.
  const wrongFile = docMismatch && errors.length === 1;
  return { valid: errors.length === 0, errors, anchor, test, wrongFile, docHash: env.document_hash };
}

async function verify() {
  $('vf-verify').disabled = true;
  $('vf-result').hidden = false;
  $('vf-result').innerHTML = '<div class="ps-banner info">' +
    (isV3 ? t('verifyingLocal') : t('verifyingRelay')) + '</div>';
  try {
    let docHash;
    try {
      docHash = await hashFileInSlices(documentFile, (pct) => {
        const el = $('vf-result');
        if (el && pct < 100) el.innerHTML = '<div class="ps-banner info">' + (isV3 ? t('verifyingLocal') : t('verifyingRelay')) + ' ' + pct + '%</div>';
      });
    } catch {
      $('vf-result').innerHTML = '<div class="ps-banner err">' + esc(t('docUnreadable')) + '</div>';
      return;
    }
    // A readable copy from /co-sign carries the signed original inside it as
    // a PDF attachment. When the chosen file is not the signed one, look
    // there: an embedded file whose SHA3-256 IS the signed hash is the signed
    // document itself, so the proof is checked against that (DASH-09-L).
    let embedded = null;
    let embeddedTooLarge = false;
    const expected = String(isMulti ? (envelope && envelope.document_hash) || ''
      : ((envelope && (envelope.stamped_hash || envelope.document_hash)) || '')).toLowerCase();
    if (expected && toHex(docHash) !== expected && documentFile && documentFile.size < 512 * 1024 * 1024) {
      try {
        const head = new Uint8Array(await documentFile.slice(0, 5).arrayBuffer());
        if (looksLikePdf(head)) {
          const all = new Uint8Array(await documentFile.arrayBuffer());
          const cands = await embeddedFiles(all);
          for (const cand of cands) {
            const h = sha3_256(cand.bytes);
            if (toHex(h) === expected) { docHash = h; embedded = cand; break; }
          }
          embeddedTooLarge = !embedded && !!cands.tooLarge;
        }
      } catch { embedded = null; }
    }
    const withEmbedded = (r) => (embedded ? { ...r, embedded } : embeddedTooLarge ? { ...r, embeddedTooLarge } : r);
    if (isMulti) {
      await renderResult(withEmbedded(verifyMultiClient(toHex(docHash))));
      return;
    }
    if (isV3) {
      // Fully offline: never touches the network for the crypto.
      await renderResult(withEmbedded(verifyV3Client(toHex(docHash))));
      return;
    }
    const res = await fetch(RELAY_URL + '/v2/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ document_hash: toHex(docHash), envelope }),
    });
    // 422 is the relay's verdict "not valid" with the reasons (relay.js
    // /v2/verify), not a fault on our side (hertest r2 R2).
    if (res.status === 422) {
      let body = null;
      try { body = await res.json(); } catch { body = null; }
      if (body && body.valid === false) {
        // A wrong file is the common case here too (an old v2 proof checked
        // against another file): the same prescribed heading as v3 gets,
        // "Dit is niet het ondertekende bestand. Controleer met het originele
        // bestand." (acceptatie r4, punt 3). Only when that is the one reason.
        const errs = Array.isArray(body.errors) ? body.errors : [];
        const onlyWrongFile = errs.length === 1 && /document_hash mismatch/i.test(String(errs[0] || ''));
        await renderResult(withEmbedded({ valid: false, errors: relayErrors(errs), note: null, wrongFile: onlyWrongFile,
          docHash: (envelope && (envelope.document_hash || envelope.stamped_hash)) || '' }));
        return;
      }
    }
    if (!res.ok && res.status !== 200) {
      const t = await res.text().catch(() => '');
      try { console.error('[paramant] /v2/verify', res.status, t.slice(0, 200)); } catch { /* no console */ }
      $('vf-result').innerHTML = '<div class="ps-banner err">' + esc(res.status === 429
          ? (LANG === 'nl' ? 'Even te veel controles tegelijk. Probeer het over een minuut opnieuw.' : 'Too many checks at once. Try again in a minute.')
          : (LANG === 'nl' ? 'De controle kon nu niet worden uitgevoerd door een storing bij ons. Probeer het zo opnieuw.' : 'The check could not run right now because of a fault on our side. Please try again shortly.')) + '</div>';
      return;
    }
    await renderResult(withEmbedded(await res.json()));
  } catch (e) {
    $('vf-result').innerHTML = t('verifyFailed', { err: esc(e.message) });
  } finally { $('vf-verify').disabled = false; }
}

// The relay's reasons for a 422, in the reader's words where we know them.
function relayErrors(list) {
  const out = [];
  for (const raw of Array.isArray(list) ? list : []) {
    const e = String(raw || '');
    if (/document_hash mismatch/i.test(e)) out.push(LANG === 'nl'
      ? 'Dit is niet het ondertekende bestand. Controleer met het originele bestand.'
      : 'This is not the signed file. Check with the original file.');
    else if (/signature/i.test(e)) out.push(LANG === 'nl'
      ? 'Een handtekening in het bewijs klopt niet.' : 'A signature in the proof does not hold.');
    else out.push(e.slice(0, 200));
  }
  if (!out.length) out.push(LANG === 'nl' ? 'Het bewijs klopt niet met dit document.' : 'The proof does not match this document.');
  return out;
}

// SHA3-256 of a File, read in 8 MB slices and hashed 1 MB at a time, with the
// event loop free between pieces: the page keeps answering and shows progress,
// and a file larger than one ArrayBuffer can hold is still hashed. Same digest
// as sha3_256(wholeBytes).
const SLICE = 8 * 1024 * 1024;
const PIECE = 1024 * 1024;
const breathe = () => new Promise((r) => setTimeout(r, 0));
async function hashFileInSlices(file, onProgress) {
  const h = sha3_256.create();
  const total = file.size || 0;
  let lastPct = -1;
  for (let off = 0; off < total; off += SLICE) {
    const buf = new Uint8Array(await file.slice(off, Math.min(total, off + SLICE)).arrayBuffer());
    for (let i = 0; i < buf.length; i += PIECE) {
      h.update(buf.subarray(i, Math.min(buf.length, i + PIECE)));
      if (total > PIECE) {
        const pct = Math.floor(((off + i + PIECE) / total) * 100);
        if (onProgress && pct !== lastPct && pct < 100) { lastPct = pct; onProgress(pct); }
        await breathe();
      }
    }
  }
  return h.digest();
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
    if (!res.ok) return { html: '', revoked: false, failed: true };
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
    return { html, revoked: !!d.revoked_at, found: true };
  } catch { return { html: '', revoked: false, failed: true }; }
}

// The qualified-signature pointer the relay puts inside the notary-signed
// receipt (relay/lib/parasign-open-api.js, psign.qes). It is signed, so it is
// a fact that the relay recorded one; the PAdES signature itself is in the pdf
// and is not checked here.
function qesHtml(env) {
  const q = env && env.qes;
  if (!q || typeof q !== 'object' || !q.provider || !q.certificate_fingerprint) return '';
  return t('qesNote', {
    provider: esc(String(q.provider)),
    fp: esc(String(q.certificate_fingerprint).slice(0, 32)),
    when: q.signed_at ? t('qesWhen', { v: esc(String(q.signed_at)) }) : '',
  });
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
  // The pdf route keeps the typed name in coords.name, the text route in
  // signer_name (sign-flow.js); both are free text outside the signature.
  const claimedName = env.signer_name || (env.coords && typeof env.coords.name === 'string' ? env.coords.name : '');
  if (claimedName) { out.push(t('claimName', { v: esc(claimedName) })); any = true; }
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

// Which file a solo proof is checked with, said in the heading itself
// (acceptatie r4, punt 3). A pdf or image is signed AFTER the seal is stamped
// on it, so the file that turns green is the signed-… copy, not the original
// the signer started from; the leek who picks that original must not be told
// to "check with the original". Hash-only documents are signed as they are.
// stamped_filename is not covered by the signature, so it only picks the
// wording (pdf or image), never a file name the page presents as fact.
function soloPick(env) {
  if (!env || !env.stamped_hash) return 'pickOriginal';
  const name = String(env.stamped_filename || env.original_filename || '');
  return /\.(png|jpe?g|webp|gif)$/i.test(name) || /image/i.test(name) ? 'pickSignedImage' : 'pickSignedPdf';
}

function wireEmbeddedSave(r) {
  const btn = $('vf-embedded-save');
  if (!btn || !r.embedded) return;
  btn.onclick = () => {
    const url = URL.createObjectURL(new Blob([r.embedded.bytes], { type: 'application/pdf' }));
    const a = document.createElement('a');
    a.href = url; a.download = LANG === 'en' ? 'signed-original.pdf' : 'ondertekend-origineel.pdf';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  };
}

async function renderResult(r) {
  const out = [];
  // A v3 solo proof binds a key, not a person: no reassuring green for a name
  // nobody checked, and a warning when the file's signer details were altered
  // (retest T3-2).
  const solo = r.valid && isV3 && !isMulti && envelope;
  const fpBad = solo && claimFingerprintBad(envelope);
  const banner = !r.valid
    ? (r.wrongFile ? t(isV3 && !isMulti ? 'wrongFileSolo' : 'wrongFile', { hash: esc(String(r.docHash || '').slice(0, 16)), pick: t(soloPick(envelope)) })
      : t('invalid'))
    : r.test ? t('validTest') : r.embedded ? t('embeddedValid') : fpBad ? t('fpTampered') : solo ? t('soloChecked') : t('valid');
  out.push(banner);
  if (r.errors && r.errors.length && !r.wrongFile) {
    out.push('<ul style="margin-top:var(--space-3)">');
    r.errors.forEach(e => out.push('<li class="ps-help">' + esc(e) + '</li>'));
    out.push('</ul>');
  }
  if (r.note) out.push('<p class="ps-help">' + esc(r.note) + '</p>');
  if (!r.valid && r.embeddedTooLarge) out.push('<p class="ps-help" id="vf-embedded-too-large">' + esc(t('embeddedTooLarge')) + '</p>');
  if (r.valid && r.embedded) out.push('<p class="ps-help" id="vf-embedded">' + esc(t('embeddedOriginal')) + ' <button type="button" class="btn btn-outline" id="vf-embedded-save">' + esc(t('embeddedSave')) + '</button></p>');
  if (isV3) {
    // The plumbing (request id, offline, the relay's key, the algorithm and
    // the raw time) goes into one fold under the result, so the banner and the
    // names are what a reader sees first (acceptance 3.1.1, 9).
    const tech = [];
    const envId = isMulti ? envelope && envelope.envelope_id : envelope && envelope.multiparty && envelope.multiparty.envelope_id;
    if (envId) tech.push(t('envOffline', { id: esc(String(envId)) }));
    if (r.valid && isMulti && r.anchor) {
      const a = r.anchor;
      const name = esc(LANG === 'en' ? a.name : (a.name_nl || a.name));
      const vars = { name, host: esc(a.host), fp: esc(String(a.fingerprint).slice(0, 16)), when: esc(a.retired_at || '') };
      tech.push(a.retired_at ? t('notaryByRetired', vars) : t('notaryBy', vars));
    }
    if (envelope && envelope.algorithm) tech.push('<p class="ps-help">' + esc(t('infoAlg', { v: envelope.algorithm })) + (isMulti && envelope.completed_at ? ' &middot; ' + esc(String(envelope.completed_at)) : '') + '</p>');
    if (r.valid && !isMulti) out.push(v3ScopeHtml(envelope));
    // The names in a multi-party proof are labels the sender typed: shown,
    // and said for what they are (acceptance r2, 5).
    if (r.valid && isMulti) out.push(partyNamesHtml(envelope));
    if (r.valid && isMulti) out.push(qesHtml(envelope));
    if (tech.length) out.push('<details class="ps-tech"><summary class="ps-help">' + esc(t('techHead')) + '</summary>' + tech.join('') + '</details>');
  } else {
    const idx = envelope && envelope.notary && envelope.notary.ct_log_index;
    if (idx != null) out.push(t('ctIndex', { idx: esc(String(idx)) }));
  }
  $('vf-result').innerHTML = out.join('');
  wireEmbeddedSave(r);
  // v1/v2 were checked by the relay already, so the account lookup rides along.
  if (r.valid && !isMulti && !isV3) {
    const attr = await lookupSignerHtml(envelope);
    if (attr.html || attr.failed) $('vf-result').innerHTML = out.join('') + (attr.html || t('lookupFailed'));
    return;
  }
  // v3 solo is checked offline, and stays offline unless the reader asks: the
  // page used to ask the relay about every key on its own, while promising
  // "no call home" (retest T3-10).
  if (solo) {
    const wrap = document.createElement('p');
    wrap.className = 'ps-help';
    const btn = document.createElement('button');
    btn.type = 'button'; btn.className = 'btn btn-outline'; btn.id = 'vf-lookup';
    btn.textContent = t('lookupBtn');
    const note = document.createElement('span');
    note.className = 'ps-help'; note.style.display = 'block';
    note.textContent = t('lookupNote');
    wrap.append(btn, note);
    $('vf-result').appendChild(wrap);
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      const attr = await lookupSignerHtml(envelope);
      // A failed lookup (429, 500, no network) is said, and the button stays
      // so the reader can ask again (fase 1 VERIFY-06-C: it just vanished).
      if (attr.failed) {
        let fail = $('vf-lookup-failed');
        if (!fail) {
          fail = document.createElement('div');
          fail.id = 'vf-lookup-failed';
          wrap.after(fail);
        }
        fail.innerHTML = t('lookupFailed');
        btn.textContent = t('lookupRetry');
        btn.disabled = false;
        return;
      }
      // A revoked key takes the green away: the proof has no signed time, so
      // "valid if signed before the revocation" cannot be checked. A key the
      // relay links to an account names the signer: then the green is earned.
      if (attr.revoked) out[0] = t('revokedBanner');
      else if (attr.found && !fpBad) out[0] = t('valid');
      $('vf-result').innerHTML = out.join('') + (attr.html || '');
    });
  }
}

function partyNamesHtml(env) {
  const parties = Array.isArray(env && env.parties) ? env.parties : [];
  const named = parties.filter((p) => p && p.label);
  if (!named.length) return '';
  return '<p class="ps-help">' + esc(t('partyNamesHead')) + '</p><ul>' +
    named.map((p) => '<li class="ps-help">' + esc(String(p.label)) + (p.signed_at ? ' (' + esc(String(p.signed_at).slice(0, 10)) + ')' : '') + '</li>').join('') + '</ul>';
}

// The signer fingerprint written in a v3 solo proof, against the key that
// actually signed (the same test v3ScopeHtml shows as claimFpBad).
function claimFingerprintBad(env) {
  const fp = keyFingerprint(env.signer_public_key);
  const claimedFp = String(env.signer_pk_fingerprint || '').toLowerCase();
  return !!(claimedFp && fp && !fp.startsWith(claimedFp.slice(0, 16)));
}

$('vf-document').addEventListener('change', e => onDoc(e.target.files[0]));
$('vf-envelope').addEventListener('change', e => onEnv(e.target.files[0]));
$('vf-verify').addEventListener('click', verify);
