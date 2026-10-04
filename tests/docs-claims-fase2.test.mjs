// Fase 2 (2026-10-04): wat docs, crypto-agility, changelog, /all-systems-go en
// /vs beloofden en wat de code doet. Elke test hieronder was rood op de basis
// (herstel/ronde3-2026-10-04) en hoort groen te blijven zolang de tekst klopt.
//
// Bronnen: sweep-api (docs-beloftes over /v1, webhooks, OT-guide), fase 1 P12
// (SITE-13, -21, -25, -26, -31, -39). Register: docs/site-claims.md rij 51.
//
// Alles in functiescope: tests/*.mjs is één gedeelde naamruimte
// (scripts/check-test-declarations.sh).
//
// Run: node --test tests/docs-claims-fase2.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

function repo(rel) {
  return fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', rel), 'utf8');
}

test('docs: /v1 bewaart de pdf zolang de envelope bestaat, en de docs zeggen dat', () => {
  const api = repo('relay/lib/parasign-open-api.js');
  assert.match(api, /store\.putBlob\(out\.id, pdf, ttlMs\)/, 'als /v1 de pdf niet meer bewaart, mag de tekst terug');
  for (const [rel, never, says] of [
    ['frontend/docs.html', /nooit het document zelf/, /bewaart de relay ook de pdf zelf/],
    ['frontend/en/docs.html', /never the document bytes/, /the relay also keeps the PDF itself/],
  ]) {
    const html = repo(rel);
    assert.doesNotMatch(html, never, `${rel}: belooft nog dat /v1 het document nooit bewaart`);
    assert.match(html, says, `${rel}: moet zeggen dat de pdf bewaard wordt`);
    assert.match(html, /365/, `${rel}: moet de maximale bewaartermijn noemen`);
  }
});

test('docs: /v2/webhook beschrijft de body, het event en de handtekening die relay.js gebruikt', () => {
  const relay = repo('relay/relay.js');
  assert.match(relay, /device_id and url required/);
  assert.match(relay, /pushWebhooks\(apiKey, deviceId, 'blob_ready'/);
  assert.match(relay, /hook\.secret\s*\n?\s*\? crypto\.createHmac\('sha256', String\(hook\.secret\)\)/);
  for (const rel of ['frontend/docs.html', 'frontend/en/docs.html']) {
    const html = repo(rel);
    assert.doesNotMatch(html, /callback_url/, `${rel}: de relay kent geen callback_url`);
    assert.doesNotMatch(html, /blob_retrieved/, `${rel}: het event blob_retrieved bestaat niet`);
    assert.doesNotMatch(html, /API key as the secret|API-sleutel als geheim/, `${rel}: de relay tekent met het secret, niet met de API-sleutel`);
    assert.match(html, /"device_id": "scanner-01", "url":/, `${rel}: registratie moet device_id en url tonen`);
    assert.match(html, /"event": "blob_ready"/, `${rel}: het event heet blob_ready`);
  }
});

test('docs: sleutel alleen in de header, ct/log leest from en publiceert geen device_hash, de relay vult niet op', () => {
  const relay = repo('relay/relay.js');
  assert.match(relay, /API key must be sent in the X-Api-Key header, not as a query parameter/);
  assert.match(relay, /const from\s*=\s*parseInt\(query\.from/);
  for (const rel of ['frontend/docs.html', 'frontend/en/docs.html']) {
    const html = repo(rel);
    assert.doesNotMatch(html, /check-key\?k=/, `${rel}: ?k= wordt geweigerd`);
    assert.doesNotMatch(html, /ct\/log\?[^"<]*offset=/, `${rel}: ct/log leest from, niet offset`);
    assert.doesNotMatch(html, /"device_hash"/, `${rel}: ct/log publiceert geen device_hash meer`);
    assert.doesNotMatch(html, /always 5MB padded/, `${rel}: de relay geeft de opgeslagen bytes terug`);
    assert.doesNotMatch(html, /scripts\/paramant-admin\.py/, `${rel}: het script staat in deploy/`);
    assert.doesNotMatch(html, /revoke --label/, `${rel}: revoke vraagt --key`);
  }
  assert.ok(fs.existsSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'deploy', 'paramant-admin.py')));
});

test('docs: paramant-sign sign heet niet meer werkend, want /v2/sign is 410', () => {
  assert.match(repo('relay/relay.js'), /POST \/v2\/sign \(legacy R017 notary\) is retired/);
  for (const rel of ['frontend/docs.html', 'frontend/en/docs.html']) {
    const html = repo(rel);
    assert.doesNotMatch(html, /Onderteken een document \(ML-DSA-65, aan de clientkant\)|It signs a document \(ML-DSA-65, client-side\)/, `${rel}: belooft nog een werkende sign-CLI`);
    assert.match(html, /\(410\)/, `${rel}: moet zeggen dat sign uit staat`);
  }
});

test('docs: de webapp-opvulling geldt alleen voor de live overdracht en de SDK', () => {
  for (const [rel, old] of [
    ['frontend/docs.html', /Geauthenticeerde blobs uit de webapp van Versturen worden vóór het uploaden opgevuld/],
    ['frontend/en/docs.html', /Authenticated blobs from the ParaSend web app are padded to exactly/],
  ]) {
    const html = repo(rel);
    assert.doesNotMatch(html, old, `${rel}: de linkroute en de route op naam vullen niet op`);
    assert.doesNotMatch(html, /blob uit de webapp binnenkwam \(allemaal vast 5 MB|web app blob arrived \(all fixed 5 MB/, `${rel}: niet alle webapp-blobs zijn 5 MB`);
  }
});

test('docs: de kern-callout noemt de route op naam en /v1 als uitzondering, en de Resend-mail draagt de sleutel', () => {
  for (const [rel, old, mail] of [
    ['frontend/docs.html', /de relay bewaart versleutelde blobs die hij niet kan ontsleutelen en Merkle-hashes die hij niet kan vervalsen\. Een bevel/, /Bestanden, documenten en sleutels gaan niet buiten de EU/],
    ['frontend/en/docs.html', /The relay stores encrypted blobs it cannot decrypt and Merkle hashes it cannot forge\. A warrant/, /Files, documents and keys do not leave the EU/],
  ]) {
    const html = repo(rel);
    assert.doesNotMatch(html, old, `${rel}: absolute zero-knowledge-zin zonder uitzondering`);
    assert.doesNotMatch(html, mail, `${rel}: bij een verzending op naam reist de sleutel via Resend`);
    assert.match(html, /niet zero-knowledge|not zero-knowledge/, `${rel}: moet de route op naam als uitzondering noemen`);
  }
});

test('docs: de SCS-audit staat niet als "alles opgelost" zolang SECURITY.md open bevindingen noemt', () => {
  const sec = repo('SECURITY.md');
  const open = /## Open findings[\s\S]*?\| 4 \| Critical/.test(sec);
  for (const rel of ['frontend/docs.html', 'frontend/en/docs.html']) {
    const row = repo(rel).split('\n').find((l) => l.includes('Smart Cyber Solutions'));
    assert.ok(row, `${rel}: de SCS-rij ontbreekt`);
    if (open) assert.doesNotMatch(row, /Alles opgelost|All resolved/, `${rel}: SECURITY.md noemt #4 en #14 nog open`);
  }
});

test('ot-guide: zegt niet dat de relay niet kan ontsleutelen zolang paramant-sender de sleutel uit de API-sleutel afleidt', () => {
  const sender = repo('scripts/paramant-sender.py');
  const derives = /derive\(key\.encode\(\)\)/.test(sender);
  const guide = repo('docs/ot-guide.md');
  if (derives) {
    assert.doesNotMatch(guide, /Relay cannot decrypt/, 'ot-guide: de relay ziet de API-sleutel en kan dus ontsleutelen');
    assert.match(guide, /can decrypt what these scripts send/, 'ot-guide: de waarschuwing moet er staan');
    assert.doesNotMatch(guide, /\| SR 4\.1[^\n]*\| ML-KEM-768 \+ ECDH P-256 client-side encryption\. Relay never holds plaintext\. \|/);
  }
});

test('open-API-spec: signer.completed en envelope.completed worden gevuurd, en staan niet als "NOT yet"', () => {
  assert.match(repo('relay/relay.js'), /emitEvent\(_pdeps, id, 'signer\.completed'/);
  const spec = repo('docs/parasign-open-api-spec.md');
  assert.doesNotMatch(spec, /NOT yet auto-fired/);
  assert.match(spec, /no retry/);
});

test('crypto-agility: alleen de core-set heet geladen, en het curl-voorbeeld is wat core antwoordt', () => {
  assert.match(repo('relay/crypto/bootstrap.js'), /'core'\s+\(default\)/);
  for (const [rel, loaded] of [
    ['frontend/crypto-agility.html', /class="safe">geladen/g],
    ['frontend/en/crypto-agility.html', /class="safe">loaded/g],
  ]) {
    const html = repo(rel);
    assert.equal((html.match(loaded) || []).length, 2, `${rel}: alleen ML-KEM-768 en ML-DSA-65 zijn geladen in core`);
    assert.doesNotMatch(html, /"name": "ML-KEM-512",\s+"loaded": true/, `${rel}: core geeft ML-KEM-512 niet terug`);
    assert.doesNotMatch(html, /"name": "Falcon-512",\s+"loaded": true/, `${rel}: core geeft Falcon niet terug`);
  }
  assert.doesNotMatch(repo('frontend/en/crypto-agility.html'), /203, 204, 205 and 206 loaded in production/);
});

test('changelog: de nieuwste release is die van CHANGELOG.md, en Gepland noemt niets wat al live is', () => {
  const cl = repo('CHANGELOG.md');
  const newest = /^## \[(\d+\.\d+\.\d+)\]/m.exec(cl)[1];
  for (const [rel, done] of [
    ['frontend/changelog.html', /<li>(WebAuthn \/ passkey als tweede factor|Openbare statuspagina)<\/li>/],
    ['frontend/en/changelog.html', /<li>(WebAuthn \/ Passkey second-factor option|Public status page)<\/li>/],
  ]) {
    const html = repo(rel);
    const first = /<h2>v(\d+\.\d+\.\d+[^<]*)<\/h2>/.exec(html)[1];
    assert.equal(first, newest, `${rel}: nieuwste release op de pagina is v${first}, CHANGELOG.md zegt ${newest}`);
    assert.doesNotMatch(html, done, `${rel}: passkeys en de statuspagina zijn al live`);
  }
});

test('all-systems-go: een 401 op /v2/health/deep is geen mislukte controle en nooit groen', async () => {
  for (const [rel, up] of [['frontend/js/all-systems-go.inline1.js', 'De relay antwoordt'], ['frontend/js/all-systems-go.inline1.en.js', 'The relay is answering']]) {
    const els = {};
    const el = (id) => (els[id] ||= { id, className: '', innerHTML: '', textContent: '' });
    const calls = [];
    const fetch = async (url) => {
      calls.push(url);
      if (url === '/v2/health/deep') return { status: 401, ok: false, json: async () => ({ error: 'unauthorized' }) };
      return { status: 200, ok: true, json: async () => ({ ok: true, version: '3.1.0', sector: 'health' }) };
    };
    const ctx = { document: { getElementById: el }, fetch, setInterval: () => 0, Date };
    vm.runInNewContext(repo(rel), ctx);
    for (let i = 0; i < 20 && !els['overall-title']?.textContent; i++) await new Promise((r) => setTimeout(r, 5));
    assert.deepEqual(calls, ['/v2/health/deep', '/health'], `${rel}: moet na 401 /health vragen`);
    assert.equal(els['overall-title'].textContent, up, `${rel}: titel`);
    assert.doesNotMatch(els['overall-dot'].className, /red|green/, `${rel}: neutraal, niet rood en niet groen`);
  }
});

test('vs: de PQ-rij noemt welke routes ML-KEM gebruiken, en geen absolute zero-knowledge', () => {
  for (const rel of ['frontend/vs.html', 'frontend/en/vs.html']) {
    const html = repo(rel);
    assert.doesNotMatch(html, /<td class="yes">ML-KEM-768 \(NIST L3\)<\/td>/, `${rel}: de linkroute gebruikt geen ML-KEM`);
    assert.doesNotMatch(html, /zero-knowledge-architectuur \(wiskundig, niet via beleid\)|zero-knowledge architecture \(mathematically, not by policy\)/, `${rel}: de route op naam is niet zero-knowledge`);
    assert.doesNotMatch(html, /(Bronnen|Sources): (persbericht|Kiteworks)/, `${rel}: ongelinkte bronnen moeten als zodanig benoemd zijn`);
  }
});
