// Fase 2 (2026-10-04): de claims die fase 1 (results-P12, results-P01) onwaar
// vond, en wat de pagina's nu zeggen. Elke test faalt op de basis
// (herstel/ronde3-2026-10-04) en slaagt na de fix.
//
// De grootste: ParaSend naar ontvangers op naam is niet zero-knowledge. De
// browser pakt de bestandssleutel in onder een token per ontvanger
// (frontend/js/send-wrap.js wrapKeyFor: SHA-256 over label en token), en stuurt
// token en ingepakte sleutel samen naar /v2/sends (frontend/js/parashare.page.js,
// `sealed[adres] = { token, wrapped_key }`). De relay mailt /ontvang/<token>
// (relay/relay.js) via Resend, en de ophaalcode gaat ook per mail. Wie token en
// code heeft, opent het bestand. Elke zin die het tegendeel zei, is aangepast.
//
// Alles in functiescope (scripts/check-test-declarations.sh).
//
// Run: node --test tests/site-claims-fase2.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

function lees(rel) {
  return fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', rel), 'utf8');
}
function tekst(rel) {
  return lees(rel).replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ').replace(/&rsquo;/g, '’').replace(/&euml;/g, 'ë').replace(/\s+/g, ' ');
}

test('de code doet wat deze tests aannemen: token en ingepakte sleutel gaan samen naar de relay, de relay mailt het token', () => {
  const page = lees('frontend/js/parashare.page.js');
  assert.match(page, /sealed\[adres(?:\.toLowerCase\(\))?\]\s*=\s*\{\s*token,\s*wrapped_key/, 'parashare.page.js stuurt niet langer token en wrapped_key samen; dan kan de tekst over ontvangers op naam terug naar zero-knowledge');
  assert.match(lees('relay/relay.js'), /'\/ontvang\/' \+ encodeURIComponent\(token\)/, 'de relay mailt het token niet meer in de uitnodiging');
});

test('SITE-30: /terms is niet absoluut en noemt de uitzonderingen (NL en EN)', () => {
  const nl = tekst('frontend/terms.html');
  const en = tekst('frontend/en/terms.html');
  assert.doesNotMatch(nl, /Wij kunnen dus niet zien wat u verstuurt/);
  assert.doesNotMatch(en, /which means we cannot see what you send/);
  assert.match(nl, /Daarop zijn drie uitzonderingen/);
  assert.match(nl, /versturen naar ontvangers op naam/);
  assert.match(nl, /extensies voor Chromium en Outlook/);
  assert.match(en, /There are three exceptions/);
  assert.match(en, /sending to named recipients/);
  assert.match(en, /Chromium and Outlook extensions/);
});

test('SITE-30: security, parasend, privacy, home en dpa noemen ontvangers op naam als uitzondering (NL en EN)', () => {
  const nl = ['security', 'parasend', 'privacy', 'index', 'dpa', 'rules'];
  for (const slug of nl) {
    assert.match(tekst(`frontend/${slug}.html`), /ontvangers op naam|genoemde ontvangers/, `${slug}: noemt de uitzondering niet`);
    assert.match(tekst(`frontend/en/${slug}.html`), /named recipients/, `en/${slug}: noemt de uitzondering niet`);
  }
  assert.match(tekst('frontend/security.html'), /Versturen naar ontvangers op naam \(per e-mailadres\) is niet zero-knowledge/);
  assert.match(tekst('frontend/en/security.html'), /Sending to named recipients \(by email address\) is not zero-knowledge/);
});

test('SITE-34/38: geen pagina zegt meer dat de mail nooit een sleutel bevat, en partners.json ook niet', () => {
  const fe = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
  const fout = [];
  const lopen = (dir) => fs.readdirSync(dir).flatMap((n) => {
    const p = path.join(dir, n);
    return fs.statSync(p).isDirectory() ? lopen(p) : (n.endsWith('.html') ? [p] : []);
  });
  for (const fp of lopen(fe)) {
    const t = fs.readFileSync(fp, 'utf8');
    if (/nooit het document of een sleutel|never the document or a key|Op de route van uw bestanden en sleutels zit geen Amerikaanse partij|No US provider touches a file or a key|Geen Amerikaanse partij komt aan een bestand of een sleutel/.test(t)) {
      fout.push(path.relative(fe, fp));
    }
  }
  assert.deepEqual(fout, [], 'pagina\'s die nog beloven dat de mail geen sleutel draagt');
  for (const f of ['frontend/partners.json', 'deploy/partners.json']) {
    const resend = JSON.parse(lees(f)).partijen.find((p) => p.id === 'resend');
    assert.doesNotMatch(resend.nooit.nl, /sleutel/, `${f}: resend.nooit belooft weer geen sleutel`);
    assert.doesNotMatch(resend.nooit.en, /key/, `${f}: resend.nooit promises no key again`);
    assert.match(resend.gegevens.nl, /ophaalcode/);
    assert.match(resend.gegevens.en, /pickup code/);
  }
});

test('SITE-31: ParaSend draait niet op "dezelfde post-quantumkern"; de pagina noemt per route het algoritme', () => {
  assert.doesNotMatch(tekst('frontend/parasend.html'), /dezelfde post-quantumkern als ParaSign/);
  assert.doesNotMatch(tekst('frontend/en/parasend.html'), /same post-quantum encryption as ParaSign/);
  assert.match(tekst('frontend/parasend.html'), /AES-256-GCM bij een eenmalige link of een verzending op naam/);
  assert.match(tekst('frontend/en/parasend.html'), /AES-256-GCM for a one-time link or a send to named recipients/);
  assert.doesNotMatch(tekst('frontend/press.html'), /na inloggen met een hybride van ML-KEM-768/);
  assert.doesNotMatch(tekst('frontend/en/press.html'), /on the authenticated paths with an ML-KEM-768/);
});

test('SITE-32: security zegt niet meer dat alle algoritmen uit FIPS 203-206 komen', () => {
  assert.doesNotMatch(tekst('frontend/security.html'), /Alle algoritmen komen uit de post-quantumstandaarden/);
  assert.doesNotMatch(tekst('frontend/en/security.html'), /All algorithms are from NIST post-quantum standards/);
  assert.match(tekst('frontend/security.html'), /ECDH P-256 naast ML-KEM \(hybride\)/);
  assert.match(lees('relay/relay.js'), /ED25519_PUBLIC_KEY/, 'de relay gebruikt geen Ed25519 meer; haal het uit de zin op /security');
});

test('SITE-36/37: de SLA belooft geen meting die niet draait en noemt de repo niet open-source', () => {
  for (const f of ['frontend/sla.html', 'frontend/en/sla.html']) {
    const t = tekst(f);
    assert.doesNotMatch(t, /wordt per kalendermaand gemeten|Uptime is measured per calendar month/, f);
    assert.doesNotMatch(t, /open-source repository/, f);
    assert.match(t, /source-available repository \(BUSL 1\.1\)/, f);
  }
});

test('SITE-45: de verwerkersovereenkomst kiest Nederlands recht (NL en EN)', () => {
  assert.doesNotMatch(lees('frontend/dpa.html'), /Bondsrepubliek Duitsland|Duitse rechter/);
  assert.doesNotMatch(lees('frontend/en/dpa.html'), /Federal Republic of Germany|courts of Germany|under German law/);
  assert.match(tekst('frontend/dpa.html'), /Op deze overeenkomst is Nederlands recht van toepassing/);
  assert.match(tekst('frontend/en/dpa.html'), /governed by the law of the Netherlands/);
});

test('SITE-11: het dpa-scherm belooft geen medeondertekend exemplaar en stuurt de versie van de pagina', () => {
  assert.doesNotMatch(tekst('frontend/dpa.html'), /medeondertekend exemplaar/);
  assert.doesNotMatch(tekst('frontend/en/dpa.html'), /countersigned copy/);
  for (const [html, js] of [['frontend/dpa.html', 'frontend/js/dpa.inline1.js'], ['frontend/en/dpa.html', 'frontend/js/dpa.inline1.en.js']]) {
    assert.match(lees(html), /data-dpa-versie="\d{4}-\d{2}-\d{2}"/, html);
    assert.doesNotMatch(lees(js), /version: '2025-01-01'/, js);
    assert.match(lees(js), /dpaVersie/, js);
  }
});

test('SITE-48: AppArmor met de echte telling, en geen NIS2-documentatie die niet bestaat', () => {
  assert.match(lees('SECURITY.md'), /119\/121 profiles enforcing/);
  // /dpa noemt geen telling meer: uitrolstap 6l toetst AppArmor aan, niet 119 van 121
  // (telling SITE-48-A). De telling blijft als historie in SECURITY.md.
  assert.doesNotMatch(tekst('frontend/dpa.html'), /119 van de 121 profielen/);
  assert.doesNotMatch(tekst('frontend/en/dpa.html'), /119 of 121 profiles/);
  // Uitrolstap 6l waarschuwt bij een miss (stopt alleen met --host-strict), dus
  // /dpa belooft de controle bij elke uitrol, nooit de uitkomst als vast feit.
  assert.match(tekst('frontend/dpa.html'), /We controleren bij elke uitrol[^.]*of AppArmor aan staat met profielen in enforcing-modus/);
  assert.match(tekst('frontend/dpa.html'), /deze pagina noemt de controle, niet de uitkomst/);
  assert.doesNotMatch(tekst('frontend/dpa.html'), /AppArmor staat aan met profielen/);
  assert.match(tekst('frontend/en/dpa.html'), /We check at every deploy[^.]*whether AppArmor is enabled with profiles in enforce mode/);
  assert.match(tekst('frontend/en/dpa.html'), /this page states the check, not its outcome/);
  assert.doesNotMatch(tekst('frontend/en/dpa.html'), /(^|[.:] )AppArmor is enabled with profiles/);
  assert.doesNotMatch(tekst('frontend/dpa.html'), /NIS2[- ]documentatie/);
  assert.doesNotMatch(tekst('frontend/en/pricing.html'), /IEC 62443 \/ NIS2 \/ NEN 7510 documentation|NEN 7510 \/ NIS2 compliance documentation/);
  assert.match(lees('docs/ot-guide.md'), /IEC 62443 compliance mapping/);
  assert.match(lees('docs/dicom-guide.md'), /NEN 7510/);
});

test('SITE-47 en SIGN-06/07: /parasign belooft geen niet-pdf-ondertekening en noemt de relaycontrole van oude bewijzen', () => {
  const nl = tekst('frontend/parasign.html');
  const en = tekst('frontend/en/parasign.html');
  assert.doesNotMatch(nl, /andere bestanden worden via hun vingerafdruk ondertekend|Elk soort bestand/);
  assert.doesNotMatch(en, /other file types are attested by fingerprint|Any file type/);
  assert.match(nl, /ParaSign ondertekent alleen pdf; zet een ander bestand eerst om naar pdf/);
  assert.match(en, /ParaSign signs PDF only; convert any other file to PDF first/);
  assert.match(nl, /ouder bewijs \(formaat v1 of v2\)/);
  assert.match(en, /older proof \(format v1 or v2\)/);
  assert.doesNotMatch(nl, /geen API-sleutel, en de controle zelf maakt geen verbinding met ons/);
});

// SITE-05-A-en pinde de Engelse hero op "Send securely". Sinds 5 oktober 2026
// (Mick: de bezoeker landt meteen in het dashboard) is er geen hero meer; de
// kop van het voorbeelddashboard draagt Create account en Try it yourself. Wat
// van SITE-05-A blijft: versturen is er vanaf het eerste scherm, via de tegel.
test('SITE-09 en SITE-05-A-en: geen + als spatie in mailto, en het Engelse eerste scherm is het voorbeelddashboard', () => {
  assert.doesNotMatch(lees('frontend/en/pricing.html'), /mailto:[^"]*subject=[^"]*\+/);
  const en = lees('frontend/en/index.html');
  assert.match(en, /<a class="hp-btn hp-btn-fill" href="\/en\/signup">Create account<\/a>/);
  assert.match(en, /<a class="hp-btn hp-btn-line" href="\/en\/sign\?mode=invite">Try it yourself<\/a>/);
  assert.match(en, /<a class="wp-tile dh-workspace" href="\/en\/parashare" data-wp-open="send"/);
});

test('SITE-40 en SITE-35: TOTP-tolerantie en de edge-log staan eerlijk op /security', () => {
  assert.match(lees('relay/lib/totp.js'), /window = 1/);
  assert.doesNotMatch(tekst('frontend/security.html'), /Een TOTP-code verloopt dertig seconden nadat hij is gemaakt/);
  assert.match(tekst('frontend/security.html'), /De edge \(Caddy\) die voor nginx staat, schrijft wel een toegangslog/);
  assert.match(tekst('frontend/en/security.html'), /The edge \(Caddy\) in front of nginx does write an access log/);
});
