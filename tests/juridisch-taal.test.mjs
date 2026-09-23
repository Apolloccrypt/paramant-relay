// Welke taal geldt bij verschil tussen de Nederlandse en de Engelse juridische
// tekst. Besluit van Mick, 2026-09-23: de Nederlandse, behalve bij de licentie,
// want de Business Source License 1.1 is een Engelse standaardtekst en een
// vertaling mag het origineel niet overrulen.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, 'frontend', rel), 'utf8');

test('elke juridische pagina zegt welke taal geldt, in beide talen', () => {
  for (const p of ['privacy', 'terms', 'dpa', 'sla']) {
    assert.match(read(`${p}.html`), /geldt de Nederlandse versie\./, `${p}: NL-zin`);
    assert.match(read(`en/${p}.html`), /the Dutch version prevails\./, `en/${p}: EN-zin`);
  }
  assert.match(read('license.html'), /geldt de Engelse versie, de originele tekst van de Business Source License 1\.1/);
  assert.match(read('en/license.html'), /the English version prevails, the original text of the Business Source License 1\.1/);
});

test('er staat nergens meer een open plek voor dit besluit', () => {
  for (const p of ['privacy', 'terms', 'dpa', 'sla', 'license']) {
    for (const f of [`${p}.html`, `en/${p}.html`]) {
      assert.doesNotMatch(read(f), /BESLUIT MICK|<mark>\[\.\.\.\]<\/mark>/, `${f} heeft nog een open plek`);
    }
  }
});
