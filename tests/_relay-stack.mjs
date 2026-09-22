// DE ENIGE MANIER WAAROP EEN BROWSERSUITE EEN RELAY START.
//
// Niet omdat het mooier is, maar omdat de CI-verdeling ervan afhangt. De repo
// splitst tests/*.test.mjs over twee banen: een die een backend bouwt (redis,
// @paramant/core, de native modules van de relay) en een die er een stubt.
// scripts/browser-suites.mjs beslist die verdeling door de imports van een
// suite af te lopen en te vragen of iets daarin een relay start.
//
// Die vraag is drie keer verkeerd beantwoord, en elke keer kostte het een dag:
//
//   04-09  playwright zat in een helper, niet in de test -> de suite kwam in de
//          baan zonder chromium en hing daar drie uur.
//   05-09  koper-hele-weg startte relays -> de gestubde baan kon hem niet
//          draaien: negen keer "Cannot find module admin/node_modules/redis".
//   22-09  ontvang-browser startte een relay in zijn EIGEN body, en de walk
//          sloeg het testbestand zelf over -> "Cannot find module 'argon2'".
//
// Drie keer dezelfde fout betekent niet dat er een geval bij moet, maar dat de
// detectie niet deugt. Dus: een suite die een relay nodig heeft importeert dit
// bestand, dit bestand noemt relay.js, en daarmee is het antwoord op de
// verdelingsvraag hetzelfde feit als het starten zelf. Ze kunnen niet meer uit
// elkaar lopen, want het is een import en geen lijst.
//
// tests/ci-verdeling.test.mjs bewaakt dat er geen tweede manier ontstaat.

import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HIER = path.dirname(fileURLToPath(import.meta.url));
export const RELAYDIR = path.join(HIER, '..', 'relay');

// Wat relay.js aan het laden nodig heeft. Ontbreekt er een, dan is het zinloos
// om te starten: dan is dit de verkeerde baan, en dat is de melding die de
// lezer verder helpt. Zonder deze controle is het symptoom een MODULE_NOT_FOUND
// of een ECONNREFUSED dertig regels verderop, en dat wijst naar de test.
const NODIG = ['argon2', 'redis'];

export function stackAanwezig() {
  const mist = NODIG.filter((naam) => {
    try { return !fs.existsSync(path.join(RELAYDIR, 'node_modules', naam)); } catch { return true; }
  });
  return { ok: mist.length === 0, mist };
}

export function vrijePoort() {
  return new Promise((res) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); });
  });
}

// Start een relay en kom pas terug als hij antwoordt op /health. Faalt dat, dan
// staat hier WAAROM: de laatste uitvoer van het proces en zijn exitcode, in
// plaats van een geweigerde verbinding bij de eerste echte stap.
export async function startRelay(opts = {}) {
  const gebrek = stackAanwezig();
  if (!gebrek.ok) {
    throw new Error(
      'deze suite start een relay maar de backend ontbreekt (' + gebrek.mist.join(', ') + ').\n'
      + 'Dat betekent dat hij in de gestubde CI-baan is beland. Een suite die dit\n'
      + 'bestand importeert hoort in `browser-suites.mjs --stack`; controleer of\n'
      + 'de import er nog staat, en draai `npm ci` in relay/ als dit lokaal is.');
  }

  const poort = opts.poort || await vrijePoort();
  const usersFile = opts.usersFile
    || path.join(RELAYDIR, '.stack-users-' + process.pid + '-' + poort + '.json');
  if (!fs.existsSync(usersFile)) fs.writeFileSync(usersFile, '{}');

  const regels = [];
  const kind = spawn(process.execPath, ['relay.js'], {
    cwd: RELAYDIR,
    // Dezelfde omgeving die relay/test/_boot-relay.js meegeeft, inclusief het
    // leegzetten van RELAY_REDIS_URL en NATS_URL: zonder dat wacht de relay op
    // een Redis die er in deze baan niet hoeft te zijn.
    env: {
      ...process.env,
      PORT: String(poort),
      RELAY_MODE: 'full',
      LOG_LEVEL: 'info',
      RELAY_REDIS_URL: '',
      NATS_URL: '',
      USERS_FILE: usersFile,
      MAIL_PROVIDER: 'dryrun',
      ADMIN_TOKEN: 'x'.repeat(40),
      PARAMANT_TOTP_MASTER_KEY: crypto.randomBytes(32).toString('base64'),
      ...(opts.env || {}),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let rest = '';
  let staart = '';
  const opLijn = (d) => {
    const tekst = d.toString();
    staart = (staart + tekst).slice(-4000);
    rest += tekst;
    const stukken = rest.split('\n');
    rest = stukken.pop();
    for (const r of stukken) { regels.push(r); if (opts.onLine) opts.onLine(r); }
  };
  kind.stdout.on('data', opLijn);
  kind.stderr.on('data', opLijn);

  const basis = 'http://127.0.0.1:' + poort;
  let gezond = false;
  for (let i = 0; i < 150; i++) {
    try { const r = await fetch(basis + '/health'); if (r.ok) { gezond = true; break; } } catch { /* nog niet */ }
    if (kind.exitCode !== null) break;
    await new Promise((r) => setTimeout(r, 200));
  }

  const stop = () => {
    try { kind.kill('SIGKILL'); } catch { /* al weg */ }
    try { fs.unlinkSync(usersFile); } catch { /* al weg */ }
  };

  if (!gezond) {
    stop();
    throw new Error('de relay kwam niet omhoog (exit ' + kind.exitCode + ').\n'
      + 'Laatste uitvoer:\n' + staart);
  }

  return { proces: kind, poort, basis, usersFile, regels, stop };
}
