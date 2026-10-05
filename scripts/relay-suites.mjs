// Welke relay-suites een echte relay opstarten, beantwoord door de imports en
// niet door een lijst in een workflow.
//
// test.yml heeft twee banen voor relay/test. De ene bouwt @paramant/core,
// installeert de relay-afhankelijkheden en heeft een redis; de andere doet dat
// alles niet en draait de pure-JS suites. Een suite die relay.js opstart kan
// alleen in de eerste, want relay.js laadt argon2, redis en de engine bij het
// laden.
//
// Tot 22-09-2026 stond die verdeling als een grep-lijst met namen in de
// workflow. Dat werkt zolang iemand hem bijwerkt. Deze tak voegde negentien
// suites toe die een relay opstarten, en geen ervan stond in die lijst: de
// baan zonder afhankelijkheden probeerde ze te draaien, de relay kwam nooit
// omhoog, en de stap bleef hangen tot hij werd afgekapt. Op main duurt diezelfde
// stap 43 seconden.
//
// Dezelfde fout is deze week drie keer gemaakt aan de andere kant van de repo
// (zie scripts/browser-suites.mjs en tests/_relay-stack.mjs), en het antwoord is
// hetzelfde: de vraag stellen aan wat de suite DOET in plaats van aan een lijst
// die iemand moet onderhouden.
//
//   node scripts/relay-suites.mjs --met-relay      start een relay.js
//   node scripts/relay-suites.mjs --zonder-relay   de rest
//
// Paden staan een per regel, gesorteerd, relatief aan relay/, zodat de uitvoer
// direct in `node --test $(...)` past vanuit die map.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TESTDIR = path.join(ROOT, 'relay', 'test');

// require('...') en import '...', wat elke vorm is die in deze map voorkomt.
const SPECIFIERS = /(?:\brequire\s*\(\s*|\bfrom\s*|\bimport\s*\(?\s*)['"]([^'"\n]+)['"]/g;

function specifiers(file) {
  try { return [...fs.readFileSync(file, 'utf8').matchAll(SPECIFIERS)].map((m) => m[1]); }
  catch { return []; }
}

function resolveLocal(from, spec) {
  const basis = path.resolve(path.dirname(from), spec);
  for (const kandidaat of [basis, basis + '.js', basis + '.mjs', path.join(basis, 'index.js')]) {
    try { if (fs.statSync(kandidaat).isFile()) return kandidaat; } catch { /* volgende */ }
  }
  return null;
}

// Loopt de relatieve imports af, zo diep als ze gaan, en vraagt van elk bereikt
// bestand of het een relay opstart. Zo verhuist een suite mee zodra een helper
// dat gaat doen, zonder dat iemand een lijst bijwerkt.
//
// NIET op de naam van de bootstrap. Er zijn er twee, _boot-relay.js en
// _relay-server.js, en de tweede zet het pad in een constante:
//
//     const child = spawn(process.execPath, [RELAY_JS], {
//
// Een regex op de letterlijke string 'relay.js' zag die niet, en dan vallen de
// twintig route-suites buiten de indeling terwijl ze wel een relay starten. De
// vraag is dus of een bestand relay.js noemt EN een proces start. Een
// vals-positief kost niets: die suite komt in de baan met alles erin, en daar
// draait hij.
const NOEMT_RELAY = /relay\.js/;
const START_PROCES = /\b(?:spawn|fork|execFile)\w*\s*\(/;

function startEenRelay(entry) {
  const gezien = new Set();
  const wachtrij = [path.resolve(entry)];
  while (wachtrij.length) {
    const bestand = wachtrij.pop();
    if (gezien.has(bestand)) continue;
    gezien.add(bestand);
    let bron = '';
    try { bron = fs.readFileSync(bestand, 'utf8'); } catch { continue; }
    if (NOEMT_RELAY.test(bron) && START_PROCES.test(bron)) return true;
    for (const spec of specifiers(bestand)) {
      if (!spec.startsWith('.')) continue;
      const lokaal = resolveLocal(bestand, spec);
      if (lokaal) wachtrij.push(lokaal);
    }
  }
  return false;
}

const suites = fs.readdirSync(TESTDIR)
  .filter((naam) => naam.endsWith('.test.js'))
  .sort();

const modi = {
  '--met-relay': (b) => b,
  '--zonder-relay': (b) => !b,
};
const modus = Object.keys(modi).find((vlag) => process.argv.includes(vlag));
if (!modus) {
  process.stderr.write('gebruik: node scripts/relay-suites.mjs ' + Object.keys(modi).join(' | ') + '\n');
  process.exit(2);
}

for (const suite of suites) {
  if (modi[modus](startEenRelay(path.join(TESTDIR, suite)))) console.log('test/' + suite);
}
