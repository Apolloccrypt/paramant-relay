// De poort op scripts/check-landen.mjs.
//
// Hij toetst niet de echte repo, want die verandert elke dag en dan toetst hij
// het weer. Hij bouwt wegwerp-repootjes waarin precies een ding waar is, en
// controleert dat de poort daar het goede van zegt. De vier gevallen die ertoe
// doen:
//
//   1. squash-merge  de tak is inhoudelijk in main, maar git ziet hem als
//                    ongemerged. Dit is het geval waar `git branch --merged` de
//                    verkeerde uitkomst geeft en deze poort dus goed moet zijn.
//   2. blijft liggen een oude tak die nergens in main zit. Moet ROOD worden.
//   3. uitstel        diezelfde tak met een datum in de toekomst in
//                    deploy/landen-uitstel.json. Groen, want bevroren.
//   4. verlopen       diezelfde tak met een datum in het verleden. Weer rood,
//                    want uitstel zonder afloop is afstel.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const POORT = join(ROOT, 'scripts', 'check-landen.mjs');

const DAG = 86400000;
const NU = Date.now();

function git(cwd, ...a) {
  return execFileSync('git', a, {
    cwd, encoding: 'utf8',
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'toets', GIT_AUTHOR_EMAIL: 'toets@example.com',
      GIT_COMMITTER_NAME: 'toets', GIT_COMMITTER_EMAIL: 'toets@example.com',
    },
  }).trim();
}

function commit(cwd, bestand, inhoud, bericht, dagenGeleden) {
  writeFileSync(join(cwd, bestand), inhoud);
  git(cwd, 'add', '-A');
  const t = new Date(NU - dagenGeleden * DAG).toISOString();
  const env = { GIT_AUTHOR_DATE: t, GIT_COMMITTER_DATE: t };
  execFileSync('git', ['commit', '-q', '-m', bericht], {
    cwd, encoding: 'utf8',
    env: {
      ...process.env, ...env,
      GIT_AUTHOR_NAME: 'toets', GIT_AUTHOR_EMAIL: 'toets@example.com',
      GIT_COMMITTER_NAME: 'toets', GIT_COMMITTER_EMAIL: 'toets@example.com',
    },
  });
  return git(cwd, 'rev-parse', 'HEAD');
}

// Een repo met main plus twee takken onder refs/remotes/origin/:
//   origin/squash-tak  een tak van drie commits die als een squash op main staat
//   origin/blijft-liggen  een oude tak die nergens in main terugkomt
function bouwRepo() {
  const dir = mkdtempSync(join(tmpdir(), 'landen-toets-'));
  git(dir, 'init', '-q', '-b', 'main');
  git(dir, 'config', 'commit.gpgsign', 'false');
  commit(dir, 'basis.txt', 'een\n', 'basis', 40);
  const basis = git(dir, 'rev-parse', 'HEAD');

  // tak van drie commits, straks als een squash op main
  git(dir, 'checkout', '-q', '-b', 'werk');
  commit(dir, 'poorten.js', 'poort = 3005\n', 'stap 1', 39);
  commit(dir, 'poorten.js', 'poort = 3005\nextra = 1\n', 'stap 2', 38);
  commit(dir, 'poorten.js', 'poort = 3000\nextra = 1\n', 'stap 3', 37);
  const takTip = git(dir, 'rev-parse', 'HEAD');

  // main krijgt dezelfde eindtoestand in een commit: dat is wat squash doet
  git(dir, 'checkout', '-q', 'main');
  commit(dir, 'poorten.js', 'poort = 3000\nextra = 1\n', 'squash van werk (#1)', 36);
  // main loopt daarna gewoon door
  commit(dir, 'later.txt', 'later\n', 'main loopt door', 5);

  // een tak die nergens in main zit, oud
  git(dir, 'checkout', '-q', '-b', 'los', basis);
  const losTip = commit(dir, 'vergeten.txt', 'nooit geland\n', 'vergeten reparatie', 90);

  git(dir, 'checkout', '-q', 'main');
  git(dir, 'update-ref', 'refs/remotes/origin/main', git(dir, 'rev-parse', 'main'));
  git(dir, 'update-ref', 'refs/remotes/origin/squash-tak', takTip);
  git(dir, 'update-ref', 'refs/remotes/origin/blijft-liggen', losTip);
  git(dir, 'branch', '-q', '-D', 'werk');
  git(dir, 'branch', '-q', '-D', 'los');
  mkdirSync(join(dir, 'deploy'), { recursive: true });
  return dir;
}

function draai(dir) {
  const env = { ...process.env, LANDEN_ROOT: dir, LANDEN_GEEN_GITHUB: '1' };
  try {
    const uit = execFileSync('node', [POORT, '--json'], { encoding: 'utf8', env, maxBuffer: 1 << 26 });
    return { code: 0, data: JSON.parse(uit) };
  } catch (e) {
    return { code: e.status, data: JSON.parse(e.stdout || '{"rijen":[]}') };
  }
}

function datum(dagenVanafNu) {
  return new Date(NU + dagenVanafNu * DAG).toISOString().slice(0, 10);
}

test('een squash-merge telt als geland, ook al ziet git de tak als ongemerged', () => {
  const dir = bouwRepo();
  try {
    // eerst het bewijs dat de naieve methode hier faalt
    const naief = git(dir, 'branch', '-r', '--merged', 'origin/main');
    assert.ok(!naief.includes('origin/squash-tak'),
      'git --merged zou deze tak als ongemerged moeten zien, anders toetst dit niets');

    const { data } = draai(dir);
    const rij = data.rijen.find((r) => r.tak === 'squash-tak');
    assert.ok(rij, 'squash-tak moet in de meting zitten');
    assert.equal(rij.geland, true, 'de inhoud staat op main, dus geland');
    assert.equal(rij.laag, 'inhoud', 'laag 4 hoort dit te vinden zonder GitHub');
    assert.equal(rij.rood, false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// SABOTAGE. Een tak die te lang blijft liggen moet de poort rood maken.
test('sabotage: een oude ongelande tak maakt de poort rood en de exitcode 1', () => {
  const dir = bouwRepo();
  try {
    const { code, data } = draai(dir);
    const rij = data.rijen.find((r) => r.tak === 'blijft-liggen');
    assert.ok(rij, 'blijft-liggen moet in de meting zitten');
    assert.equal(rij.geland, false, 'deze tak zit nergens in main');
    assert.ok(rij.dagen > data.termijn, `${rij.dagen} dagen moet boven de termijn van ${data.termijn} liggen`);
    assert.equal(rij.rood, true, 'te lang buiten main zonder uitstel is rood');
    assert.equal(code, 1, 'de poort moet met 1 afsluiten, anders blokkeert hij niets');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('uitstel met een datum in de toekomst zet de poort weer groen', () => {
  const dir = bouwRepo();
  try {
    writeFileSync(join(dir, 'deploy', 'landen-uitstel.json'), JSON.stringify({
      uitstel: [{ tak: 'blijft-liggen', stapel: 'waarde', tot: datum(30), reden: 'toets' }],
    }, null, 2));
    const { code, data } = draai(dir);
    const rij = data.rijen.find((r) => r.tak === 'blijft-liggen');
    assert.equal(rij.rood, false, 'bevroren met een geldige datum is niet rood');
    assert.equal(rij.geland, false, 'uitstel maakt een tak niet geland');
    assert.equal(code, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('uitstel waarvan de datum verstreken is, is weer rood', () => {
  const dir = bouwRepo();
  try {
    writeFileSync(join(dir, 'deploy', 'landen-uitstel.json'), JSON.stringify({
      uitstel: [{ tak: 'blijft-liggen', stapel: 'waarde', tot: datum(-1), reden: 'toets' }],
    }, null, 2));
    const { code, data } = draai(dir);
    const rij = data.rijen.find((r) => r.tak === 'blijft-liggen');
    assert.equal(rij.uitstelVerlopen, true);
    assert.equal(rij.rood, true, 'uitstel zonder afloop is afstel');
    assert.equal(code, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// De lijst is geen losse tekst maar de invoer van de poort hierboven. Als hij
// wegloopt van de werkelijkheid, dan is de inhaalslag weer een verhaal.
test('deploy/landen-uitstel.json is geldig en elke post is compleet', async () => {
  const { readFileSync, existsSync } = await import('node:fs');
  const pad = join(ROOT, 'deploy', 'landen-uitstel.json');
  assert.ok(existsSync(pad), 'deploy/landen-uitstel.json hoort te bestaan');
  const data = JSON.parse(readFileSync(pad, 'utf8'));
  assert.ok(Array.isArray(data.uitstel), 'uitstel moet een lijst zijn');
  const stapels = new Set(['in-main-anders', 'achterhaald', 'waarde']);
  const gezien = new Set();
  for (const post of data.uitstel) {
    assert.ok(post.tak, 'elke post heeft een tak');
    assert.ok(!gezien.has(post.tak), `${post.tak} staat er twee keer in`);
    gezien.add(post.tak);
    assert.ok(stapels.has(post.stapel), `${post.tak}: stapel "${post.stapel}" bestaat niet`);
    assert.match(post.tot, /^\d{4}-\d{2}-\d{2}$/, `${post.tak}: tot moet JJJJ-MM-DD zijn`);
    assert.ok(post.reden && post.reden.length > 15, `${post.tak}: reden is te dun`);
  }
});

test('deploy/landen.md legt de methode en de termijn uit', async () => {
  const { readFileSync, existsSync } = await import('node:fs');
  const pad = join(ROOT, 'deploy', 'landen.md');
  assert.ok(existsSync(pad), 'deploy/landen.md hoort te bestaan');
  const tekst = readFileSync(pad, 'utf8');
  for (const woord of ['voorouder', 'pr-merged', 'patch-id', 'inhoud', 'squash']) {
    assert.ok(tekst.includes(woord), `deploy/landen.md moet laag "${woord}" beschrijven`);
  }
  assert.ok(/\b7\b/.test(tekst), 'de termijn hoort in deploy/landen.md te staan');
});
