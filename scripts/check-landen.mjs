#!/usr/bin/env node
// Werk dat niet landt, kost twee keer.
//
// Op 10 juni 2026 stond fix/sector-port-drift klaar: vier sectorpoorten in
// admin/server.js die naar een poort wijzen waar niets luistert. De tak is nooit
// op main gekomen. Op 5 september 2026 vond een tweede onderzoek dezelfde fout
// opnieuw, en werd hij een tweede keer gerepareerd. Dat is de kostenpost die
// deze poort meet: niet rommel, maar dubbel werk.
//
// git ziet een squash-merge niet als merge, dus `git branch --merged` is hier
// onbruikbaar: het merkt takken aan als ongeland terwijl de inhoud er wel in
// zit. Deze poort bepaalt "geland" daarom in vier lagen, van goedkoop naar duur,
// en meldt per tak welke laag de uitspraak deed:
//
//   1. voorouder   git merge-base --is-ancestor  (echte merge of fast-forward)
//   2. pr-merged   een pull request met deze tak als head is MERGED
//                  (dit is de laag die squash opvangt; alleen met GitHub)
//   3. patch-id    git cherry: elke commit heeft een gelijke patch-id op main
//                  (vangt cherry-pick en rebase, en squash van een tak van
//                   precies een commit)
//   4. inhoud      de netto wijziging van de tak ten opzichte van zijn
//                  merge-base laat zich omgekeerd toepassen op main. Dan staan
//                  de hunks er al, ook als main daarna verder is gelopen.
//
// Laag 1 en 3 kunnen alleen ja zeggen, nooit nee: ze bewijzen dat iets geland
// is. Geen enkele laag ja = ongeland, en dat is een bovengrens, geen exact
// getal. Wat overblijft is met de hand na te lopen; deploy/landen.md legt uit
// hoe.
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = process.env.LANDEN_ROOT || join(dirname(fileURLToPath(import.meta.url)), '..');
const UITSTEL = join(ROOT, 'deploy', 'landen-uitstel.json');

// Zeven dagen. Niet omdat het netjes is, maar omdat het de termijn is waarbinnen
// de schrijver van een reparatie zich hem nog herinnert. Daarna wordt hij door
// een tweede paar ogen opnieuw gevonden en opnieuw geschreven, en dat is precies
// wat er tussen 10 juni en 5 september met de sectorpoorten gebeurde. De board
// zette deze termijn op 30 augustus 2026 al vast; deze poort dwingt hem af.
const TERMIJN_DAGEN = Number(process.env.LANDEN_TERMIJN_DAGEN || 7);

const args = new Set(process.argv.slice(2));
const GEEN_GITHUB = args.has('--geen-github') || process.env.LANDEN_GEEN_GITHUB === '1';
const JSON_UIT = args.has('--json');
const MAIN = process.env.LANDEN_MAIN || 'origin/main';

function git(...a) {
  return execFileSync('git', a, { cwd: ROOT, encoding: 'utf8', maxBuffer: 1 << 28 }).trim();
}
function gitStil(...a) {
  try { git(...a); return true; } catch { return false; }
}

function takken() {
  const uit = git('for-each-ref', '--format=%(refname:short)%09%(objectname)%09%(committerdate:unix)', 'refs/remotes/origin');
  const rows = [];
  for (const regel of uit.split('\n')) {
    if (!regel.trim()) continue;
    const [ref, sha, ts] = regel.split('\t');
    const naam = ref.replace(/^origin\//, '');
    if (naam === 'HEAD' || naam === 'main') continue;
    rows.push({ tak: naam, sha, laatste: Number(ts) });
  }
  return rows.sort((a, b) => a.laatste - b.laatste);
}

function prStatus() {
  if (GEEN_GITHUB) return null;
  try {
    const uit = execFileSync('gh', ['pr', 'list', '--state', 'all', '--limit', '1000',
      '--json', 'number,headRefName,state,mergedAt'], { cwd: ROOT, encoding: 'utf8', maxBuffer: 1 << 26 });
    const per = new Map();
    for (const pr of JSON.parse(uit)) {
      const lijst = per.get(pr.headRefName) || [];
      lijst.push(pr);
      per.set(pr.headRefName, lijst);
    }
    return per;
  } catch {
    return null; // geen gh, geen net, geen token: de poort werkt door zonder laag 2
  }
}

// Laag 4: staat de netto wijziging van de tak al in main?
function inhoudZitErAl(sha, indexBestand) {
  let base;
  try { base = git('merge-base', MAIN, sha); } catch { return false; }
  if (base === sha) return true;
  let patch;
  try {
    patch = execFileSync('git', ['diff', base, sha], { cwd: ROOT, encoding: 'utf8', maxBuffer: 1 << 28 });
  } catch { return false; }
  if (!patch.trim()) return true; // lege netto wijziging telt als geland
  const env = { ...process.env, GIT_INDEX_FILE: indexBestand };
  try {
    execFileSync('git', ['read-tree', MAIN], { cwd: ROOT, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    execFileSync('git', ['apply', '--check', '-R', '--cached', '-'],
      { cwd: ROOT, env, input: patch, encoding: 'utf8', maxBuffer: 1 << 28, stdio: ['pipe', 'pipe', 'ignore'] });
    return true;
  } catch { return false; }
}

function uitstellijst() {
  if (!existsSync(UITSTEL)) return new Map();
  const data = JSON.parse(readFileSync(UITSTEL, 'utf8'));
  const per = new Map();
  for (const post of data.uitstel || []) per.set(post.tak, post);
  return per;
}

export function meet({ nu = Date.now() } = {}) {
  const prs = prStatus();
  const uitstel = uitstellijst();
  const tmp = mkdtempSync(join(tmpdir(), 'landen-'));
  const indexBestand = join(tmp, 'index');
  const rijen = [];
  try {
    for (const t of takken()) {
      let geland = false, laag = null;

      if (gitStil('merge-base', '--is-ancestor', t.sha, MAIN)) { geland = true; laag = 'voorouder'; }

      if (!geland && prs) {
        const mijn = prs.get(t.tak) || [];
        if (mijn.some((p) => p.state === 'MERGED')) { geland = true; laag = 'pr-merged'; }
      }

      if (!geland) {
        try {
          const cherry = git('cherry', MAIN, t.sha);
          const regels = cherry.split('\n').filter((r) => r.trim());
          if (regels.length && regels.every((r) => r.startsWith('-'))) { geland = true; laag = 'patch-id'; }
        } catch { /* geen gemeenschappelijke voorouder: laat aan laag 4 */ }
      }

      if (!geland && inhoudZitErAl(t.sha, indexBestand)) { geland = true; laag = 'inhoud'; }

      const dagen = Math.floor((nu - t.laatste * 1000) / 86400000);
      const post = uitstel.get(t.tak) || null;
      let uitstelTot = null, uitstelVerlopen = false;
      if (post) {
        uitstelTot = post.tot;
        uitstelVerlopen = Date.parse(`${post.tot}T23:59:59Z`) < nu;
      }

      const teLang = !geland && dagen > TERMIJN_DAGEN;
      const rood = teLang && (!post || uitstelVerlopen);

      rijen.push({
        tak: t.tak, sha: t.sha.slice(0, 8), dagen, geland, laag,
        heeftPr: prs ? (prs.get(t.tak) || []).length > 0 : null,
        uitstelTot, uitstelVerlopen, rood,
      });
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
  return { termijn: TERMIJN_DAGEN, github: prs !== null, rijen };
}

function hoofd() {
  const r = meet();
  if (JSON_UIT) { console.log(JSON.stringify(r, null, 2)); }
  else {
    const rood = r.rijen.filter((x) => x.rood);
    const ongeland = r.rijen.filter((x) => !x.geland);
    const bevroren = r.rijen.filter((x) => x.uitstelTot && !x.uitstelVerlopen && !x.geland);
    console.log(`LANDEN  termijn ${r.termijn} dagen  github-laag ${r.github ? 'aan' : 'uit'}`);
    console.log(`  takken op origin      ${r.rijen.length}`);
    console.log(`  inhoud staat op main  ${r.rijen.length - ongeland.length}`);
    console.log(`  ongeland              ${ongeland.length}  (bovengrens)`);
    console.log(`  bevroren met datum    ${bevroren.length}`);
    console.log(`  te lang buiten main   ${rood.length}`);
    if (ongeland.length) {
      console.log('\n  ongeland, oudste eerst:');
      for (const x of ongeland) {
        const merk = x.rood ? 'ROOD' : (x.uitstelTot ? `tot ${x.uitstelTot}` : 'binnen termijn');
        console.log(`    ${String(x.dagen).padStart(4)}d  ${merk.padEnd(15)} ${x.tak}`);
      }
    }
    if (rood.length) {
      console.log(`\nROOD: ${rood.length} tak(ken) langer dan ${r.termijn} dagen ongeland en zonder geldig uitstel.`);
      console.log('Merge hem, gooi hem weg, of zet hem in deploy/landen-uitstel.json met een datum.');
    } else {
      console.log('\nGROEN: geen tak langer dan de termijn ongeland zonder geldig uitstel.');
    }
  }
  process.exit(r.rijen.some((x) => x.rood) ? 1 : 0);
}

if (process.argv[1] && process.argv[1].endsWith('check-landen.mjs')) hoofd();
