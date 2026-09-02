// Every environment variable the relay or the admin panel reads must be written
// down in deploy/.env.example.
//
// Measured on 2026-09-02: the code read 57 names from the environment and 40 of
// them appeared in no .env.example at all, including BILLING_MODE,
// MOLLIE_API_KEY, INTERNAL_AUTH_TOKEN, PARAMANT_TOTP_MASTER_KEY, REDIS_URL and
// PARASIGN_STORE_KEY. deploy/.env.example listed three. A second developer
// could not have brought the stack up from the documentation, and neither
// could the first one a year from now.
//
// This suite is the thing that keeps that from happening again: add a
// process.env read without a line in deploy/.env.example and CI goes red.
//
// The reverse also holds. A variable documented here that nothing reads is a
// lie with a longer shelf life than an undocumented one, so it has to be listed
// in NOT_READ_BY_NODE below, with a reason.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join, relative } from 'path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const ENV_EXAMPLE = 'deploy/.env.example';

// Variables that belong in the file but that no relay/admin source reads:
// docker-compose.yml, the installer or an operator consumes them. Each one
// needs a reason, because "documented but dead" is its own kind of wrong.
const NOT_READ_BY_NODE = {
  LOG_LEVEL: 'consumed by docker-compose.yml only; the relay logs at a fixed level',
  HTTP_PORT: 'read by deploy/preflight.sh and deploy/post-install.sh, both shell',
  HTTPS_PORT: 'read by deploy/preflight.sh and deploy/post-install.sh, both shell',
  ADMIN_TOTP_SECRET: 'passed to the relays by docker-compose.yml, read by nothing (see the note in the file)',
  PARAMANT_VERSION: 'which git tag the three self-host installers clone; all shell',
};

// ── what the code reads ──────────────────────────────────────────────────────
// process.env.X, plus env.X in the modules that take an injectable env object
// (`env = env || process.env`, the pattern used by developer-gate, webauthn and
// entitlements so they can be unit-tested without a real environment).
// Assignments (`env.X = ...`) are writes into a child process environment, not
// configuration this deployment reads, so they are excluded.
const READ = /(?:process\.)?\benv\.([A-Z][A-Z0-9_]*)\b(?!\s*=[^=])/g;

function sources(dir, acc = []) {
  for (const e of readdirSync(join(ROOT, dir), { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === 'node_modules' || e.name === 'test') continue;
      sources(p, acc);
    } else if (/\.(js|mjs)$/.test(e.name) && !/\.test\.(js|mjs)$/.test(e.name)) {
      acc.push(p);
    }
  }
  return acc;
}

const readNames = new Map(); // NAME -> [file, ...]
for (const f of [...sources('relay'), ...sources('admin')]) {
  const src = readFileSync(join(ROOT, f), 'utf8');
  for (const m of src.matchAll(READ)) {
    if (!readNames.has(m[1])) readNames.set(m[1], []);
    const where = readNames.get(m[1]);
    if (!where.includes(f)) where.push(f);
  }
}

// ── what the file documents ──────────────────────────────────────────────────
// A name counts as documented when it appears as an assignment, set or
// commented out: `NAME=value` for something you must fill in, `# NAME=default`
// for an optional override you can leave alone.
const exampleText = readFileSync(join(ROOT, ENV_EXAMPLE), 'utf8');
const documented = new Set(
  [...exampleText.matchAll(/^#?\s*([A-Z][A-Z0-9_]*)=/gm)].map((m) => m[1])
);

test('E1 every variable the code reads is documented in deploy/.env.example', () => {
  const missing = [...readNames.keys()].filter((n) => !documented.has(n)).sort();
  assert.deepEqual(
    missing.map((n) => `${n}  (read in ${readNames.get(n).map((f) => relative('.', f)).join(', ')})`),
    [],
    `Undocumented environment variables. Add one line per name to ${ENV_EXAMPLE}: ` +
    'what it does, required or optional, its default, and where it is read. ' +
    'Set it as NAME= if an operator must fill it in, or comment it out as ' +
    '# NAME=default if it is an optional override.'
  );
});

test('E2 every variable documented in deploy/.env.example is read somewhere', () => {
  const stale = [...documented]
    .filter((n) => !readNames.has(n) && !(n in NOT_READ_BY_NODE))
    .sort();
  assert.deepEqual(stale, [],
    `${ENV_EXAMPLE} documents variables that no relay or admin source reads. ` +
    'Remove them, or list them in NOT_READ_BY_NODE in this file with the reason ' +
    'they belong there anyway (docker-compose, the installer, an operator tool).');
});

test('E3 every entry in NOT_READ_BY_NODE really is absent from the code', () => {
  // Keeps the allowlist from quietly outliving its reason: once something in it
  // becomes a real process.env read, it must be documented as one.
  const nowRead = Object.keys(NOT_READ_BY_NODE).filter((n) => readNames.has(n)).sort();
  assert.deepEqual(nowRead, [],
    'These are listed as "not read by node" but the code now reads them. ' +
    'Drop them from NOT_READ_BY_NODE.');
});

// Pairs each documented variable with the comment block directly above it.
function documentedBlocks() {
  const lines = exampleText.split('\n');
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^#?\s*([A-Z][A-Z0-9_]*)=/);
    if (!m) continue;
    let j = i - 1;
    let block = '';
    while (j >= 0 && /^#/.test(lines[j]) && !/^#\s*[A-Z][A-Z0-9_]*=/.test(lines[j])) {
      block = lines[j] + '\n' + block;
      j--;
    }
    out.push({ name: m[1], line: i + 1, block });
  }
  return out;
}

test('E4 each documented variable carries a one-line explanation above it', () => {
  // A bare NAME= is not documentation. Every assignment must be preceded by a
  // comment block, and that block must say where the value is read.
  const bad = documentedBlocks()
    .filter((b) => !/\bread in:/.test(b.block))
    .map((b) => `line ${b.line}: ${b.name}`);
  assert.deepEqual(bad, [],
    `Each variable in ${ENV_EXAMPLE} needs a comment block above it ending in a ` +
    '"read in: <file>" line, so the reader can go look at what actually uses it.');
});

test('E6 every file named in a "read in:" line exists and mentions the variable', () => {
  // Without this, "read in:" is a claim nobody checks, and a wrong pointer is
  // worse than none: it sends the reader to the wrong file with confidence.
  // Two of these lines were wrong on the first pass. HTTP_PORT and HTTPS_PORT
  // were credited to docker-compose.yml, which does not read them and has no
  // nginx service at all; they live in deploy/preflight.sh and
  // deploy/post-install.sh. PARAMANT_VERSION named install.sh alone while
  // frontend/install.sh and frontend/install-pi.sh read it too.
  const bad = [];
  for (const { name, line, block } of documentedBlocks()) {
    const m = block.match(/^#\s*read in:\s*(.+)$/m);
    if (!m) continue; // E4 reports a missing line; this test only checks the ones that exist.
    const targets = m[1]
      .replace(/\([^)]*\)/g, '')           // drop asides like "(and nothing else)"
      .split(',')
      .map((t) => t.trim())
      .filter((t) => /\.(js|mjs|sh|yml|yaml|json)$/.test(t));
    if (targets.length === 0) {
      bad.push(`line ${line}: ${name} names no file in its "read in:" line`);
      continue;
    }
    for (const t of targets) {
      let src;
      try {
        src = readFileSync(join(ROOT, t), 'utf8');
      } catch {
        bad.push(`line ${line}: ${name} points at ${t}, which does not exist`);
        continue;
      }
      // Whole word: PORT must not be satisfied by HTTP_PORT.
      if (!new RegExp(`\\b${name}\\b`).test(src)) {
        bad.push(`line ${line}: ${name} points at ${t}, which never mentions it`);
      }
    }
  }
  assert.deepEqual(bad, [],
    `Wrong "read in:" pointers in ${ENV_EXAMPLE}. Each named file must exist ` +
    'and contain the variable name. Run grep before writing the line down.');
});

test('E5 the count in the file header matches the number of variables documented', () => {
  const header = exampleText.match(/^#\s*(\d+)\s+variables\b/m);
  assert.ok(header, `${ENV_EXAMPLE} must state how many variables it documents in its header`);
  assert.equal(Number(header[1]), documented.size,
    `${ENV_EXAMPLE} header says ${header && header[1]} variables but documents ${documented.size}`);
});
