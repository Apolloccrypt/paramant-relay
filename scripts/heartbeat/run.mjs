#!/usr/bin/env node
// The hourly proof run.
//
//   node scripts/heartbeat/run.mjs                 every step
//   node scripts/heartbeat/run.mjs parasend        one step by name
//   HEARTBEAT_DRY_RUN=1 node scripts/heartbeat/run.mjs   wiring only, no network
//
// Design rules, all of them a reaction to the heartbeat this replaces:
//
//   * no step may be green without evidence. Every step writes a JSON file with
//     ids, hashes, statuses and timings, and a step that recorded no proof is
//     failed by runStep even if nothing threw.
//   * a missing secret is a hard failure that names the secret. There is no
//     skip anywhere in this directory, because a skip is what made run
//     33624449015 green while doing nothing.
//   * one summary line goes to the top of the run. GitHub renders ::error::
//     annotations at the head of the run page, above the log, which is the only
//     place in Actions that is genuinely "the top". The same line also opens the
//     job summary and is written to heartbeat-evidence/summary.json for the
//     issue step to read.
//
// Exit code 0 green, 1 red. Nothing else.
import fs from 'node:fs';
import path from 'node:path';
import { EVIDENCE_DIR, DRY_RUN, RELAY, SITE, runStep, nowIso } from './lib.mjs';
import { parasign, parasignReceipt } from './parasign.mjs';
import { parasend } from './parasend.mjs';
import { surface } from './surface.mjs';

const STEPS = [
  // Ordered cheapest and most diagnostic first: if the relay is not answering
  // its liveness probe at all, that is the line worth putting at the top rather
  // than a signing timeout thirty seconds later.
  ['surface', surface],
  ['parasend', parasend],
  ['parasign-receipt', parasignReceipt],
  ['parasign-public-sign', parasign],
];

const only = process.argv.slice(2).filter((a) => !a.startsWith('-'));
const steps = only.length ? STEPS.filter(([n]) => only.includes(n)) : STEPS;
if (only.length && steps.length !== only.length) {
  console.error(`unknown step(s): ${only.filter((n) => !STEPS.some(([s]) => s === n)).join(', ')}`);
  console.error(`known steps: ${STEPS.map(([n]) => n).join(', ')}`);
  process.exit(1);
}

console.log(`heartbeat ${nowIso()}`);
console.log(`  relay ${RELAY}`);
console.log(`  site  ${SITE}`);
console.log(`  mode  ${DRY_RUN ? 'DRY RUN (nothing is contacted, and a dry run can never stand in for proof)' : 'live'}`);

const results = [];
for (const [name, fn] of steps) {
  // Every step runs even after a failure. A dead page must never hide a dead
  // signer: that is why the workflow it replaces used if: always() on each step,
  // and the same reasoning applies inside one process.
  results.push(await runStep(name, fn));
}

const failed = results.filter((r) => !r.ok);
// A dry run is never green, whatever its steps did. It contacted nothing, so it
// proved nothing about production, and a green tick that means "the wiring
// parses" is precisely the kind of tick this rewrite exists to abolish. It is
// counted as a failed run: summary.ok false, non-zero exit, and therefore no
// issue closed by the workflow's `if: success()` step.
const stepsOk = failed.length === 0;
const summary = {
  at: nowIso(),
  ok: stepsOk && !DRY_RUN,
  steps_ok: stepsOk,
  dry_run: DRY_RUN,
  relay: RELAY,
  run_id: process.env.GITHUB_RUN_ID || null,
  steps: results,
  // The one line. Step first, then cause, because the step is what tells you
  // which product is down and that is the first thing anyone needs.
  line: !stepsOk
    ? `Heartbeat RED at ${failed.map((r) => `${r.name} (${r.cause})`).join('; ')}`
    : DRY_RUN
      ? `Heartbeat DRY RUN: ${results.length} steps wired correctly, ${results.reduce((a, r) => a + r.proofs, 0)} local checks, and nothing proven about production`
      : `Heartbeat green: ${results.length} steps, ${results.reduce((a, r) => a + r.proofs, 0)} proofs`,
};

fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
fs.writeFileSync(path.join(EVIDENCE_DIR, 'summary.json'), JSON.stringify(summary, null, 2));

console.log('\n' + '='.repeat(72));
for (const r of results) console.log(`  ${r.ok ? 'GREEN' : 'RED  '}  ${r.name}${r.ok ? ` (${r.proofs} proofs)` : `: ${r.cause}`}`);
console.log('='.repeat(72));
console.log(summary.line);

if (process.env.GITHUB_STEP_SUMMARY) {
  const md = [
    `### ${summary.ok ? 'Heartbeat green' : stepsOk ? 'Heartbeat dry run' : 'Heartbeat RED'}`,
    '',
    summary.line,
    '',
    '| step | result | proofs |',
    '| --- | --- | --- |',
    ...results.map((r) => `| ${r.name} | ${r.ok ? 'green' : `RED: ${r.cause}`} | ${r.proofs} |`),
    '',
  ].join('\n');
  try { fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, md); } catch { /* summary is a nicety */ }
}

if (!stepsOk) {
  // Rendered at the head of the run page, above the whole log.
  console.log(`::error title=Heartbeat rood::${summary.line}`);
  process.exit(1);
}
if (DRY_RUN) {
  // Every step was wired correctly and none of them touched production, so this
  // is not an alarm and does not get the red annotation. It is still a non-zero
  // exit: a dry run must never be mistaken for a green production run, by a
  // future reader of this log or by a workflow reading the exit code.
  console.log('::notice title=Heartbeat dry run::wiring only. Nothing was contacted, nothing is proven about production, and this run exits non-zero so it can never be read as green.');
  process.exit(2);
}
process.exit(0);
