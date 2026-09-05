// Do the guards still bark?
//
// WHY THIS FILE EXISTS. In one night three separate safeguards turned out to be
// decoration. Each of them read, in the code, like a working check:
//
//   * the hourly self-test that proves the products work was switched off behind
//     a repository variable, and the alarm that should have reported that was a
//     step INSIDE the job the variable switches off. Nineteen scheduled runs in
//     a row reported "skipped", which GitHub does not colour red and does not
//     notify anyone about. Nobody noticed for three days.
//   * the secret scan sat red for seven weeks over two masked example keys, so
//     no change could go green on it and the signal meant nothing.
//   * the memory guard was set above the container's own limit, so the kernel
//     always acted first and the guard could never refuse anything.
//
// A fourth had the same shape: a gitleaks allowlist accepted `condition = "AND"`
// and then ignored it, which turned a narrowing rule into a whole-file pass.
//
// One pattern, four times: A CHECK THAT CANNOT FIRE. That is worse than no check
// at all, because it produces calm. This file is the check on the checks.
//
// THE RULE, taken from relay/test/_requires.js and applied one level up. There,
// a test that cannot meet its precondition fails unless the runner names it as
// deliberately absent (RELAY_TEST_SKIP), which moves the decision out of the
// test and into a file a reviewer reads. Here, anything that can stop a workflow
// gate from firing is a hard failure unless it is named in DECLARED below, with
// the reason and with the thing that keeps it visible while it is off.
//
// It also works the other way: an entry in DECLARED that is no longer found is a
// failure too. A silencer that gets removed must be removed from the list, so
// the list cannot fill up with reassuring entries about things that are gone.
//
//   node scripts/check-guards.mjs          report and exit non-zero on a finding
//   node scripts/check-guards.mjs --list   print what was found, exit 0
//
// tests/guards-can-fire.test.mjs runs this, and the "guards" workflow reports
// the half that only live state can answer: whether the switches are actually on.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const WORKFLOW_DIR = path.join(ROOT, '.github', 'workflows');

// ---------------------------------------------------------------------------
// A workflow file, read structurally.
//
// Deliberately not a YAML library. The repo has no yaml dependency and the root
// job installs only what tests/heartbeat-lib.test.mjs needs; adding a parser to
// production dependencies to read CI config is the wrong trade. What is needed
// here is small and indentation-driven: which jobs exist, the `if:` on each, and
// the steps with their keys. Anything this parser cannot read, it reports rather
// than skips (see UNREADABLE), because a guard file that silently parses to zero
// jobs would be the very failure this file exists to catch.
// ---------------------------------------------------------------------------

const indentOf = (line) => line.length - line.trimStart().length;
const isBlank = (line) => line.trim() === '' || line.trim().startsWith('#');

// A `key:` whose value runs on over following, more-indented lines (`|`, `>-`).
// Returns the whole value as one flat string so a regex can be asked about it.
function blockValue(lines, i, keyIndent) {
  const first = lines[i].slice(lines[i].indexOf(':') + 1).trim();
  if (!/^[|>][-+]?$/.test(first)) return { value: first, next: i + 1 };
  const parts = [];
  let j = i + 1;
  for (; j < lines.length; j++) {
    if (isBlank(lines[j])) { parts.push(''); continue; }
    if (indentOf(lines[j]) <= keyIndent) break;
    parts.push(lines[j].trim());
  }
  return { value: parts.join(' ').trim(), next: j };
}

export function parseWorkflow(file) {
  const text = fs.readFileSync(file, 'utf8');
  const lines = text.split('\n');
  const wf = {
    file,
    name: path.basename(file),
    triggers: new Set(),
    jobs: [],
    text,
    unreadable: [],
  };

  // The `on:` block. Both `on:` and the quoted `"on":` spelling, and both the
  // list form (`on: [push]`) and the mapping form.
  let i = 0;
  for (; i < lines.length; i++) {
    const m = /^(?:on|"on"|'on'):(.*)$/.exec(lines[i]);
    if (!m) continue;
    const inline = m[1].trim();
    if (inline) {
      for (const t of inline.replace(/[[\]]/g, '').split(',')) {
        if (t.trim()) wf.triggers.add(t.trim());
      }
      break;
    }
    for (let j = i + 1; j < lines.length; j++) {
      if (isBlank(lines[j])) continue;
      if (indentOf(lines[j]) === 0) break;
      const e = /^\s{2}([a-z_]+):/.exec(lines[j]);
      if (e && indentOf(lines[j]) === 2) wf.triggers.add(e[1]);
    }
    break;
  }

  // The `jobs:` block: job ids at indent 2, their keys at indent 4, steps as
  // list items at indent 6 with their keys at indent 8.
  const jobsAt = lines.findIndex((l) => /^jobs:\s*$/.test(l));
  if (jobsAt === -1) {
    wf.unreadable.push('no `jobs:` block found');
    return wf;
  }

  let job = null;
  let step = null;
  for (let k = jobsAt + 1; k < lines.length; k++) {
    const line = lines[k];
    if (isBlank(line)) continue;
    const ind = indentOf(line);
    if (ind === 0) break;

    const jobHead = ind === 2 && /^\s{2}([A-Za-z_][\w-]*):\s*$/.exec(line);
    if (jobHead) {
      job = { id: jobHead[1], line: k + 1, ifExpr: '', steps: [], keys: {} };
      wf.jobs.push(job);
      step = null;
      continue;
    }
    if (!job) continue;

    // Job-level keys.
    if (ind === 4 && /^\s{4}[A-Za-z_][\w-]*:/.test(line)) {
      const key = line.trim().split(':')[0];
      if (key === 'if') {
        const { value } = blockValue(lines, k, 4);
        job.ifExpr = value;
      } else {
        job.keys[key] = line.slice(line.indexOf(':') + 1).trim();
      }
      if (key !== 'steps') step = null;
      continue;
    }

    // A step: `      - key: value`, or `      - uses: ...`.
    const stepHead = ind === 6 && /^\s{6}-\s+(\S)/.test(line);
    if (stepHead) {
      step = { id: '', name: '', uses: '', run: '', keys: {}, line: k + 1 };
      job.steps.push(step);
      const inner = line.replace(/^\s{6}-\s+/, '');
      const km = /^([A-Za-z_][\w-]*):(.*)$/.exec(inner);
      if (km) {
        const key = km[1];
        const val = km[2].trim();
        if (key === 'run' && /^[|>][-+]?$/.test(val)) {
          const { value } = blockValue(lines, k, 6);
          step.run = value;
        } else if (key in step) {
          step[key] = val;
        } else {
          step.keys[key] = val;
        }
      }
      continue;
    }

    // A step's own keys, at indent 8.
    if (step && ind === 8 && /^\s{8}[A-Za-z_][\w-]*:/.test(line)) {
      const key = line.trim().split(':')[0];
      const { value } = blockValue(lines, k, 8);
      if (key === 'run' || key === 'id' || key === 'name' || key === 'uses') {
        step[key] = value;
      } else {
        step.keys[key] = value;
      }
      continue;
    }

    // `with:` and `env:` bodies sit deeper than a step key. Their contents are
    // flattened onto the step so `if-no-files-found` and the like are visible
    // without modelling the whole tree.
    if (step && ind >= 10) {
      const km = /^\s*([A-Za-z_][\w-]*):(.*)$/.exec(line);
      if (km) step.keys[km[1]] = km[2].trim();
    }
  }

  if (!wf.jobs.length) wf.unreadable.push('`jobs:` block parsed to zero jobs');
  return wf;
}

// ---------------------------------------------------------------------------
// What counts as a silencer: something that can stop a gate from firing without
// anything turning red.
// ---------------------------------------------------------------------------

// An expression that can switch a whole job off from outside the repository's
// code: a repository variable or a secret read in a job-level `if:`.
const SWITCH_RE = /\b(vars|secrets)\.([A-Z][A-Z0-9_]*)/g;

// A step that opens or comments on an issue. This is what "the alarm" looks like
// in this repo (heartbeat.yml and security-posture.yml both do it this way).
const ALARMS = /issues\.create|issues\.createComment|actions\/github-script/;

export function findSilencers(workflows) {
  const found = [];
  const add = (id, kind, where, detail) => found.push({ id, kind, where, detail });

  for (const wf of workflows) {
    for (const u of wf.unreadable) {
      add(`${wf.name}#unreadable`, 'unreadable', `${wf.name}`, u);
    }

    // R4. A workflow that no change ever runs cannot gate a change. It may still
    // be a fine alarm, but then something else has to notice when it stops.
    if (!wf.triggers.has('push') && !wf.triggers.has('pull_request')) {
      add(`${wf.name}#no-change-trigger`, 'no-change-trigger', wf.name,
        `triggers are ${[...wf.triggers].join(', ') || 'none'}: no push or pull_request`);
    }

    for (const job of wf.jobs) {
      const where = `${wf.name}:${job.line} job "${job.id}"`;

      // R1. A switch on the job. This is how the heartbeat went quiet.
      const switches = [...job.ifExpr.matchAll(SWITCH_RE)].map((m) => `${m[1]}.${m[2]}`);
      for (const sw of new Set(switches)) {
        add(`${wf.name}/${job.id}#switch:${sw}`, 'switch', where,
          `job-level if reads ${sw}: unset means this job does not run, and a job that does not run is "skipped", not red`);
      }

      // R6. The circular alarm, which is the shape of the original bug: the step
      // that raises the alarm lives inside the job the switch turns off, so the
      // one thing that could report the silence is silenced by the same switch.
      if (switches.length) {
        const alarm = job.steps.find(
          (s) => (s.keys.if || '').includes('failure()') && ALARMS.test(`${s.uses} ${s.run}`),
        );
        if (alarm) {
          add(`${wf.name}/${job.id}#circular-alarm`, 'circular-alarm', where,
            `the alarm at line ${alarm.line} runs on failure() inside a job gated by ${[...new Set(switches)].join(', ')}. While the switch is off the job is skipped, failure() never fires, and the alarm cannot report its own silence. Something OUTSIDE this job has to.`);
        }
      }

      for (const step of job.steps) {
        const label = step.id || step.name || step.uses || `line ${step.line}`;

        // R2. continue-on-error is not itself a bypass: both workflows that use
        // it settle the outcome in a later step. But it IS a bypass the moment
        // that later step goes away, so the settling step has to be found, by
        // name, and a step without an id can never be settled at all.
        if ((step.keys['continue-on-error'] || '') === 'true') {
          const later = job.steps.slice(job.steps.indexOf(step) + 1);
          // Two shapes count as settling it, and both are in use here.
          //   a. a later step reads steps.<id>.outcome and exits on it
          //      (heartbeat.yml, "Say in one line what failed")
          //   b. a later `if: always()` step re-derives the verdict from the
          //      evidence and exits 1 on it (security-posture.yml, "A run
          //      without a report is a failed run"). This is the stronger of
          //      the two: it asserts what was produced, not what was returned.
          const readsOutcome = step.id && later.some(
            (s) => new RegExp(`steps\\.${step.id}\\.(outcome|conclusion)`).test(`${s.run} ${s.keys.if || ''}`),
          );
          const alwaysVerdict = later.some(
            (s) => /always\(\)/.test(s.keys.if || '') && /\bexit 1\b|process\.exit\(1\)/.test(s.run),
          );
          if (!readsOutcome && !alwaysVerdict) {
            add(`${wf.name}/${job.id}#soft:${label}`, 'unsettled-soft-failure', where,
              step.id
                ? `step "${label}" (line ${step.line}) is continue-on-error, and no later step reads steps.${step.id}.outcome or re-derives a verdict under if: always(). Its failure ends the job green.`
                : `step "${label}" (line ${step.line}) is continue-on-error and has no id, so no later step can read its outcome`);
          }
        }

        // R3. Evidence that is allowed to be absent. A run that records nothing
        // and says so with a warning is a run that proves nothing.
        if ((step.keys['if-no-files-found'] || '') === 'warn') {
          add(`${wf.name}/${job.id}#warn-artifact:${label}`, 'evidence-optional', where,
            `step "${label}" (line ${step.line}) uploads evidence with if-no-files-found: warn, so a run that produced no evidence still passes this step`);
        }

        // R7. A pipe without pipefail. GitHub runs a `run:` block as `bash -e`,
        // which does NOT set pipefail, so `a | tee b` reports tee's exit code
        // and tee practically always succeeds. Every gate in this repo that
        // pipes a test runner into tee and then greps the log depends on this,
        // and the repo already writes `set -o pipefail` in all four of them by
        // hand. A hand-kept habit is not a guard, so it is checked: a piped
        // command whose failure is swallowed is a check that cannot fire.
        // A pipe inside `$( ... )` does not decide the step's exit code (the
        // command around it does), so those are removed before asking.
        const topLevel = step.run.replace(/\$\([^)]*\)/g, '');
        if (/\|\s*(tee|grep|head|tail)\b/.test(topLevel) && !/set -[a-z]*o[a-z]* pipefail|set -o pipefail/.test(step.run)) {
          add(`${wf.name}/${job.id}#unpiped:${label}`, 'pipe-without-pipefail', where,
            `step "${label}" (line ${step.line}) pipes a command and does not set pipefail, so the step reports the exit code of the LAST command in the pipe and a failure on the left of the pipe passes silently`);
        }

        // R5. A tool the runner may or may not have, with a warning instead of a
        // failure when it does not. The check quietly shrinks to whatever is
        // installed, and the log line that says so is not red.
        if (/::warning[ :]/.test(step.run) && /command -v\s+(\S+)/.test(step.run)) {
          const tool = /command -v\s+(\S+)/.exec(step.run)[1];
          add(`${wf.name}/${job.id}#optional-tool:${tool}`, 'optional-tool', where,
            `step "${label}" (line ${step.line}) degrades to a ::warning:: when ${tool} is missing, so the check shrinks without going red`);
        }
      }
    }
  }
  return found;
}

// ---------------------------------------------------------------------------
// DECLARED. Every silencer that is allowed to exist, by id, with the reason and
// with the thing that keeps it visible. Anything not named here fails the gate;
// anything named here that is no longer found fails it too.
//
// "visible" is the load-bearing column. A silencer is acceptable only when
// something OUTSIDE it reports that it is silent. For the two switches that is
// .github/workflows/guards.yml, which has no switch of its own (guarded by
// NO_SWITCH_WORKFLOWS below) and opens one issue while a guard is off.
// ---------------------------------------------------------------------------

export const DECLARED = {
  'heartbeat.yml#no-change-trigger': {
    why: 'the hourly proof runs against production, so a pull request must not fire it. It is a schedule, not a gate.',
    visible: 'guards.yml checks that a successful heartbeat run exists within HEARTBEAT_MAX_AGE_HOURS and opens an issue when it does not',
  },
  'heartbeat.yml/proof#switch:vars.HEARTBEAT_ENABLED': {
    why: 'the two canary secrets do not exist yet and only Mick can create them. Ungated, the job would go red at :17 every hour for a known reason, and an alarm that cries hourly is one people learn to ignore.',
    visible: 'guards.yml reports the switch itself as red-in-an-issue while it is off, so "off" costs an open issue instead of nothing',
  },
  'heartbeat.yml/proof#circular-alarm': {
    why: 'the issue-opening step is correctly placed for a run that HAPPENS; it cannot also cover a run that is skipped.',
    visible: 'guards.yml is that outside observer. It runs on a schedule of its own and cannot be switched off.',
  },
  'heartbeat.yml/proof#warn-artifact:Keep the evidence': {
    why: 'a run that fails before it writes anything must still reach the step that turns the failure red; if-no-files-found: error here would fail the upload first and hide the cause.',
    visible: 'the "Say in one line what failed" step settles the job regardless, and scripts/heartbeat/run.mjs fails any step that records no proof',
  },
  'security-posture.yml/posture#switch:vars.SECURITY_POSTURE_ENABLED': {
    why: 'same order-of-operations reason as the heartbeat: the nightly scan is known-red until the deploy decisions are carried out.',
    visible: 'guards.yml reports the switch as red-in-an-issue while it is off',
  },
  'security-posture.yml/posture#circular-alarm': {
    why: 'as heartbeat: the alarm covers a run that happens, not a run that is skipped.',
    visible: 'guards.yml, from outside',
  },
  'security-posture.yml/selftest#optional-tool:shellcheck': {
    why: 'shellcheck is a lint on top of `bash -n`, which always runs and is the actual gate.',
    visible: 'the ::warning:: is emitted on the run page, and bash -n failing is still a hard red',
  },
};

// The guards that .github/workflows/guards.yml watches from outside, and what
// "running" means for each. Every DECLARED switch must appear here: a silencer
// is only acceptable while something reports it, and this list is that
// something. tests/guards-can-fire.test.mjs holds the two lists against each
// other, so a switch cannot be declared as watched without actually being
// watched.
//
// `job` is the DISPLAY name of the job, because the job is what has to be asked
// about. security-posture.yml reports the whole run as "success" when its
// production job was skipped and only the self-test ran, so a run-level check
// there would confirm a guard that measured nothing.
export const WATCHED = [
  {
    workflow: 'heartbeat.yml',
    job: 'heartbeat - production',
    switchVar: 'HEARTBEAT_ENABLED',
    // It runs at :17 every hour. Three hours allows for a queue, a re-run and
    // an hour of GitHub being slow before it counts as absent.
    maxAgeHours: 3,
    what: 'the hourly proof that a file still transfers and a document still signs',
    turnOn: 'gh secret set PARAMANT_CANARY_KEY && gh secret set PARASIGN_CANARY_KEY && gh variable set HEARTBEAT_ENABLED --body true',
  },
  {
    workflow: 'security-posture.yml',
    job: 'security posture, production',
    switchVar: 'SECURITY_POSTURE_ENABLED',
    // Daily at 04:43. Two days allows one missed night without crying.
    maxAgeHours: 48,
    what: 'the nightly scan of the public surface: DNS, TLS, headers and the closed ParaID route',
    turnOn: 'gh variable set SECURITY_POSTURE_ENABLED --body true',
  },
];

// Workflows that may never carry a switch, because they are what watches the
// switched things. A gate on the watchdog is the bug this whole file is about.
export const NO_SWITCH_WORKFLOWS = ['guards.yml'];

// ---------------------------------------------------------------------------
// Invariants that are not exception-able: rules with no legitimate exception, so
// they carry no DECLARED entry to add.
// ---------------------------------------------------------------------------

// "8g" / "1500m" / "512" as a number of MB.
function toMB(raw) {
  const m = /^(\d+(?:\.\d+)?)\s*([gGmMkK]?)b?$/.exec(String(raw).trim().replace(/["']/g, ''));
  if (!m) return null;
  const n = parseFloat(m[1]);
  const unit = m[2].toLowerCase();
  if (unit === 'g') return Math.round(n * 1024);
  if (unit === 'k') return Math.round(n / 1024);
  return Math.round(n); // docker-compose treats a bare number as bytes, but this
  // file always writes a unit; a bare number here is a mistake worth reporting
  // rather than silently reading as 8192 bytes.
}

export function checkRamGuards(file = path.join(ROOT, 'docker-compose.yml')) {
  const problems = [];
  if (!fs.existsSync(file)) return [`${path.basename(file)} is missing; the RAM guard's ceiling cannot be checked.`];
  const lines = fs.readFileSync(file, 'utf8').split('\n');

  // Defaults from the shared anchors: `RAM_LIMIT_MB: "${RAM_LIMIT_MB:-1024}"`
  // and the `memory:` under the shared resources anchor.
  const defaultOf = (name) => {
    const re = new RegExp(`${name}:\\s*"?\\$\\{${name}:-(\\d+)\\}`);
    for (const l of lines) { const m = re.exec(l); if (m) return parseInt(m[1], 10); }
    return null;
  };
  const defaults = { limit: defaultOf('RAM_LIMIT_MB'), reserve: defaultOf('RAM_RESERVE_MB') };

  // The `memory:` directly under a `limits:` key, anywhere in the file, indexed
  // by the service block it sits in. `reservations:` also carries a `memory:`
  // and must not be mistaken for the ceiling.
  const servicesAt = lines.findIndex((l) => /^services:\s*$/.test(l));
  if (servicesAt === -1) return ['docker-compose.yml has no `services:` block.'];

  let anchorLimit = null;
  for (let i = 0; i < servicesAt; i++) {
    if (/^\s*limits:\s*$/.test(lines[i])) {
      for (let j = i + 1; j < Math.min(i + 4, servicesAt); j++) {
        const m = /^\s*memory:\s*(\S+)/.exec(lines[j]);
        if (m) { anchorLimit = toMB(m[1]); break; }
      }
    }
  }

  const services = [];
  let cur = null;
  let inLimits = false;
  for (let i = servicesAt + 1; i < lines.length; i++) {
    const line = lines[i];
    if (isBlank(line)) continue;
    const ind = indentOf(line);
    if (ind === 0) break;
    const head = ind === 2 && /^\s{2}([A-Za-z_][\w-]*):\s*$/.exec(line);
    if (head) {
      cur = { name: head[1], line: i + 1, limitMB: null, ramLimit: null, ramReserve: null };
      services.push(cur);
      inLimits = false;
      continue;
    }
    if (!cur) continue;
    if (/^\s*limits:\s*$/.test(line)) { inLimits = true; continue; }
    if (/^\s*(reservations|environment|volumes|ports|networks):\s*$/.test(line)) { inLimits = false; continue; }
    const mem = /^\s*memory:\s*(\S+)/.exec(line);
    if (mem && inLimits) cur.limitMB = toMB(mem[1]);
    const rl = /^\s*RAM_LIMIT_MB:\s*"?(\d+)"?\s*$/.exec(line);
    if (rl) cur.ramLimit = parseInt(rl[1], 10);
    const rr = /^\s*RAM_RESERVE_MB:\s*"?(\d+)"?\s*$/.exec(line);
    if (rr) cur.ramReserve = parseInt(rr[1], 10);
  }

  let checked = 0;
  for (const s of services) {
    const limit = s.limitMB ?? anchorLimit;
    const ramLimit = s.ramLimit ?? defaults.limit;
    const reserve = s.ramReserve ?? defaults.reserve;
    // Services that run no relay (redis, the admin panel) set no RAM_LIMIT_MB
    // and inherit no relay env; nothing to compare.
    if (limit == null || ramLimit == null || reserve == null) continue;
    if (!/relay/.test(s.name)) continue;
    checked++;
    const trips = ramLimit + reserve;
    if (trips >= limit) {
      problems.push(
        `docker-compose.yml service "${s.name}" (line ${s.line}): the RAM guard refuses at ` +
        `RAM_LIMIT_MB + RAM_RESERVE_MB = ${ramLimit} + ${reserve} = ${trips} MB, but the container is ` +
        `capped at ${limit} MB. The kernel kills it first, so the guard can never refuse an upload: ` +
        `relay.js:1356 is unreachable on this service. Set the sum below ${limit}.`,
      );
    }
  }
  // A parser that quietly matched nothing would report a clean bill of health
  // over an unread file, which is the shape of bug this whole script is about.
  if (!checked) {
    problems.push('docker-compose.yml: no relay service could be read for its RAM guard. The check matched nothing and would have passed over anything.');
  }
  return problems;
}

export function checkInvariants() {
  const problems = [];

  // I1. gitleaks: no `paths` key, and no singular [allowlist] table.
  //
  // Neither the pinned 8.28.0 nor any earlier version enforces
  // `condition = "AND"`: it is accepted and then ignored. So in an allowlist
  // block that also has `regexes`, a `paths` entry does not narrow the rule, it
  // replaces it, and the whole file is allowlisted. Measured on this repo: with
  // paths set, an injected stripe-access-token in frontend/js/relay-trust-
  // anchors.js was not reported; without it, it was. The rule was written down
  // in a comment in .gitleaks.toml, and a comment is not a gate.
  const gitleaksFile = path.join(ROOT, '.gitleaks.toml');
  if (!fs.existsSync(gitleaksFile)) {
    problems.push('.gitleaks.toml is gone. The secret scan falls back to the default config and the documented placeholders go red again.');
  } else {
    const toml = fs.readFileSync(gitleaksFile, 'utf8');
    const code = toml.split('\n').filter((l) => !l.trim().startsWith('#')).join('\n');
    if (/^\s*paths\s*=/m.test(code)) {
      problems.push('.gitleaks.toml has a `paths` entry. gitleaks accepts `condition = "AND"` and ignores it, so paths beside regexes allowlists the WHOLE file, not the matching line. A real key in that file would go unreported. Narrow with regexes only.');
    }
    if (/^\s*\[allowlist\]\s*$/m.test(code)) {
      problems.push('.gitleaks.toml has a singular [allowlist] table. Use [[allowlists]]: the singular form is the one older gitleaks silently ignores.');
    }
  }

  // I2. A guard whose threshold sits above the ceiling that kills the process
  // first can never refuse anything.
  //
  // relay.js:1356 refuses an upload when
  //   rss + BLOB_SIZE_MB * (inFlight + 1) > RAM_LIMIT_MB + RAM_RESERVE_MB
  // and the container is killed by the kernel at its cgroup limit. If the sum on
  // the right is at or above that limit, the kernel always acts first and the
  // branch is dead code: the relay never answers "at capacity", it just
  // disappears mid-upload. That is what relay-health has been doing, with the
  // guard set to 8192+512 inside a container capped at 8192.
  //
  // Note that RAM_RESERVE_MB is added, not subtracted, so it is headroom ABOVE
  // the limit rather than a reserve held back below it. That is why the sum is
  // what has to be compared, not RAM_LIMIT_MB on its own.
  problems.push(...checkRamGuards());

  // I3. The watchdog may not be switchable, and must run both on a schedule and
  // on a change, so it cannot rot unnoticed between deploys.
  for (const name of NO_SWITCH_WORKFLOWS) {
    const file = path.join(WORKFLOW_DIR, name);
    if (!fs.existsSync(file)) {
      problems.push(`${name} is missing. It is what reports that a switched-off guard is off; without it that silence costs nothing again.`);
      continue;
    }
    const wf = parseWorkflow(file);
    for (const job of wf.jobs) {
      if (SWITCH_RE.test(job.ifExpr)) {
        SWITCH_RE.lastIndex = 0;
        problems.push(`${name} job "${job.id}" is gated on a variable or secret. The watchdog may not have an off switch.`);
      }
      SWITCH_RE.lastIndex = 0;
    }
    for (const need of ['schedule', 'pull_request']) {
      if (!wf.triggers.has(need)) {
        problems.push(`${name} has no ${need} trigger. It needs the schedule to notice a guard going quiet and the pull request to notice itself being broken.`);
      }
    }
  }

  return problems;
}

// ---------------------------------------------------------------------------

export function readWorkflows() {
  return fs.readdirSync(WORKFLOW_DIR)
    .filter((f) => f.endsWith('.yml') || f.endsWith('.yaml'))
    .sort()
    .map((f) => parseWorkflow(path.join(WORKFLOW_DIR, f)));
}

export function run() {
  const workflows = readWorkflows();
  const found = findSilencers(workflows);
  const foundIds = new Set(found.map((f) => f.id));

  const undeclared = found.filter((f) => !(f.id in DECLARED));
  const stale = Object.keys(DECLARED).filter((id) => !foundIds.has(id));
  const invariants = checkInvariants();

  return { workflows, found, undeclared, stale, invariants };
}

function main() {
  const list = process.argv.includes('--list');
  const { workflows, found, undeclared, stale, invariants } = run();

  console.log(`guards: read ${workflows.length} workflows, ${workflows.reduce((n, w) => n + w.jobs.length, 0)} jobs`);
  if (list) {
    for (const f of found) {
      const state = f.id in DECLARED ? 'declared' : 'UNDECLARED';
      console.log(`  [${state}] ${f.id}\n      ${f.detail}`);
    }
    return;
  }

  let bad = false;
  if (undeclared.length) {
    bad = true;
    console.log('\nSomething can stop a guard from firing, and it is not declared:');
    for (const f of undeclared) {
      console.log(`  ${f.id}\n      at ${f.where}\n      ${f.detail}`);
    }
    console.log('\n  Either remove it, or add it to DECLARED in scripts/check-guards.mjs with');
    console.log('  the reason AND the thing that reports it while it is silent. A silencer');
    console.log('  nothing watches is the bug this gate exists to catch.');
  }
  if (stale.length) {
    bad = true;
    console.log('\nDeclared, but no longer there:');
    for (const id of stale) console.log(`  ${id}`);
    console.log('\n  Remove these from DECLARED. A list that keeps entries for things that are');
    console.log('  gone stops describing the repository and starts reassuring about it.');
  }
  if (invariants.length) {
    bad = true;
    console.log('\nInvariant broken:');
    for (const p of invariants) console.log(`  ${p}`);
  }

  if (bad) {
    process.exitCode = 1;
    return;
  }
  console.log(`guards: ${found.length} silencers, all ${Object.keys(DECLARED).length} declared and each one watched from outside; ${'invariants hold'}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
