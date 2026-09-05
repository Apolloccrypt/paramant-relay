// Can every guard in this repository still fire?
//
// The gate on scripts/check-guards.mjs, and the place where its two registers
// are held against each other. Picked up automatically by
// scripts/browser-suites.mjs --no-browser, so it runs in test.yml on every push
// and every pull request with no list to keep.
//
// The failure this defends against, in one sentence: a check that cannot fire
// reports green, and green is what people act on. Three of those turned up in
// one night, and the reason none of them was noticed is that every one of them
// looked correct in the code.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

import {
  ROOT, DECLARED, WATCHED, NO_SWITCH_WORKFLOWS,
  parseWorkflow, findSilencers, readWorkflows, checkInvariants, checkRamGuards, run,
} from '../scripts/check-guards.mjs';

const wfPath = (n) => path.join(ROOT, '.github', 'workflows', n);

test('the workflow reader actually reads: jobs, triggers and steps', () => {
  // The reader is hand-rolled, so it gets asserted before anything is concluded
  // from it. A parser that quietly returns nothing would make every check below
  // pass over an unread file, which is the exact shape of the bug being fixed.
  const workflows = readWorkflows();
  assert.ok(workflows.length >= 8, `expected at least 8 workflows, read ${workflows.length}`);
  for (const wf of workflows) {
    assert.equal(wf.unreadable.length, 0, `${wf.name}: ${wf.unreadable.join('; ')}`);
    assert.ok(wf.jobs.length > 0, `${wf.name} parsed to zero jobs`);
    assert.ok(wf.triggers.size > 0, `${wf.name} parsed to zero triggers`);
  }

  const heartbeat = parseWorkflow(wfPath('heartbeat.yml'));
  assert.deepEqual([...heartbeat.triggers].sort(), ['schedule', 'workflow_dispatch']);
  assert.equal(heartbeat.jobs.length, 1);
  assert.match(heartbeat.jobs[0].ifExpr, /vars\.HEARTBEAT_ENABLED/,
    'the reader must see the job-level if, which is where the switch lives');
  assert.ok(heartbeat.jobs[0].steps.length >= 8,
    `heartbeat proof job parsed to ${heartbeat.jobs[0].steps.length} steps`);
});

test('every way a guard can be silenced is declared, and every declaration is still real', () => {
  const { undeclared, stale } = run();
  assert.deepEqual(undeclared.map((u) => u.id), [],
    'undeclared silencer: something can stop a guard firing and nothing says so. '
    + 'Add it to DECLARED in scripts/check-guards.mjs with the reason and with what reports it while it is silent.');
  assert.deepEqual(stale, [],
    'DECLARED names a silencer that no longer exists. Remove it: a list that keeps '
    + 'entries for things that are gone stops describing the repository and starts reassuring about it.');
});

test('a declared switch is watched from outside, by name', () => {
  // The load-bearing link. A switch may be declared only because something
  // outside the switched job reports it, and this is where "outside" is checked
  // rather than asserted in a comment.
  const declaredSwitches = Object.keys(DECLARED)
    .filter((id) => id.includes('#switch:'))
    .map((id) => id.split('#switch:')[1].replace(/^vars\./, ''));
  assert.ok(declaredSwitches.length > 0, 'no declared switches found; the parser or the ids changed shape');

  const watchedVars = WATCHED.map((w) => w.switchVar);
  for (const sw of declaredSwitches) {
    assert.ok(watchedVars.includes(sw),
      `${sw} is declared as an acceptable switch but WATCHED does not list it, so nothing reports it while it is off. `
      + 'That is exactly how the heartbeat went quiet for three days.');
  }
});

test('every watched guard names a job that exists in the workflow it names', () => {
  // A watcher that looks for a job name nobody uses any more finds nothing and
  // reports nothing, which reads identically to "all is well".
  for (const w of WATCHED) {
    const file = wfPath(w.workflow);
    assert.ok(fs.existsSync(file), `WATCHED names ${w.workflow}, which does not exist`);
    const wf = parseWorkflow(file);
    const names = wf.jobs.map((j) => j.keys.name && j.keys.name.replace(/^['"]|['"]$/g, ''));
    assert.ok(names.includes(w.job),
      `WATCHED expects a job called "${w.job}" in ${w.workflow}, which has ${JSON.stringify(names)}. `
      + 'The watcher would look for a job that is not there and find nothing to complain about.');
    assert.match(wf.jobs.map((j) => j.ifExpr).join(' '), new RegExp(`vars\\.${w.switchVar}`),
      `${w.workflow} no longer reads vars.${w.switchVar}; the watcher is watching a switch that is gone`);
  }
});

test('the watchdog has no off switch of its own', () => {
  for (const name of NO_SWITCH_WORKFLOWS) {
    const wf = parseWorkflow(wfPath(name));
    for (const job of wf.jobs) {
      assert.doesNotMatch(job.ifExpr, /\b(vars|secrets)\./,
        `${name} job "${job.id}" is gated on a variable or a secret. The thing that reports a switched-off guard may not itself be switchable.`);
    }
    for (const need of ['schedule', 'pull_request']) {
      assert.ok(wf.triggers.has(need), `${name} lost its ${need} trigger`);
    }
  }
});

test('a piped gate sets pipefail, so a failure on the left of the pipe is not swallowed', () => {
  // Four gates in test.yml pipe a test runner into tee and then grep the log.
  // Under `bash -e`, which is what GitHub runs, the exit code of a pipeline is
  // the LAST command's, and tee always succeeds. Every one of them writes
  // `set -o pipefail` by hand today; this is what keeps it that way.
  const found = findSilencers(readWorkflows()).filter((f) => f.kind === 'pipe-without-pipefail');
  assert.deepEqual(found.map((f) => f.id), [], found.map((f) => f.detail).join('\n'));
});

test('the RAM guard trips before the kernel does', () => {
  // relay.js:1356 refuses an upload above RAM_LIMIT_MB + RAM_RESERVE_MB, and the
  // container is killed at its cgroup limit. Set the sum at or above that limit
  // and the branch is dead code: the relay never says "at capacity", it vanishes
  // mid-upload. relay-health shipped that way, 8192 + 512 inside a cap of 8192.
  assert.deepEqual(checkRamGuards(), []);
});

test('the gitleaks allowlist narrows a rule instead of switching off a file', () => {
  // gitleaks accepts `condition = "AND"` and then ignores it, in every version
  // this repo has run including the pinned 8.28.0. So `paths` beside `regexes`
  // does not narrow the allowlist, it widens it to the whole file, and a real
  // key dropped into that file goes unreported. The rule was written down as a
  // comment in .gitleaks.toml; this is the same rule as something that fails.
  const toml = fs.readFileSync(path.join(ROOT, '.gitleaks.toml'), 'utf8');
  const code = toml.split('\n').filter((l) => !l.trim().startsWith('#')).join('\n');
  assert.doesNotMatch(code, /^\s*paths\s*=/m,
    'a `paths` entry in .gitleaks.toml allowlists the whole file rather than narrowing the rule');
  assert.doesNotMatch(code, /^\s*\[allowlist\]\s*$/m,
    'the singular [allowlist] table is the one older gitleaks silently ignores; use [[allowlists]]');
  assert.match(code, /\[\[allowlists\]\]/, 'the allowlists are gone entirely, which is a different bug');
});

test('every invariant holds on the repository as it stands', () => {
  assert.deepEqual(checkInvariants(), []);
});

// The sabotage cases. Each one switches off the thing a check guards and proves
// the check goes red, because a check that has never been seen to fail is a
// check nobody has tested.
test('sabotage: an undeclared switch on a job is caught', () => {
  const wf = parseWorkflow(wfPath('csp-inline-check.yml'));
  // csp-inline-check has no switch today. Give it one, in memory.
  wf.jobs[0].ifExpr = "vars.CSP_CHECK_ENABLED == 'true'";
  const found = findSilencers([wf]);
  const hit = found.find((f) => f.kind === 'switch');
  assert.ok(hit, 'a job gated on a repository variable must be reported');
  assert.ok(!(hit.id in DECLARED), 'and it must not already be declared');
});

test('sabotage: an unsettled continue-on-error is caught', () => {
  const wf = parseWorkflow(wfPath('sign-e2e.yml'));
  const job = wf.jobs[0];
  job.steps[job.steps.length - 1].keys['continue-on-error'] = 'true';
  const found = findSilencers([wf]).filter((f) => f.kind === 'unsettled-soft-failure');
  assert.equal(found.length, 1,
    'a continue-on-error step whose outcome nothing reads must be reported: its failure ends the job green');
});

test('sabotage: a settled continue-on-error is not reported', () => {
  // The other direction. heartbeat.yml uses continue-on-error three times and
  // settles all three; security-posture.yml settles its one by re-deriving the
  // verdict from the evidence under `if: always()`. A gate that cannot tell
  // those apart would be turned off within a week.
  const found = findSilencers([parseWorkflow(wfPath('security-posture.yml'))]);
  assert.deepEqual(found.filter((f) => f.kind === 'unsettled-soft-failure'), []);
});

test('sabotage: the RAM guard check goes red when the threshold passes the cap', () => {
  const original = fs.readFileSync(path.join(ROOT, 'docker-compose.yml'), 'utf8');
  const broken = original.replace(/RAM_LIMIT_MB: "6656"/, 'RAM_LIMIT_MB: "8192"');
  assert.notEqual(broken, original, 'the sabotage did not apply; the value moved');
  const tmp = path.join(ROOT, 'docker-compose.sabotage.tmp.yml');
  try {
    fs.writeFileSync(tmp, broken);
    const problems = checkRamGuards(tmp);
    assert.equal(problems.length, 1, 'the unreachable RAM guard must be reported');
    assert.match(problems[0], /relay-health/);
    assert.match(problems[0], /8704 MB, but the container is capped at 8192 MB/);
  } finally {
    fs.rmSync(tmp, { force: true });
  }
});

test('sabotage: a pipe that loses its pipefail is caught', () => {
  const wf = parseWorkflow(wfPath('test.yml'));
  const job = wf.jobs.find((j) => j.id === 'admin-unit-tests');
  const step = job.steps.find((s) => /pipefail/.test(s.run));
  assert.ok(step, 'expected a piped gate with pipefail in admin-unit-tests');
  step.run = step.run.replace(/set -o pipefail/, '');
  const found = findSilencers([wf]).filter((f) => f.kind === 'pipe-without-pipefail');
  assert.equal(found.length, 1, 'a piped gate without pipefail reports the exit code of tee, which always succeeds');
});

test('a "not 500" check fails when there was no response at all', () => {
  // curl writes %{http_code} as 000 when nothing answered, and "000" is not
  // "500", so the ten check_not assertions in tests/auth-smoke.sh reported PASS
  // for a route that never replied. That script is the post-deploy and
  // post-rollback gate, so the check that should catch a broken route was
  // green precisely when the route was at its most broken.
  //
  // The real function is extracted from the file rather than restated here: a
  // copy of the logic would keep passing after the original was changed back.
  const src = fs.readFileSync(path.join(ROOT, 'tests', 'auth-smoke.sh'), 'utf8');
  const fn = /^check_not\(\) \{$[\s\S]*?^\}$/m.exec(src);
  assert.ok(fn, 'check_not() could not be found in tests/auth-smoke.sh');

  const drive = (code) => {
    return execFileSync('bash', ['-c', `PASS=0; FAIL=0; FAILURES=""
${fn[0]}
check_not 'x not 500' '${code}' '500'
echo "FAIL=$FAIL"`], { encoding: 'utf8' });
  };

  assert.match(drive('000'), /FAIL=1/, 'no response at all must fail, not pass for not being a 500');
  assert.match(drive(''), /FAIL=1/, 'an empty status must fail too');
  assert.match(drive('500'), /FAIL=1/, 'the case it was written for must still fail');
  assert.match(drive('401'), /FAIL=0/, 'a real answer that is not the bad one must still pass');
});

console.log('\nguards-can-fire: every silencer declared, every declared switch watched from outside, and each check seen to go red');
