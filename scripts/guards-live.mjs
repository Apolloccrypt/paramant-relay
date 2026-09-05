// Are the guards actually running? The half of the question only live state can
// answer.
//
// scripts/check-guards.mjs reads the workflow files and proves that every way a
// guard could be silenced is declared and watched. It cannot tell whether the
// switch is on today, or whether the job behind it has actually produced a run.
// That is what this does, from OUTSIDE the jobs it watches, which is the part
// that was missing:
//
//   heartbeat.yml has an alarm, and the alarm is a step inside the job that a
//   repository variable switches off. With the variable unset the job is
//   skipped, `if: failure()` never fires, and the one thing that could report
//   the silence is silenced by the same switch. Nineteen scheduled runs in a
//   row came back "skipped", which GitHub renders grey and notifies nobody
//   about, and nothing anywhere went red for three days.
//
// security-posture.yml is the same shape with a worse disguise: only its
// production job is switched off, so the run as a whole still reports "success"
// off the back of the self-test job that always passes.
//
// So this asks about the JOB, not the run. A workflow that is green because the
// only job that did anything was the one testing itself is not a guard.
//
//   node scripts/guards-live.mjs              report, exit 0
//   GUARDS_ENFORCE=1 node scripts/guards-live.mjs   exit 1 on a silent guard
//
// Enforcing is on for the scheduled run and off for a pull request. Not to be
// lenient: while HEARTBEAT_ENABLED is off, and only Mick can turn it on, a
// hard failure on every pull request would block work on a thing no pull
// request can fix, and a check that is always red is one people route around.
// The scheduled run costs an open issue and a red run once a day instead, which
// is a signal that survives being ignored for a week.

import { WATCHED } from './check-guards.mjs';

const REPO = process.env.GITHUB_REPOSITORY || 'Apolloccrypt/paramant-relay';
const TOKEN = process.env.GH_TOKEN || process.env.GITHUB_TOKEN || '';

async function api(pathname) {
  const res = await fetch(`https://api.github.com${pathname}`, {
    headers: {
      accept: 'application/vnd.github+json',
      'x-github-api-version': '2022-11-28',
      ...(TOKEN ? { authorization: `Bearer ${TOKEN}` } : {}),
    },
  });
  if (!res.ok) throw new Error(`GET ${pathname} -> ${res.status} ${res.statusText}`);
  return res.json();
}

const hoursSince = (iso) => (Date.now() - Date.parse(iso)) / 3600000;
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

// The state of one watched guard, read from the runs API.
async function inspect(guard) {
  const state = {
    ...guard,
    switchOn: (process.env[`SWITCH_${guard.switchVar}`] || '').trim() === 'true',
    lastGoodRun: null,
    lastGoodAgeH: null,
    skippedStreak: 0,
    jobConclusion: null,
    problems: [],
  };

  const { workflow_runs: runs = [] } = await api(
    `/repos/${REPO}/actions/workflows/${guard.workflow}/runs?event=schedule&per_page=30`,
  );

  // The newest scheduled run whose WATCHED JOB actually reached a conclusion.
  // Deliberately not the run's own conclusion: security-posture.yml reports
  // "success" for a run in which the production job was skipped and only the
  // self-test ran.
  for (const run of runs) {
    if (run.conclusion === 'skipped') { state.skippedStreak++; continue; }
    break;
  }

  for (const run of runs.slice(0, 8)) {
    let jobs;
    try { ({ jobs } = await api(`/repos/${REPO}/actions/runs/${run.id}/jobs?per_page=30`)); }
    catch { continue; }
    const job = jobs.find((j) => j.name === guard.job);
    if (!job) continue;
    if (state.jobConclusion === null) state.jobConclusion = job.conclusion;
    if (job.conclusion === 'success') {
      state.lastGoodRun = run;
      state.lastGoodAgeH = hoursSince(run.created_at);
      break;
    }
  }

  if (!state.switchOn) {
    state.problems.push(
      `the switch is off: repository variable ${guard.switchVar} is not "true", so every scheduled run of ${guard.workflow} skips the job "${guard.job}". A skipped job is grey, not red, and notifies nobody.`
      + (state.skippedStreak ? ` The last ${plural(state.skippedStreak, 'scheduled run has', 'scheduled runs have')} been skipped.` : ''),
    );
  }
  if (state.lastGoodRun === null) {
    state.problems.push(
      `no scheduled run of "${guard.job}" has succeeded in the last ${runs.length} scheduled runs`
      + (state.jobConclusion ? ` (most recent conclusion: ${state.jobConclusion})` : ' (the job did not run at all)')
      + `. ${guard.what} is not being proved by anything.`,
    );
  } else if (state.lastGoodAgeH > guard.maxAgeHours) {
    state.problems.push(
      `the last successful "${guard.job}" was ${Math.round(state.lastGoodAgeH)} hours ago, and it is expected at least every ${guard.maxAgeHours}. ${guard.what} has been unproved since then.`,
    );
  }
  return state;
}

function render(states) {
  const lines = [];
  const bad = states.filter((s) => s.problems.length);
  lines.push(bad.length
    ? `${plural(bad.length, 'guard is', 'guards are')} not running.`
    : 'Every watched guard has run and passed within its window.');
  lines.push('');
  for (const s of states) {
    lines.push(`### ${s.workflow} - ${s.what}`);
    if (!s.problems.length) {
      lines.push(`- green: last successful "${s.job}" ${Math.round(s.lastGoodAgeH)}h ago, within the ${s.maxAgeHours}h window.`);
    } else {
      for (const p of s.problems) lines.push(`- RED: ${p}`);
      lines.push(`- to turn it on: \`${s.turnOn}\``);
    }
    lines.push('');
  }
  return lines.join('\n');
}

// The two outputs the workflow reads. Written on every path, including the
// failure path: a step that goes red without setting `silent` would leave the
// issue step with an empty body, which is a report that says nothing.
async function emit(silent, body) {
  if (!process.env.GITHUB_OUTPUT) return;
  const { appendFileSync } = await import('node:fs');
  appendFileSync(process.env.GITHUB_OUTPUT, `silent=${silent}\n`);
  appendFileSync(process.env.GITHUB_OUTPUT, `body<<GUARDS_EOF\n${body}\nGUARDS_EOF\n`);
}

async function main() {
  const states = [];
  for (const guard of WATCHED) states.push(await inspect(guard));
  const body = render(states);
  console.log(body);

  const bad = states.filter((s) => s.problems.length);
  await emit(bad.length, body);
  if (bad.length) {
    console.log(`::error title=A guard is not running::${bad.map((s) => s.workflow).join(', ')}: see the summary above.`);
    if (process.env.GUARDS_ENFORCE === '1') process.exitCode = 1;
  }
}

main().catch(async (e) => {
  // A watchdog that cannot reach the API must say so and go red. Answering
  // "nothing to report" because the lookup failed is the failure mode this
  // whole file exists to prevent. It counts as one silent guard so the issue is
  // opened with a body that says what actually happened.
  const body = `The guard watcher could not read the run history, so it does not know whether any guard is running.\n\n- RED: ${e.message}`;
  console.log(body);
  console.log(`::error title=The guard watcher could not run::${e.message}`);
  await emit(1, body);
  process.exitCode = 1;
});
