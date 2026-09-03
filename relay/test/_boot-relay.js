'use strict';
// Booting relay.js as a black box, for the three suites that do exactly that:
// inbound-hash-verify, deep-health-gate and billing-stance-boot.
//
// WHY THIS FILE EXISTS. test.yml runs those three in ONE `node --test`
// invocation, so they run as three parallel processes, and every one of them
// used to derive its port from its own pid:
//
//   deep-health-gate      34500 / 34900 / 35300 + (pid % 400)
//   billing-stance-boot   34900 + (pid % 400) + (number of children so far)
//   inbound-hash-verify   34000 + (pid % 5000)
//
// Siblings started by the same runner get near-consecutive pids, so the second
// and third windows overlap the first often enough to matter, and the last one
// covers both. Run 33695615761 on main (c85e542) went red in the "relay -
// crypto suite" job on deep-health-gate's "ghost_pipe without
// INTERNAL_AUTH_TOKEN" with "relay did not become healthy in time". A relay
// that finds its port taken dies on EADDRINUSE within a second, but stdio was
// 'ignore', so nothing recorded that. All the suite could report was that
// /health never answered, which reads like a slow boot and sent everyone
// looking at the wrong thing.
//
// Three changes, and they are really one fix plus the diagnosis it needed:
//
//   1. PORT FROM THE OS. freeRelayPort() binds :0 on 127.0.0.1, reads the port
//      back and closes. No pid arithmetic, so two boots in the same run cannot
//      land on the same number. There is a theoretical gap between the close
//      and the child's own bind; nothing else in this run takes random ports,
//      and if it ever does lose that race the message now says EADDRINUSE.
//
//   2. THE OUTPUT IS KEPT. Both pipes are drained and the last 2 KB of each is
//      held. A boot that fails puts the exit code, the signal and those tails
//      in the Error, so EADDRINUSE, a missing module or a bad env read as
//      themselves instead of as a timeout. BOTH streams, not just stderr: the
//      relay's structured logger writes to stdout, so the fatal line for a
//      taken port is {"level":"error","msg":"listen EADDRINUSE ...","code":
//      "EADDRINUSE"} on stdout, followed by shutdown_clean. A helper that kept
//      only stderr would have shown an empty tail for exactly the failure this
//      file exists to explain.
//
//   3. 40s, NOT 15s. In the crypto job this step runs straight after the Rust
//      build of @paramant/core, and a cold runner regularly needs more than 15s
//      to get a relay listening. The deadline only costs time on a run that was
//      going to fail anyway.
//
// Deliberately NOT here: the scratch dirs, the users.json handling and the
// request helper of _relay-server.js. Those three suites each carry their own
// env on purpose (billing-stance-boot boots with real-looking Mollie keys, and
// _relay-server.js strips exactly those), so this stays a spawn and a wait.
// A suite that tests routes rather than the boot itself wants _relay-server.js.

const { spawn } = require('child_process');
const net = require('net');
const path = require('path');

const BOOT_RELAY_DIR = path.join(__dirname, '..');
// How long a boot gets, whether the suite waits for /health or for a log
// line. See point 3 above.
const BOOT_TIMEOUT_MS = 40000;
// Per stream. Enough for a stack trace and the boot log around it.
const BOOT_TAIL_BYTES = 2048;

// Every child this module spawned, so a suite's after() hook kills the lot even
// when a test threw before its own cleanup ran.
const _booted = new Set();

// The env all three suites already shared, before their own extras. Kept here
// so the shape of a test relay is stated once: no redis, no NATS, no api keys.
function bootRelayBaseEnv(port) {
  return {
    ...process.env,
    PORT: String(port),
    USERS_JSON: '{"api_keys":[]}',
    RELAY_REDIS_URL: '',
    NATS_URL: '',
  };
}

// A port the OS just told us is free.
function freeRelayPort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const chosen = srv.address().port;
      srv.close(() => resolve(chosen));
    });
  });
}

// Spawn relay.js on `port`.
//
//   extraEnv     wins over the base env above.
//   opts.unset   env names to delete BEFORE extraEnv is applied, for a suite
//                that must boot with a variable genuinely absent rather than
//                inherited from the developer's shell or the runner.
//   opts.onLine  called with each complete stdout line, for a suite that reads
//                the boot log instead of polling /health.
//
// Returns a handle. Both pipes are drained here, unconditionally: a piped
// stream nobody reads fills its buffer and stalls the child.
function spawnRelay(port, extraEnv, opts = {}) {
  const env = bootRelayBaseEnv(port);
  for (const name of opts.unset || []) delete env[name];
  Object.assign(env, extraEnv || {});

  const child = spawn(process.execPath, ['relay.js'], {
    cwd: BOOT_RELAY_DIR,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  _booted.add(child);

  const handle = {
    child,
    port,
    base: `http://127.0.0.1:${port}`,
    exitCode: null,
    exitSignal: null,
    exited: false,
    stdoutTail: '',
    stderrTail: '',
    // Both tails, labelled, for an error message. Says so when a stream stayed
    // empty: "no stderr" is itself a clue that the child never got that far.
    output() {
      return `  stderr tail: ${handle.stderrTail ? `\n${handle.stderrTail}` : '(empty)'}\n` +
             `  stdout tail: ${handle.stdoutTail ? `\n${handle.stdoutTail}` : '(empty)'}`;
    },
    kill() {
      _booted.delete(child);
      try { child.kill('SIGKILL'); } catch (_) { /* already gone */ }
    },
  };

  let pending = '';
  child.stdout.on('data', (d) => {
    const text = d.toString();
    handle.stdoutTail = (handle.stdoutTail + text).slice(-BOOT_TAIL_BYTES);
    if (!opts.onLine) return;
    pending += text;
    const lines = pending.split('\n');
    pending = lines.pop();
    for (const line of lines) opts.onLine(line);
  });
  child.stderr.on('data', (d) => {
    handle.stderrTail = (handle.stderrTail + d.toString()).slice(-BOOT_TAIL_BYTES);
  });
  child.on('exit', (code, signal) => {
    handle.exited = true;
    handle.exitCode = code;
    handle.exitSignal = signal;
  });
  child.on('error', (e) => {
    handle.stderrTail = (handle.stderrTail + `spawn error: ${e.message}\n`).slice(-BOOT_TAIL_BYTES);
  });

  return handle;
}

// A one-line "how did this boot end" for an error message.
function bootRelayExitLine(handle) {
  if (!handle.exited) return 'still running';
  return `exited code=${handle.exitCode} signal=${handle.exitSignal}`;
}

// Poll /health until it answers, the child dies, or the deadline passes. Every
// failure carries the exit state and both output tails: the point of this
// helper is that a boot never fails silently again.
async function waitRelayHealthy(handle, timeoutMs = BOOT_TIMEOUT_MS) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (handle.exited) {
      throw new Error(
        `relay.js exited before /health answered on port ${handle.port} ` +
        `(${bootRelayExitLine(handle)})\n${handle.output()}`);
    }
    try {
      const r = await fetch(`${handle.base}/health`);
      // A healthy answer is only OUR relay's answer while our child is alive.
      // On a port collision the other process answers too, and a suite that
      // takes that for its own boot goes green having asserted against someone
      // else's relay. That is the quiet half of the same bug.
      if (r.ok && !handle.exited) return handle;
    } catch (_) { /* not listening yet */ }
    if (Date.now() > deadline) {
      throw new Error(
        `relay.js did not become healthy on port ${handle.port} within ${timeoutMs}ms ` +
        `(${bootRelayExitLine(handle)})\n${handle.output()}`);
    }
    await new Promise((r) => setTimeout(r, 250));
  }
}

// freeRelayPort + spawnRelay + waitRelayHealthy, for the common case.
async function bootHealthyRelay(extraEnv, opts = {}) {
  const handle = spawnRelay(await freeRelayPort(), extraEnv, opts);
  await waitRelayHealthy(handle, opts.timeoutMs);
  return handle;
}

// Call from a suite's after() hook. SIGKILL, which is what these three suites
// have always used: they assert on a boot, not on a shutdown, and none of them
// runs under coverage. A suite that needs the clean SIGTERM exit (and the V8
// coverage profile that comes with it) wants _relay-server.js instead.
function killSpawnedRelays() {
  for (const c of _booted) {
    try { c.kill('SIGKILL'); } catch (_) { /* already gone */ }
  }
  _booted.clear();
}

module.exports = {
  BOOT_TIMEOUT_MS,
  BOOT_RELAY_DIR,
  bootHealthyRelay,
  freeRelayPort,
  killSpawnedRelays,
  spawnRelay,
  waitRelayHealthy,
};
