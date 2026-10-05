'use strict';
// A HEAD THE RELAY SERVED MUST BE ON DISK WHEN THE RELAY IS GONE.
//
// WHY THIS SUITE EXISTS. route-ct-persistence proves the transparency log
// survives a restart. It cannot prove that what the relay ANSWERED WITH before
// the restart is what survives, and that gap is where the relay was losing
// data: the append logs were written through an fs.WriteStream, and the exit
// path wrote the queue and called process.exit() in the same tick. A stream
// write is handed to the thread pool; process.exit does not wait for it. So the
// relay served tree_size N over /v2/sth, was stopped, and came back at N-1.
//
// Measured on this branch against the old exit path, forty uploads fired in
// parallel and a normal SIGTERM: 20 runs out of 20 lost heads, worst case 38 of
// 40, and the CT log lost the matching entries. Against the fixed one: 0 of 20.
//
// Two things follow from a lost head, and only one of them is a test problem:
//
//   * route-ct-persistence read it as a fork. It uploads four blobs, reads
//     tree_size 4 off the live relay, restarts, and expects 4 back. When the
//     fourth head never reached the disk the relay came back believing 3 was
//     the largest size it had ever signed, refused the next head as a
//     contradiction, and the suite went red on two unrelated pull requests
//     while staying green on main. That is what a flaky test is FOR, and the
//     right answer is not a longer wait or a retry.
//   * a relay stopped by systemctl lost the tail of its transparency log, in
//     production, with no warning. The receipts issued for those entries stop
//     resolving, exactly as they did before persistence was made the default.
//
// The fix waits on the streams' own 'finish' events (relay.js,
// _flushAppendLogsOnExit), so the assertion here is an equality and not a
// tolerance: everything served is on disk, or the suite is red.
// Run: node --test relay/test/route-ct-exit-durability.test.js

const { test, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { boot, killAll } = require('./_relay-server');
const { summary } = require('./_requires');

// The fixture account's api key. Padded with zeroes on purpose: gitleaks'
// generic-api-key rule fires above 3.7 bits of entropy and a name made of five
// distinct words scores 3.94, so a key that says what it is in words reads as a
// leak. Same shape as the one in route-ct-persistence.
const EXIT_KEY = 'pgp_ct_exit_key_0000000000000001';
const exitUsers = {
  api_keys: [{ key: EXIT_KEY, plan: 'pro', active: true, email: 'sender@example.test', account_id: 'acct_sender' }],
};

// Forty, fired in parallel. The number is not decoration: the queue has to be
// DEEP when the signal lands, because that is the state a runner with twenty
// suites on four cores puts the relay in, and it is the state in which the old
// exit path lost data every single time rather than one run in twenty.
const EXIT_BURST = 40;

let exitChecks = 0;
const exitDid = () => { exitChecks++; };
const exitDirs = [];

function exitScratch(tag) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), `ctexit-${tag}-`));
  exitDirs.push(d);
  return d;
}

function burst(srv, n) {
  return Promise.all(Array.from({ length: n }, (_, i) => {
    const payload = Buffer.from(`burst-${i}-${crypto.randomBytes(8).toString('hex')}`);
    const hash = crypto.createHash('sha256').update(payload).digest('hex');
    return srv.post('/v2/inbound', { headers: { 'X-Api-Key': EXIT_KEY }, body: { hash, payload: payload.toString('base64') } })
      .then((r) => { assert.strictEqual(r.status, 200, `upload ${i}: ${JSON.stringify(r.json)}`); });
  }));
}

const jsonl = (p) => fs.readFileSync(p, 'utf8').split('\n').filter((l) => l.trim());

after(async () => {
  summary('route-ct-exit-durability', exitChecks);
  await killAll();
  for (const d of exitDirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) { /* gone */ } }
});

test('every signed head the relay served is on disk after it is stopped', async () => {
  const dir = exitScratch('heads');
  const srv = await boot({ tag: 'ctexit1', dir, usersFile: true, users: exitUsers });
  await burst(srv, EXIT_BURST);

  // What the relay PUBLISHED. From here on it owes the disk exactly this.
  const served = (await srv.get('/v2/sth')).json.sth;
  assert.strictEqual(served.tree_size, EXIT_BURST, 'all forty appends were signed');
  const history = (await srv.get('/v2/sth/history?limit=1000')).json.sths;
  assert.strictEqual(history.length, EXIT_BURST);

  await srv.stop();   // a plain SIGTERM, the same one systemctl sends

  const onDisk = jsonl(path.join(dir, 'sth-log.jsonl')).map((l) => JSON.parse(l));
  assert.strictEqual(onDisk.length, EXIT_BURST,
    `the relay served ${EXIT_BURST} heads and left ${onDisk.length} on disk. The exit path did not `
    + 'wait for the append stream to reach the fd, so heads it had already published are gone. '
    + 'A receipt for any of them no longer resolves, and the next boot sees a tree that walked '
    + 'backwards and refuses to sign at all.');
  assert.deepStrictEqual(onDisk.map((s) => s.tree_size), history.map((s) => s.tree_size),
    'and in the same order, head for head');
  assert.strictEqual(onDisk[onDisk.length - 1].sha3_root, served.sha3_root,
    'the last head on disk is the last head served, root and all');
  exitDid();
});

test('the transparency log itself keeps its tail through the same shutdown', async () => {
  // The heads are only half of it. A head attests to a tree, and the entries
  // that tree is made of go through the same queue-and-exit path.
  const dir = exitScratch('entries');
  const srv = await boot({ tag: 'ctexit2', dir, usersFile: true, users: exitUsers });
  await burst(srv, EXIT_BURST);
  const size = (await srv.get('/v2/ct/log?from=0&limit=1')).json.size;
  assert.strictEqual(size, EXIT_BURST);
  await srv.stop();
  assert.strictEqual(jsonl(path.join(dir, 'ct-log.json')).length, EXIT_BURST,
    'the CT log on disk is short. Every entry missing here is a receipt that stops resolving.');
  exitDid();
});

test('a restart after a busy shutdown is not read as a fork', async () => {
  // The end of the story route-ct-persistence tells, made deterministic. A lost
  // head is indistinguishable from a relay that walked backwards, so the guard
  // fires, the relay freezes, and nothing about the failure points at the
  // shutdown that caused it.
  const dir = exitScratch('nofork');
  let srv = await boot({ tag: 'ctexit3', dir, usersFile: true, users: exitUsers, captureLog: true });
  await burst(srv, EXIT_BURST);
  const served = (await srv.get('/v2/sth')).json.sth.tree_size;
  await srv.stop();

  srv = await boot({ tag: 'ctexit4', dir, usersFile: true, captureLog: true });
  const back = await srv.get('/v2/sth');
  assert.strictEqual(back.json.sth.tree_size, served,
    'the relay came back at a different tree size than the one it served before the stop');
  assert.ok(!back.json.forked, 'and it does not believe it has forked');

  // It also has to keep WORKING: the tree came back with the heads, so the next
  // append is head 41 and the guard has no reason to fire.
  await burst(srv, 1);
  const grown = await srv.get('/v2/sth');
  assert.strictEqual(grown.json.sth.tree_size, EXIT_BURST + 1, 'and it signs the next head');
  assert.ok(!/"msg":"sth_refused_would_fork"/.test(srv.log()), 'no fork was refused');
  await srv.stop();
  exitDid();
});
