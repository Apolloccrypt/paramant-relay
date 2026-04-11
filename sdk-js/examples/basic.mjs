/**
 * Basic send / receive example.
 *
 * Run on two machines (or two terminals):
 *   node basic.mjs setup              → register receiver pubkeys
 *   node basic.mjs send               → send a payload, prints hash
 *   node basic.mjs receive <hash>     → decrypt and print payload
 */

import { GhostPipe } from 'paramant-sdk';

const API_KEY  = 'pgp_xxx';
const SENDER   = 'laptop-001';
const RECEIVER = 'server-001';

const [, , cmd, arg] = process.argv;

async function setup() {
  const gp = new GhostPipe({ apiKey: API_KEY, device: RECEIVER });
  const result = await gp.registerPubkeys();
  console.log(`Receiver registered. Fingerprint: ${result.fingerprint}`);
  console.log('Now run: node basic.mjs send');
}

async function send() {
  const gp = new GhostPipe({ apiKey: API_KEY, device: SENDER });
  const payload = new TextEncoder().encode('Hello from Ghost Pipe!');
  const h = await gp.send(payload, { recipient: RECEIVER });
  console.log(`Transfer hash: ${h}`);
  console.log(`On the receiver, run:`);
  console.log(`  node basic.mjs receive ${h}`);
}

async function receive(hash) {
  const gp = new GhostPipe({ apiKey: API_KEY, device: RECEIVER });
  const data = await gp.receive(hash);
  console.log(`Received ${data.length} bytes: ${new TextDecoder().decode(data)}`);
}

switch (cmd) {
  case 'setup':   await setup();          break;
  case 'send':    await send();           break;
  case 'receive': await receive(arg);     break;
  default:
    console.log('Commands: setup | send | receive <hash>');
}
