/**
 * WebSocket streaming example.
 *
 * Two patterns:
 *   stream  — async generator, yields all events for this device
 *   listen  — wait for a specific transfer hash to arrive
 *
 * In one terminal:  node streaming.mjs stream
 * In another:       node streaming.mjs send
 */

import { GhostPipe } from 'paramant-sdk';

const API_KEY  = 'pgp_xxx';
const DEVICE   = 'ws-listener-001';
const SENDER   = 'ws-sender-001';

const [, , cmd, arg] = process.argv;

async function streamAll() {
  const gp = new GhostPipe({ apiKey: API_KEY, device: DEVICE });
  console.log(`Streaming events for device: ${DEVICE}`);
  console.log('Press Ctrl+C to stop.\n');

  for await (const event of gp.stream()) {
    console.log(`[${event.type ?? 'event'}]`, JSON.stringify(event, null, 2));
    await gp.ack(event.id);
  }
}

async function waitForTransfer(hash) {
  const gp = new GhostPipe({ apiKey: API_KEY, device: DEVICE });
  console.log(`Waiting for transfer: ${hash}`);

  await gp.listen(hash, async (event) => {
    const data = await gp.receive(hash);
    console.log(`Received ${data.length} bytes: ${new TextDecoder().decode(data)}`);
  });
}

async function sendPayload() {
  const gp = new GhostPipe({ apiKey: API_KEY, device: SENDER });
  const h = await gp.send(
    new TextEncoder().encode('WebSocket test payload'),
    { recipient: DEVICE }
  );
  console.log(`Sent — hash: ${h}`);
}

switch (cmd) {
  case 'stream': await streamAll();              break;
  case 'listen': await waitForTransfer(arg);     break;
  case 'send':   await sendPayload();            break;
  default:
    console.log('Commands: stream | send | listen <hash>');
}
