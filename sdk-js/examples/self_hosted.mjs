/**
 * Self-hosted relay example.
 *
 * Shows how to point the SDK at your own relay instead of relay.paramant.app.
 */

import { GhostPipe } from 'paramant-sdk';

const API_KEY  = 'pgp_xxx';
const MY_RELAY = 'https://relay.example.com';   // your relay URL

const gp = new GhostPipe({
  apiKey: API_KEY,
  device: 'sender-001',
  relay: MY_RELAY,
});

// Health check
const info = await gp.health();
console.log(`Relay version: ${info.version}  uptime: ${info.uptime}s`);

// Send
const h = await gp.send(
  new TextEncoder().encode('Confidential payload'),
  { recipient: 'receiver-001' }
);
console.log(`Transfer hash: ${h}`);

// Receive
const gp2 = new GhostPipe({
  apiKey: API_KEY,
  device: 'receiver-001',
  relay: MY_RELAY,
});
await gp2.registerPubkeys();
const data = await gp2.receive(h);
console.log(`Got: ${new TextDecoder().decode(data)}`);
