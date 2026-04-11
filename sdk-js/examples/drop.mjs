/**
 * Anonymous drop (BIP39) example.
 *
 * No API key required. Sender gets a 12-word mnemonic.
 * Receiver uses the mnemonic — no account needed.
 *
 *   node drop.mjs drop                  → drop some data, print mnemonic
 *   node drop.mjs pickup "<mnemonic>"   → retrieve it
 */

import { GhostPipe } from 'paramant-sdk';
import { readFileSync } from 'fs';

const [, , cmd, ...rest] = process.argv;
const gp = new GhostPipe({ apiKey: '', device: '' });

async function dropData() {
  const payload = new TextEncoder().encode('Secret document — anonymous drop');
  const { mnemonic, hash } = await gp.drop(payload, { ttl: 86400 });
  console.log('=== ANONYMOUS DROP ===');
  console.log(`Hash:     ${hash}`);
  console.log(`Mnemonic: ${mnemonic}`);
  console.log('');
  console.log('Give the mnemonic to your contact via a secure channel.');
  console.log('They retrieve it with:');
  console.log(`  node drop.mjs pickup "${mnemonic}"`);
}

async function pickupData(mnemonic) {
  const data = await gp.pickup(mnemonic);
  console.log(`Retrieved ${data.length} bytes:`);
  console.log(new TextDecoder().decode(data));
}

if (cmd === 'drop') {
  await dropData();
} else if (cmd === 'pickup') {
  const mnemonic = rest.join(' ');
  if (!mnemonic) {
    console.error('Usage: node drop.mjs pickup "<12-word mnemonic>"');
    process.exit(1);
  }
  await pickupData(mnemonic);
} else {
  console.log('Commands: drop | pickup "<mnemonic>"');
}
