// Herreview #560, uitrol. With MAIL_PROVIDER empty the relay takes the first
// carrier whose keys are present, and lettermint heads that list: filling in
// LETTERMINT_API_TOKEN would switch carrier silently. The template pins the
// carrier and the runbook says the production .env must do the same.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const ENV = readFileSync(join(ROOT, 'deploy/.env.example'), 'utf8');
const RUNBOOK = readFileSync(join(ROOT, 'RUNBOOK.md'), 'utf8');

test('deploy/.env.example pins MAIL_PROVIDER to a carrier', () => {
  const m = /^MAIL_PROVIDER=(.*)$/m.exec(ENV);
  assert.ok(m, 'MAIL_PROVIDER is set in the template');
  assert.equal(m[1].trim(), 'mailjet');
});

test('RUNBOOK.md: the deploy section says production must carry MAIL_PROVIDER', () => {
  const deploy = RUNBOOK.slice(RUNBOOK.indexOf('## 2. Deploy and rollback'), RUNBOOK.indexOf('## 3.'));
  assert.match(deploy, /`MAIL_PROVIDER=mailjet`/);
  assert.match(deploy, /MAILJET_API_KEY/);
});
