'use strict';
// Catalogue for the /developer operations dashboard. Source of truth for the
// descriptions is paramant-solutions/tools/. Pure data + a couple of pure
// helpers so it is unit-testable without booting the server. The tools are not
// on PyPI yet (known-issue C9): `install` reflects that honestly.
//
// `usage` carries a {KEY} placeholder the frontend fills with the developer's
// real pgp_ key (already revealable via /api/user/account/key, behind the gate).

const SOURCE_BASE = 'https://github.com/Apolloccrypt/paramant-solutions/tree/main/tools';

const DEVELOPER_TOOLS = [
  { name: 'paramant-dev-transfer',  category: 'transfer', tagline: 'WeTransfer for the terminal — send a file, get a token.',
    usage: 'PARAMANT_API_KEY={KEY} paramant-dev-transfer send report.pdf' },
  { name: 'paramant-s3-migrate',    category: 'migrate',  tagline: 'Move an S3 object to a device, encrypted, no copy left behind.',
    usage: 'PARAMANT_API_KEY={KEY} paramant-s3-migrate s3://bucket/key --to bob' },
  { name: 'paramant-db-backup',     category: 'backup',   tagline: 'Off-site database backups, encrypted before they leave the box.',
    usage: 'PARAMANT_API_KEY={KEY} paramant-db-backup --pg mydb --to backups' },
  { name: 'paramant-git-archive',   category: 'archive',  tagline: 'Send a repo snapshot at any ref, encrypted, without a remote.',
    usage: 'PARAMANT_API_KEY={KEY} paramant-git-archive HEAD --to teammate' },
  { name: 'paramant-docker-migrate',category: 'migrate',  tagline: 'Move a Docker volume to another host, encrypted.',
    usage: 'PARAMANT_API_KEY={KEY} paramant-docker-migrate my-volume --to host2' },
  { name: 'paramant-secrets-sync',  category: 'sync',     tagline: 'Team secrets sync without a cloud vault.',
    usage: 'PARAMANT_API_KEY={KEY} paramant-secrets-sync push .env --to team' },
  { name: 'paramant-ci-artifact',   category: 'ship',     tagline: 'Ship CI/CD build artifacts, encrypted, from the pipeline.',
    usage: 'PARAMANT_API_KEY={KEY} paramant-ci-artifact dist/ --to release' },
  { name: 'paramant-log-ship',      category: 'ship',     tagline: 'Tamper-evident log shipping — ML-DSA-65-signed batches to the SIEM.',
    usage: 'PARAMANT_API_KEY={KEY} paramant-log-ship /var/log/app.log --to siem' },
  { name: 'paramant-package-sign',  category: 'sign',     tagline: 'Code-sign a release artifact with post-quantum ML-DSA-65.',
    usage: 'PARAMANT_API_KEY={KEY} paramant-package-sign app-1.0.tgz' },
  { name: 'paramant-db-replicate',  category: 'replicate',tagline: 'Cross-region database replication, post-quantum encrypted.',
    usage: 'PARAMANT_API_KEY={KEY} paramant-db-replicate --pg mydb --to dr-region' },
].map((t) => ({
  ...t,
  // Honest install: not published to PyPI yet (C9) — clone + editable install.
  install: `git clone https://github.com/Apolloccrypt/paramant-solutions && pip install -e paramant-solutions/tools/${t.name}`,
  source: `${SOURCE_BASE}/${t.name}`,
}));

// Audit-event types this dashboard treats as a "tool run" for status/stats.
// None are emitted yet (tools are not wired to the per-user audit) — so every
// tool reads as "never used" today. Honest: stats appear once runs are logged.
const TOOL_RUN_TYPES = new Set(['tool_run', 'transfer_sent', 'sign_completed']);

function isToolEvent(ev) {
  return ev && (TOOL_RUN_TYPES.has(ev.event_type) || (ev.metadata && ev.metadata.tool));
}

// Per-tool status from the account's audit events. Pure.
function toolsStatusFromAudit(tools, audit) {
  const out = {};
  const weekAgo = 7 * 24 * 3600 * 1000;
  const nowTsFromAudit = audit.length ? Math.max(...audit.map((e) => e.ts || 0)) : 0;
  for (const t of tools) {
    const runs = audit.filter((e) => isToolEvent(e) && (e.metadata?.tool === t.name || e.event_type === t.name));
    if (!runs.length) { out[t.name] = { state: 'never_used', last_run: null, runs_week: 0, success_rate: null, avg_ms: null }; continue; }
    const week = runs.filter((e) => nowTsFromAudit - (e.ts || 0) <= weekAgo);
    const ok = week.filter((e) => e.metadata?.result !== 'fail').length;
    const durs = week.map((e) => e.metadata?.duration_ms).filter((n) => typeof n === 'number');
    out[t.name] = {
      state: 'idle',
      last_run: Math.max(...runs.map((e) => e.ts || 0)),
      runs_week: week.length,
      success_rate: week.length ? Math.round((ok / week.length) * 100) : null,
      avg_ms: durs.length ? Math.round(durs.reduce((a, b) => a + b, 0) / durs.length) : null,
    };
  }
  return out;
}

module.exports = { DEVELOPER_TOOLS, isToolEvent, toolsStatusFromAudit, SOURCE_BASE };
