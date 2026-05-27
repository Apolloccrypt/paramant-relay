'use strict';
// Audit logging for /admin/cli command execution.
//
// Every command execution emits at least two events:
//   cli_command_started   { command, args, admin_id }
//   cli_command_completed  { command, exit_code, duration_ms, admin_id }
// plus cli_command_denied / cli_command_error for the rejected/failed paths.
//
// Events are kept in a capped in-memory ring (for quick local inspection) and
// forwarded to a permanent sink (the relay CT log) when one is registered via
// setForwarder(). The forwarder is intentionally injected by the server so this
// module stays free of transport/relay coupling.

const { maskArgs } = require('./cli-commands');

const MAX_ENTRIES = 500;
const auditLog = []; // in-memory ring; production record lives in the CT log
let forwarder = null;

// Register an async sink: (entry) => Promise<void>. Errors are swallowed so a
// failing audit sink can never block or break command execution.
function setForwarder(fn) {
  forwarder = typeof fn === 'function' ? fn : null;
}

function logCommand(event, data = {}) {
  const entry = {
    ts: new Date().toISOString(),
    event,
    ...data,
    args: maskArgs(data.args || {}),
  };
  auditLog.push(entry);
  if (auditLog.length > MAX_ENTRIES) auditLog.splice(0, auditLog.length - MAX_ENTRIES);
  if (forwarder) {
    Promise.resolve()
      .then(() => forwarder(entry))
      .catch(err => console.error('[cli-audit] forward failed:', err.message));
  }
  return entry;
}

function getRecent(limit = 50) {
  return auditLog.slice(-limit).reverse();
}

module.exports = { logCommand, setForwarder, getRecent, MAX_ENTRIES };
