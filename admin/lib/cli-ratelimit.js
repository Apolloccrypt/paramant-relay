'use strict';
// Per-admin rate limit for /admin/cli command execution.
// Sliding window: max LIMIT executions per WINDOW ms.

const buckets = new Map(); // adminId -> number[] (timestamps)
const LIMIT = 30;
const WINDOW = 60_000;

// Returns true if the command is allowed (and records it), false if the
// admin has exceeded LIMIT in the last WINDOW.
function checkRate(adminId) {
  const now = Date.now();
  const bucket = (buckets.get(adminId) || []).filter(t => now - t < WINDOW);
  if (bucket.length >= LIMIT) {
    buckets.set(adminId, bucket);
    return false;
  }
  bucket.push(now);
  buckets.set(adminId, bucket);
  return true;
}

// How many executions remain in the current window (for response headers).
function remaining(adminId) {
  const now = Date.now();
  const bucket = (buckets.get(adminId) || []).filter(t => now - t < WINDOW);
  return Math.max(0, LIMIT - bucket.length);
}

// Periodic cleanup so idle admins don't leak entries.
const sweep = setInterval(() => {
  const now = Date.now();
  for (const [k, v] of buckets) {
    const recent = v.filter(t => now - t < WINDOW);
    if (recent.length === 0) buckets.delete(k);
    else buckets.set(k, recent);
  }
}, WINDOW);
if (sweep.unref) sweep.unref();

module.exports = { checkRate, remaining, LIMIT, WINDOW };
