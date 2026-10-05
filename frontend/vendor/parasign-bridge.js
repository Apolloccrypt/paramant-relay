// ParaSign bridge: exposes the ESM ml-dsa65 + sha3_256 (paramant-pqc) and
// vault helpers (vault.js) to non-module inline scripts. Same-origin only.
//
// Non-module callers wait with `await ready.when('parasign')`. That signal is
// sticky, so it resolves whether the caller runs before or after this file — a
// plain event here would be lost exactly like the mlkem one was, see
// frontend/js/ready.js. A page loading this file must also load /js/ready.js;
// tests/frontend-loading-contract.test.mjs enforces that.
//
// No page currently loads this bridge (sign-flow.js dropped it and only the
// comment stayed behind), but the file is served on production, so it is kept
// working rather than left as a trap for the next caller.
import { ml_dsa65, sha3_256 } from '/vendor/paramant-pqc.js';
import { vaultAvailable, vaultList } from '/vendor/vault.js?v=5';

window.__parasign = { ml_dsa65, sha3_256, vaultAvailable, vaultList };
window.ready.signal('parasign', window.__parasign);
