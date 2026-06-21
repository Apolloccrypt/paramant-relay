// ParaSign bridge: exposes the ESM ml-dsa65 + sha3_256 (paramant-pqc) and
// vault helpers (vault.js) to non-module inline scripts. Same-origin only.
//
// Non-module callers wait for the 'parasign:ready' CustomEvent (or check
// window.__parasign).
import { ml_dsa65, sha3_256 } from '/vendor/paramant-pqc.js';
import { vaultAvailable, vaultList } from '/vendor/vault.js?v=4';

window.__parasign = { ml_dsa65, sha3_256, vaultAvailable, vaultList };
window.dispatchEvent(new CustomEvent('parasign:ready'));
