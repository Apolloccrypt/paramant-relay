// ParaID document tier: read the passport machine-readable zone with the camera,
// validate its check digits, and upgrade the credential from presence to
// substantial with a real age_over_18 and nationality. Only those two attributes
// are ever sealed; the name, birthdate and document number stay on the device.
import { ml_dsa65, sha3_256 } from '/vendor/paramant-pqc.js';
import { parseTD3, ageFromMrzDob } from '/js/mrz.js';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const b64 = (u8) => btoa(String.fromCharCode(...u8));
const b64url = (u8) => b64(u8).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64 = (s) => new Uint8Array([...atob(s)].map((c) => c.charCodeAt(0)));
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

// Reuse the wallet's device holder key so the substantial credential binds to
// the same device the presence check was on.
function loadHolder() {
  try { const s = JSON.parse(localStorage.getItem('paraid.holder.v1')); if (s) return { publicKey: fromB64(s.pk), secretKey: fromB64(s.sk) }; } catch {}
  const kp = ml_dsa65.keygen(rand(32));
  localStorage.setItem('paraid.holder.v1', JSON.stringify({ pk: b64(kp.publicKey), sk: b64(kp.secretKey) }));
  return kp;
}
function holderBinding(kp) { return b64url(sha3_256(kp.publicKey)); }
function livenessPassed() {
  try { const r = JSON.parse(localStorage.getItem('paraid.liveness.v1')); return !!(r && r.passed); } catch { return false; }
}

let stream = null;
async function startCamera() {
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment', width: { ideal: 1280 } }, audio: false });
    const v = $('doc-video'); v.srcObject = stream; await v.play().catch(() => {});
    $('doc-cam-hint').textContent = 'Hold the passport photo page so the two long lines at the bottom fill the guide, then read them off and type or paste them below.';
  } catch (e) {
    $('doc-cam-hint').textContent = 'Camera unavailable (' + (e.message || e) + '). You can still type the two MRZ lines below.';
  }
}

function validateAndShow() {
  const l1 = $('doc-mrz1').value.trim();
  const l2 = $('doc-mrz2').value.trim();
  const r = parseTD3(l1, l2);
  const out = $('doc-validate');
  out.hidden = false;
  if (!r.valid) {
    out.className = 'doc-validate err';
    out.innerHTML = '<b>Not accepted.</b><br>' + (r.errors || []).map(esc).join('<br>') + '<br><span class="doc-dim">A single misread character fails a check digit. Re-read the lines and try again.</span>';
    $('doc-issue').disabled = true;
    return null;
  }
  const age = ageFromMrzDob(r.fields.dob, new Date());
  out.className = 'doc-validate ok';
  out.innerHTML = '<b>&#10003; MRZ internally consistent</b> (all check digits pass)<br>' +
    'Derived on this device: <b>18 or older: ' + (age >= 18 ? 'yes' : 'no') + '</b>, nationality <b>' + esc(r.fields.nationality) + '</b>.<br>' +
    '<span class="doc-dim">Read but NOT sent: name (' + esc(r.fields.surname) + '), birthdate, document number.</span>';
  $('doc-issue').disabled = !livenessPassed();
  if (!livenessPassed()) out.innerHTML += '<br><span class="doc-warn">Complete the separate <a href="/liveness?return=/paraid-document">browser presence step</a> first. It does not verify the document holder.</span>';
  return { l1, l2, r, age };
}

async function issue() {
  const v = validateAndShow();
  if (!v) return;
  const kp = loadHolder();
  $('doc-status').textContent = 'Asking the registered issuer to sign the MRZ-derived claims...';
  try {
    const resp = await fetch('/v1/paraid/issue-document', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ holder_binding: holderBinding(kp), mrz_line1: v.l1, mrz_line2: v.l2 }),
    });
    if (!resp.ok) { const e = await resp.json().catch(() => ({})); throw new Error(e.error || ('issuance failed (' + resp.status + ')')); }
    const { credential } = await resp.json();
    localStorage.setItem('paraid.credential.v1', JSON.stringify(credential));
    localStorage.setItem('paraid.identity.v1', JSON.stringify({ verified: true, method: 'document', tier: 'substantial' }));
    if (stream) { stream.getTracks().forEach((t) => t.stop()); stream = null; }
    $('doc-status').innerHTML = '<b>Done.</b> Your wallet now holds a credential recording age_over_18 = ' + esc(credential.fields.age_over_18) + ' and nationality = ' + esc(credential.fields.nationality) + ' as derived from the entered MRZ data. This is not a document-authenticity result.';
    $('doc-done').hidden = false;
  } catch (e) { $('doc-status').textContent = 'Could not issue: ' + (e.message || e); }
}

document.addEventListener('DOMContentLoaded', () => {
  if (!livenessPassed()) $('doc-liveness-warn').hidden = false;
  $('doc-start-cam').addEventListener('click', startCamera);
  $('doc-mrz1').addEventListener('input', validateAndShow);
  $('doc-mrz2').addEventListener('input', validateAndShow);
  $('doc-validate-btn').addEventListener('click', validateAndShow);
  $('doc-issue').addEventListener('click', issue);
});
