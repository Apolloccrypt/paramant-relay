// banner.js — injected progress + error UI for the content scripts.
// An ES module (bundled into the content script). Styling lives in banner.css.
// All host-supplied text is written with textContent, never innerHTML.

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

// startUpload(filename, { onCancel }) → handle { setProgress, succeed, fail, remove }
export function startUpload(filename, { onCancel } = {}) {
  remove('paramant-upload-ui');

  const root = el('div', 'paramant-upload-ui');
  root.id = 'paramant-upload-ui';
  root.setAttribute('role', 'status');
  root.setAttribute('aria-live', 'polite');

  const spinner = el('span', 'paramant-upload-spinner');
  spinner.setAttribute('aria-hidden', 'true');

  const col  = el('div', 'paramant-upload-col');
  const row  = el('div', 'paramant-upload-row');
  const name = el('span', 'paramant-upload-name');
  name.textContent = filename;
  const pct  = el('span', 'paramant-upload-pct', '0%');

  const cancelBtn = el('button', 'paramant-upload-cancel', '✕');
  cancelBtn.setAttribute('aria-label', 'Cancel');
  if (onCancel) cancelBtn.addEventListener('click', () => onCancel());
  else cancelBtn.style.display = 'none';

  const track = el('div', 'paramant-upload-track');
  const fill  = el('div', 'paramant-upload-fill');
  track.appendChild(fill);

  row.append(name, pct, cancelBtn);
  col.append(row, track);
  root.append(spinner, col);
  document.body.appendChild(root);

  return {
    setProgress(fraction) {
      const p = Math.max(0, Math.min(100, Math.round(fraction * 100)));
      fill.style.width = p + '%';
      pct.textContent = p + '%';
    },
    succeed(message) {
      root.className = 'paramant-upload-ui paramant-upload-success';
      spinner.remove();
      cancelBtn.remove();
      pct.textContent = '✓';
      if (message) name.textContent = message;
      setTimeout(() => root.remove(), 2500);
    },
    fail(message) { root.remove(); showError(message); },
    remove() { root.remove(); },
  };
}

export function showError(message) {
  remove('paramant-upload-ui');
  const root = el('div', 'paramant-upload-ui paramant-upload-error');
  root.setAttribute('role', 'alert');
  root.append(el('span', null, message));
  document.body.appendChild(root);
  setTimeout(() => root.remove(), 5000);
}

function remove(id) {
  document.getElementById(id)?.remove();
}
