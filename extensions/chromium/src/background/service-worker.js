import {
  getCapabilities,
  loginWithApiKey,
  loginWithTotp,
  verifySession,
  logout,
  uploadFile,
} from './auth-client.js';

// ── Message router ────────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  switch (msg.type) {
    case 'GET_CAPABILITIES':
      getCapabilities().then(sendResponse);
      return true;

    case 'CHECK_SESSION':
      verifySession().then(sendResponse);
      return true;

    case 'LOGIN_APIKEY':
      loginWithApiKey(msg.apikey).then(sendResponse);
      return true;

    case 'LOGIN_TOTP':
      loginWithTotp(msg.email, msg.totp).then(sendResponse);
      return true;

    case 'LOGOUT':
      logout().then(() => broadcastAuthState()).then(sendResponse);
      return true;

    case 'UPLOAD_FILE':
      uploadFile(msg.fileData, msg.metadata).then(sendResponse);
      return true;
  }
});

// ── Auth state broadcast ──────────────────────────────────────────────────────

async function broadcastAuthState() {
  const tabs = await chrome.tabs.query({
    url: [
      'https://mail.google.com/*',
      'https://outlook.live.com/*',
      'https://outlook.office.com/*',
      'https://outlook.office365.com/*',
    ],
  });

  const state = await verifySession();
  for (const tab of tabs) {
    chrome.tabs.sendMessage(tab.id, { type: 'AUTH_STATE_CHANGED', state }).catch(() => {});
  }
}

chrome.runtime.onInstalled.addListener(broadcastAuthState);
