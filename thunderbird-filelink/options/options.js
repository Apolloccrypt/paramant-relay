"use strict";

const apiKeyEl   = document.getElementById("apiKey");
const relayUrlEl = document.getElementById("relayUrl");
const statusEl   = document.getElementById("status");

// Thunderbird passes the account ID as a URL parameter
const accountId = new URLSearchParams(window.location.search).get("accountId");

browser.storage.local.get(["apiKey", "relayUrl"]).then(({ apiKey, relayUrl }) => {
  if (apiKey)   apiKeyEl.value   = apiKey;
  if (relayUrl) relayUrlEl.value = relayUrl;
});

document.getElementById("save").addEventListener("click", async () => {
  const apiKey   = apiKeyEl.value.trim();
  const relayUrl = relayUrlEl.value.trim() || null;

  if (!apiKey) {
    statusEl.textContent = "API key is required.";
    statusEl.className = "status err";
    return;
  }

  await browser.storage.local.set({ apiKey, relayUrl });

  // Tell Thunderbird this account is now configured
  if (accountId) {
    await browser.cloudFile.updateAccount(accountId, { configured: true });
  }

  statusEl.textContent = "Saved.";
  statusEl.className = "status ok";
  setTimeout(() => { statusEl.textContent = ""; }, 2000);
});
