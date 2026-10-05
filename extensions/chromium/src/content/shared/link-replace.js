// link-replace.js — re-exports the shared, framework-agnostic link builder so the Gmail and
// Outlook content scripts and the Outlook add-in all emit identical, escaped link markup.
export { buildLinkHtml, escapeHtml, formatExpiry } from '../../../../shared/link-block.js';
