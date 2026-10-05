'use strict';
// A readable label for a session's user agent: "Safari · iPhone",
// "Chrome · Windows". The account page showed the first word of the raw
// string, which for every browser is "Mozilla/5.0" (ACCT-26). The label has
// no words of one language in it, so the Dutch account page no longer reads
// "Chrome on Linux" (acceptatie 3.1.1, taal #52): the server does not know
// which language the page is in, and a browser and a system need no verb.
function uaLabel(ua) {
  const s = String(ua || '');
  if (!s) return 'Browser';
  let browser = null;
  if (/Edg(?:e|A|iOS)?\//.test(s)) browser = 'Edge';
  else if (/OPR\/|Opera/.test(s)) browser = 'Opera';
  else if (/Firefox\/|FxiOS\//.test(s)) browser = 'Firefox';
  else if (/SamsungBrowser\//.test(s)) browser = 'Samsung Internet';
  else if (/Chrome\/|CriOS\//.test(s)) browser = 'Chrome';
  else if (/Safari\//.test(s) && /Version\//.test(s)) browser = 'Safari';
  else if (/^curl\//i.test(s)) browser = 'curl';
  else if (/python-requests|Go-http-client|node-fetch|undici|axios/i.test(s)) browser = 'Script';
  let os = null;
  if (/iPhone/.test(s)) os = 'iPhone';
  else if (/iPad/.test(s)) os = 'iPad';
  else if (/Android/.test(s)) os = 'Android';
  else if (/Windows NT/.test(s)) os = 'Windows';
  else if (/Mac OS X|Macintosh/.test(s)) os = 'Mac';
  else if (/CrOS/.test(s)) os = 'ChromeOS';
  else if (/Linux/.test(s)) os = 'Linux';
  if (browser && os) return `${browser} · ${os}`;
  if (browser || os) return browser || os;
  return s.split(/[\s/]/)[0].slice(0, 40) || 'Browser';
}
module.exports = { uaLabel };
