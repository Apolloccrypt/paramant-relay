// Who actually visited, as opposed to who claimed to.
//
// THE STANDING ASSUMPTION FOR THIS SITE, read this before using any number
// below: paramant.app sends `Referrer-Policy: no-referrer` on every response
// (deploy/nginx/snippets/paramant-security-headers.conf, frontend/_headers).
// A real browser therefore sends NO referer, not between our own pages and not
// on the assets a page pulls in. That inverts the usual reading in both
// directions:
//
//   absence of a referer  is normal, and says nothing
//   presence of a referer on OUR OWN pages means the client ignored the header,
//                         which is what a scanner does to look like a browser
//
// So no rule here may depend on a referer. One exception stands: a referer from
// SOMEONE ELSE'S site is governed by their policy, not ours, so an external
// referer remains meaningful for the question "did anyone arrive from a link".
//
// WHY THIS FILE EXISTS. The first pass at this used a user-agent regex, and on
// 1 September 2026 it produced a funnel that read like a conversion story: 17
// visitors on /sign against 4 on /pricing. It was not. 31 of the 36 IPs that
// reached /sign fetched no CSS, JS, font or favicon at all. They were scanners
// carrying a browser string, and a whole evening of conclusions was built on
// them before anyone ran the test that tells the two apart.
//
// A user-agent is a self-declaration. Anyone who lies puts a browser in it, so a
// filter that asks for identity measures how well someone lies. This one asks
// what the client DID.
//
// Node builtins only, so it runs in the existing root integration job.

import fs from 'node:fs';
import zlib from 'node:zlib';

export const LINE = /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\d+) "([^"]*)" "([^"]*)"/;

// A rendered page pulls these in. Fetching none of them means nothing rendered.
export const ASSET = /\.(css|js|woff2?|svg|png|jpe?g|webp|ico|gif|avif)(\?|$)/i;

// Paths only an attacker or a scanner ever asks for. One hit is enough: a
// visitor does not accidentally request /.env.
export const PROBE = /\.(php|env|git|aws|bak|sql|old|save)\b|wp-content|wp-admin|wp-json|wp-includes|phpunit|eval-stdin|xmlrpc|rest_route|\/vendor\/|\/\.git|\/\.env|\/\.aws|cgi-bin|\/autodiscover|\/owa\//i;

// Self-declared automation. Kept as a SUPPORTING signal only, never as the sole
// test: it is the one every liar can edit. heritrix is on it because it was
// missed the first time and it renders, which makes it look human to the asset
// rule.
export const UA_AUTOMATION = /bot\b|crawl|spider|slurp|curl|wget|python|go-http|okhttp|libwww|java\/|node-fetch|axios|httpx|scrapy|heritrix|censys|expanse|shodan|masscan|zgrab|nuclei|palo alto|internet-measurement|uptimerobot|pingdom|statuscake|headlesschrome|phantomjs|puppeteer|playwright|selenium/i;

// Operator traffic. NOT hardcoded: this is a public repository, and the home
// address of the person running the service is personal data that does not
// belong in git. Supply it at call time (PARAMANT_OPERATOR_IPS, comma
// separated). Counted and reported separately rather than silently dropped, so
// a reader can see how much of the traffic was us.
export function operatorIpsFromEnv(env = process.env) {
  return new Set(String(env.PARAMANT_OPERATOR_IPS || '').split(',').map((s) => s.trim()).filter(Boolean));
}

function* readLines(paths) {
  for (const p of paths) {
    let buf;
    try { buf = fs.readFileSync(p); } catch { continue; }
    if (p.endsWith('.gz')) { try { buf = zlib.gunzipSync(buf); } catch { continue; } }
    for (const line of buf.toString('utf8').split('\n')) if (line) yield line;
  }
}

// Fold a log into one record per client address.
export function collect(lines) {
  const per = new Map();
  for (const line of lines) {
    const m = LINE.exec(line);
    if (!m) continue;
    const [, ip, ts, method, path, code, size, referer, ua] = m;
    let d = per.get(ip);
    if (!d) {
      d = { ip, requests: 0, assets: 0, pages: 0, probes: 0, uas: new Set(), clientErrors: 0, externalReferers: 0, first: ts, last: ts };
      per.set(ip, d);
    }
    d.requests++;
    d.last = ts;
    d.uas.add(ua);
    if (code[0] === '4') d.clientErrors++;
    if (PROBE.test(path)) d.probes++;
    if (ASSET.test(path)) d.assets++; else d.pages++;
    // Only a referer from somebody ELSE'S origin carries information here; see
    // the no-referrer note at the top.
    if (referer && referer !== '-' && !/paramant\.app/i.test(referer) && /^https?:\/\//i.test(referer)) d.externalReferers++;
  }
  return [...per.values()];
}

// The verdict for one client, and the reason. Ordered so the cheapest and most
// certain exclusions come first; `reason` names the rule that decided, which is
// what makes the tally below readable.
export function classify(d, operatorIps = new Set()) {
  if (operatorIps.has(d.ip)) return { verdict: 'operator', reason: 'operator_ip' };
  if (d.probes > 0) return { verdict: 'machine', reason: 'probe_path' };
  if (d.assets === 0) return { verdict: 'machine', reason: 'rendered_nothing' };
  if (d.uas.size > 3) return { verdict: 'machine', reason: 'many_user_agents' };
  if (d.requests >= 4 && d.clientErrors > d.requests / 2) return { verdict: 'machine', reason: 'mostly_client_errors' };
  // Reaches this line having actually rendered something. A crawler that
  // renders lands here too, so it is reported apart rather than counted as a
  // person: it is a machine we can name, not a visitor.
  if ([...d.uas].some((u) => UA_AUTOMATION.test(u))) return { verdict: 'declared_automation', reason: 'automation_user_agent' };
  return { verdict: 'possible_visitor', reason: 'rendered_and_unremarkable' };
}

// The whole picture, including which rule did the work. Reporting only the
// final number is what let a bad filter go unnoticed: with the tally, a future
// reader can see at a glance that (say) `rendered_nothing` carried 83% of the
// exclusions and judge whether that still holds.
export function analyse(lines, { operatorIps = new Set() } = {}) {
  const clients = collect(lines);
  const byReason = new Map();
  const verdicts = new Map();
  const visitors = [];
  for (const d of clients) {
    const c = classify(d, operatorIps);
    byReason.set(c.reason, (byReason.get(c.reason) || 0) + 1);
    verdicts.set(c.verdict, (verdicts.get(c.verdict) || 0) + 1);
    if (c.verdict === 'possible_visitor') visitors.push(d);
  }
  return {
    clients: clients.length,
    // Deliberately named as a bound. Every one of these could still be a
    // headless browser that renders; nothing here proves a person. A point
    // estimate would claim more than the data can carry.
    atMostVisitors: visitors.length,
    verdicts: Object.fromEntries([...verdicts].sort((a, b) => b[1] - a[1])),
    excludedBy: Object.fromEntries([...byReason].sort((a, b) => b[1] - a[1])),
    visitors,
  };
}

export function analyseFiles(paths, opts) {
  return analyse(readLines(paths), opts);
}

// CLI: node scripts/access-log-visitors.mjs /var/log/nginx/access.log*
if (import.meta.url === `file://${process.argv[1]}`) {
  const paths = process.argv.slice(2);
  if (!paths.length) {
    console.error('usage: access-log-visitors.mjs <nginx access log>...   (PARAMANT_OPERATOR_IPS=a,b to name our own)');
    process.exit(2);
  }
  const r = analyseFiles(paths, { operatorIps: operatorIpsFromEnv() });
  console.log(`clients seen         : ${r.clients}`);
  console.log(`AT MOST visitors     : ${r.atMostVisitors}   (upper bound, never a count of people)`);
  console.log('\nverdicts');
  for (const [k, v] of Object.entries(r.verdicts)) console.log(`  ${k.padEnd(22)} ${String(v).padStart(6)}`);
  console.log('\nwhich rule decided');
  for (const [k, v] of Object.entries(r.excludedBy)) {
    console.log(`  ${k.padEnd(28)} ${String(v).padStart(6)}  ${(100 * v / r.clients).toFixed(1)}%`);
  }
}
