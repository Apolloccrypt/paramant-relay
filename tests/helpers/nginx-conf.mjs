// A small nginx config parser, enough to answer one question the way nginx
// does: which proxy_set_header lines reach the upstream for a given location.
//
// nginx rule (ngx_http_proxy_module): proxy_set_header is inherited from the
// enclosing level ONLY IF the current level sets none itself. One header set
// in a location drops every server-level header for that location. That is
// how deploy/nginx-selfhost.conf lost X-Real-IP on /admin/ (review PR #546).

export function tokenize(text) {
  const out = [];
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === '#') { while (i < text.length && text[i] !== '\n') i++; continue; }
    if (/\s/.test(c)) { i++; continue; }
    if (c === '{' || c === '}' || c === ';') { out.push(c); i++; continue; }
    if (c === '"' || c === "'") {
      let j = i + 1; let s = '';
      while (j < text.length && text[j] !== c) { if (text[j] === '\\') { s += text[j + 1]; j += 2; continue; } s += text[j++]; }
      out.push({ q: s }); i = j + 1; continue;
    }
    let j = i;
    while (j < text.length && !/[\s{};]/.test(text[j])) j++;
    out.push(text.slice(i, j)); i = j;
  }
  return out;
}

// Tree of { name, args, block? }.
export function parse(text) {
  const toks = tokenize(text);
  let p = 0;
  const val = (t) => (typeof t === 'string' ? t : t.q);
  function list() {
    const items = [];
    while (p < toks.length && toks[p] !== '}') {
      const words = [];
      while (p < toks.length && toks[p] !== ';' && toks[p] !== '{' && toks[p] !== '}') words.push(val(toks[p++]));
      if (toks[p] === ';') { p++; items.push({ name: words[0], args: words.slice(1) }); continue; }
      if (toks[p] === '{') { p++; const block = list(); p++; items.push({ name: words[0], args: words.slice(1), block }); continue; }
      if (words.length) items.push({ name: words[0], args: words.slice(1) });
    }
    return items;
  }
  return list();
}

const own = (items) => items.filter((d) => d.name === 'proxy_set_header').map((d) => [d.args[0], d.args[1] ?? '']);

// Every location that proxies, with the headers nginx sends for it.
// `inherited` = the http-level headers (the self-host conf is an http include).
export function proxyLocations(tree) {
  const out = [];
  const httpHeaders = own(tree);
  for (const srv of tree.filter((d) => d.name === 'server' && d.block)) {
    const sHeaders = own(srv.block).length ? own(srv.block) : httpHeaders;
    const names = (srv.block.find((d) => d.name === 'server_name') || { args: ['(none)'] }).args.join(' ');
    const listen = (srv.block.find((d) => d.name === 'listen') || { args: [] }).args.join(' ');
    const walk = (items, parentHeaders, trail) => {
      for (const loc of items.filter((d) => d.name === 'location' && d.block)) {
        const mine = own(loc.block);
        const eff = mine.length ? mine : parentHeaders;
        const label = `${trail}location ${loc.args.join(' ')}`;
        const pp = loc.block.find((d) => d.name === 'proxy_pass');
        const internal = loc.block.some((d) => d.name === 'internal');
        if (pp) out.push({ server: names, listen, location: loc.args, label, proxyPass: pp.args[0], internal, headers: Object.fromEntries(eff.map(([k, v]) => [k.toLowerCase(), v])) });
        walk(loc.block, eff, `${label} > `);
      }
    };
    walk(srv.block, sHeaders, '');
  }
  return out;
}

// The client-address and internal-header contract every proxying location
// must meet. Returns a list of problems, empty when the location is clean.
export function headerProblems(loc) {
  const h = loc.headers;
  const p = [];
  if (h['x-real-ip'] !== '$remote_addr') p.push(`X-Real-IP is ${h['x-real-ip'] === undefined ? 'not set (client value passes through)' : h['x-real-ip']}`);
  if (h['x-internal-auth'] !== '') p.push('X-Internal-Auth not blanked');
  if (h['x-paramant-client-ip'] !== '') p.push('X-Paramant-Client-IP not blanked');
  if (h['x-forwarded-for'] !== undefined && h['x-forwarded-for'] !== '$remote_addr') p.push(`X-Forwarded-For is ${h['x-forwarded-for']} (client-controlled)`);
  if (h['x-forwarded-for'] === undefined) p.push('X-Forwarded-For not set (client value passes through)');
  if (h.host === undefined) p.push('Host not set (upstream sees the proxy address)');
  return p;
}
