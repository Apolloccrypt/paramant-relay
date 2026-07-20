#!/usr/bin/env python3
"""Replace <nav class="nav"> + <div class="nav-mobile"> in every page that uses the shared nav.
Also injects design-system.css, nav.css, and nav.js into <head>/<body>."""

import re, os, glob

# UI-herindeling fase 1 (homepage, 2026-07-20): the shared nav collapses to the
# three verbs + Docs, with Pricing + account as a small right-hand cluster.
# Everything that used to live in the dropdowns now lives in NEW_FOOTER, so
# nothing becomes unreachable. NOTE: this template is staged for a site-wide
# fase-2 run; it was NOT applied to every page in fase 1 (only index.html was
# rebuilt by hand). The .nav-right cluster is styled in nav.css (?v=16) — that
# bump must ship before this template is applied site-wide.
NEW_NAV = '''\
<nav class="nav">
  <a href="/" class="nav-logo" aria-label="Paramant"><img src="/favicon-32.png" alt="" class="nav-logo-mark">aramant</a>

  <ul class="nav-links">
    <li><a href="/parashare" class="nav-link">Send</a></li>
    <li><a href="/sign" class="nav-link">Sign</a></li>
    <li><a href="/verify" class="nav-link">Verify</a></li>
    <li><a href="/docs" class="nav-link">Docs</a></li>
  </ul>

  <div class="nav-right">
    <a href="/pricing" class="nav-link nav-pricing">Pricing</a>
    <div class="nav-auth" id="nav-auth">
      <a href="/auth/login" class="nav-signin">Sign in</a>
      <a href="/signup" class="nav-cta">Create account</a>
    </div>
  </div>

  <button class="nav-hamburger" id="nav-hamburger" aria-label="Open menu" aria-expanded="false">
    <span></span><span></span><span></span>
  </button>
</nav>'''

NEW_MOBILE = '''\
<div class="nav-mobile" id="nav-mobile">
  <a href="/parashare" class="nav-mobile-standalone">Send</a>
  <a href="/sign" class="nav-mobile-standalone">Sign</a>
  <a href="/verify" class="nav-mobile-standalone">Verify</a>
  <a href="/docs" class="nav-mobile-standalone">Docs</a>
  <a href="/pricing" class="nav-mobile-standalone">Pricing</a>
  <a href="/auth/login" class="nav-mobile-standalone">Sign in</a>
  <a href="/signup" class="nav-mobile-standalone">Create account</a>
  <a href="/help" class="nav-mobile-standalone">Help</a>
</div>'''

# Footer template — with the nav collapsed to the three verbs + Docs, the footer
# becomes the full site map so nothing the dropdowns used to reach (compliance,
# sovereignty, self-host, trust, ParaRules, CT log, ...) is orphaned. Brand
# block + four content columns (footer-grid = 240px + repeat(4,1fr)).
NEW_FOOTER = '''\
<footer>
  <div class="container-lg">
    <div class="footer-grid">
      <div>
        <div class="logo" style="margin-bottom:var(--space-3)"><span class="a">Para</span><span class="b">MANT</span></div>
        <p style="font-size:var(--text-xs);color:var(--ink-dim);line-height:1.7;max-width:220px">Encrypted file relay. RAM-only. Burn-on-read.</p>
        <p style="font-family:var(--mono);font-size:var(--text-xs);color:var(--ink-dim);margin-top:var(--space-4);line-height:1.8">FIPS 203 / 204 &middot; Hetzner DE<br>GDPR &middot; no US CLOUD Act<br>BUSL-1.1 &middot; &copy; 2026 PARAMANT</p>
      </div>
      <div>
        <div class="footer-col-label">Products</div>
        <div class="footer-links">
          <a href="/parashare">Send a file</a>
          <a href="/sign">Sign a document</a>
          <a href="/verify">Verify a signature</a>
          <a href="/dashboard">Dashboard</a>
          <a href="/developer">Developer dashboard</a>
          <a href="/pricing">Pricing</a>
        </div>
      </div>
      <div>
        <div class="footer-col-label">Developers &amp; self-host</div>
        <div class="footer-links">
          <a href="/docs">Docs</a>
          <a href="/docs#api">API reference</a>
          <a href="/ct-log">CT Log</a>
          <a href="/docs#self-hosting">Deploy guide</a>
          <a href="/setup">Relay setup wizard</a>
          <a href="/install.sh">install.sh</a>
          <a href="/install-pi.sh">install-pi.sh</a>
          <a href="https://pypi.org/project/paramant-sdk/" target="_blank" rel="noopener">SDK &middot; PyPI</a>
          <a href="https://www.npmjs.com/package/paramant-sdk" target="_blank" rel="noopener">SDK &middot; npm</a>
          <a href="/download">ParamantOS</a>
          <a href="https://github.com/Apolloccrypt/paramant-relay" target="_blank" rel="noopener">GitHub</a>
          <a href="https://hub.docker.com/r/mtty001/relay" target="_blank" rel="noopener">Docker Hub</a>
          <a href="https://github.com/Apolloccrypt/paramant-relay/releases" target="_blank" rel="noopener">Releases</a>
          <a href="/changelog">Changelog</a>
        </div>
      </div>
      <div>
        <div class="footer-col-label">Compliance &amp; sovereignty</div>
        <div class="footer-links">
          <a href="/sovereignty">Jurisdiction</a>
          <a href="/government">Government &amp; public sector</a>
          <a href="/compliance/nis2">NIS2 (EU 2022/2555)</a>
          <a href="/compliance/iec62443">IEC 62443 (Industrial IoT)</a>
          <a href="/compliance/nen7510">NEN 7510 (Dutch Healthcare)</a>
          <a href="/ot">OT guide</a>
          <a href="/ot-vs-data-diodes">OT vs data diodes</a>
          <a href="/hndl">HNDL threat</a>
          <a href="/quantum-urgency">Quantum urgency</a>
          <a href="/crypto-agility">Crypto agility</a>
          <a href="/vs">Compare</a>
        </div>
      </div>
      <div>
        <div class="footer-col-label">Trust, legal &amp; connect</div>
        <div class="footer-links">
          <a href="/pararules">ParaRules</a>
          <a href="/status">Status</a>
          <a href="/security">Security</a>
          <a href="/trust">Trust</a>
          <a href="/sla">SLA</a>
          <a href="/license">License</a>
          <a href="/press">Press kit</a>
          <a href="/privacy">Privacy Policy</a>
          <a href="/dpa">Data Processing Agreement</a>
          <a href="/partners">Partners</a>
          <a href="/about">About Paramant</a>
          <a href="mailto:privacy@paramant.app">Contact</a>
          <a href="/signup">Create account</a>
          <a href="/auth/login">Sign in</a>
          <a href="/help">Help</a>
        </div>
      </div>
    </div>
  </div>
</footer>'''

DS_LINK   = '<link rel="stylesheet" href="/design-system.css?v=19">'
NAV_LINK  = '<link rel="stylesheet" href="/nav.css?v=16">'
NAV_JS    = '<script src="/nav.js?v=12" defer></script>'
NAV_AUTH_JS = '<script src="/js/nav-auth.js" defer></script>'

# Pages that don't have <nav class="nav"> yet but should — inject the canonical
# nav after <body> (or after a skip-link if present). App shells (admin,
# dashboard, billing) and printable standalones (briefs, one-pager,
# pattern-library) intentionally stay nav-less and are not in this set.
ADD_NAV_TO = {
    '404.html',
    'changelog.html',
    'download.html',
    'partners.html',
    'security/acknowledgements.html',
    'signup/verified.html',
}


def inject_design_system(html):
    html = re.sub(
        r'<link rel="stylesheet" href="/design-system\.css(?:\?v=\d+)?">',
        DS_LINK, html)
    html = re.sub(
        r'<link rel="stylesheet" href="/nav\.css(?:\?v=\d+)?">',
        NAV_LINK, html)
    if DS_LINK not in html:
        if NAV_LINK in html:
            html = html.replace(NAV_LINK, DS_LINK + '\n' + NAV_LINK, 1)
        else:
            head_close = html.find('</head>')
            if head_close != -1:
                html = html[:head_close] + DS_LINK + '\n' + NAV_LINK + '\n' + html[head_close:]
                return html
    if NAV_LINK not in html:
        head_close = html.find('</head>')
        if head_close != -1:
            html = html[:head_close] + NAV_LINK + '\n' + html[head_close:]
    return html


def inject_nav_js(html):
    # Normalise any existing nav.js script tag to ?v=5
    html = re.sub(
        r'<script src="/nav\.js(?:\?v=\d+)?" defer></script>',
        NAV_JS, html)
    # Inject before </body> if still missing
    if NAV_JS not in html:
        body_close = html.rfind('</body>')
        if body_close != -1:
            html = html[:body_close] + NAV_JS + '\n' + html[body_close:]
    return html


def inject_nav_auth_js(html):
    html = re.sub(
        r'<script src="/js/nav-auth\.js(?:\?v=\d+)?" defer></script>',
        NAV_AUTH_JS, html)
    if NAV_AUTH_JS not in html:
        # Insert after nav.js if present, else before </body>
        if NAV_JS in html:
            html = html.replace(NAV_JS, NAV_JS + '\n' + NAV_AUTH_JS, 1)
        else:
            body_close = html.rfind('</body>')
            if body_close != -1:
                html = html[:body_close] + NAV_AUTH_JS + '\n' + html[body_close:]
    return html


def inject_nav_block(html):
    """Insert NEW_NAV + NEW_MOBILE after the skip-link (or <body> if none)."""
    skip = re.search(r'<a href="#main-content"[^>]*class="skip-link"[^>]*>[^<]*</a>', html)
    if skip:
        i = skip.end()
    else:
        body = re.search(r'<body[^>]*>', html)
        if not body:
            return html
        i = body.end()
    return html[:i] + '\n' + NEW_NAV + '\n' + NEW_MOBILE + html[i:]


def replace_mobile_div(html):
    """Replace <div class="nav-mobile"...>...</div>, counting nested divs."""
    start = html.find('<div class="nav-mobile"')
    if start == -1:
        nav_end = html.find('</nav>') + len('</nav>')
        return html[:nav_end] + '\n' + NEW_MOBILE + html[nav_end:]
    depth, i = 0, start
    while i < len(html):
        if html[i:i+4] == '<div':
            depth += 1
            i += 4
        elif html[i:i+6] == '</div>':
            depth -= 1
            if depth == 0:
                return html[:start] + NEW_MOBILE + html[i + 6:]
            i += 6
        else:
            i += 1
    return html


def process(fpath):
    with open(fpath, encoding='utf-8') as f:
        original = f.read()
    rel = os.path.relpath(fpath, frontend).replace(os.sep, '/')
    content = original
    if '<nav class="nav">' not in content:
        if rel not in ADD_NAV_TO:
            return False
        content = inject_nav_block(content)
        if '<nav class="nav">' not in content:
            return False
    updated = re.sub(r'<nav class="nav">.*?</nav>', NEW_NAV, content, flags=re.DOTALL)
    updated = replace_mobile_div(updated)
    updated = re.sub(r'<footer>.*?</footer>', NEW_FOOTER, updated, flags=re.DOTALL)
    updated = inject_design_system(updated)
    updated = inject_nav_js(updated)
    updated = inject_nav_auth_js(updated)
    if updated == original:
        return False
    with open(fpath, 'w', encoding='utf-8') as f:
        f.write(updated)
    return True


frontend = os.path.join(os.path.dirname(__file__))
files = sorted(glob.glob(os.path.join(frontend, '**/*.html'), recursive=True))

changed, skipped = [], []
for fp in files:
    (changed if process(fp) else skipped).append(os.path.relpath(fp, frontend))

print(f"Updated {len(changed)} files:")
for f in changed: print(f"  {f}")
print(f"\nSkipped {len(skipped)} (no shared nav):")
for f in skipped: print(f"  {f}")
