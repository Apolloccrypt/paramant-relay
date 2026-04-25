#!/usr/bin/env python3
"""Replace <nav class="nav"> + <div class="nav-mobile"> in every page that uses the shared nav.
Also injects design-system.css, nav.css, and nav.js into <head>/<body>."""

import re, os, glob

NEW_NAV = '''\
<nav class="nav">
  <a href="/" class="nav-logo"><span class="logo-para">Para</span><span class="logo-mant">MANT</span></a>

  <ul class="nav-links">

    <li class="nav-dropdown">
      <button class="nav-dropdown-trigger" aria-haspopup="true" aria-expanded="false">Products</button>
      <ul class="nav-dropdown-menu" role="menu">
        <li role="none"><a href="/send" role="menuitem">Send a file</a></li>
        <li role="none"><a href="/parashare" role="menuitem">ParaShare</a></li>
        <li role="none"><a href="/drop" role="menuitem">ParaDrop</a></li>
        <li role="none"><a href="/dashboard" role="menuitem">Dashboard</a></li>
      </ul>
    </li>

    <li><a href="/pricing" class="nav-link">Pricing</a></li>

    <li class="nav-dropdown">
      <button class="nav-dropdown-trigger" aria-haspopup="true" aria-expanded="false">Developers</button>
      <ul class="nav-dropdown-menu" role="menu">
        <li role="none"><a href="/docs" role="menuitem">Docs</a></li>
        <li role="none"><a href="/docs#api" role="menuitem">API reference</a></li>
        <li role="none"><a href="/ct-log" role="menuitem">CT Log</a></li>
        <li role="none"><a href="https://github.com/Apolloccrypt/paramant-relay" role="menuitem">GitHub</a></li>
        <li role="none"><a href="https://hub.docker.com/r/mtty001/relay" role="menuitem">Docker Hub</a></li>
        <li role="none"><a href="/changelog" role="menuitem">Changelog</a></li>
      </ul>
    </li>

    <li class="nav-dropdown">
      <button class="nav-dropdown-trigger" aria-haspopup="true" aria-expanded="false">Self-host</button>
      <ul class="nav-dropdown-menu" role="menu">
        <li role="none"><a href="/docs#self-hosting" role="menuitem">Deploy guide</a></li>
        <li role="none"><a href="/install.sh" role="menuitem">install.sh</a></li>
        <li role="none"><a href="/install-pi.sh" role="menuitem">install-pi.sh</a></li>
        <li role="none"><a href="https://pypi.org/project/paramant-sdk/" role="menuitem">SDK · PyPI</a></li>
        <li role="none"><a href="https://www.npmjs.com/package/paramant-sdk" role="menuitem">SDK · npm</a></li>
        <li role="none"><a href="/download" role="menuitem">ParamantOS</a></li>
        <li role="none"><a href="https://github.com/Apolloccrypt/paramant-relay/releases" role="menuitem">Releases</a></li>
      </ul>
    </li>

    <li class="nav-dropdown">
      <button class="nav-dropdown-trigger" aria-haspopup="true" aria-expanded="false">Compliance</button>
      <ul class="nav-dropdown-menu" role="menu">
        <li class="nav-subheader" role="presentation">Standards</li>
        <li role="none"><a href="/compliance/nis2" role="menuitem">NIS2 (EU 2022/2555)</a></li>
        <li role="none"><a href="/compliance/iec62443" role="menuitem">IEC 62443 (Industrial IoT)</a></li>
        <li role="none"><a href="/compliance/nen7510" role="menuitem">NEN 7510 (Dutch Healthcare)</a></li>
        <li class="nav-subheader" role="presentation">Sovereignty</li>
        <li role="none"><a href="/sovereignty" role="menuitem">Jurisdiction</a></li>
        <li role="none"><a href="/government" role="menuitem">Government &amp; public sector</a></li>
        <li class="nav-subheader" role="presentation">OT</li>
        <li role="none"><a href="/ot" role="menuitem">OT guide</a></li>
        <li role="none"><a href="/ot-vs-data-diodes" role="menuitem">OT vs data diodes</a></li>
        <li class="nav-subheader" role="presentation">Post-quantum</li>
        <li role="none"><a href="/hndl" role="menuitem">HNDL threat</a></li>
        <li role="none"><a href="/quantum-urgency" role="menuitem">Quantum urgency</a></li>
        <li role="none"><a href="/crypto-agility" role="menuitem">Crypto agility</a></li>
        <li class="nav-subheader" role="presentation">Legal</li>
        <li role="none"><a href="/dpa" role="menuitem">Data Processing Agreement</a></li>
      </ul>
    </li>

    <li><a href="/vs" class="nav-link">Compare</a></li>

    <li class="nav-dropdown">
      <button class="nav-dropdown-trigger" aria-haspopup="true" aria-expanded="false">About</button>
      <ul class="nav-dropdown-menu" role="menu">
        <li role="none"><a href="/status" role="menuitem">Status</a></li>
        <li role="none"><a href="/security" role="menuitem">Security</a></li>
        <li role="none"><a href="/sla" role="menuitem">SLA</a></li>
        <li role="none"><a href="/license" role="menuitem">License</a></li>
        <li role="none"><a href="/press" role="menuitem">Press kit</a></li>
        <li role="none"><a href="mailto:privacy@paramant.app" role="menuitem">Contact</a></li>
      </ul>
    </li>

  </ul>

  <div class="nav-auth" id="nav-auth">
    <a href="/auth/login" class="nav-signin">Sign in</a>
    <a href="/signup" class="nav-cta">Create account</a>
  </div>

  <button class="nav-hamburger" id="nav-hamburger" aria-label="Open menu" aria-expanded="false">
    <span></span><span></span><span></span>
  </button>
</nav>'''

NEW_MOBILE = '''\
<div class="nav-mobile" id="nav-mobile">
  <div class="nav-mobile-group">
    <button class="nav-mobile-group-btn" aria-expanded="false">Products</button>
    <div class="nav-mobile-group-items">
      <a href="/send">Send a file</a>
      <a href="/parashare">ParaShare</a>
      <a href="/drop">ParaDrop</a>
      <a href="/dashboard">Dashboard</a>
    </div>
  </div>

  <a href="/pricing" class="nav-mobile-standalone">Pricing</a>

  <div class="nav-mobile-group">
    <button class="nav-mobile-group-btn" aria-expanded="false">Developers</button>
    <div class="nav-mobile-group-items">
      <a href="/docs">Docs</a>
      <a href="/docs#api">API reference</a>
      <a href="/ct-log">CT Log</a>
      <a href="https://github.com/Apolloccrypt/paramant-relay">GitHub</a>
      <a href="https://hub.docker.com/r/mtty001/relay">Docker Hub</a>
      <a href="/changelog">Changelog</a>
    </div>
  </div>

  <div class="nav-mobile-group">
    <button class="nav-mobile-group-btn" aria-expanded="false">Self-host</button>
    <div class="nav-mobile-group-items">
      <a href="/docs#self-hosting">Deploy guide</a>
      <a href="/install.sh">install.sh</a>
      <a href="/install-pi.sh">install-pi.sh</a>
      <a href="https://pypi.org/project/paramant-sdk/">SDK · PyPI</a>
      <a href="https://www.npmjs.com/package/paramant-sdk">SDK · npm</a>
      <a href="/download">ParamantOS</a>
      <a href="https://github.com/Apolloccrypt/paramant-relay/releases">Releases</a>
    </div>
  </div>

  <div class="nav-mobile-group">
    <button class="nav-mobile-group-btn" aria-expanded="false">Compliance</button>
    <div class="nav-mobile-group-items">
      <a href="/compliance/nis2">NIS2 (EU 2022/2555)</a>
      <a href="/compliance/iec62443">IEC 62443 (Industrial IoT)</a>
      <a href="/compliance/nen7510">NEN 7510 (Dutch Healthcare)</a>
      <a href="/sovereignty">Jurisdiction</a>
      <a href="/government">Government &amp; public sector</a>
      <a href="/ot">OT guide</a>
      <a href="/ot-vs-data-diodes">OT vs data diodes</a>
      <a href="/hndl">HNDL threat</a>
      <a href="/quantum-urgency">Quantum urgency</a>
      <a href="/crypto-agility">Crypto agility</a>
      <a href="/dpa">Data Processing Agreement</a>
    </div>
  </div>

  <a href="/vs" class="nav-mobile-standalone">Compare</a>

  <div class="nav-mobile-group">
    <button class="nav-mobile-group-btn" aria-expanded="false">About</button>
    <div class="nav-mobile-group-items">
      <a href="/status">Status</a>
      <a href="/security">Security</a>
      <a href="/sla">SLA</a>
      <a href="/license">License</a>
      <a href="/press">Press kit</a>
      <a href="mailto:privacy@paramant.app">Contact</a>
    </div>
  </div>

  <a href="/help" class="nav-mobile-standalone">Help</a>
</div>'''

DS_LINK   = '<link rel="stylesheet" href="/design-system.css?v=18">'
NAV_LINK  = '<link rel="stylesheet" href="/nav.css?v=12">'
NAV_JS    = '<script src="/nav.js?v=11" defer></script>'
NAV_AUTH_JS = '<script src="/js/nav-auth.js" defer></script>'

# Pages that don't have <nav class="nav"> yet but should — inject the canonical
# nav after <body> (or after a skip-link if present). App shells (admin,
# dashboard, billing) and printable standalones (briefs, one-pager,
# pattern-library) intentionally stay nav-less and are not in this set.
ADD_NAV_TO = {
    '404.html',
    'changelog.html',
    'download.html',
    'legal.html',
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
