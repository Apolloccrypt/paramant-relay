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
        <li role="none"><a href="/install-client.sh" role="menuitem">install-client.sh</a></li>
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

  <button class="nav-hamburger" id="nav-hamburger" aria-label="Open menu" aria-expanded="false">
    <span></span><span></span><span></span>
  </button>
</nav>'''

NEW_MOBILE = '''\
<div class="nav-mobile" id="nav-mobile">
  <div class="nav-mobile-header">
    <button class="nav-mobile-close" id="nav-mobile-close" aria-label="Close menu">&times;</button>
  </div>

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
      <a href="/install-client.sh">install-client.sh</a>
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
</div>'''

DS_LINK   = '<link rel="stylesheet" href="/design-system.css?v=4">'
NAV_LINK  = '<link rel="stylesheet" href="/nav.css?v=4">'
NAV_JS    = '<script src="/nav.js?v=4" defer></script>'


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
                html = html[:head_close] + DS_LINK + '\n' + html[head_close:]
    return html


def inject_nav_js(html):
    # Normalise any existing nav.js script tag to ?v=4
    html = re.sub(
        r'<script src="/nav\.js(?:\?v=\d+)?" defer></script>',
        NAV_JS, html)
    # Inject before </body> if still missing
    if NAV_JS not in html:
        body_close = html.rfind('</body>')
        if body_close != -1:
            html = html[:body_close] + NAV_JS + '\n' + html[body_close:]
    return html


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
        content = f.read()
    if '<nav class="nav">' not in content:
        return False
    updated = re.sub(r'<nav class="nav">.*?</nav>', NEW_NAV, content, flags=re.DOTALL)
    updated = replace_mobile_div(updated)
    updated = inject_design_system(updated)
    updated = inject_nav_js(updated)
    if updated == content:
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
