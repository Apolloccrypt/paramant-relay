#!/usr/bin/env python3
"""Replace <nav class="nav"> + <div class="nav-mobile"> in every page that uses the shared nav.
Also injects <link rel="stylesheet" href="/design-system.css"> into <head>."""

import re, os, glob

NEW_NAV = '''\
<nav class="nav">
  <a href="/" class="nav-logo"><span class="logo-para">Para</span><span class="logo-mant">MANT</span></a>

  <ul class="nav-links">

    <li class="nav-dropdown">
      <button class="nav-dropdown-trigger">Product &#9662;</button>
      <ul class="nav-dropdown-menu">
        <li><a href="/send">Send a file</a></li>
        <li><a href="/parashare">ParaShare</a></li>
        <li><a href="/drop">ParaDrop</a></li>
        <li><a href="/dashboard">Dashboard</a></li>
        <li><a href="/ct-log">CT Log</a></li>
        <li><a href="/docs">Docs</a></li>
        <li class="nav-dropdown-divider"></li>
        <li><a href="/docs#api">API reference</a></li>
        <li><a href="/vs">vs. alternatives</a></li>
        <li><a href="/press">Press kit</a></li>
        <li><a href="/changelog">Changelog</a></li>
      </ul>
    </li>

    <li><a href="/pricing" class="nav-link">Pricing</a></li>

    <li class="nav-dropdown">
      <button class="nav-dropdown-trigger">Self-host &#9662;</button>
      <ul class="nav-dropdown-menu">
        <li><a href="https://github.com/Apolloccrypt/paramant-relay">GitHub</a></li>
        <li><a href="https://github.com/Apolloccrypt/paramant-relay/releases">Releases</a></li>
        <li><a href="https://hub.docker.com/r/mtty001/relay">Docker Hub</a></li>
        <li><a href="/docs#self-hosting">Deploy guide</a></li>
        <li class="nav-dropdown-divider"></li>
        <li><a href="/install.sh">install.sh</a></li>
        <li><a href="/install-pi.sh">install-pi.sh</a></li>
        <li><a href="/install-client.sh">install-client.sh</a></li>
        <li><a href="/download">ParamantOS</a></li>
        <li class="nav-dropdown-divider"></li>
        <li><a href="/status">Status</a></li>
      </ul>
    </li>

    <li class="nav-dropdown">
      <button class="nav-dropdown-trigger">Compliance &#9662;</button>
      <ul class="nav-dropdown-menu">
        <li><a href="/compliance/nis2">NIS2 (EU 2022/2555)</a></li>
        <li><a href="/compliance/iec62443">IEC 62443 (Industrial IoT)</a></li>
        <li><a href="/compliance/nen7510">NEN 7510 (Dutch Healthcare)</a></li>
        <li><a href="/dpa">Data Processing Agreement</a></li>
        <li class="nav-dropdown-divider"></li>
        <li><a href="/ot">OT guide</a></li>
        <li><a href="/government">Government &amp; public sector</a></li>
        <li><a href="/hndl">HNDL threat</a></li>
        <li><a href="/crypto-agility">Crypto agility</a></li>
      </ul>
    </li>

    <li class="nav-dropdown">
      <button class="nav-dropdown-trigger">Info &#9662;</button>
      <ul class="nav-dropdown-menu">
        <li><a href="mailto:privacy@paramant.app">Contact</a></li>
        <li><a href="/request-key">Free API key</a></li>
        <li><a href="/status">Status</a></li>
        <li><a href="/sla">SLA</a></li>
        <li><a href="/security">Security</a></li>
        <li><a href="/license">License</a></li>
      </ul>
    </li>

  </ul>

  <button class="nav-hamburger" id="nav-hamburger" aria-label="Menu">
    <span></span><span></span><span></span>
  </button>
</nav>'''

NEW_MOBILE = '''\
<div class="nav-mobile" id="nav-mobile">
  <div class="nav-mobile-group">
    <div class="nav-mobile-label">Product</div>
    <a href="/send">Send a file</a>
    <a href="/parashare">ParaShare</a>
    <a href="/drop">ParaDrop</a>
    <a href="/dashboard">Dashboard</a>
    <a href="/ct-log">CT Log</a>
    <a href="/docs">Docs</a>
    <a href="/docs#api">API reference</a>
    <a href="/vs">vs. alternatives</a>
    <a href="/press">Press kit</a>
    <a href="/changelog">Changelog</a>
  </div>
  <div class="nav-mobile-group">
    <div class="nav-mobile-label">Pricing</div>
    <a href="/pricing" class="nav-mobile-standalone">Pricing plans →</a>
  </div>
  <div class="nav-mobile-group">
    <div class="nav-mobile-label">Self-host</div>
    <a href="https://github.com/Apolloccrypt/paramant-relay">GitHub</a>
    <a href="https://github.com/Apolloccrypt/paramant-relay/releases">Releases</a>
    <a href="https://hub.docker.com/r/mtty001/relay">Docker Hub</a>
    <a href="/docs#self-hosting">Deploy guide</a>
    <a href="/install.sh">install.sh</a>
    <a href="/install-pi.sh">install-pi.sh</a>
    <a href="/download">ParamantOS</a>
    <a href="/status">Status</a>
  </div>
  <div class="nav-mobile-group">
    <div class="nav-mobile-label">Compliance</div>
    <a href="/compliance/nis2">NIS2</a>
    <a href="/compliance/iec62443">IEC 62443</a>
    <a href="/compliance/nen7510">NEN 7510</a>
    <a href="/dpa">Data Processing Agreement</a>
    <a href="/ot">OT guide</a>
    <a href="/government">Government</a>
    <a href="/hndl">HNDL threat</a>
    <a href="/crypto-agility">Crypto agility</a>
  </div>
  <div class="nav-mobile-group">
    <div class="nav-mobile-label">Info</div>
    <a href="mailto:privacy@paramant.app">Contact</a>
    <a href="/request-key">Free API key</a>
    <a href="/status">Status</a>
    <a href="/sla">SLA</a>
    <a href="/security">Security</a>
    <a href="/license">License</a>
  </div>
</div>'''

DS_LINK = '<link rel="stylesheet" href="/design-system.css">'


def inject_design_system(html):
    if DS_LINK in html:
        return html
    # Inject before nav.css if present, otherwise before </head>
    nav_css = '<link rel="stylesheet" href="/nav.css">'
    if nav_css in html:
        return html.replace(nav_css, DS_LINK + '\n' + nav_css, 1)
    head_close = html.find('</head>')
    if head_close != -1:
        return html[:head_close] + DS_LINK + '\n' + html[head_close:]
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
