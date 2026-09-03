#!/usr/bin/env python3
"""Replace <nav class="nav"> + <div class="nav-mobile"> in every page that uses the shared nav.
Also injects design-system.css, nav.css, and nav.js into <head>/<body>."""

import re, os, glob

NEW_NAV = '''\
<nav class="nav">
  <a href="/" class="nav-logo"><span class="logo-para">Para</span><span class="logo-mant">MANT</span></a>

  <ul class="nav-links">
    <li><a href="/#products" class="nav-link">Product</a></li>
    <li><a href="/security" class="nav-link">Security</a></li>
    <li><a href="/pricing" class="nav-link">Pricing</a></li>
    <li><a href="/docs" class="nav-link">Docs</a></li>
  </ul>

  <div class="nav-auth" id="nav-auth">
    <a href="/help" class="nav-help">Help</a>
    <a href="/auth/login" class="nav-signin">Sign in</a>
    <a href="/signup" class="nav-cta">Create account</a>
  </div>

  <button class="nav-hamburger" id="nav-hamburger" aria-label="Open menu" aria-expanded="false">
    <span></span><span></span><span></span>
  </button>
</nav>'''

# The drawer itself carries the four destinations and nothing else: it mirrors
# the desktop bar, and js/nav-auth.js rewrites its whole inside after the
# session check. The two secondary routes a phone loses from the bar -- Sign in
# and Help -- therefore hang under it as their own strip, which nav.js opens
# and closes with the drawer. Signed in, nav-auth.js rewrites that strip down
# to Help alone: Sign in is not an action you still need, and Help is, on the
# one surface a phone has left for it. It used to REMOVE the strip there, which
# is how a signed-in phone ended up with no route to support at all.
NEW_MOBILE = '''\
<div class="nav-mobile" id="nav-mobile">
  <a href="/#products" class="nav-mobile-standalone">Product</a>
  <a href="/security" class="nav-mobile-standalone">Security</a>
  <a href="/pricing" class="nav-mobile-standalone">Pricing</a>
  <a href="/docs" class="nav-mobile-standalone">Docs</a>
</div>
<div class="nav-mobile-tail" id="nav-mobile-tail">
  <a href="/auth/login" class="nav-tail-btn">Sign in</a>
  <a href="/help" class="nav-tail-link">Help</a>
</div>'''

# Footer template - the site-map footer is gone. What stays is the company
# behind the product plus the legal documents a visitor has a right to find.
# Everything else (status, press, self-host, partners) is reachable from the
# four nav links or from the pages they lead to; a footer is not a second
# navigation.
NEW_FOOTER = '''\
<footer>
  <div class="container-lg">
    <div class="footer-grid footer-slim">
      <div>
        <div class="logo" style="margin-bottom:var(--space-3)"><span class="a">Para</span><span class="b">MANT</span></div>
        <p style="font-size:var(--text-xs);color:var(--ink-dim);line-height:1.8;max-width:320px">Paramant is a product of <strong>Paramantis Solutions B.V.</strong><br>Harderwijk, the Netherlands<br>KvK 42115132<br><a href="mailto:privacy@paramant.app">privacy@paramant.app</a></p>
        <p style="font-family:var(--mono);font-size:var(--text-xs);color:var(--ink-dim);margin-top:var(--space-4);line-height:1.8">BUSL-1.1 &middot; &copy; 2026 PARAMANTIS SOLUTIONS B.V.</p>
      </div>
      <div>
        <div class="footer-col-label">Company</div>
        <div class="footer-links">
          <a href="/about">About</a>
          <a href="/changelog">Changelog</a>
        </div>
      </div>
      <div>
        <div class="footer-col-label">Legal</div>
        <div class="footer-links">
          <a href="/privacy">Privacy Policy</a>
          <a href="/dpa">Data Processing Agreement</a>
          <a href="/terms">Terms of Service</a>
          <a href="/sla">SLA</a>
          <a href="/license">License</a>
        </div>
      </div>
    </div>
  </div>
</footer>'''

# Pages with the shared nav but no footer (auth, account, download, signup)
# still owe the visitor the three legal documents. One line, three links, no
# second navigation.
LEGAL_STRIP = '''\
<footer class="legal-strip">
  <a href="/privacy">Privacy</a><span class="legal-sep">&middot;</span><a href="/dpa">Data Processing Agreement</a><span class="legal-sep">&middot;</span><a href="/terms">Terms of Service</a>
</footer>'''

DS_LINK   = '<link rel="stylesheet" href="/design-system.css?v=25">'
NAV_LINK  = '<link rel="stylesheet" href="/nav.css?v=20">'
NAV_JS    = '<script src="/nav.js?v=15" defer></script>'
NAV_AUTH_JS = '<script src="/js/nav-auth.js?v=8" defer></script>'

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


# Application shells that deliberately keep their own, narrower nav. The
# marketing nav is for visitors; these pages are for people already inside the
# product, so the generator leaves them alone.
KEEP_OWN_NAV = {
    'co-sign.html',
    'developer.html',
}


def inject_legal_strip(html):
    """Give footerless pages one line with privacy, dpa and terms.

    Pages that already carry a real <footer> keep it. The strip uses
    <footer class="legal-strip">, which the plain <footer> replacement above
    never matches, so stamping stays idempotent and edits here still
    propagate on the next run."""
    if 'class="legal-strip"' in html:
        return re.sub(r'<footer class="legal-strip">.*?</footer>', LEGAL_STRIP,
                      html, flags=re.DOTALL)
    if re.search(r'<footer\b', html):
        return html
    body_close = html.rfind('</body>')
    if body_close == -1:
        # download.html has no </body> at all. The strip still belongs on the
        # page, so append it rather than skip the page.
        return html.rstrip() + '\n' + LEGAL_STRIP + '\n'
    return html[:body_close] + LEGAL_STRIP + '\n' + html[body_close:]


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
    """Replace <div class="nav-mobile"...>...</div>, counting nested divs.

    NEW_MOBILE stamps two siblings: the drawer and its tail. An earlier run
    left a tail behind, and the div counter below stops at the drawer's own
    </div>, so without this the second run would leave the old tail sitting
    after the new one and the idempotency gate would go red. The tail holds
    anchors and no nested divs, so one non-greedy match takes it out."""
    html = re.sub(r'\n?<div class="nav-mobile-tail".*?</div>', '',
                  html, flags=re.DOTALL)
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
    if rel in KEEP_OWN_NAV:
        return False
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
    updated = inject_legal_strip(updated)
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
