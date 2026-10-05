#!/usr/bin/env python3
"""Replace <nav class="nav"> + <div class="nav-mobile"> in every page that uses the shared nav.
Also injects design-system.css, nav.css, and nav.js into <head>/<body>."""

import re, os, glob

NEW_NAV = '''\
<nav class="nav">
  <a href="/" class="nav-logo"><span class="logo-para">Para</span><span class="logo-mant">MANT</span></a>

  <ul class="nav-links">
    <li><a href="/#products" class="nav-link">Product</a></li>
    <li><a href="/gereedschap" class="nav-link">Tools</a></li>
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
  <a href="/gereedschap" class="nav-mobile-standalone">Tools</a>
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
# Everything else (status, press, self-host) is reachable from the four nav
# links or from the pages they lead to; a footer is not a second navigation.
# /partners is the exception: every outside party the service depends on, with
# its status, read from deploy/partners.json. It sits with the legal documents
# because /privacy and /dpa point at it.
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
          <a href="/partners">Partners</a>
        </div>
      </div>
    </div>
  </div>
</footer>'''

# The four pages whose main language is Dutch since 23 September 2026 (/,
# /pricing, /about, /security; the English text moved to /en/...). They carry
# the same bar in Dutch, with the two outward product names Mick settled on:
# Versturen and Ondertekenen. js/nav-auth.js re-renders the same Dutch list
# when <html lang="nl">, so the two may never drift apart.
# Account and sign-in pages followed on the same day: one language from the
# first screen to the dashboard. Sending and receiving (get, ontvang, parasend,
# parashare, verify) too.
NL_PAGES = {
    'index.html', 'pricing.html', 'about.html', 'security.html',
    'auth/login.html', 'auth/setup.html', 'auth/backup.html',
    'auth/request-reset.html', 'auth/reset-confirm.html',
    'signup.html', 'signup/verified.html', 'request-key.html',
    'account.html', 'dashboard.html',
    'get.html', 'ontvang.html', 'parasend.html', 'parashare.html', 'verify.html',
}
# The signing pages and the help articles followed the same day, with their
# English text under /en/sign, /en/parasign and /en/help/.
NL_PAGES_SIGN_HELP = {'sign.html', 'parasign.html'} | {
    'help/' + f for f in os.listdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'help'))
    if f.endswith('.html')}

# Since the whole site went Dutch, the language of the bar no longer comes from
# NL_PAGES but from the page itself: the Dutch bar, footer and strip on every
# page whose <html lang> is not "en", the English ones where it is (the copies
# under /en, and any page not yet translated). NL_PAGES stays as the record of
# the first four; a page listed there is Dutch by its own lang anyway. nav.js
# and js/nav-auth.js decide on the same <html lang>, so the generator and the
# re-render can never disagree about a page.
def is_english(rel):
    """Where the page sits: under /en or not. Decides the link targets."""
    return rel.startswith('en/')


def speaks_english(html):
    """What the page says it is. Decides the language of the bar."""
    m = re.search(r'<html\b[^>]*\blang="([^"]+)"', html)
    return bool(m) and m.group(1).lower().startswith('en')


# The language switch. Every page carries "NL | EN" in the bar, the current
# language marked, and each half links to the same page in that language: the
# path with or without /en in front. A page without a counterpart links to the
# home page of the other language instead of to a 404. No cookie, no redirect
# on the browser's language: the URL is the whole truth, so a link someone
# shares opens in the language they read it in.
def url_of(rel):
    slug = rel[:-len('.html')]
    if slug == 'index':
        return '/'
    if slug.endswith('/index'):
        slug = slug[:-len('/index')]
    return '/' + slug


def lang_urls(rel):
    """(nl_url, en_url) for the page at rel, each falling back to the home
    page of that language when the counterpart file does not exist."""
    if is_english(rel):
        nl_rel, en_rel = rel[len('en/'):], rel
    else:
        nl_rel, en_rel = rel, 'en/' + rel
    nl = url_of(nl_rel) if os.path.exists(os.path.join(frontend, nl_rel)) else '/'
    en = url_of(en_rel) if os.path.exists(os.path.join(frontend, en_rel)) else '/en'
    return nl, en


def to_english_links(block):
    """Point the links of an English bar or footer at the English page where
    one exists, so an English reader is not dropped on a Dutch page by the
    chrome of an English one. A route with no English page keeps its link."""
    def swap(m):
        path, frag = m.group(1), m.group(2) or ''
        rel = 'index.html' if path == '/' else path.lstrip('/') + '.html'
        if os.path.exists(os.path.join(frontend, 'en', rel)):
            return 'href="' + ('/en' if path == '/' else '/en' + path) + frag + '"'
        return m.group(0)
    return re.sub(r'href="(/[^"#?]*)(#[^"]*)?"', swap, block)


def lang_switch(rel, tag='div', english=None):
    nl, en = lang_urls(rel)
    if english is None:
        english = is_english(rel)
    on = ' aria-current="true"'
    return (f'<{tag} class="nav-lang" role="group" aria-label="Taal / Language">'
            f'<a href="{nl}" hreflang="nl" lang="nl"{"" if english else on}>NL</a>'
            '<span class="nav-lang-sep" aria-hidden="true">|</span>'
            f'<a href="{en}" hreflang="en" lang="en"{on if english else ""}>EN</a></{tag}>')

# The theme switch. It sits beside NL | EN and has the same form: two halves
# and a bar between them, the current one drawn solid. A sun and a moon as
# inline SVG, one button, aria-pressed says whether the dark edition is on.
# /js/theme.js handles the press (delegated, so nav-auth.js may re-render the
# drawer around it) and keeps aria-pressed true to the page on load.
SUN = ('<svg class="nav-theme-icon" viewBox="0 0 16 16" width="16" height="16" aria-hidden="true" focusable="false">'
       '<circle cx="8" cy="8" r="2.9" fill="none" stroke="currentColor" stroke-width="1.5"/>'
       '<path d="M8 1.2v1.5M8 13.3v1.5M1.2 8h1.5M13.3 8h1.5M3.2 3.2l1.05 1.05M11.75 11.75l1.05 1.05M3.2 12.8l1.05-1.05M11.75 4.25l1.05-1.05" '
       'fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>')
MOON = ('<svg class="nav-theme-icon" viewBox="0 0 16 16" width="16" height="16" aria-hidden="true" focusable="false">'
        '<path d="M13.6 9.9A5.8 5.8 0 0 1 6.1 2.4a5.8 5.8 0 1 0 7.5 7.5z" fill="none" stroke="currentColor" '
        'stroke-width="1.5" stroke-linejoin="round"/></svg>')


def theme_switch(english=False):
    label, hint = ('Theme', 'Light or dark') if english else ('Thema', 'Licht of donker')
    return (f'<button type="button" class="nav-theme" data-theme-toggle aria-label="{label}" aria-pressed="false" title="{hint}">'
            f'<span class="nav-theme-opt nav-theme-light">{SUN}</span>'
            '<span class="nav-theme-sep" aria-hidden="true">|</span>'
            f'<span class="nav-theme-opt nav-theme-dark">{MOON}</span></button>')


# The script that picks the edition before the first paint, in the <head> of
# every page that links the design system, including the ones that keep their
# own nav. And the dark ground in each page's critical <style>, so the very
# first frame is already the right colour.
THEME_JS = '<script src="/js/theme.js?v=6"></script>'
CRITICAL_DARK = ('html[data-theme="dark"],html[data-theme="dark"] body{background:#0E141B;color:#E6EDF5}'
                 'html[data-theme="dark"]{color-scheme:dark}')


def inject_theme(html):
    if '/design-system.css' not in html and '/app-2026.css' not in html:
        return html
    html = re.sub(r'<script src="/js/theme\.js(?:\?v=\d+)?"></script>', THEME_JS, html)
    if THEME_JS not in html:
        head_close = html.find('</head>')
        if head_close != -1:
            html = html[:head_close] + THEME_JS + '\n' + html[head_close:]

    def critical(m):
        body = m.group(2)
        body = re.sub(r'@media \(prefers-color-scheme:\s*dark\)\{html\[data-theme="auto"\].*?\}\}', '', body)
        body = re.sub(r'html\[data-theme="dark"\][^{]*\{[^}]*\}', '', body)
        return m.group(1) + body + CRITICAL_DARK + m.group(3)
    return re.sub(r'(<style id="critical-css">)(.*?)(</style>)', critical, html, count=1, flags=re.DOTALL)


NEW_NAV_NL = '''\
<nav class="nav">
  <a href="/" class="nav-logo"><span class="logo-para">Para</span><span class="logo-mant">MANT</span></a>

  <ul class="nav-links">
    <li><a href="/parasend" class="nav-link">Versturen</a></li>
    <li><a href="/parasign" class="nav-link">Ondertekenen</a></li>
    <li><a href="/gereedschap" class="nav-link">Gereedschap</a></li>
    <li><a href="/security" class="nav-link">Beveiliging</a></li>
    <li><a href="/pricing" class="nav-link">Prijzen</a></li>
  </ul>

  <div class="nav-auth" id="nav-auth">
    <a href="/help" class="nav-help">Hulp</a>
    <a href="/auth/login" class="nav-signin">Inloggen</a>
    <a href="/signup" class="nav-cta">Account maken</a>
  </div>

  <button class="nav-hamburger" id="nav-hamburger" aria-label="Menu openen" aria-expanded="false">
    <span></span><span></span><span></span>
  </button>
</nav>'''

NEW_MOBILE_NL = '''\
<div class="nav-mobile" id="nav-mobile">
  <a href="/parasend" class="nav-mobile-standalone">Versturen</a>
  <a href="/parasign" class="nav-mobile-standalone">Ondertekenen</a>
  <a href="/gereedschap" class="nav-mobile-standalone">Gereedschap</a>
  <a href="/security" class="nav-mobile-standalone">Beveiliging</a>
  <a href="/pricing" class="nav-mobile-standalone">Prijzen</a>
</div>
<div class="nav-mobile-tail" id="nav-mobile-tail">
  <a href="/auth/login" class="nav-tail-btn">Inloggen</a>
  <a href="/help" class="nav-tail-link">Hulp</a>
</div>'''

NEW_FOOTER_NL = '''\
<footer>
  <div class="container-lg">
    <div class="footer-grid footer-slim">
      <div>
        <div class="logo" style="margin-bottom:var(--space-3)"><span class="a">Para</span><span class="b">MANT</span></div>
        <p style="font-size:var(--text-xs);color:var(--ink-dim);line-height:1.8;max-width:320px">Paramant is een product van <strong>Paramantis Solutions B.V.</strong><br>Harderwijk, Nederland<br>KvK 42115132<br><a href="mailto:privacy@paramant.app">privacy@paramant.app</a></p>
        <p style="font-family:var(--mono);font-size:var(--text-xs);color:var(--ink-dim);margin-top:var(--space-4);line-height:1.8">BUSL-1.1 &middot; &copy; 2026 PARAMANTIS SOLUTIONS B.V.</p>
      </div>
      <div>
        <div class="footer-col-label">Bedrijf</div>
        <div class="footer-links">
          <a href="/about">Over Paramant</a>
          <a href="/changelog">Wijzigingen</a>
        </div>
      </div>
      <div>
        <div class="footer-col-label">Juridisch</div>
        <div class="footer-links">
          <a href="/privacy">Privacybeleid</a>
          <a href="/dpa">Verwerkersovereenkomst</a>
          <a href="/terms">Voorwaarden</a>
          <a href="/sla">SLA</a>
          <a href="/license">Licentie</a>
          <a href="/partners">Partners</a>
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
  <a href="/privacy">Privacy</a><span class="legal-sep">&middot;</span><a href="/dpa">Data Processing Agreement</a><span class="legal-sep">&middot;</span><a href="/terms">Terms of Service</a><span class="legal-sep">&middot;</span><a href="/partners">Partners</a>
</footer>'''

LEGAL_STRIP_NL = '''\
<footer class="legal-strip">
  <a href="/privacy">Privacy</a><span class="legal-sep">&middot;</span><a href="/dpa">Verwerkersovereenkomst</a><span class="legal-sep">&middot;</span><a href="/terms">Voorwaarden</a><span class="legal-sep">&middot;</span><a href="/partners">Partners</a>
</footer>'''

DS_LINK   = '<link rel="stylesheet" href="/design-system.css?v=33">'
NAV_LINK  = '<link rel="stylesheet" href="/nav.css?v=29">'
NAV_JS    = '<script src="/nav.js?v=17" defer></script>'
NAV_AUTH_JS = '<script src="/js/nav-auth.js?v=12" defer></script>'

# Pages that don't have <nav class="nav"> yet but should — inject the canonical
# nav after <body> (or after a skip-link if present). App shells (admin,
# dashboard, billing) and printable standalones (briefs, one-pager,
# pattern-library) intentionally stay nav-less and are not in this set.
ADD_NAV_TO = {
    '404.html',
    'changelog.html',
    'download.html',
    'gereedschap.html',
    'partners.html',
    'security/acknowledgements.html',
    'signup/verified.html',
}


# Application shells that deliberately keep their own, narrower nav. The
# marketing nav is for visitors; these pages are for people already inside the
# product, so the generator leaves them alone.
KEEP_OWN_NAV = {
    'co-sign.html',
    'en/co-sign.html',
    'developer.html',
}


def inject_legal_strip(html, strip=None):
    """Give footerless pages one line with privacy, dpa and terms.

    Pages that already carry a real <footer> keep it. The strip uses
    <footer class="legal-strip">, which the plain <footer> replacement above
    never matches, so stamping stays idempotent and edits here still
    propagate on the next run."""
    strip = strip or LEGAL_STRIP_NL
    if 'class="legal-strip"' in html:
        return re.sub(r'<footer class="legal-strip">.*?</footer>', lambda m: strip,
                      html, flags=re.DOTALL)
    if re.search(r'<footer\b', html):
        return html
    body_close = html.rfind('</body>')
    if body_close == -1:
        # download.html has no </body> at all. The strip still belongs on the
        # page, so append it rather than skip the page.
        return html.rstrip() + '\n' + strip + '\n'
    return html[:body_close] + strip + '\n' + html[body_close:]


# The line to the same page in the other language ("This page in English").
# It used to be a loose <p> with an inline style between the page and the
# footer, which on a zoomed desktop read as a stray link under the layout
# (2026-09-24). It belongs to the footer: the last item of the legal strip, or
# a line in the brand column of the site footer under the licence. The link
# itself is the page's own (some pages keep an id that their script rewrites),
# so the generator lifts it out wherever it stands and puts it back in the
# footer, which keeps the stamp idempotent: on the next run it is lifted out
# of the footer and put back in the same place.
LANG_LINE_RE = re.compile(
    r'\n*[ \t]*<(p|span) class="lang-switch"[^>]*>\s*'
    r'(?:<span class="legal-sep"[^>]*>[^<]*</span>)?\s*(<a\b[^>]*>[^<]*</a>)\s*</\1>')
FOOTER_LICENCE = 'BUSL-1.1 &middot; &copy; 2026 PARAMANTIS SOLUTIONS B.V.</p>'


def take_lang_line(html):
    m = LANG_LINE_RE.search(html)
    if not m:
        return html, None
    link = re.sub(r'\s+style="[^"]*"', '', m.group(2))
    return html[:m.start()] + html[m.end():], link


def place_lang_line(html, link):
    if not link:
        return html
    strip = re.search(r'<footer class="legal-strip">.*?(?=\n</footer>)', html, flags=re.DOTALL)
    if strip:
        piece = f'<span class="lang-switch"><span class="legal-sep">&middot;</span>{link}</span>'
        return html[:strip.end()] + piece + html[strip.end():]
    footer = re.search(r'<footer>.*?</footer>', html, flags=re.DOTALL)
    if footer and FOOTER_LICENCE in footer.group(0):
        i = html.index(FOOTER_LICENCE, footer.start()) + len(FOOTER_LICENCE)
        return html[:i] + f'\n        <p class="lang-switch">{link}</p>' + html[i:]
    # No footer the generator knows: the end of the page content.
    at = re.search(r'<footer\b', html)
    i = at.start() if at else html.rfind('</body>')
    return html[:i] + f'<p class="lang-switch">{link}</p>\n' + html[i:]


def inject_main(html):
    """Give a page without a <main> landmark one, from under the nav to the
    footer. A screen reader jumps by landmarks, and 19 pages had none.

    Most of these pages already put id="main-content" on their first section,
    which is where the skip-link lands and what their own CSS styles, so that
    id stays where it is and the landmark goes around it. A page without the id
    gets it on the <main>. A page that already has a <main> is left alone,
    which keeps the stamp idempotent."""
    if re.search(r'<main\b', html):
        return html
    tail = re.search(r'<div class="nav-mobile-tail" id="nav-mobile-tail">.*?</div>\n', html, flags=re.DOTALL)
    if not tail:
        return html
    start = tail.end()
    foot = re.search(r'<footer\b', html[start:])
    if not foot:
        return html
    end = start + foot.start()
    opener = '<main>' if 'id="main-content"' in html else '<main id="main-content" tabindex="-1">'
    return html[:start] + opener + '\n' + html[start:end] + '</main>\n' + html[end:]


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


def inject_nav_block(html, nav=None, mobile=None):
    """Insert the nav + mobile drawer after the skip-link (or <body> if none)."""
    nav = nav or NEW_NAV_NL
    mobile = mobile or NEW_MOBILE_NL
    skip = re.search(r'<a href="#main-content"[^>]*class="skip-link"[^>]*>[^<]*</a>', html)
    if skip:
        i = skip.end()
    else:
        body = re.search(r'<body[^>]*>', html)
        if not body:
            return html
        i = body.end()
    return html[:i] + '\n' + nav + '\n' + mobile + html[i:]


def replace_mobile_div(html, mobile=None):
    """Replace <div class="nav-mobile"...>...</div>, counting nested divs.

    NEW_MOBILE stamps two siblings: the drawer and its tail. An earlier run
    left a tail behind, and the div counter below stops at the drawer's own
    </div>, so without this the second run would leave the old tail sitting
    after the new one and the idempotency gate would go red. The tail holds
    anchors and no nested divs, so one non-greedy match takes it out."""
    mobile = mobile or NEW_MOBILE_NL
    html = re.sub(r'\n?<div class="nav-mobile-tail".*?</div>', '',
                  html, flags=re.DOTALL)
    start = html.find('<div class="nav-mobile"')
    if start == -1:
        nav_end = html.find('</nav>') + len('</nav>')
        return html[:nav_end] + '\n' + mobile + html[nav_end:]
    depth, i = 0, start
    while i < len(html):
        if html[i:i+4] == '<div':
            depth += 1
            i += 4
        elif html[i:i+6] == '</div>':
            depth -= 1
            if depth == 0:
                return html[:start] + mobile + html[i + 6:]
            i += 6
        else:
            i += 1
    return html


def renumber_shared_assets(fpath, html):
    """Carry the ?v= of design-system.css and nav.css to pages the generator
    otherwise leaves alone.

    co-sign.html and developer.html keep their own nav, and setup.html and
    all-systems-go.html carry no shared nav at all, but all four still LINK
    these two stylesheets. Bumping the version here and nowhere else left them
    pointing at the old cache key, which scripts/check-cache-bust.sh fails on
    ("one file, two cache keys") while the idempotency gate stayed green. This
    only rewrites links that are already there; it injects nothing.

    developer.html links nav.js and nav-auth.js as well, and those were left
    behind by the same omission: bumping NAV_AUTH_JS moved every stamped
    page and not that one, which is "one file, two cache keys" again on a
    different file."""
    updated = re.sub(r'<link rel="stylesheet" href="/design-system\.css(?:\?v=\d+)?">', DS_LINK, html)
    updated = re.sub(r'<link rel="stylesheet" href="/nav\.css(?:\?v=\d+)?">', NAV_LINK, updated)
    updated = re.sub(r'<script src="/nav\.js(?:\?v=\d+)?" defer></script>', NAV_JS, updated)
    updated = re.sub(r'<script src="/js/nav-auth\.js(?:\?v=\d+)?" defer></script>', NAV_AUTH_JS, updated)
    updated = inject_theme(updated)
    if updated == html:
        return False
    with open(fpath, 'w', encoding='utf-8') as f:
        f.write(updated)
    return True


def process(fpath):
    with open(fpath, encoding='utf-8') as f:
        original = f.read()
    rel = os.path.relpath(fpath, frontend).replace(os.sep, '/')
    if rel in KEEP_OWN_NAV:
        return renumber_shared_assets(fpath, original)
    content = original
    english = speaks_english(content)
    if english:
        nav, mobile, footer, strip = (to_english_links(b) for b in (NEW_NAV, NEW_MOBILE, NEW_FOOTER, LEGAL_STRIP))
    else:
        nav, mobile, footer, strip = NEW_NAV_NL, NEW_MOBILE_NL, NEW_FOOTER_NL, LEGAL_STRIP_NL
    if '<nav class="nav">' not in content:
        if rel not in ADD_NAV_TO:
            return renumber_shared_assets(fpath, original)
        content = inject_nav_block(content, nav, mobile)
        if '<nav class="nav">' not in content:
            return False
    # The switch sits in the bar from 701px up. Below that the bar keeps its one
    # action beside the menu button (nav.css), and the switch hangs in the strip
    # under the drawer instead, next to Sign in and Help. A <span> there, not a
    # <div>: replace_mobile_div takes the strip out with a non-greedy match up to
    # its first </div>, which a nested div would cut short.
    nav = nav.replace('  <button class="nav-hamburger"', '  ' + lang_switch(rel, english=english) + '\n  ' + theme_switch(english) + '\n\n  <button class="nav-hamburger"', 1)
    assert mobile.endswith('</div>')
    mobile = (mobile[:-len('</div>')] + '  <span class="nav-prefs">' + lang_switch(rel, 'span', english)
              + theme_switch(english) + '</span>\n</div>')
    content, lang_link = take_lang_line(content)
    updated = re.sub(r'<nav class="nav">.*?</nav>', lambda m: nav, content, flags=re.DOTALL)
    updated = replace_mobile_div(updated, mobile)
    updated = re.sub(r'<footer>.*?</footer>', lambda m: footer, updated, flags=re.DOTALL)
    updated = inject_legal_strip(updated, strip)
    updated = place_lang_line(updated, lang_link)
    updated = re.sub(r'(<a href="#main-content" class="skip-link">)[^<]*(</a>)',
                     lambda m: m.group(1) + ('Skip to main content' if english else 'Naar de inhoud') + m.group(2),
                     updated, count=1)
    updated = inject_main(updated)
    updated = inject_design_system(updated)
    updated = inject_nav_js(updated)
    updated = inject_nav_auth_js(updated)
    updated = inject_theme(updated)
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
