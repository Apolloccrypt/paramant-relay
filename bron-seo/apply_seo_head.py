#!/usr/bin/env python3
"""Fill in the head-level SEO contract for every frontend page.

Everything this script writes lives inside <head> and changes nothing a visitor
sees: a canonical link, Open Graph tags, a robots meta for private pages, and a
JSON-LD block. No analytics, no cookies, no third-party request is added
anywhere -- the whole point is that a page can be findable on static markup
alone.

Idempotent: running it twice produces the same file. It never overwrites a tag
that is already there, except the JSON-LD block it wrote itself (marked with
data-paramant-seo) so the graph can be regenerated.

Run: python3 bron-seo/apply_seo_head.py [--check]
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND = os.path.join(ROOT, "frontend")
ORIGIN = "https://paramant.app"
SKIP_DIRS = {"node_modules", "vendor"}

# Behind a login, one-shot flows, error pages. These get noindex and stay out
# of the sitemap. Keep in step with PRIVATE in tests/seo-contract.test.mjs.
REDIRECTS = {"iot"}

PRIVATE = {
    "404", "account", "admin", "all-systems-go", "claim", "co-sign", "dashboard",
    "developer", "get", "ontvang", "request-key", "setup",
    # /parashare sits behind the same nginx auth_request the test's PRIVATE set
    # names it for. It was in this list's counterpart and not in this list, so
    # the two files disagreed about one page.
    "parashare",
    "auth/backup", "auth/login", "auth/request-reset", "auth/reset-confirm",
    "auth/setup", "billing/checkout", "signup/verified"}

# Pages that describe an actual piece of software a visitor can use. These earn
# SoftwareApplication; the rest stay WebPage. Claiming SoftwareApplication on a
# policy page is the kind of over-tagging that gets structured data ignored.
SOFTWARE = {
    "index", "parasend", "parasign", "parashare", "sign", "verify", "vault", "download",
    "co-sign"}

# Where a page ships a SoftwareApplication node that is more specific than the
# generic one, it is written down here instead of by hand in the HTML, or the
# next run of this script quietly reverts it. The homepage sells ParaSign by
# name (#328) and offers the Community plan at EUR 0, which is what
# frontend/pricing.html prints on the ParaSign Community card.
SOFTWARE_OVERRIDES = {
    "index": {
        "name": "ParaSign by Paramant",
        "applicationCategory": "BusinessApplication",
        "offers": {
            "@type": "Offer",
            "price": "0",
            "priceCurrency": "EUR",
            "url": ORIGIN + "/pricing"}},
}


def pages():
    for base, dirs, files in os.walk(FRONTEND):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in sorted(files):
            if fn.endswith(".html"):
                rel = os.path.relpath(os.path.join(base, fn), FRONTEND)
                yield rel[:-5].replace(os.sep, "/"), os.path.join(base, fn)


def url_for(slug):
    if slug == "index":
        return ORIGIN + "/"
    if slug.endswith("/index"):
        return f"{ORIGIN}/{slug[:-len('/index')]}"
    return f"{ORIGIN}/{slug}"


def find(pattern, html, group=1):
    m = re.search(pattern, html, re.I | re.S)
    return m.group(group).strip() if m else ""


def clean(text):
    """Collapse an HTML fragment into one line of plain sentence text."""
    text = re.sub(r"<[^>]+>", " ", text)
    text = (text.replace("&mdash;", "-").replace("&middot;", "\u00b7")
                .replace("&amp;", "&").replace("&nbsp;", " ")
                .replace("&quot;", '"').replace("&#39;", "'"))
    return re.sub(r"\s+", " ", text).strip()


def lead_sentence(html, limit=158):
    """A description taken from the page's own opening prose.

    Never invent a description: an inaccurate one costs more in trust than a
    missing one costs in ranking. This lifts the first real paragraph, so what
    Google shows is what the page actually says.
    """
    body = re.sub(r"<(script|style|nav|header|footer)[^>]*>.*?</\1>", " ", html, flags=re.S | re.I)
    for m in re.finditer(r"<p[^>]*>(.*?)</p>", body, re.S | re.I):
        text = clean(m.group(1))
        if len(text) < 50 or text.lower().startswith(("cookie", "javascript")):
            continue
        if len(text) <= limit:
            return text
        cut = text[:limit]
        stop = max(cut.rfind(". "), cut.rfind("? "), cut.rfind("! "))
        return (cut[:stop + 1] if stop > 60 else cut.rsplit(" ", 1)[0]).strip()
    return ""


def trim(text, limit=158):
    if len(text) <= limit:
        return text
    cut = text[:limit]
    return cut.rsplit(" ", 1)[0].rstrip(" ,;:-.") + "..."


# Every field here is already printed on the site: the legal name, the town and
# the KvK number come from the footer that apply-nav.py stamps on every page,
# the founder and his title come from /about, and the server location comes from
# the jurisdiction table on /security. Nothing is asserted that a reader cannot
# check on the page itself. The old description said "built and hosted in the
# Netherlands", which contradicted /security: the company is Dutch, the servers
# are Hetzner Nuremberg.
ORG = {
    "@type": "Organization",
    "@id": f"{ORIGIN}/#organization",
    "name": "Paramant",
    "legalName": "Paramantis Solutions B.V.",
    "url": ORIGIN + "/",
    "description": "Document signing and encrypted file transfer for "
                   "professional firms in the EU. Dutch company, servers in "
                   "Germany.",
    "founder": {
        "@type": "Person",
        "name": "Mick Beer",
        "jobTitle": "Privacy and security researcher"},
    "address": {
        "@type": "PostalAddress",
        "addressLocality": "Harderwijk",
        "addressCountry": "NL"},
    "identifier": {
        "@type": "PropertyValue",
        "name": "KvK",
        "value": "42115132"},
    "email": "privacy@paramant.app",
    "areaServed": "EU",
    "knowsLanguage": ["nl", "en"]}


def graph_for(slug, title, desc):
    """The JSON-LD graph for one page.

    Deliberately small. Every node here is something we can point at on the
    page itself; nothing is asserted that a reader could not verify. No rating,
    no review, no price -- those are exactly the claims that get a site a manual
    action when they are not backed by real data.
    """
    url = url_for(slug)
    page = {
        "@type": "WebPage",
        "@id": url + "#webpage",
        "url": url,
        "name": clean(title),
        "isPartOf": {"@id": f"{ORIGIN}/#website"},
        "publisher": {"@id": f"{ORIGIN}/#organization"},
        "inLanguage": "en"}
    if desc:
        page["description"] = desc
    nodes = [page]

    # A breadcrumb only where there is a real hierarchy to describe.
    if "/" in slug:
        section = slug.split("/")[0]
        items = [
            {"@type": "ListItem", "position": 1, "name": "Paramant", "item": ORIGIN + "/"},
            {"@type": "ListItem", "position": 2, "name": section.capitalize(), "item": f"{ORIGIN}/{section}"},
        ]
        if not slug.endswith("/index"):
            items.append({"@type": "ListItem", "position": 3, "name": clean(title).split("—")[0].split("·")[0].strip()})
        nodes.append({"@type": "BreadcrumbList", "@id": url + "#breadcrumb", "itemListElement": items})

    if slug in SOFTWARE:
        app = {
            "@type": "SoftwareApplication",
            "@id": url + "#software",
            "name": "Paramant",
            "applicationCategory": "SecurityApplication",
            "operatingSystem": "Web browser",
            "url": url}
        app.update(SOFTWARE_OVERRIDES.get(slug, {}))
        app["publisher"] = {"@id": f"{ORIGIN}/#organization"}
        nodes.append(app)

    # The Organization node goes on every public page, not just the homepage.
    # Every other page already pointed a publisher @id at it while the node
    # itself existed on one URL only, so a crawler landing on /pricing or
    # /about saw a dangling reference and no founder at all.
    nodes.append(ORG)

    if slug == "index":
        nodes.append({
            "@type": "WebSite",
            "@id": f"{ORIGIN}/#website",
            "url": ORIGIN + "/",
            "name": "Paramant",
            "publisher": {"@id": f"{ORIGIN}/#organization"},
            "inLanguage": "en"})

    return {"@context": "https://schema.org", "@graph": nodes}


MARK = ' data-paramant-seo="1"'


def apply(slug, path, check=False):
    html = open(path, encoding="utf-8").read()
    original = html
    changes = []
    # A redirect stub needs no description of its own, but must NOT be
    # noindexed: its canonical is what passes the signal on to the real page.
    redirect = slug in REDIRECTS
    private = slug in PRIVATE
    skip_content = private or redirect
    url = url_for(slug)

    title = find(r"<title[^>]*>(.*?)</title>", html)
    desc = find(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']*)["\']', html)

    # 1. Description: keep a good one, shorten a long one, derive a missing one
    #    from the page's own opening paragraph.
    if not skip_content:
        new_desc = desc
        # A 6-character description is worse than none: Google drops it and
        # writes its own snippet anyway, but the tag hides the problem from
        # every audit that only checks for presence.
        if len(desc) < 50:
            derived = lead_sentence(html)
            if derived:
                new_desc = derived
                changes.append(f"description ({'from lead paragraph' if not desc else f'was only {len(desc)} chars'})")
        elif len(desc) > 165:
            new_desc = trim(desc)
            changes.append(f"description shortened {len(desc)}->{len(new_desc)}")
        if new_desc and new_desc != desc:
            tag = f'<meta name="description" content="{new_desc}">'
            if desc:
                html = re.sub(r'<meta[^>]+name=["\']description["\'][^>]*>', tag, html, count=1, flags=re.I)
            else:
                html = re.sub(r"(</title>)", r"\1\n" + tag, html, count=1, flags=re.I)
        desc = new_desc

    # 2. Canonical. Without it, every query string is a duplicate page.
    if not re.search(r'rel=["\']canonical["\']', html, re.I):
        html = re.sub(r"(</title>)", r"\1\n" + f'<link rel="canonical" href="{url}">', html, count=1, flags=re.I)
        changes.append("canonical")

    # 3. robots noindex for anything private.
    if private and not re.search(r'name=["\']robots["\'][^>]*noindex', html, re.I):
        html = re.sub(r"(</title>)", r"\1\n" + '<meta name="robots" content="noindex, nofollow">', html, count=1, flags=re.I)
        changes.append("noindex")

    # 4. Open Graph, so a link pasted in Signal or LinkedIn renders as a card.
    if not skip_content:
        og = []
        if not re.search(r'property=["\']og:title["\']', html, re.I):
            og.append(f'<meta property="og:title" content="{clean(title)}">')
        if desc and not re.search(r'property=["\']og:description["\']', html, re.I):
            og.append(f'<meta property="og:description" content="{desc}">')
        if not re.search(r'property=["\']og:url["\']', html, re.I):
            og.append(f'<meta property="og:url" content="{url}">')
        if not re.search(r'property=["\']og:type["\']', html, re.I):
            og.append('<meta property="og:type" content="website">')
        if not re.search(r'property=["\']og:site_name["\']', html, re.I):
            og.append('<meta property="og:site_name" content="Paramant">')
        if og:
            html = re.sub(r"(</title>)", r"\1\n" + "\n".join(og), html, count=1, flags=re.I)
            changes.append(f"open graph ({len(og)} tags)")

    # 5. JSON-LD. Regenerate our own block; never touch a hand-written one.
    if not skip_content:
        block = json.dumps(graph_for(slug, title, desc), ensure_ascii=False, indent=2)
        tag = f'<script type="application/ld+json"{MARK}>\n{block}\n</script>'
        existing = re.search(r'<script[^>]*data-paramant-seo="1"[^>]*>.*?</script>', html, re.S | re.I)
        if existing:
            if existing.group(0) != tag:
                html = html[:existing.start()] + tag + html[existing.end():]
                changes.append("json-ld (updated)")
        elif not re.search(r'application/ld\+json', html, re.I):
            html = re.sub(r"(</head>)", tag + r"\n\1", html, count=1, flags=re.I)
            changes.append("json-ld")

    if html != original and not check:
        open(path, "w", encoding="utf-8").write(html)
    return changes


def main():
    check = "--check" in sys.argv
    touched = 0
    for slug, path in pages():
        changes = apply(slug, path, check)
        if changes:
            touched += 1
            print(f"  {slug:38} {', '.join(changes)}")
    print(f"\n{'would change' if check else 'changed'}: {touched} pages")
    return 1 if (check and touched) else 0


if __name__ == "__main__":
    sys.exit(main())
