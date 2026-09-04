# Making a release

There are 268 commits between the `v3.0.0` tag and `main`, no `v3.1.0` tag, and
a CHANGELOG that stood still from 2026-06-01 to 2026-09-02. Nobody could say
what was running in production without an SSH session, and a rollback meant
guessing at a date. That is the problem this document exists to end.

The rule, in one line: **a release is a tag, the tag builds the image, and
production runs that image.** Everything below is that rule spelled out.

Attribution: commits, tags and PR text are all in Mick's name, per `AGENTS.md`.
No co-author trailers, no tool attribution, no em-dashes and no emoji.
`scripts/check-commit-style.sh` enforces it and `tests/static-sanity.sh` runs
it over the last commit.

---

## What a version number means here

`package.json` at the repository root is the version. Nothing else states it.

| Place | How it gets the version |
|---|---|
| `relay/package.json`, `admin/package.json` | copied by hand at bump time |
| both `package-lock.json` files | copied by hand at bump time |
| `relay.js` `VERSION`, and therefore `/health` and `/metrics` | `require('./package.json').version` at runtime |
| `org.opencontainers.image.version` on both images | `ARG IMAGE_VERSION`, defaulted to the same string, passed explicitly by `docker-publish.yml` |
| `scripts/post-deploy-verify.sh` | reads `relay/package.json` |
| the git tag | `v` plus the version |

`tests/version-consistency.test.mjs` fails the build if any of those drift, so
you do not have to remember the list. Bump `package.json`, run the suite, and it
tells you what else moved.

Semver, as the project actually uses it:

- **patch** (3.1.0 to 3.1.1): fixes only, no new endpoint, no changed response.
- **minor** (3.1.0 to 3.2.0): new endpoints, new features, anything a client can
  newly rely on. This is the usual one.
- **major**: a wire-format break or a removed endpoint. `docs/wire-format-v1.md`
  is the contract; breaking it is a major.

---

## Cutting a release

Steps 1 to 4 are a normal pull request. Step 5 onwards happens on `main`.

### 1. Write the CHANGELOG section first

Before touching a version number. The section is what the release *is*; the
number is just its name.

```bash
git fetch origin
git log v3.0.0..origin/main --pretty=format:'%ad %s' --date=short
```

Take the last tag, not the last release date. Group into the headings this
CHANGELOG already uses: **Security**, **Added**, **Changed**, **Fixed**,
**Removed**, **Build, CI and dependencies**. Cite the PR number where the commit
carries one.

One trap, learned the hard way: a trailing `(#nn)` in a commit subject is *not*
always a pull request. Several of them are security-finding or issue numbers,
and #19 and #21 in the 3.1.0 log are exactly that. Check before you write it
down:

```bash
gh pr view 19 --json number,title,state
```

Rename `## [Unreleased]` to `## [X.Y.Z] - unreleased` and open a fresh empty
`## [Unreleased]` above it.

### 2. Bump the version

```bash
# root package.json is the source; the rest follow it.
$EDITOR package.json relay/package.json admin/package.json
$EDITOR package-lock.json relay/package-lock.json admin/package-lock.json  # "version" twice in each
$EDITOR relay/Dockerfile admin/Dockerfile                                   # ARG IMAGE_VERSION default

node --test tests/version-consistency.test.mjs
```

That suite is the checklist. If it passes, every copy agrees.

### 3. Run what CI runs

These mirror `.github/workflows/test.yml`. When that file changes, change these
with it; the exclusion lists are the part that drifts.

```bash
# relay unit suite (installs nothing, so no redis and no engine)
cd relay && RELAY_TEST_SKIP=redis node --test --test-reporter=tap \
  $(ls test/*.test.js | grep -vE \
  'inbound-hash-verify|deep-health-gate|billing-stance-boot|parasign-sandbox|parasign-open-api-e2e|parasign-envelope-index|parasign-signs-quota|route-')
cd ../admin && node --test test/*.test.js
cd ..

# root integration suites, no browser. CI installs the root deps first, and so
# must you: tests/heartbeat-lib.test.mjs imports @noble/post-quantum.
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm ci
node --test $(node scripts/browser-suites.mjs --no-browser)

# the static gates
tests/static-sanity.sh
npx --yes eslint@9 .
find . -name '*.sh' -not -path './node_modules/*' -print0 | xargs -0 -n1 bash -n
```

The route suites and the crypto suite are not in that list. They need a booted
`relay.js`, a redis service and the built `@paramant/core`, which is why they
live in their own CI jobs; run them there rather than locally.

`--test-reporter=tap` on the first command is not cosmetic. Two steps in
`test.yml` parse TAP diagnostic lines to catch a suite that runs and asserts
nothing, and Node's default reporter for a non-TTY changed from tap to spec
between Node 20 and Node 24. Under spec those gates see nothing and pass.

Node 24 is the supported line (`.nvmrc`, and `engines` allows 22 and 24). If
your machine is on something else, run the suites in the image instead:

```bash
docker run --rm -v "$PWD:/w" -w /w node:24-alpine sh -c \
  'cd relay && RELAY_TEST_SKIP=redis node --test test/*.test.js'
```

### 4. Open the PR, merge it

Normal review. The `Build prod image (drift gate)` job builds the real
production Dockerfile on the PR; that is the job that catches a toolchain break
before it reaches `main`, and it is not optional.

### 5. Tag

Only after the PR is on `main` and green.

```bash
git checkout main && git pull
git tag -a v3.1.0 -m "Release 3.1.0"
git push origin v3.1.0
```

Annotated, never lightweight. The tag message is the version and nothing else;
the CHANGELOG section carries the content.

### 6. The tag builds and publishes the image

Pushing `v*.*.*` triggers `.github/workflows/docker-publish.yml`, which:

- builds `relay/Dockerfile` for amd64 and arm64,
- pushes `mtty001/relay:3.1.0` and `mtty001/relay:latest`,
- passes `IMAGE_VERSION=3.1.0` so the image label matches the tag,
- signs the image with cosign (keyless, Sigstore), attaches an SBOM and records
  SLSA provenance, all bound to the digest and not to a mutable tag.

Watch it finish and write the digest down. It is what the next step and any
rollback refer to.

```bash
gh run watch
docker buildx imagetools inspect mtty001/relay:3.1.0 --format '{{.Manifest.Digest}}'
```

### 7. Deploy

Follow `deploy/DEPLOY-3.1.md` step by step. It is written for this specific
release, ends with a rollback section, and expects to be read on the server.

Known gap, stated rather than hidden: `docs/RUNBOOK-DEPLOY-3.0.0.md` describes
the older reality, where the server built the images itself from a `git pull`
and there was no registry. `docker-publish.yml` has been pushing images for
some time, so the published image and the running image are two different build
paths today. Closing that gap (production pulls the tagged image instead of
building it) is a deploy-time decision and is deliberately not part of this
document; until it is made, `deploy/DEPLOY-3.1.md` is what actually happens.

### 8. Verify, then say it is done

```bash
# on the server, so the local relay is reachable
scripts/post-deploy-verify.sh https://paramant.app http://127.0.0.1:3000
```

Be precise about what that proves. The script compares the version `/health`
returns against the version in the `relay/package.json` **of the checkout you
run it from**. It does not read the tag. Run from a checkout of `v3.1.0`, tag
and `package.json` agree by construction (that is what
`tests/version-consistency.test.mjs` guarantees), so the comparison cannot
catch a tag-versus-package mismatch. What it does catch is the failure that
actually happens: production still serving an older build after a deploy that
looked like it worked. So run it from the tag you just deployed, and a
disagreement means the deploy did not land, not that the tag is wrong.

Nothing here compares the running image digest against the digest the tag
published. That check needs production access and does not exist yet; it is in
"What still is not automated" below.

### 9. Afterwards

- Bump the `RELAY_VERSION` fallback pin in all three installers to the new tag,
  so a self-host install clones the release rather than an older one:
  `install.sh`, `frontend/install.sh` and `frontend/install-pi.sh`. All three
  read `PARAMANT_VERSION` with their own default, and check 9 of
  `tests/static-sanity.sh` holds them to that shape. Do this *after* the tag
  exists; doing it before points the installer at a tag nobody can clone.
- If anything in `deploy/.env.example` changed, say so in the CHANGELOG under a
  migration note. Self-hosters read that file, not the diff.

---

## Rolling back

The tag is what makes this possible at all.

- **Image rollback** (fast, no rebuild): the previous release tag is still in
  the registry by digest. `deploy/DEPLOY-3.1.md` step 8 has the commands, and
  step 2 tags the running images before touching anything.
- **Code rollback**: `git checkout v3.0.0`. This is the part that was guesswork
  before there was a tag per deploy.

Do not delete or move a published tag. A tag that once pointed at an image is a
promise about which bytes ran.

---

## What still is not automated

Written down because a process document that overclaims is worse than none.

- Nothing verifies that the digest running on production equals the digest the
  tag published. That check needs production access and does not exist yet.
- The CHANGELOG is compiled by hand from `git log`. It could be generated from
  PR titles, but half the commits since `v3.0.0` were pushed straight to `main`
  without a PR, so a generator would miss them.
- There is no staging environment. The drift gate and the unit suites are what
  stand between a merge and production.

---

## See also

- `CHANGELOG.md` for what is in each version.
- `deploy/DEPLOY-3.1.md` for the deploy itself.
- `deploy/.env.example` for every environment variable, what it does and where
  it is read.
- `AGENTS.md` for the commit and PR style gate.
- `docs/adrs/` for why the architecture is what it is.
