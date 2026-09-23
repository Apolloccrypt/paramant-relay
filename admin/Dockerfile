# Pinned by digest. Tag node:24-alpine3.24 resolved 2026-09-02 (Node 24.20.0,
# Alpine 3.24.1). Node 24 is the newest LTS line; this was node:25-alpine3.21,
# and Node 25 is end-of-life. Kept in lockstep with relay/Dockerfile.
FROM node:24-alpine3.24@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf

# See relay/Dockerfile: default matches admin/package.json, CI overrides it per
# build, and tests/version-consistency.test.mjs holds the two together.
ARG IMAGE_VERSION=3.1.0

LABEL org.opencontainers.image.title="paramant-admin" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.description="PARAMANT admin panel" \
      org.opencontainers.image.licenses="BUSL-1.1"

# THE IMAGE MIRRORS THE REPO, one directory deeper than it used to.
#
# admin/lib/email-templates.js reaches for ../../relay/lib/mail, because since
# "mail leaves the United States" every mail in the product goes through one
# carrier and MAIL_PROVIDER decides which. With the app flattened into /app
# that path resolved to /relay/lib/mail, which is outside the image: the
# container crash-looped on MODULE_NOT_FOUND and the 22-09 deploy stopped on it.
#
# So the build context is the repository root and the layout is kept: the admin
# sits in /app/admin and the one relay file it shares sits in /app/relay/lib.
# Now ../../relay/lib/mail resolves the same way it does on a developer's
# machine, and the require needs no knowledge of how the image was built.
#
# relay/lib/mail.js requires nothing outside node's standard library, so this is
# one file and no dependency tree.
WORKDIR /app/admin
# Copy the lockfile too and use `npm ci` so the build installs the exact
# versions in package-lock.json instead of re-resolving the ^ ranges on every
# rebuild (reproducible, supply-chain-pinned image).
COPY admin/package.json admin/package-lock.json ./
RUN npm ci --omit=dev --quiet && npm cache clean --force
COPY admin/server.js .
COPY admin/lib/ lib/
COPY admin/public/ public/
COPY relay/lib/mail.js /app/relay/lib/mail.js

# Non-root user — admin server never needs root
RUN addgroup -S admin && adduser -S admin -G admin

USER admin

EXPOSE 4200

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:${PORT:-4200}/api/auth/check || exit 1

CMD ["node", "server.js"]
