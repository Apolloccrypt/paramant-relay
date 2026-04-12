FROM node:22-alpine3.21

LABEL org.opencontainers.image.title="paramant-admin" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.description="PARAMANT admin panel" \
      org.opencontainers.image.licenses="BUSL-1.1"

WORKDIR /app
COPY package.json .
RUN npm install --production --quiet && npm cache clean --force
COPY server.js .
COPY public/ public/

# Non-root user — admin server never needs root
RUN addgroup -S admin && adduser -S admin -G admin

USER admin

EXPOSE 4200

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:${PORT:-4200}/api/auth/check || exit 1

CMD ["node", "server.js"]
