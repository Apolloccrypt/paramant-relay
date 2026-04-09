FROM node:20-alpine3.21

LABEL org.opencontainers.image.title="paramant-relay" \
      org.opencontainers.image.version="2.3.2" \
      org.opencontainers.image.description="Post-quantum encrypted file relay — RAM-only, burn-on-read" \
      org.opencontainers.image.source="https://github.com/Apolloccrypt/paramant-relay" \
      org.opencontainers.image.licenses="BUSL-1.1"

# Build tools required for argon2 native module
RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY relay.js ./

# Non-root user — relay never needs root after install
RUN addgroup -S relay && adduser -S relay -G relay
USER relay

# Sector ports: health=3005 legal=3002 finance=3003 iot=3004
EXPOSE 3001 3002 3003 3004 3005

# wget is built into alpine; curl is not
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:${PORT:-3001}/health || exit 1

CMD ["node", "relay.js"]
