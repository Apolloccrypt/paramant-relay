FROM node:20-alpine

# argon2 needs build tools
RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY relay.js ./

# Non-root user
RUN addgroup -S relay && adduser -S relay -G relay
USER relay

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/health | grep -q '"ok":true' || exit 1

CMD ["node", "relay.js"]
