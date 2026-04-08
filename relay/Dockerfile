FROM node:20-alpine

# Build tools for argon2 native module
RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY relay.js ./

RUN addgroup -S relay && adduser -S relay -G relay
USER relay

# Port is set via PORT env var per sector
EXPOSE 3001 3002 3003 3004 3005

CMD ["node", "relay.js"]
