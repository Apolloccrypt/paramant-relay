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

CMD ["node", "relay.js"]
