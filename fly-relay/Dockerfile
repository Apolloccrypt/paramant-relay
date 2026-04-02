FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY relay.js ./
EXPOSE 8080
CMD ["node", "relay.js"]
