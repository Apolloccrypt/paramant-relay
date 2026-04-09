FROM node:20-alpine
WORKDIR /app
COPY package.json .
RUN npm install --production --quiet
COPY server.js .
COPY public/ public/
EXPOSE 4200
CMD ["node", "server.js"]
