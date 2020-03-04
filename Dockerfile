FROM node:12-alpine

RUN apk add dumb-init

ADD . .

RUN npm ci

ENTRYPOINT ["dumb-init", "node", "index.js"]
