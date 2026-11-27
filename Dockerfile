FROM node:24-alpine

WORKDIR /usr/src/app

COPY package.json ./
COPY src ./src
COPY .actor ./.actor

ENV NODE_ENV=production

CMD ["node", "src/apify-actor.mjs"]
