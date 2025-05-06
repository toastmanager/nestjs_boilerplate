FROM node:23.11.0-alpine3.20
RUN corepack enable

# Installing dependecies
WORKDIR /usr/src/app
COPY package.json .
COPY yarn.lock .
RUN yarn install

# Generating prisma files
COPY /prisma ./prisma
RUN yarn prisma generate

# Building app
COPY . .
RUN yarn build

# Removing source files
RUN rm -rf /src
RUN rm -rf /prisma
RUN rm -rf /test

# Running app
ENV NODE_ENV=production
CMD [ "node", "dist/main.js" ]