# Compiling
FROM node:18.16.0-alpine AS build

WORKDIR /app
COPY package.json ./package.json
COPY yarn.lock ./yarn.lock

RUN yarn install --frozen-lockfile

COPY . .
RUN yarn build



# Downloading libraries (excluding development dependencies)
FROM node:18.16.0-alpine AS install

COPY --from=build /app/package.json /app/package.json
COPY --from=build /app/yarn.lock /app/yarn.lock
WORKDIR /app

RUN yarn --production



# Actual deployment
FROM node:18.16.0-alpine

COPY --from=build /app/build /app/build
COPY --from=build /app/package.json /app/package.json
COPY --from=install /app/node_modules /app/node_modules

ENV NODE_ENV=production
WORKDIR /app

CMD ["build"]
