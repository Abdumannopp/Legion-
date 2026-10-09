# Legion API. Build context is the REPOSITORY ROOT (see docker-compose.yml):
# the server depends on the workspace package packages/agent-identity.

FROM node:22-alpine AS build
WORKDIR /app
COPY . .
# The root postinstall builds packages/agent-identity.
RUN npm ci
RUN npm run build -w server
# Keep only what the server needs at run time.
RUN npm prune --omit=dev

FROM node:22-alpine
# NODE_ENV is deliberately NOT set to "production" here: that mode demands HTTPS,
# SMTP and a public origin, which a laptop evaluation does not have. Internet-facing
# servers run the systemd setup in DEPLOY-ONLINE.md, which does set it.
WORKDIR /app
COPY --from=build /app /app
WORKDIR /app/server
# The first-run setup token is written into this folder (see setup-token.ts).
RUN chown node:node /app/server
# Not root: the process only needs its own files and the network.
USER node
EXPOSE 8000
CMD ["node", "dist/index.js"]
