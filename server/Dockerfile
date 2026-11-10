# Legion API. Build context is the REPOSITORY ROOT (see docker-compose.yml):
# the server depends on the workspace package packages/agent-identity.

FROM node:26-alpine@sha256:8996bb5821d62a8fd9bb27c1cb07462f3fdce6e47d640c6a881ead0b064ce216 AS build
WORKDIR /app
COPY . .
# The root postinstall builds packages/agent-identity.
RUN npm ci
RUN npm run build -w server
# Keep only what the server needs at run time.
RUN npm prune --omit=dev

FROM node:26-alpine@sha256:8996bb5821d62a8fd9bb27c1cb07462f3fdce6e47d640c6a881ead0b064ce216
# NODE_ENV is deliberately NOT set to "production" here: that mode demands HTTPS,
# SMTP and a public origin, which a laptop evaluation does not have. Internet-facing
# servers run the systemd setup in DEPLOY-ONLINE.md, which does set it.
WORKDIR /app
COPY --from=build /app /app
WORKDIR /app/server
# The first-run setup token is written into this folder (see setup-token.ts).
RUN chown node:node /app/server
# State directory for the pilot stack (docker-compose.pilot.yml mounts a volume here and runs with a
# read-only root filesystem). Created and owned by the non-root user so a fresh volume inherits it.
RUN mkdir -p /var/lib/legion && chown node:node /var/lib/legion
# Not root: the process only needs its own files and the network.
USER node
EXPOSE 8000
CMD ["node", "dist/index.js"]
