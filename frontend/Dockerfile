# Legion dashboard (Next.js, standalone output). Build context is the
# REPOSITORY ROOT (see docker-compose.yml), because this is an npm workspace.

FROM node:22-alpine AS build
WORKDIR /app
COPY . .
RUN npm ci
# NEXT_PUBLIC_* values are compiled into the JavaScript at build time.
ARG NEXT_PUBLIC_API_URL
ARG NEXT_PUBLIC_WS_URL
ARG NEXT_PUBLIC_OPERATOR_NAME
ARG NEXT_PUBLIC_SUPPORT_EMAIL
ARG NEXT_PUBLIC_DATA_LOCATION
ARG NEXT_PUBLIC_PRICE_LABEL
ARG NEXT_PUBLIC_TURNSTILE_SITE_KEY
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build -w frontend

FROM node:22-alpine
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1
# Listen on all interfaces inside the container (Docker maps the port out).
ENV HOSTNAME=0.0.0.0 PORT=3000
WORKDIR /app
COPY --from=build /app/frontend/.next/standalone ./
COPY --from=build /app/frontend/.next/static ./frontend/.next/static
COPY --from=build /app/frontend/public ./frontend/public
USER node
EXPOSE 3000
CMD ["node", "frontend/server.js"]
