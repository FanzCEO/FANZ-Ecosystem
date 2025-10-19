# syntax=docker/dockerfile:1
FROM node:20-alpine AS base
ENV PNPM_HOME="/root/.local/share/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
# Use corepack to install pnpm version from package.json "packageManager"
RUN corepack enable

WORKDIR /app
# Copy manifests first for better caching
COPY FanzDash/package.json FanzDash/pnpm-lock.yaml ./

# Clean install all dependencies
RUN corepack prepare pnpm@9.12.1 --activate && \
    pnpm config set store-dir /root/.local/share/pnpm/store && \
    pnpm install --prefer-offline

# Copy FanzDash source code
COPY FanzDash/ .

# Runtime image (small)
FROM node:20-alpine AS runner
ENV NODE_ENV=production
ENV PNPM_HOME="/root/.local/share/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable && corepack prepare pnpm@9.12.1 --activate
WORKDIR /app
COPY --from=base /app ./

# IMPORTANT: bind to PORT env (DigitalOcean sets $PORT); do not hardcode 8080
ENV PORT=3000
EXPOSE 3000

# Healthcheck (optional, if /health endpoint exists)
HEALTHCHECK --interval=30s --timeout=3s --retries=5 CMD wget -qO- http://localhost:${PORT}/health || exit 1

CMD ["pnpm","dev"]
