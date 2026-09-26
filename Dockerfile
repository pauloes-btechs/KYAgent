FROM node:20-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
# Reproducible install of the declared runtime dependencies (the MongoDB driver) from the lockfile.
RUN npm ci --omit=dev --no-audit --no-fund
COPY src ./src
# migrate.js / seed.js are run by the one-shot compose services.
COPY scripts ./scripts
COPY dashboard ./dashboard
COPY docs ./docs
USER node
EXPOSE 8080
CMD ["node", "src/server.js"]
