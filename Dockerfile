FROM node:20-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json ./
# The API has zero runtime dependencies; the MongoDB driver is only needed for MongoStore.
RUN npm install --omit=dev --no-save --no-audit --no-fund mongodb@6
COPY src ./src
# migrate.js / seed.js are run by the one-shot compose services.
COPY scripts ./scripts
COPY dashboard ./dashboard
COPY docs ./docs
# Offline fixture embeddings (EMBEDDINGS_MODE=fixture).
COPY fixtures ./fixtures
USER node
EXPOSE 8080
CMD ["node", "src/server.js"]
