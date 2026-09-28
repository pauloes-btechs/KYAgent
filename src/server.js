// Process entrypoint: loadConfig -> store -> buildApp -> listen.
import { buildApp } from './app.js';
import { ConfigError, loadConfig } from './config.js';
import { createLogger } from './logger.js';
import { MemoryStore } from './store/memory.js';
import { MongoStore } from './store/mongo.js';
import { SanctionsWatcher } from './watchers/sanctionsWatcher.js';

async function main() {
  let config;
  try {
    config = loadConfig(process.env);
  } catch (err) {
    if (err instanceof ConfigError) {
      process.stderr.write(`Configuration error: ${err.message}\n`);
      process.exit(1);
    }
    throw err;
  }
  const logger = createLogger(config.logLevel);
  for (const w of config.warnings) logger.warn(w);
  logger.info('secrets loaded', { signingKey: config.sources.signingKey, pepper: config.sources.pepper, kid: config.kid });

  const store = config.mongoUri ? new MongoStore(config.mongoUri, config.mongoDb) : new MemoryStore();
  const app = buildApp({ config, store, logger });
  try {
    await app.init();
  } catch (err) {
    logger.fatal('store initialisation failed', { error: err.message });
    process.exit(1);
  }
  const addr = await app.listen();
  logger.info('KYAgent listening', { port: addr.port, store: store.kind, dashboard: `http://localhost:${addr.port}/dashboard/` });

  // Continuous KYA (investigation-pipeline.md §7): only where change streams exist (Atlas).
  let watcher = null;
  if (store.capabilities?.changeStreams) {
    // Least privilege (docs/SECURITY_REVIEW_HARNESS.md §3): the watcher runs as a user with
    // readWrite on the app db only. Refused in production; a loud warning elsewhere.
    const priv = await store.privileges().catch(() => ({ ok: false, excess: [], authenticated: false }));
    if (!priv.ok) {
      const fields = { required: `readWrite@${config.mongoDb}`, excess: priv.excess.map((r) => `${r.role}@${r.db}`), authenticated: priv.authenticated };
      if (config.production) {
        logger.fatal('sanctions watcher refused: the MongoDB user is not least-privilege', fields);
        await app.close().catch(() => {});
        process.exit(1);
      }
      logger.warn('sanctions watcher: the MongoDB user is not least-privilege (refused in production)', fields);
    }
    watcher =new SanctionsWatcher({ store, audit: app.services.audit, events: app.events, logger });
    try {
      await watcher.start();
      logger.info('sanctions watcher started');
    } catch (err) {
      logger.fatal('sanctions watcher failed to start', { error: err.message });
      await app.close().catch(() => {});
      process.exit(1);
    }
  } else {
    logger.warn('sanctions watcher disabled: store has no change streams', { store: store.kind });
  }

  const shutdown = () =>
    (watcher ? watcher.stop() : Promise.resolve())
      .catch(() => {})
      .then(() => app.close())
      .finally(() => process.exit(0));
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main();
