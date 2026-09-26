// Applies pending MongoDB schema migrations (src/store/migrations.js) and exits.
// Run by the `migrate` service in docker-compose.yml before the API starts;
// locally: `npm run migrate` with MONGODB_URI set. Never prints secrets.
import { ConfigError, loadConfig } from '../src/config.js';
import { MongoStore } from '../src/store/mongo.js';

let config;
try {
  config = loadConfig(process.env);
} catch (err) {
  if (!(err instanceof ConfigError)) throw err;
  process.stderr.write(`Configuration error: ${err.message}\n`);
  process.exit(1);
}
if (!config.mongoUri) {
  process.stderr.write('MONGODB_URI is not set: the in-memory store has no schema to migrate\n');
  process.exit(1);
}

const store = new MongoStore(config.mongoUri, config.mongoDb);
try {
  await store.init();
  const { applied, skipped } = store.migrations;
  const list = applied.length ? ` (${applied.join(', ')})` : '';
  process.stdout.write(`migrations: ${applied.length} applied${list}, ${skipped.length} already up to date\n`);
} catch (err) {
  process.stderr.write(`migration failed: ${err.message}\n`);
  process.exitCode = 1;
} finally {
  await store.close();
}
