// Structured JSON logger. Callers must never pass secrets, Authorization headers,
// credentials (JWS), private keys or the pepper.
const LEVELS = { trace: 10, debug: 20, info: 30, warn: 40, error: 50, fatal: 60, silent: Infinity };

// Defence in depth for MONGODB_URI / ATLAS_TEST_URI: any MongoDB connection string that reaches a
// log line (message, field, nested value, driver error text) is replaced. A JSON.stringify replacer
// sees values after toJSON(), so Dates, ObjectIds and Buffers keep their usual serialisation.
const MONGO_URI_RE = /mongodb(?:\+srv)?:\/\/[^\s"'`<>]+/gi;
export const REDACTED_MONGO_URI = 'mongodb://[REDACTED]';
export const redactMongoUris = (s) => s.replace(MONGO_URI_RE, REDACTED_MONGO_URI);
const redact = (_key, value) => (typeof value === 'string' ? redactMongoUris(value) : value);

export function createLogger(level = 'info', write = (line) => process.stdout.write(`${line}\n`)) {
  const threshold = LEVELS[level] ?? LEVELS.info;
  const log = (lvl) => (msg, fields = {}) => {
    if (LEVELS[lvl] < threshold) return;
    write(JSON.stringify({ time: new Date().toISOString(), level: lvl, msg, ...fields }, redact));
  };
  return { trace: log('trace'), debug: log('debug'), info: log('info'), warn: log('warn'), error: log('error'), fatal: log('fatal') };
}
