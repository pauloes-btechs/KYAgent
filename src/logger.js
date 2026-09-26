// Structured JSON logger. Callers must never pass secrets, Authorization headers,
// credentials (JWS), private keys or the pepper.
const LEVELS = { trace: 10, debug: 20, info: 30, warn: 40, error: 50, fatal: 60, silent: Infinity };

export function createLogger(level = 'info', write = (line) => process.stdout.write(`${line}\n`)) {
  const threshold = LEVELS[level] ?? LEVELS.info;
  const log = (lvl) => (msg, fields = {}) => {
    if (LEVELS[lvl] < threshold) return;
    write(JSON.stringify({ time: new Date().toISOString(), level: lvl, msg, ...fields }));
  };
  return { trace: log('trace'), debug: log('debug'), info: log('info'), warn: log('warn'), error: log('error'), fatal: log('fatal') };
}
