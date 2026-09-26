// Creates a local .env from .env.example with freshly generated secrets
// (server signing key, API-key pepper, bootstrap admin key). .env is git-ignored
// and written with mode 0600. Refuses to overwrite an existing file unless --force.
// Secret values are written to the file only, never printed.
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateApiKey } from '../src/crypto/apiKeys.js';

export const GENERATED_SECRETS = {
  KYA_SIGNING_PRIVATE_KEY: () =>
    generateKeyPairSync('ed25519').privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
  KYA_API_KEY_PEPPER: () => randomBytes(32).toString('base64url'),
  KYA_BOOTSTRAP_ADMIN_API_KEY: () => generateApiKey().plaintext,
};

/** Fill empty secret assignments in the example text; everything else is kept verbatim. */
export function renderEnv(exampleText, generators = GENERATED_SECRETS) {
  return exampleText
    .split('\n')
    .map((line) => {
      const m = line.match(/^([A-Z0-9_]+)=\s*$/);
      return m && generators[m[1]] ? `${m[1]}=${generators[m[1]]()}` : line;
    })
    .join('\n');
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const target = resolve(root, '.env');
  if (existsSync(target) && !process.argv.includes('--force')) {
    process.stderr.write('.env already exists; not overwriting (use --force to regenerate secrets)\n');
    process.exit(1);
  }
  writeFileSync(target, renderEnv(readFileSync(resolve(root, '.env.example'), 'utf8')), { mode: 0o600 });
  process.stdout.write(
    `Wrote .env with generated ${Object.keys(GENERATED_SECRETS).join(', ')}.\n` +
      'Your first admin API key is KYA_BOOTSTRAP_ADMIN_API_KEY in .env. Never commit this file.\n',
  );
}
