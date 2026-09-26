// The only module that reads process.env (docs/contracts/environment.md).
// Secret values are never logged or included in error messages.
import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { keyThumbprint, publicKeyB64u, b64u } from './crypto/ed25519.js';
import { parseApiKey } from './crypto/apiKeys.js';

/**
 * Publicly documented test-vector seed (RFC 8032 §7.1 TEST 1), used by
 * test/vectors/sig-v1.json. It is NOT secret and must never be a server key.
 */
export const TEST_VECTOR_SEED_HEX = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';

export class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
  }
}

const LOG_LEVELS = ['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'];

function readSecret(env, name) {
  const direct = env[name];
  const file = env[`${name}_FILE`];
  const hasDirect = typeof direct === 'string' && direct !== '';
  const hasFile = typeof file === 'string' && file !== '';
  if (hasDirect && hasFile) throw new ConfigError(`${name} and ${name}_FILE are both set; set only one`);
  if (hasFile) {
    try {
      return { value: readFileSync(file, 'utf8').replace(/\s+$/, ''), source: 'file' };
    } catch {
      throw new ConfigError(`${name}_FILE could not be read`);
    }
  }
  if (hasDirect) return { value: direct, source: 'env' };
  return { value: undefined, source: 'unset' };
}

function intVar(env, name, def, min, max) {
  const raw = env[name];
  if (raw === undefined || raw === '') return def;
  if (!/^-?\d+$/.test(raw)) throw new ConfigError(`${name} must be an integer`);
  const n = Number(raw);
  if (n < min || n > max) throw new ConfigError(`${name} must be between ${min} and ${max}`);
  return n;
}

function parseSigningKey(value) {
  let key;
  try {
    if (value.includes('-----BEGIN')) {
      key = createPrivateKey({ key: value.replace(/\\n/g, '\n'), format: 'pem' });
    } else {
      if (!/^[A-Za-z0-9+/_=-]+$/.test(value)) throw new Error('bad encoding');
      const der = Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      key = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
    }
  } catch {
    throw new ConfigError('KYA_SIGNING_PRIVATE_KEY is not a valid PKCS#8 private key');
  }
  if (key.asymmetricKeyType !== 'ed25519') throw new ConfigError('KYA_SIGNING_PRIVATE_KEY must be an Ed25519 key');
  return key;
}

export function loadConfig(env = process.env) {
  const warnings = [];
  const nodeEnv = env.NODE_ENV || 'development';
  if (!['production', 'development', 'test'].includes(nodeEnv)) {
    throw new ConfigError('NODE_ENV must be production, development or test');
  }
  const production = nodeEnv === 'production';

  const logLevel = env.LOG_LEVEL || (nodeEnv === 'test' ? 'silent' : 'info');
  if (!LOG_LEVELS.includes(logLevel)) throw new ConfigError('LOG_LEVEL is invalid');

  const maxSkew = intVar(env, 'KYA_SIGNATURE_MAX_SKEW_SECONDS', 300, 30, 900);
  const maxTtl = intVar(env, 'KYA_CREDENTIAL_MAX_TTL_SECONDS', 3600, 60, 86400);
  const defaultTtl = intVar(env, 'KYA_CREDENTIAL_DEFAULT_TTL_SECONDS', Math.min(900, maxTtl), 60, maxTtl);
  const maxBodyBytes = intVar(env, 'KYA_MAX_BODY_BYTES', 65536, 1024, 10 * 1024 * 1024);
  const port = intVar(env, 'PORT', 8080, 0, 65535);

  // --- rate limiting (REQ-016)
  const rlEnabledRaw = env.KYA_RATE_LIMIT_ENABLED;
  if (rlEnabledRaw !== undefined && rlEnabledRaw !== '' && rlEnabledRaw !== 'true' && rlEnabledRaw !== 'false') {
    throw new ConfigError('KYA_RATE_LIMIT_ENABLED must be true or false');
  }
  const rateLimit = {
    enabled: rlEnabledRaw !== 'false',
    windowSeconds: intVar(env, 'KYA_RATE_LIMIT_WINDOW_SECONDS', 60, 1, 3600),
    ipPerWindow: intVar(env, 'KYA_RATE_LIMIT_IP_PER_WINDOW', 1200, 1, 1_000_000),
    verifyPerWindow: intVar(env, 'KYA_RATE_LIMIT_VERIFY_PER_WINDOW', 600, 1, 1_000_000),
    registerPerWindow: intVar(env, 'KYA_RATE_LIMIT_REGISTER_PER_WINDOW', 30, 1, 1_000_000),
  };

  // --- server signing key
  const signingSecret = readSecret(env, 'KYA_SIGNING_PRIVATE_KEY');
  let signingKey;
  let signingKeySource = signingSecret.source;
  if (signingSecret.value !== undefined) {
    signingKey = parseSigningKey(signingSecret.value);
    if (production && signingKey.export({ format: 'jwk' }).d === b64u(Buffer.from(TEST_VECTOR_SEED_HEX, 'hex'))) {
      throw new ConfigError('KYA_SIGNING_PRIVATE_KEY is the public test-vector key and cannot be used in production');
    }
  } else if (production) {
    throw new ConfigError('KYA_SIGNING_PRIVATE_KEY (or KYA_SIGNING_PRIVATE_KEY_FILE) is required in production');
  } else {
    signingKey = generateKeyPairSync('ed25519').privateKey;
    signingKeySource = 'ephemeral';
    warnings.push('KYA_SIGNING_PRIVATE_KEY not set: using an ephemeral signing key; credentials will not survive restart');
  }
  const signingPublicKey = createPublicKey(signingKey);
  const kidRaw = env.KYA_SIGNING_KEY_ID;
  if (kidRaw && !/^[A-Za-z0-9._-]{1,128}$/.test(kidRaw)) throw new ConfigError('KYA_SIGNING_KEY_ID is invalid');
  const kid = kidRaw || keyThumbprint(publicKeyB64u(signingPublicKey));

  // --- API key pepper
  const pepperSecret = readSecret(env, 'KYA_API_KEY_PEPPER');
  let pepper;
  let pepperSource = pepperSecret.source;
  if (pepperSecret.value !== undefined) {
    if (Buffer.byteLength(pepperSecret.value, 'utf8') < 32) {
      throw new ConfigError('KYA_API_KEY_PEPPER must be at least 32 bytes (e.g. 43+ char base64url)');
    }
    pepper = Buffer.from(pepperSecret.value, 'utf8');
  } else if (production) {
    throw new ConfigError('KYA_API_KEY_PEPPER (or KYA_API_KEY_PEPPER_FILE) is required in production');
  } else {
    pepper = randomBytes(32);
    pepperSource = 'ephemeral';
    warnings.push('KYA_API_KEY_PEPPER not set: using an ephemeral pepper; API keys will not survive restart');
  }

  // --- bootstrap admin key (optional)
  const bootstrap = readSecret(env, 'KYA_BOOTSTRAP_ADMIN_API_KEY');
  if (bootstrap.value !== undefined && !parseApiKey(bootstrap.value)) {
    throw new ConfigError('KYA_BOOTSTRAP_ADMIN_API_KEY is malformed (generate one with npm run gen:admin-key)');
  }

  // --- storage
  const mongoUri = env.MONGODB_URI || undefined;
  if (!mongoUri) {
    if (production) throw new ConfigError('MONGODB_URI is required in production');
    warnings.push('MONGODB_URI not set: using the in-memory store; data is not persisted');
  }

  // --- data-source modes (mongo-collections.md §0): live|fixture, default fixture. Fixture
  // changes only where data comes from, never the store; every mode works offline by default.
  const modes = {};
  for (const [key, name] of [['sanctions', 'SANCTIONS_MODE'], ['chain', 'CHAIN_MODE'], ['llm', 'LLM_MODE'], ['embeddings', 'EMBEDDINGS_MODE']]) {
    const raw = env[name];
    // `mock` / `off` are the legacy operator-onboarding values of SANCTIONS_MODE (data-schema.md).
    const legacy = name === 'SANCTIONS_MODE' && (raw === 'mock' || raw === 'off');
    if (raw !== undefined && raw !== '' && raw !== 'live' && raw !== 'fixture' && !legacy) {
      throw new ConfigError(`${name} must be live or fixture`);
    }
    modes[key] = raw === 'live' ? 'live' : 'fixture';
  }
  // Operator-onboarding name screen (kyc.js): `off` skips it; anything else screens (fail safe).
  const sanctionsMode = env.SANCTIONS_MODE === 'off' ? 'off' : 'mock';
  if (env.SANCTIONS_MODE === 'off') warnings.push('SANCTIONS_MODE=off: operator onboarding name screening is skipped');
  if (!rateLimit.enabled) warnings.push('KYA_RATE_LIMIT_ENABLED=false: public verification and registration endpoints are not rate limited');

  const config = {
    nodeEnv,
    production,
    port,
    host: env.HOST || '0.0.0.0',
    logLevel,
    mongoDb: env.MONGODB_DB || 'kyagent',
    issuer: env.KYA_ISSUER || 'kyagent',
    kid,
    maxSkewSeconds: maxSkew,
    credentialDefaultTtlSeconds: defaultTtl,
    credentialMaxTtlSeconds: maxTtl,
    maxBodyBytes,
    rateLimit,
    sanctionsMode,
    modes,
    sources: { signingKey: signingKeySource, pepper: pepperSource, bootstrapAdmin: bootstrap.source },
    warnings,
  };
  // Secrets are non-enumerable so accidental JSON.stringify / logging of config omits them.
  Object.defineProperties(config, {
    signingKey: { value: signingKey, enumerable: false },
    signingPublicKey: { value: signingPublicKey, enumerable: false },
    pepper: { value: pepper, enumerable: false },
    bootstrapAdminApiKey: { value: bootstrap.value, enumerable: false },
    mongoUri: { value: mongoUri, enumerable: false },
  });
  return config;
}
