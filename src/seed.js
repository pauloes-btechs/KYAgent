// Demo seed data for local deployments (REQ-020). Goes through the same services
// as the HTTP API, so every record is validated and audited like a real request.
// Idempotent: if the seed business already exists nothing is written.
//
// Secrets: API-key plaintexts and the demo agent's private-key seed are *returned*
// to the caller exactly once (the store keeps only HMAC hashes / the public key).
import { randomBytes } from 'node:crypto';
import { agentKeyFromSeed, proofOfPossession } from './sdk/agentSigner.js';

export const SEED_BUSINESS_NAME = 'Globex Payments (seed)';
export const SEED_OPERATOR = {
  type: 'organization',
  legalName: 'Acme Robotics Ltd (seed)',
  contactEmail: 'ops@acme.example',
  country: 'GB',
};
export const SEED_GRANT = {
  actions: ['payments:create', 'orders:*'],
  constraints: { maxAmount: 10000, currency: 'USD' },
  lifetimeDays: 30,
};

const SEED_PRINCIPAL = { role: 'admin', apiKeyId: null, requestId: 'seed' };

/** @param app result of buildApp() after init() */
export async function seedDemo(app, { clock = { now: () => new Date() } } = {}) {
  const { services: s, store } = app;
  const existing = await store.businesses.list({ filter: { name: SEED_BUSINESS_NAME }, limit: 1 });
  if (existing.data.length) return { alreadySeeded: true, businessId: existing.data[0].id };

  const operator = await s.operators.create(SEED_PRINCIPAL, { ...SEED_OPERATOR });
  const verified = await s.operators.verify(SEED_PRINCIPAL, operator.id);
  if (verified.status !== 'verified') throw new Error(`seed operator verification returned ${verified.status}`);
  const business = await s.businesses.create(SEED_PRINCIPAL, { name: SEED_BUSINESS_NAME });

  const operatorKey = await s.apiKeys.create(SEED_PRINCIPAL, { name: 'seed operator', role: 'operator', ownerId: operator.id });
  const businessKey = await s.apiKeys.create(SEED_PRINCIPAL, { name: 'seed business', role: 'business', ownerId: business.id });
  const opPrincipal = { role: 'operator', apiKeyId: operatorKey.apiKey.id, operatorId: operator.id, requestId: 'seed' };
  const bizPrincipal = { role: 'business', apiKeyId: businessKey.apiKey.id, businessId: business.id, requestId: 'seed' };

  // The agent key would normally be generated on the agent host; the seed plays that role.
  const agentSeed = randomBytes(32);
  const agentKey = agentKeyFromSeed(agentSeed);
  const agent = await s.agents.register(opPrincipal, {
    name: 'Invoice Bot (seed)',
    description: 'Demo agent created by the seed script',
    publicKey: agentKey.publicKey,
    proofOfPossession: proofOfPossession(agentKey.privateKey, operator.id, agentKey.publicKey),
  });

  const expiresAt = new Date(clock.now().getTime() + SEED_GRANT.lifetimeDays * 86400_000).toISOString();
  const grant = await s.grants.create(bizPrincipal, {
    agentId: agent.id,
    actions: SEED_GRANT.actions,
    constraints: SEED_GRANT.constraints,
    expiresAt,
  });

  return {
    alreadySeeded: false,
    operatorId: operator.id,
    businessId: business.id,
    agentId: agent.id,
    grantId: grant.id,
    secrets: {
      operatorApiKey: operatorKey.secret,
      businessApiKey: businessKey.secret,
      agentPrivateKeySeed: agentSeed.toString('hex'),
    },
  };
}
