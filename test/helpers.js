// Test harness: real HTTP server on an ephemeral port, in-memory store,
// ephemeral secrets and a controllable clock. No fixed secrets in the repo.
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { generateApiKey } from '../src/crypto/apiKeys.js';
import { buildVerifyRequest, generateAgentKey, proofOfPossession } from '../src/sdk/agentSigner.js';
import { MemoryStore } from '../src/store/memory.js';

export async function startApp({ env = {} } = {}) {
  const admin = generateApiKey().plaintext;
  const config = loadConfig({ NODE_ENV: 'test', LOG_LEVEL: 'silent', KYA_BOOTSTRAP_ADMIN_API_KEY: admin, ...env });
  const store = new MemoryStore();
  const clockState = { ms: Date.now() };
  const clock = { now: () => new Date(clockState.ms) };
  const app = buildApp({ config, store, clock });
  await app.init();
  const { port } = await app.listen(0, '127.0.0.1');
  const base = `http://127.0.0.1:${port}`;

  async function call(key, method, path, body, { raw, headers = {} } = {}) {
    const h = { ...headers };
    if (key) h.authorization = `Bearer ${key}`;
    let payload;
    if (raw !== undefined) payload = raw;
    else if (body !== undefined) {
      payload = JSON.stringify(body);
      h['content-type'] ??= 'application/json';
    }
    const res = await fetch(base + path, { method, headers: h, body: payload });
    const text = await res.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
    return { status: res.status, body: json, text, headers: res.headers };
  }

  return {
    app,
    base,
    admin,
    store,
    config,
    call,
    nowSec: () => Math.floor(clockState.ms / 1000),
    advance: (seconds) => {
      clockState.ms += seconds * 1000;
    },
    close: () => app.close(),
  };
}

export async function createOperator(t, { legalName = 'Acme Robotics Ltd', verify = true } = {}) {
  const op = (await t.call(t.admin, 'POST', '/v1/operators', { type: 'organization', legalName, contactEmail: 'Ops@Acme.example', country: 'GB' })).body;
  if (verify) await t.call(t.admin, 'POST', `/v1/operators/${op.id}/verification`);
  const key = (await t.call(t.admin, 'POST', '/v1/api-keys', { name: 'op key', role: 'operator', ownerId: op.id })).body.secret;
  return { op, key };
}

export async function createBusiness(t, name = 'Globex') {
  const biz = (await t.call(t.admin, 'POST', '/v1/businesses', { name })).body;
  const key = (await t.call(t.admin, 'POST', '/v1/api-keys', { name: 'biz key', role: 'business', ownerId: biz.id })).body.secret;
  return { biz, key };
}

export async function registerAgent(t, operator, name = 'Invoice Bot') {
  const agentKey = generateAgentKey();
  const res = await t.call(operator.key, 'POST', '/v1/agents', {
    name,
    publicKey: agentKey.publicKey,
    proofOfPossession: proofOfPossession(agentKey.privateKey, operator.op.id, agentKey.publicKey),
  });
  if (res.status !== 201) throw new Error(`register failed ${res.status} ${res.text}`);
  return { agent: res.body, ...agentKey };
}

export async function createGrant(t, business, agentId, { actions = ['payments:create'], constraints = { maxAmount: 10000, currency: 'USD' }, seconds = 86400 } = {}) {
  const res = await t.call(business.key, 'POST', '/v1/grants', {
    agentId,
    actions,
    constraints,
    expiresAt: new Date((t.nowSec() + seconds) * 1000).toISOString(),
  });
  if (res.status !== 201) throw new Error(`grant failed ${res.status} ${res.text}`);
  return res.body;
}

/** Full onboarding: verified operator, business, agent, grant. */
export async function world() {
  const t = await startApp();
  const operator = await createOperator(t);
  const business = await createBusiness(t);
  const agent = await registerAgent(t, operator);
  const grant = await createGrant(t, business, agent.agent.id);
  const signed = (opts = {}) =>
    buildVerifyRequest(opts.privateKey ?? agent.privateKey, {
      agentId: opts.agentId ?? agent.agent.id,
      audience: opts.audience ?? business.biz.id,
      action: opts.action ?? 'payments:create',
      resource: opts.resource,
      context: 'context' in opts ? opts.context : { amount: 1500, currency: 'USD' },
      credential: opts.credential,
      timestamp: opts.timestamp ?? t.nowSec(),
      nonce: opts.nonce,
    });
  const verify = async (body, key = business.key) => (await t.call(key, 'POST', '/v1/verify', body)).body;
  return { t, operator, business, agent, grant, signed, verify };
}
