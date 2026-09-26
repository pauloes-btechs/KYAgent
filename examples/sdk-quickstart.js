// SDK quickstart (REQ-018): an agent signs HTTP requests with agentSigner.js and
// a business server verifies them with businessVerifier.js.
//
// Runs fully locally: KYAgent in-process (in-memory store, ephemeral secrets), a
// tiny business HTTP server, and an agent client. Prints decisions only; no keys.
//   node examples/sdk-quickstart.js
import { createServer } from 'node:http';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { generateApiKey } from '../src/crypto/apiKeys.js';
import { generateAgentKey, proofOfPossession, signedHeaders } from '../src/sdk/agentSigner.js';
import { createVerifier, isAllowed } from '../src/sdk/businessVerifier.js';
import { MemoryStore } from '../src/store/memory.js';

if (process.env.NODE_ENV === 'production') {
  process.stderr.write('The quickstart is not available with NODE_ENV=production\n');
  process.exit(1);
}

// ---- 1. KYAgent service + onboarding (normally done once via the API/dashboard)
const admin = generateApiKey().plaintext;
const kyaApp = buildApp({
  config: loadConfig({ NODE_ENV: 'development', LOG_LEVEL: 'silent', SANCTIONS_MODE: process.env.SANCTIONS_MODE, KYA_BOOTSTRAP_ADMIN_API_KEY: admin }),
  store: new MemoryStore(),
});
await kyaApp.init();
const kyaBase = `http://127.0.0.1:${(await kyaApp.listen(0, '127.0.0.1')).port}`;

async function api(key, method, path, body) {
  const res = await fetch(kyaBase + path, {
    method,
    headers: { authorization: `Bearer ${key}`, ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json();
  if (res.status >= 400) throw new Error(`${method} ${path} -> ${res.status} ${json?.error?.code ?? ''}`);
  return json;
}

const op = await api(admin, 'POST', '/v1/operators', { type: 'organization', legalName: 'Acme Robotics Ltd', contactEmail: 'ops@acme.example', country: 'GB' });
await api(admin, 'POST', `/v1/operators/${op.id}/verification`);
const biz = await api(admin, 'POST', '/v1/businesses', { name: 'Globex Payments' });
const opKey = (await api(admin, 'POST', '/v1/api-keys', { name: 'acme', role: 'operator', ownerId: op.id })).secret;
const bizKey = (await api(admin, 'POST', '/v1/api-keys', { name: 'globex', role: 'business', ownerId: biz.id })).secret;

// The agent key is generated on the agent host; only the public key is registered.
const agentKey = generateAgentKey();
const agent = await api(opKey, 'POST', '/v1/agents', {
  name: 'Invoice Bot',
  publicKey: agentKey.publicKey,
  proofOfPossession: proofOfPossession(agentKey.privateKey, op.id, agentKey.publicKey),
});
await api(bizKey, 'POST', '/v1/grants', {
  agentId: agent.id,
  actions: ['payments:create'],
  constraints: { maxAmount: 10000, currency: 'USD' },
  expiresAt: new Date(Date.now() + 86400_000).toISOString(),
});

// ---- 2. Business server: derives action/context from the request it will execute
const kya = createVerifier({ baseUrl: kyaBase, apiKey: bizKey });
const bizServer = createServer(async (req, res) => {
  let raw = '';
  for await (const chunk of req) raw += chunk;
  let payment;
  try {
    payment = JSON.parse(raw);
  } catch {
    payment = null;
  }
  if (req.method !== 'POST' || req.url !== '/payments' || !payment) {
    res.writeHead(400).end();
    return;
  }
  const decision = await kya.verifyIncoming({
    headers: req.headers,
    action: 'payments:create',
    context: { amount: payment.amount, currency: payment.currency },
  });
  const code = decision.reasons[0].code;
  if (!isAllowed(decision)) {
    res.writeHead(403, { 'content-type': 'application/json' }).end(JSON.stringify({ error: code }));
    return;
  }
  res.writeHead(201, { 'content-type': 'application/json' }).end(JSON.stringify({ paid: payment.amount, agentId: decision.agentId }));
});
await new Promise((r) => bizServer.listen(0, '127.0.0.1', r));
const bizBase = `http://127.0.0.1:${bizServer.address().port}`;

// ---- 3. Agent client: signs exactly what it asks the business to do
async function pay(amount, { signedAmount = amount } = {}) {
  const headers = signedHeaders(agentKey.privateKey, {
    agentId: agent.id,
    audience: biz.id,
    action: 'payments:create',
    context: { amount: signedAmount, currency: 'USD' },
  });
  const res = await fetch(`${bizBase}/payments`, {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/json' },
    body: JSON.stringify({ amount, currency: 'USD' }),
  });
  return { status: res.status, body: await res.json() };
}

const results = [
  ['pay 1500 USD (within grant)', await pay(1500), 201],
  ['pay 50000 USD (over maxAmount)', await pay(50000), 403],
  ['tampered: signed 100, sent 9000', await pay(9000, { signedAmount: 100 }), 403],
];
let ok = true;
for (const [label, r, expected] of results) {
  console.log(`  ${String(r.status).padEnd(4)} ${(r.body.error ?? 'ALLOWED').padEnd(22)} ${label}`);
  if (r.status !== expected) ok = false;
}

bizServer.close();
await kyaApp.close();
process.exit(ok ? 0 : 1);
