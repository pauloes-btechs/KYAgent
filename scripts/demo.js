// End-to-end demo: starts KYAgent in-process (in-memory store, ephemeral secrets),
// walks the vertical slice, prints each decision, then keeps serving so you can
// open the dashboard. Demo-only API keys are printed because they are ephemeral
// and needed to sign in; never do this with real keys.
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { generateApiKey } from '../src/crypto/apiKeys.js';
import { buildVerifyRequest, generateAgentKey, proofOfPossession } from '../src/sdk/agentSigner.js';
import { MemoryStore } from '../src/store/memory.js';

if (process.env.NODE_ENV === 'production') {
  process.stderr.write('The demo is not available with NODE_ENV=production\n');
  process.exit(1);
}

const admin = generateApiKey().plaintext;
const config = loadConfig({
  NODE_ENV: 'development',
  PORT: process.env.PORT || '8080',
  HOST: '127.0.0.1',
  LOG_LEVEL: 'warn',
  SANCTIONS_MODE: process.env.SANCTIONS_MODE,
  KYA_BOOTSTRAP_ADMIN_API_KEY: admin,
});
const app = buildApp({ config, store: new MemoryStore() });
await app.init();
const { port } = await app.listen();
const base = `http://127.0.0.1:${port}`;

async function call(key, method, path, body) {
  const res = await fetch(base + path, {
    method,
    headers: { authorization: `Bearer ${key}`, ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json();
  if (res.status >= 400 && path !== '/v1/verify') throw new Error(`${method} ${path} -> ${res.status} ${JSON.stringify(json)}`);
  return json;
}

const show = (label, r) => console.log(`  ${r.decision.padEnd(5)} ${r.reasons[0].code.padEnd(24)} ${label}`);

console.log('1. Admin onboards an operator (mock KYC + sanctions) and a business');
const op = await call(admin, 'POST', '/v1/operators', { type: 'organization', legalName: 'Acme Robotics Ltd', contactEmail: 'ops@acme.example', country: 'GB' });
await call(admin, 'POST', `/v1/operators/${op.id}/verification`);
const biz = await call(admin, 'POST', '/v1/businesses', { name: 'Globex Payments' });
const opKey = (await call(admin, 'POST', '/v1/api-keys', { name: 'acme ops', role: 'operator', ownerId: op.id })).secret;
const bizKey = (await call(admin, 'POST', '/v1/api-keys', { name: 'globex', role: 'business', ownerId: biz.id })).secret;

console.log('2. Operator registers an agent with its Ed25519 public key + proof of possession');
const agentKey = generateAgentKey();
const agent = await call(opKey, 'POST', '/v1/agents', {
  name: 'Invoice Bot',
  publicKey: agentKey.publicKey,
  proofOfPossession: proofOfPossession(agentKey.privateKey, op.id, agentKey.publicKey),
});
console.log(`   agent ${agent.id} thumbprint ${agent.keyThumbprint}`);

console.log('3. Business grants payments:create up to 10000 USD for 1 day');
const grant = await call(bizKey, 'POST', '/v1/grants', {
  agentId: agent.id,
  actions: ['payments:create'],
  constraints: { maxAmount: 10000, currency: 'USD' },
  expiresAt: new Date(Date.now() + 86400_000).toISOString(),
});

console.log('4. Operator issues a scoped, expiring, key-bound credential');
const { credential, record } = await call(opKey, 'POST', `/v1/agents/${agent.id}/credentials`, { grantId: grant.id, ttlSeconds: 900 });

console.log('5. Agent signs requests; business calls /v1/verify');
const req = (action, context, extra = {}) =>
  buildVerifyRequest(agentKey.privateKey, { agentId: agent.id, audience: biz.id, action, context, ...extra });
show('payments:create 1500 USD with credential', await call(bizKey, 'POST', '/v1/verify', req('payments:create', { amount: 1500, currency: 'USD' }, { credential })));
show('payments:create 1500 USD (grant lookup)', await call(bizKey, 'POST', '/v1/verify', req('payments:create', { amount: 1500, currency: 'USD' })));
show('payments:create 50000 USD (over limit)', await call(bizKey, 'POST', '/v1/verify', req('payments:create', { amount: 50000, currency: 'USD' })));
show('payments:refund (out of scope)', await call(bizKey, 'POST', '/v1/verify', req('payments:refund', { amount: 10, currency: 'USD' })));
const replay = req('payments:create', { amount: 100, currency: 'USD' });
show('first use of a nonce', await call(bizKey, 'POST', '/v1/verify', replay));
show('same request replayed', await call(bizKey, 'POST', '/v1/verify', replay));
const tampered = req('payments:create', { amount: 100, currency: 'USD' });
tampered.signedRequest.signature = tampered.signedRequest.signature.replace(/^./, (c) => (c === 'A' ? 'B' : 'A'));
show('tampered signature', await call(bizKey, 'POST', '/v1/verify', tampered));

console.log('6. Revocation takes effect on the very next verification');
await call(opKey, 'POST', `/v1/credentials/${record.id}/revoke`, { reason: 'demo' });
show('credential after revocation', await call(bizKey, 'POST', '/v1/verify', req('payments:create', { amount: 1500, currency: 'USD' }, { credential })));
await call(opKey, 'POST', `/v1/agents/${agent.id}/revoke`, { reason: 'demo' });
show('agent after revocation', await call(bizKey, 'POST', '/v1/verify', req('payments:create', { amount: 1500, currency: 'USD' })));

console.log(`\nDashboard: ${base}/dashboard/  (in-memory; data is lost when this process exits)`);
console.log('Demo-only API keys (ephemeral, valid until you stop this process):');
console.log(`  admin    ${admin}`);
console.log(`  operator ${opKey}`);
console.log(`  business ${bizKey}`);
console.log('Press Ctrl+C to stop.');
if (process.argv.includes('--exit')) await app.close();
