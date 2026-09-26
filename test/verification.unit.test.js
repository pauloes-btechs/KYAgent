// REQ-014 unit tests: the verification engine (ARCHITECTURE §3) exercised
// directly — no HTTP — against an in-memory store seeded with raw documents and
// a controllable clock. Each test names the requirement and check it traces to.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loadConfig } from '../src/config.js';
import { signCredential } from '../src/crypto/credentials.js';
import { b64u, keyThumbprint } from '../src/crypto/ed25519.js';
import { buildVerifyRequest, generateAgentKey } from '../src/sdk/agentSigner.js';
import { auditService } from '../src/services/audit.js';
import { verificationService } from '../src/services/verification.js';
import { MemoryStore } from '../src/store/memory.js';

const OP = 'op_01J8ZQ4Y5N3V6K2M7P9R0S1T2A';
const BIZ = 'biz_01J8ZQ4Y5N3V6K2M7P9R0S1T2B';
const BIZ2 = 'biz_01J8ZQ4Y5N3V6K2M7P9R0S1T2C';
const AGT = 'agt_01J8ZQ4Y5N3V6K2M7P9R0S1T2D';
const GRT = 'grt_01J8ZQ4Y5N3V6K2M7P9R0S1T2E';
const CRD = 'crd_01J8ZQ4Y5N3V6K2M7P9R0S1T2F';

async function setup({ grant = {}, operatorStatus = 'verified', agentStatus = 'active' } = {}) {
  const config = loadConfig({ NODE_ENV: 'test', LOG_LEVEL: 'silent' });
  const store = new MemoryStore();
  const state = { ms: Date.UTC(2026, 0, 1) };
  const clock = { now: () => new Date(state.ms) };
  const nowSec = () => Math.floor(state.ms / 1000);
  const key = generateAgentKey();
  const created = clock.now();

  await store.operators.insert({ id: OP, status: operatorStatus, createdAt: created });
  await store.agents.insert({
    id: AGT,
    operatorId: OP,
    publicKey: key.publicKey,
    keyThumbprint: keyThumbprint(key.publicKey),
    status: agentStatus,
    createdAt: created,
  });
  await store.grants.insert({
    id: GRT,
    agentId: AGT,
    businessId: BIZ,
    actions: ['payments:create'],
    constraints: { maxAmount: 10000, currency: 'USD' },
    status: 'active',
    expiresAt: new Date(state.ms + 3600_000),
    createdAt: created,
    ...grant,
  });

  const svc = verificationService({ store, clock, config, audit: auditService({ store, clock }) });
  const principal = { role: 'business', businessId: BIZ };
  const signed = (o = {}) =>
    buildVerifyRequest(o.privateKey ?? key.privateKey, {
      agentId: o.agentId ?? AGT,
      audience: o.audience ?? BIZ,
      action: o.action ?? 'payments:create',
      resource: o.resource,
      context: 'context' in o ? o.context : { amount: 100, currency: 'USD' },
      credential: o.credential,
      timestamp: o.timestamp ?? nowSec(),
      nonce: o.nonce,
    });
  const run = async (body, p = principal) => (await svc.verify(p, { ok: true, body }, 'req-1')).body;
  const runFull = (body, p = principal) => svc.verify(p, { ok: true, body }, 'req-1');

  const baseClaims = () => ({
    iss: config.issuer,
    sub: AGT,
    aud: BIZ,
    iat: nowSec(),
    nbf: nowSec(),
    exp: nowSec() + 600,
    jti: CRD,
    kya_operator: OP,
    kya_grant: GRT,
    kya_actions: ['payments:create'],
    kya_constraints: { maxAmount: 10000, currency: 'USD' },
    cnf: { jkt: keyThumbprint(key.publicKey) },
  });
  const credRecord = (patch = {}) =>
    store.credentials.insert({
      id: CRD,
      agentId: AGT,
      operatorId: OP,
      businessId: BIZ,
      grantId: GRT,
      actions: ['payments:create'],
      status: 'active',
      issuedAt: clock.now(),
      expiresAt: new Date(state.ms + 600_000),
      revokedAt: null,
      ...patch,
    });
  const sign = (claims) => signCredential(claims, { privateKey: config.signingKey, kid: config.kid });

  return {
    config,
    store,
    key,
    nowSec,
    advance: (s) => (state.ms += s * 1000),
    signed,
    run,
    runFull,
    baseClaims,
    credRecord,
    sign,
  };
}

const code = (r) => {
  assert.equal(r.reasons.length, 1, 'a decision carries exactly one reason');
  return r.reasons[0].code;
};

test('REQ-014 unit: baseline ALLOW sets grantId and a single ALLOWED reason', async () => {
  const s = await setup();
  const r = await s.run(s.signed());
  assert.equal(r.decision, 'ALLOW');
  assert.equal(code(r), 'ALLOWED');
  assert.equal(r.grantId, GRT);
  assert.equal(r.operatorId, OP);
});

test('REQ-014 unit [tampered]: any bit flip in the signature or signed fields is SIGNATURE_INVALID', async () => {
  const s = await setup();
  const base = s.signed();
  const sigBytes = Buffer.from(base.signedRequest.signature, 'base64url');
  for (const i of [0, 31, 63]) {
    const body = structuredClone(base);
    const sig = Buffer.from(sigBytes);
    sig[i] ^= 0x80;
    body.signedRequest.signature = b64u(sig);
    assert.equal(code(await s.run(body)), 'SIGNATURE_INVALID', `byte ${i}`);
  }
  // timestamp and nonce are signed too: changing them breaks the signature
  const ts = structuredClone(base);
  ts.signedRequest.timestamp -= 1;
  assert.equal(code(await s.run(ts)), 'SIGNATURE_INVALID');
  const nonce = structuredClone(base);
  nonce.signedRequest.nonce = `${nonce.signedRequest.nonce.slice(0, -1)}${nonce.signedRequest.nonce.endsWith('A') ? 'B' : 'A'}`;
  assert.equal(code(await s.run(nonce)), 'SIGNATURE_INVALID');
  // resource changed consistently in body and signedRequest
  const res = s.signed({ resource: 'invoice-1' });
  res.resource = 'invoice-2';
  res.signedRequest.resource = 'invoice-2';
  assert.equal(code(await s.run(res)), 'SIGNATURE_INVALID');
  // untouched original still ALLOWs: failed attempts did not consume the nonce
  assert.equal((await s.run(base)).decision, 'ALLOW');
});

test('REQ-014 unit [tampered]: unsigned body fields disagreeing with signed fields are MALFORMED_REQUEST', async () => {
  const s = await setup();
  const mutate = [
    (b) => (b.agentId = 'agt_01J8ZQ4Y5N3V6K2M7P9R0S1T2Z'),
    (b) => (b.action = 'payments:refund'),
    (b) => (b.resource = 'other'),
    (b) => (b.context = { amount: 1, currency: 'USD' }),
    (b) => (b.signedRequest.contextSha256 = '0'.repeat(64)),
  ];
  for (const m of mutate) {
    const b = s.signed();
    m(b);
    assert.equal(code(await s.run(b)), 'MALFORMED_REQUEST', m.toString());
  }
  // unparsable body (parser reported failure)
  const wallClock = { now: () => new Date() };
  const r = await verificationService({
    store: s.store,
    clock: wallClock,
    config: s.config,
    audit: auditService({ store: s.store, clock: wallClock }),
  }).verify(
    { role: 'business', businessId: BIZ },
    { ok: false },
    'r',
  );
  assert.equal(r.body.decision, 'DENY');
  assert.equal(code(r.body), 'MALFORMED_REQUEST');
});

test('REQ-014 unit [expired]: timestamp window boundaries are inclusive at ±maxSkew', async () => {
  const s = await setup();
  const skew = s.config.maxSkewSeconds;
  assert.equal((await s.run(s.signed({ timestamp: s.nowSec() - skew }))).decision, 'ALLOW');
  assert.equal((await s.run(s.signed({ timestamp: s.nowSec() + skew }))).decision, 'ALLOW');
  assert.equal(code(await s.run(s.signed({ timestamp: s.nowSec() - skew - 1 }))), 'TIMESTAMP_OUT_OF_WINDOW');
  assert.equal(code(await s.run(s.signed({ timestamp: s.nowSec() + skew + 1 }))), 'TIMESTAMP_OUT_OF_WINDOW');
});

test('REQ-014 unit [expired]: an expired grant is not evaluated (NO_GRANT) and credentials against it are GRANT_EXPIRED', async () => {
  const s = await setup();
  await s.credRecord();
  const credential = s.sign(s.baseClaims());
  assert.equal((await s.run(s.signed({ credential }))).decision, 'ALLOW');
  s.advance(3600); // grant.expiresAt == now: expired (strict >)
  assert.equal(code(await s.run(s.signed())), 'NO_GRANT');
  // credential still unexpired per its own claims, but the grant is expired
  const longLived = s.sign({ ...s.baseClaims(), exp: s.nowSec() + 600 });
  assert.equal(code(await s.run(s.signed({ credential: longLived }))), 'GRANT_EXPIRED');
});

test('REQ-014 unit [expired]: credential exp boundary (exp == now is expired) and nbf in the future', async () => {
  const s = await setup();
  await s.credRecord();
  assert.equal(code(await s.run(s.signed({ credential: s.sign({ ...s.baseClaims(), exp: s.nowSec() }) }))), 'CREDENTIAL_EXPIRED');
  assert.equal(code(await s.run(s.signed({ credential: s.sign({ ...s.baseClaims(), nbf: s.nowSec() + 1 }) }))), 'CREDENTIAL_NOT_YET_VALID');
  assert.equal((await s.run(s.signed({ credential: s.sign({ ...s.baseClaims(), exp: s.nowSec() + 1 }) }))).decision, 'ALLOW');
});

test('REQ-014 unit [revoked]: agent, operator, credential and grant status are re-read on every call', async () => {
  const s = await setup();
  await s.credRecord();
  const credential = s.sign(s.baseClaims());
  assert.equal((await s.run(s.signed({ credential }))).decision, 'ALLOW');

  await s.store.credentials.revoke(CRD, { revokedAt: new Date() });
  assert.equal(code(await s.run(s.signed({ credential }))), 'CREDENTIAL_REVOKED');

  await s.store.grants.revoke(GRT, { revokedAt: new Date() });
  assert.equal(code(await s.run(s.signed())), 'NO_GRANT');

  await s.store.operators.update(OP, null, { status: 'rejected' });
  assert.equal(code(await s.run(s.signed())), 'OPERATOR_NOT_VERIFIED');
  await s.store.operators.update(OP, null, { status: 'suspended' });
  assert.equal(code(await s.run(s.signed())), 'OPERATOR_SUSPENDED');

  await s.store.agents.setStatus(AGT, null, { status: 'revoked' });
  assert.equal(code(await s.run(s.signed())), 'AGENT_REVOKED');
  // unknown status values fail closed
  await s.store.agents.setStatus(AGT, null, { status: 'weird' });
  assert.equal((await s.run(s.signed())).decision, 'DENY');
});

test('REQ-014 unit [revoked]: a revoked grant invalidates a still-active credential derived from it', async () => {
  const s = await setup();
  await s.credRecord();
  const credential = s.sign(s.baseClaims());
  await s.store.grants.revoke(GRT, { revokedAt: new Date() });
  assert.equal(code(await s.run(s.signed({ credential }))), 'GRANT_REVOKED');
});

test('REQ-014 unit [replayed]: nonce is single-use per agent, even under concurrency', async () => {
  const s = await setup();
  const body = s.signed();
  const results = await Promise.all(Array.from({ length: 10 }, () => s.run(structuredClone(body))));
  assert.equal(results.filter((r) => r.decision === 'ALLOW').length, 1);
  assert.equal(results.filter((r) => r.reasons[0].code === 'NONCE_REPLAYED').length, 9);
  // a fresh nonce with identical content is a new request
  assert.equal((await s.run(s.signed())).decision, 'ALLOW');
});

test('REQ-014 unit [replayed]: nonce not consumed by requests denied before the signature check', async () => {
  const s = await setup();
  const body = s.signed();
  await s.store.agents.setStatus(AGT, null, { status: 'suspended' });
  assert.equal(code(await s.run(body)), 'AGENT_SUSPENDED');
  await s.store.agents.setStatus(AGT, null, { status: 'active' });
  assert.equal((await s.run(body)).decision, 'ALLOW');
  assert.equal(code(await s.run(body)), 'NONCE_REPLAYED');
});

test('REQ-014 unit [replayed]: a nonce is consumed even when the request is later denied for scope', async () => {
  // The nonce is recorded at step 8; a replay of an out-of-scope request must not be re-evaluated.
  const s = await setup();
  const body = s.signed({ action: 'payments:refund' });
  assert.equal(code(await s.run(body)), 'ACTION_NOT_PERMITTED');
  assert.equal(code(await s.run(body)), 'NONCE_REPLAYED');
});

test('REQ-014 unit [out-of-scope]: action matching, grants from other businesses, and credential/grant intersection', async () => {
  const s = await setup({ grant: { actions: ['payments:create', 'orders:*'], constraints: {} } });
  assert.equal((await s.run(s.signed({ action: 'orders:refund:partial', context: {} }))).decision, 'ALLOW');
  assert.equal(code(await s.run(s.signed({ action: 'orders', context: {} }))), 'ACTION_NOT_PERMITTED');
  assert.equal(code(await s.run(s.signed({ action: 'ordersx:create', context: {} }))), 'ACTION_NOT_PERMITTED');
  assert.equal(code(await s.run(s.signed({ action: 'payments:create:bulk', context: {} }))), 'ACTION_NOT_PERMITTED');

  // A grant issued by another business does not authorize requests to this one.
  const other = { role: 'business', businessId: BIZ2 };
  assert.equal(code(await s.run(s.signed({ audience: BIZ2, context: {} }), other)), 'NO_GRANT');

  // Credential narrower than grant: credential scope wins.
  await s.credRecord();
  const narrow = s.sign({ ...s.baseClaims(), kya_actions: ['payments:create'], kya_constraints: {} });
  assert.equal(code(await s.run(s.signed({ credential: narrow, action: 'orders:create', context: {} }))), 'ACTION_NOT_PERMITTED');
  // Credential wider than grant (e.g. grant narrowed later): grant scope wins.
  const wide = s.sign({ ...s.baseClaims(), kya_actions: ['refunds:*'], kya_constraints: {} });
  assert.equal(code(await s.run(s.signed({ credential: wide, action: 'refunds:create', context: {} }))), 'ACTION_NOT_PERMITTED');
});

test('REQ-014 unit [out-of-scope]: constraints — first satisfying grant wins, otherwise CONSTRAINT_VIOLATION', async () => {
  const s = await setup();
  assert.equal(code(await s.run(s.signed({ context: { amount: 50000, currency: 'USD' } }))), 'CONSTRAINT_VIOLATION');
  assert.equal(code(await s.run(s.signed({ context: { amount: '100', currency: 'USD' } }))), 'CONSTRAINT_VIOLATION');
  await s.store.grants.insert({
    id: 'grt_01J8ZQ4Y5N3V6K2M7P9R0S1T2G',
    agentId: AGT,
    businessId: BIZ,
    actions: ['payments:create'],
    constraints: { maxAmount: 100000, currency: 'USD' },
    status: 'active',
    expiresAt: new Date(Date.UTC(2026, 0, 2)),
    createdAt: new Date(Date.UTC(2026, 0, 1, 0, 0, 1)),
  });
  const r = await s.run(s.signed({ context: { amount: 50000, currency: 'USD' } }));
  assert.equal(r.decision, 'ALLOW');
  assert.equal(r.grantId, 'grt_01J8ZQ4Y5N3V6K2M7P9R0S1T2G');
  // small amounts still match the older grant first
  assert.equal((await s.run(s.signed())).grantId, GRT);
});

test('REQ-014 unit: checks short-circuit in normative order (first failure wins)', async () => {
  const s = await setup();
  // audience (2) beats agent-not-found (3)
  assert.equal(code(await s.run(s.signed({ audience: BIZ2, agentId: 'agt_01J8ZQ4Y5N3V6K2M7P9R0S1T2Z' }))), 'AUDIENCE_MISMATCH');
  // expired timestamp (6) beats bad signature (7)
  const stale = s.signed({ timestamp: s.nowSec() - 10_000 });
  stale.signedRequest.signature = b64u(Buffer.alloc(64));
  assert.equal(code(await s.run(stale)), 'TIMESTAMP_OUT_OF_WINDOW');
  // bad signature (7) beats a forged credential (9a)
  const forged = s.signed({ credential: 'a.b.c' });
  forged.signedRequest.signature = b64u(Buffer.alloc(64));
  assert.equal(code(await s.run(forged)), 'SIGNATURE_INVALID');
  // revoked agent (4) beats everything after it
  await s.store.agents.setStatus(AGT, null, { status: 'revoked' });
  assert.equal(code(await s.run(s.signed({ timestamp: 1 }))), 'AGENT_REVOKED');
});

test('REQ-014 unit: every decision is audited and store failures fail closed', async () => {
  const s = await setup();
  await s.run(s.signed());
  await s.run(s.signed({ action: 'payments:refund' }));
  const events = (await s.store.verificationEvents.list({ limit: 10 })).data;
  assert.deepEqual(events.map((e) => e.decision).sort(), ['ALLOW', 'DENY']);

  s.store.nonces.insertOnce = async () => {
    throw new Error('nonce store down');
  };
  const res = await s.runFull(s.signed());
  assert.equal(res.status, 500);
  assert.equal(res.body.decision, 'DENY');
  assert.equal(code(res.body), 'INTERNAL_ERROR');
});
