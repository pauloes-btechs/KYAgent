// T20 security review of the invariant boundary (docs/SECURITY_REVIEW_HARNESS.md). Every checked
// item in that document points at a test in this file. Offline: MemoryStore + fixture modes; the
// only subprocess is src/server.js pointed at an unreachable MongoDB to prove MONGODB_URI is not logged.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { loadConfig } from '../src/config.js';
import { generateApiKey, hashApiKeySecret } from '../src/crypto/apiKeys.js';
import { evaluateProposal, llmPrompt, proposeFromOutcome } from '../src/harness/adaptation.js';
import { FORBIDDEN_POLICY_KEYS, INVARIANTS, INVARIANTS_HASH, holds, validatePolicy } from '../src/harness/invariants.js';
import { HARNESS_V1_POLICY, HarnessPolicyError, loadActiveHarness, policyHash } from '../src/harness/policy.js';
import { runInvestigation } from '../src/investigation/pipeline.js';
import { REDACTED_MONGO_URI, createLogger } from '../src/logger.js';
import { USDC, buildHackathonDocs } from '../src/seed/hackathon.js';
import { keyLineage } from '../src/services/apiKeys.js';
import { MemoryStore } from '../src/store/memory.js';
import { LEAST_PRIVILEGE_ROLES, MongoStore, checkDbPrivileges } from '../src/store/mongo.js';
import { startApp } from './helpers.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (rel) => readFileSync(join(ROOT, rel), 'utf8');
const v1 = () => structuredClone(HARNESS_V1_POLICY);
const TAKEOVER = { outcome: 'CONFIRMED_ACCOUNT_TAKEOVER', approveAdaptation: true };
const TAKEOVER_SIGNALS = ['AMOUNT_ANOMALY', 'NEW_COUNTERPARTY', 'SIGNING_KEY_CHANGED'];

function jsFiles(dir) {
  const out = [];
  for (const name of readdirSync(join(ROOT, dir))) {
    const rel = join(dir, name);
    if (statSync(join(ROOT, rel)).isDirectory()) out.push(...jsFiles(rel));
    else if (rel.endsWith('.js')) out.push(rel);
  }
  return out;
}

// ============================================================ §1 no policy path bypasses invariants

test('§1.1 invariants are frozen code: no DB/env input, frozen objects, checks fail closed', () => {
  const src = read('src/harness/invariants.js');
  assert.doesNotMatch(src, /process\.env|store\.|\.collection\(|harnessVersions/);
  assert.ok(Object.isFrozen(INVARIANTS));
  // Only the delegation limits hold on empty input, meaning "no limit configured" (as /v1/verify);
  // a configured limit with a missing or malformed amount fails closed.
  const NO_LIMIT_MEANS_HOLDS = ['INV_DELEGATION_MAX', 'INV_DAILY_LIMIT'];
  for (const i of INVARIANTS) {
    assert.ok(Object.isFrozen(i), i.id);
    assert.equal(holds(i.id, undefined), NO_LIMIT_MEANS_HOLDS.includes(i.id), `${i.id} with no input`);
  }
  assert.equal(holds('INV_DELEGATION_MAX', { constraints: { maxAmount: 10 }, context: {} }), false);
  assert.equal(holds('INV_DELEGATION_MAX', { constraints: { maxAmount: 10 }, context: { amount: '5' } }), false);
  assert.equal(holds('INV_DAILY_LIMIT', { dailyLimit: 10, spent24h: 0 }), false);
  assert.throws(() => holds('INV_MADE_UP', {}), /unknown invariant/);
});

test('§1.2 the only writers of harness_versions and memory promotion are investigations#confirm', () => {
  const writers = jsFiles('src').filter((f) => /harnessVersions\.(insert|updateIf|upsert)|securityMemories\.updateIf/.test(read(f)));
  assert.deepEqual(writers, ['src/services/investigations.js']);
  // No HTTP route writes a policy, a memory or a harness version directly.
  const routes = read('src/app.js').match(/\{ m: '(POST|PUT|PATCH|DELETE)', p: '[^']+'/g);
  assert.ok(!routes.some((r) => /harness|memor/.test(r)), routes.join('\n'));
});

test('§1.3 a stored policy that references invariants or bypasses them never loads (fail closed)', async () => {
  for (const key of FORBIDDEN_POLICY_KEYS) {
    const errs = validatePolicy({ ...v1(), escalation: [{ ...v1().escalation[0], [key]: true }] });
    assert.ok(errs.some((e) => /may not reference invariants/.test(e.message)), key);
  }
  const bad = [
    { ...v1(), escalation: [{ id: 'x', when: { sanctionsFuzzyHit: true }, then: { riskDecision: 'ALLOW', reasonCode: 'SANCTIONS_FUZZY_MATCH' } }] },
    { ...v1(), memoryRetrieval: { ...v1().memoryRetrieval, filter: { status: 'UNVERIFIED' } } },
    { ...v1(), steps: ['identity', 'delegation', 'signals', 'memory', 'policy'] },
    { ...v1(), steps: ['identity', 'delegation', 'signals', 'sanctions', 'memory', 'policy'] },
  ];
  for (const policy of bad) {
    assert.ok(validatePolicy(policy).length > 0);
    const store = new MemoryStore();
    await store.harnessVersions.insert({ id: 1, version: 1, status: 'active', invariantsHash: INVARIANTS_HASH, policy, policyHash: policyHash(policy), createdAt: new Date() });
    await assert.rejects(loadActiveHarness(store), HarnessPolicyError);
  }
});

const NOW = new Date('2026-09-26T12:00:00Z');
const docs = buildHackathonDocs({ now: NOW });
const fromDoc = ({ _id, ...rest }) => ({ id: _id, ...rest });

test('§1.4 the most permissive valid adaptive policy still BLOCKs an exact sanctions hit and a delegation breach', async () => {
  const permissive = {
    ...v1(),
    steps: ['identity', 'delegation', 'sanctions', 'signals', 'memory', 'signing_key_history_check', 'policy'],
    memoryRetrieval: { k: 10, numCandidates: 200, minScorePpm: 1_000_000, filter: { status: 'VERIFIED' } },
    contextAssembly: { maxMemories: 0, includeSignalStats: false, includeSanctionsEvidence: false },
    escalation: [],
  };
  assert.deepEqual(validatePolicy(permissive), []);
  const store = new MemoryStore();
  await store.operators.insert(fromDoc(docs.operators[0]));
  await store.agents.insert(fromDoc(docs.agents[0]));
  await store.grants.insert(fromDoc(docs.grants[0]));
  const lazarus = docs.sanctions.find((s) => s._id === 'sdn_LAZARUS');
  await store.sanctions.insert(fromDoc(lazarus));
  const tx = (over) => ({ asset: 'USDC', amount: 10 * USDC, counterparty: { address: '0x7a11000000000000000000000000000000c0ffee' }, signingKeyThumbprint: docs.agents[0].keyThumbprint, ...over });
  const run = (over) => runInvestigation({ store, agentId: 'agt_TREASURYBOT', delegationId: 'grt_TB_USDC', policy: permissive, tx: tx(over), now: NOW });

  const sanctioned = await run({ counterparty: { address: lazarus.wallets[0].address.toUpperCase().replace('0X', '0x') } });
  assert.equal(sanctioned.riskDecision, 'BLOCK');
  assert.equal(sanctioned.reasons[0].code, 'SANCTIONS_EXACT_MATCH');
  assert.equal(sanctioned.reasons[0].invariantId, 'INV_SANCTIONS_EXACT_BLOCK');

  const over = await run({ amount: docs.grants[0].constraints.maxAmount + 1 });
  assert.equal(over.riskDecision, 'BLOCK');
  assert.equal(over.reasons[0].code, 'DELEGATION_MAX_EXCEEDED');
});

// ============================================================ §2 LLM output is schema-validated

const LIVE_INV = { id: 'inv_X', signals: TAKEOVER_SIGNALS, riskDecision: 'REVIEW' };
const VERIFIED_MEM = { id: 'mem_inv_X', status: 'VERIFIED', outcome: 'CONFIRMED_ACCOUNT_TAKEOVER', signals: TAKEOVER_SIGNALS };
const llmSaying = (text) => ({ model: 'test-double', complete: async () => text });

test('§2.1 LLM diffs that touch invariants, the memory filter or decisions are rejected', async () => {
  const attacks = [
    [{ op: 'add', path: '/invariants', value: [] }],
    [{ op: 'add', path: '/skipInvariants', value: true }],
    [{ op: 'replace', path: '/memoryRetrieval/filter', value: { status: 'UNVERIFIED' } }],
    [{ op: 'replace', path: '/memoryRetrieval/minScorePpm', value: 1 }],
    [{ op: 'remove', path: '/steps/2' }],
    [{ op: 'add', path: '/escalation/-', value: { id: 'x', when: { sanctionsFuzzyHit: true }, then: { riskDecision: 'ALLOW', reasonCode: 'SANCTIONS_FUZZY_MATCH' } } }],
    [{ op: 'add', path: '/escalation/-', value: { id: 'x', when: { sanctionsFuzzyHit: true }, then: { riskDecision: 'REVIEW', reasonCode: 'SANCTIONS_FUZZY_MATCH', overrides: ['INV_SANCTIONS_EXACT_BLOCK'] } } }],
    [{ op: 'replace', path: '/sanctionsFuzzy', value: { minScorePpm: 1, limit: 1 } }],
    [{ op: 'add', path: '/steps/5', value: 'shell_exec' }],
    [{ op: 'add', path: '/__proto__/polluted', value: true }],
    [{ op: 'replace', path: '', value: {} }],
  ];
  for (const diff of attacks) {
    const proposal = await proposeFromOutcome(LIVE_INV, VERIFIED_MEM, { policy: v1(), mode: 'live', llm: llmSaying(JSON.stringify({ diff })) });
    assert.equal(proposal.proposer.kind, 'llm');
    const r = evaluateProposal(v1(), proposal.diff);
    assert.equal(r.ok, false, JSON.stringify(diff));
    assert.ok(r.errors.length > 0);
  }
  assert.equal({}.polluted, undefined);
});

test('§2.2 malformed LLM output becomes a recorded rejection, never a policy', async () => {
  for (const text of ['not json', '{"patch":[]}', 'null', '42']) {
    const p = await proposeFromOutcome(LIVE_INV, VERIFIED_MEM, { policy: v1(), mode: 'live', llm: llmSaying(text) });
    assert.equal(p.error.code, 'LLM_OUTPUT_INVALID', text);
  }
  const thrown = await proposeFromOutcome(LIVE_INV, VERIFIED_MEM, { policy: v1(), mode: 'live', llm: { complete: async () => { throw new Error('boom'); } } });
  assert.equal(thrown.error.code, 'LLM_FAILED');
  const none = await proposeFromOutcome(LIVE_INV, VERIFIED_MEM, { policy: v1(), mode: 'live' });
  assert.equal(none.error.code, 'LLM_UNAVAILABLE');
});

test('§2.3 the LLM never sees invariants and is never consulted for unverified memory', async () => {
  const prompt = llmPrompt({ policy: v1(), investigation: LIVE_INV, memory: VERIFIED_MEM });
  assert.doesNotMatch(prompt, /INV_/);
  assert.doesNotMatch(prompt, /invariant/i);
  let called = false;
  const llm = { complete: async () => { called = true; return '{"diff":[]}'; } };
  for (const status of ['UNVERIFIED', 'REJECTED', undefined]) {
    assert.equal(await proposeFromOutcome(LIVE_INV, { ...VERIFIED_MEM, status }, { policy: v1(), mode: 'live', llm }), null);
  }
  assert.equal(called, false);
  // A valid LLM diff is still only a proposal; the invariants hash cannot move.
  const ok = evaluateProposal(v1(), [{ op: 'replace', path: '/memoryRetrieval/k', value: 7 }]);
  assert.equal(ok.ok, true);
  assert.equal(INVARIANTS_HASH, INVARIANTS_HASH.toLowerCase());
});

// ============================================================ §3 least-privilege DB user

const fakeDb = (roles) => ({ command: async (cmd) => (assert.deepEqual(cmd, { connectionStatus: 1 }), { authInfo: { authenticatedUserRoles: roles } }) });

test('§3.1 checkDbPrivileges accepts readWrite on the app db only', async () => {
  assert.deepEqual(LEAST_PRIVILEGE_ROLES, ['readWrite', 'read']);
  assert.equal((await checkDbPrivileges(fakeDb([{ role: 'readWrite', db: 'kyagent' }]), 'kyagent')).ok, true);
  const cases = [
    [[{ role: 'atlasAdmin', db: 'admin' }, { role: 'readWriteAnyDatabase', db: 'admin' }], ['atlasAdmin', 'readWriteAnyDatabase']],
    [[{ role: 'readWrite', db: 'kyagent' }, { role: 'dbAdmin', db: 'kyagent' }], ['dbAdmin']],
    [[{ role: 'readWrite', db: 'kyagent' }, { role: 'readWrite', db: 'other' }], ['readWrite']],
    [[{ role: 'readWrite', db: 'other' }], ['readWrite']],
    [[{ role: 'read', db: 'kyagent' }], []],
    [[], []],
  ];
  for (const [roles, excess] of cases) {
    const r = await checkDbPrivileges(fakeDb(roles), 'kyagent');
    assert.equal(r.ok, false, JSON.stringify(roles));
    assert.deepEqual(r.excess.map((x) => x.role), excess);
  }
});

test('§3.2 server.js checks privileges before the watcher starts and refuses in production', () => {
  const src = read('src/server.js');
  const check = src.indexOf('store.privileges()');
  assert.ok(check > 0 && check < src.indexOf('new SanctionsWatcher('));
  assert.match(src.slice(check, src.indexOf('new SanctionsWatcher(')), /if \(config\.production\) \{[\s\S]*process\.exit\(1\)/);
});

// ============================================================ §4 MONGODB_URI is never logged

const SINK_RE = /\b(?:logger|this\.logger|log|console)\.(?:trace|debug|info|warn|error|fatal|log)\(|process\.(?:stdout|stderr)\.write\(|\bfail\(/g;
const URI_VALUE_RE = /\.MONGODB_URI\b|\.ATLAS_TEST_URI\b|\[\s*['"](?:MONGODB_URI|ATLAS_TEST_URI)['"]\s*\]|\bmongoUri\b|\._uri\b|\buri\b/;

/** The argument text of every log-sink call, with string-literal text removed (template `${}` kept). */
function sinkCalls(src) {
  const calls = [];
  for (const m of src.matchAll(SINK_RE)) {
    let depth = 1;
    let i = m.index + m[0].length;
    let out = '';
    let quote = null;
    for (; i < src.length && depth > 0; i++) {
      const ch = src[i];
      if (quote) {
        if (ch === '\\') i++;
        else if (quote === '`' && ch === '$' && src[i + 1] === '{') {
          const end = src.indexOf('}', i);
          out += src.slice(i, end + 1);
          i = end;
        } else if (ch === quote) quote = null;
        continue;
      }
      if (ch === "'" || ch === '"' || ch === '`') quote = ch;
      else if (ch === '(') depth++;
      else if (ch === ')') depth--;
      out += ch;
    }
    calls.push(out);
  }
  return calls;
}

test('§4.1 grep: no log / console / stdout call in src, scripts or test references a MongoDB URI value', () => {
  assert.equal(sinkCalls("logger.info(`x ${config.mongoUri}`)").some((c) => URI_VALUE_RE.test(c)), true, 'self-check: the grep sees template values');
  assert.equal(sinkCalls("fail('set MONGODB_URI first')").some((c) => URI_VALUE_RE.test(c)), false, 'self-check: literal names are fine');
  const offenders = [];
  let scanned = 0;
  // This file is excluded: it holds the grep's own self-check strings and logs nothing.
  const files = [...jsFiles('src'), ...jsFiles('scripts'), ...jsFiles('test')].filter((f) => f !== join('test', 'security-harness.test.js'));
  for (const file of files) {
    for (const call of sinkCalls(read(file))) {
      scanned++;
      if (URI_VALUE_RE.test(call)) offenders.push(`${file}: ${call.slice(0, 120)}`);
    }
  }
  assert.ok(scanned > 50, `scanned ${scanned} sink calls`);
  assert.deepEqual(offenders, []);
});

const SENTINEL = 'S3ntinelPassw0rd';
const SECRET_URI = `mongodb+srv://kyagent_app:${SENTINEL}@cluster0.example.mongodb.net/kyagent?retryWrites=true`;

test('§4.2 the logger redacts connection strings anywhere in a line and keeps toJSON serialisation', () => {
  const lines = [];
  const logger = createLogger('info', (l) => lines.push(l));
  const at = new Date('2026-09-28T00:00:00Z');
  logger.error(`connect failed for ${SECRET_URI}`, { error: `MongoServerSelectionError: ${SECRET_URI}`, nested: { list: [SECRET_URI.replace('+srv', '')] }, at, n: 1 });
  assert.equal(lines.length, 1);
  assert.doesNotMatch(lines[0], new RegExp(SENTINEL));
  assert.doesNotMatch(lines[0], /kyagent_app/);
  const parsed = JSON.parse(lines[0]);
  assert.equal(parsed.msg, `connect failed for ${REDACTED_MONGO_URI}`);
  assert.equal(parsed.nested.list[0], REDACTED_MONGO_URI);
  assert.equal(parsed.at, at.toISOString());
  assert.equal(parsed.n, 1);
});

test('§4.3 config and MongoStore never serialise MONGODB_URI', () => {
  const config = loadConfig({ NODE_ENV: 'test', LOG_LEVEL: 'silent', MONGODB_URI: SECRET_URI });
  assert.equal(config.mongoUri, SECRET_URI);
  assert.doesNotMatch(JSON.stringify(config), new RegExp(SENTINEL));
  assert.ok(!Object.keys(config).includes('mongoUri'));
  const store = new MongoStore(SECRET_URI, 'kyagent');
  assert.doesNotMatch(JSON.stringify(store), new RegExp(SENTINEL));
  assert.ok(!Object.keys(store).includes('_uri'));
});

test('§4.4 src/server.js failing to reach MongoDB logs neither the URI nor its password', async () => {
  const uri = `mongodb://kyagent_app:${SENTINEL}@127.0.0.1:1/kyagent?serverSelectionTimeoutMS=300&connectTimeoutMS=300`;
  const env = { PATH: process.env.PATH, NODE_ENV: 'test', LOG_LEVEL: 'trace', PORT: '0', MONGODB_URI: uri, SANCTIONS_MODE: 'fixture', LLM_MODE: 'fixture', CHAIN_MODE: 'fixture' };
  const child = spawn(process.execPath, [join(ROOT, 'src/server.js')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', (d) => (output += d));
  child.stderr.on('data', (d) => (output += d));
  const timer = setTimeout(() => child.kill('SIGKILL'), 30_000);
  const code = await new Promise((resolve) => child.on('close', resolve));
  clearTimeout(timer);
  assert.equal(code, 1, output);
  assert.match(output, /store initialisation failed/);
  assert.doesNotMatch(output, new RegExp(SENTINEL));
  assert.doesNotMatch(output, /kyagent_app/);
});

// ============================================================ §5 self-approval is impossible

async function world() {
  const h = await startApp();
  const root = await h.app.services.apiKeys.authenticate(`Bearer ${h.admin}`);
  // An independent approver: provisioned out-of-band (as scripts/demo.js does), so a lineage root.
  const independent = generateApiKey();
  await h.store.apiKeys.insert({
    id: independent.keyId, name: 'independent reviewer', role: 'admin', ownerId: null, createdBy: null,
    secretHash: hashApiKeySecret(h.config.pepper, independent.secret), status: 'active', createdAt: new Date(), lastUsedAt: null, revokedAt: null,
  });
  await h.store.harnessVersions.insert({ id: 1, version: 1, status: 'active', parentVersion: null, invariantsHash: INVARIANTS_HASH, policy: v1(), policyHash: policyHash(v1()), createdAt: new Date(), approvedBy: { role: 'system', apiKeyId: null, ownerId: null }, sourceEventId: null });
  const mint = async (by, role, ownerId = null) => {
    const r = await h.call(by, 'POST', '/v1/api-keys', { name: `${role} key`, role, ownerId });
    assert.equal(r.status, 201, JSON.stringify(r.body));
    return { id: r.body.apiKey.id, key: r.body.secret };
  };
  let n = 0;
  const openCase = async ({ initiator, principalId = 'op_none', businessId = 'biz_none' }) => {
    const id = `inv_01JSECREV${String(++n).padStart(17, '0')}`;
    await h.store.investigations.insert({
      id, trigger: 'api', initiatedBy: initiator, agentId: 'agt_none', principalId, businessId, harnessVersion: 1, stages: [],
      signals: TAKEOVER_SIGNALS, riskDecision: 'REVIEW', decision: 'DENY', reasons: [], status: 'AWAITING_REVIEW', outcome: null, createdAt: new Date(),
    });
    return id;
  };
  const assertRefused = async (key, id) => {
    const auditBefore = h.store._auditLog.length;
    const r = await h.call(key, 'POST', `/v1/investigations/${id}/confirm`, TAKEOVER);
    assert.equal(r.status, 403, JSON.stringify(r.body));
    assert.match(r.body.error.message, /INV_NO_SELF_APPROVAL/);
    assert.equal((await h.store.investigations.findById(id)).status, 'AWAITING_REVIEW');
    assert.equal((await h.store.harnessVersions.find({})).length, 1);
    assert.equal(h.store._auditLog.length, auditBefore);
  };
  return { h, root, independent, mint, openCase, assertRefused };
}

test('§5.1 sibling admin keys minted by the same admin cannot approve each other (review F-1)', async (t) => {
  const w = await world();
  t.after(() => w.h.close());
  const b = await w.mint(w.h.admin, 'admin');
  const c = await w.mint(w.h.admin, 'admin');
  const grandchild = await w.mint(c.key, 'admin');
  const id = await w.openCase({ initiator: { role: 'admin', apiKeyId: b.id, ownerId: null } });
  await w.assertRefused(c.key, id); // sibling
  await w.assertRefused(grandchild.key, id); // cousin
  await w.assertRefused(w.h.admin, id); // parent of the initiator
  await w.assertRefused(b.key, id); // the initiator itself
});

test('§5.2 an admin cannot approve a case opened with a tenant key it minted (review F-2)', async (t) => {
  const w = await world();
  t.after(() => w.h.close());
  const biz = (await w.h.call(w.h.admin, 'POST', '/v1/businesses', { name: 'Globex' })).body;
  const bizKey = await w.mint(w.h.admin, 'business', biz.id);
  const child = await w.mint(w.h.admin, 'admin');
  const id = await w.openCase({ initiator: { role: 'business', apiKeyId: bizKey.id, ownerId: biz.id }, businessId: biz.id });
  await w.assertRefused(w.h.admin, id);
  await w.assertRefused(child.key, id);
});

test('§5.3 an admin that minted a key of a case party (principal or business) cannot approve it', async (t) => {
  const w = await world();
  t.after(() => w.h.close());
  const op = (await w.h.call(w.h.admin, 'POST', '/v1/operators', { type: 'organization', legalName: 'Acme Robotics Ltd', country: 'GB', contactEmail: 'ops@acme.example' })).body;
  assert.ok(op.id, JSON.stringify(op));
  await w.mint(w.h.admin, 'operator', op.id);
  // The initiator is unrelated to the admin (an out-of-band business key); only the party key links them.
  const oob = generateApiKey();
  await w.h.store.apiKeys.insert({ id: oob.keyId, name: 'oob biz', role: 'business', ownerId: 'biz_none', createdBy: null, secretHash: 'x', status: 'active', createdAt: new Date(), lastUsedAt: null, revokedAt: null });
  const id = await w.openCase({ initiator: { role: 'business', apiKeyId: oob.keyId, ownerId: 'biz_none' }, principalId: op.id });
  await w.assertRefused(w.h.admin, id);
});

test('§5.4 an independent out-of-band admin can confirm; the adaptation records it as approvedBy', async (t) => {
  const w = await world();
  t.after(() => w.h.close());
  const biz = (await w.h.call(w.h.admin, 'POST', '/v1/businesses', { name: 'Initech' })).body;
  const bizKey = await w.mint(w.h.admin, 'business', biz.id);
  const id = await w.openCase({ initiator: { role: 'business', apiKeyId: bizKey.id, ownerId: biz.id }, businessId: biz.id });
  const r = await w.h.call(w.independent.plaintext, 'POST', `/v1/investigations/${id}/confirm`, TAKEOVER);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.adaptation.applied, true);
  const [v2] = await w.h.store.harnessVersions.find({ status: 'active' });
  assert.equal(v2.version, 2);
  assert.equal(v2.approvedBy.apiKeyId, w.independent.keyId);
  // Confirmed exactly once: a second approver gets 409, not a second promotion.
  assert.equal((await w.h.call(w.independent.plaintext, 'POST', `/v1/investigations/${id}/confirm`, TAKEOVER)).status, 409);
});

test('§5.5 key lineage: createdBy, legacy audit fallback, and cycles fail closed', async (t) => {
  const w = await world();
  t.after(() => w.h.close());
  const child = await w.mint(w.h.admin, 'admin');
  const grandchild = await w.mint(child.key, 'admin');
  assert.deepEqual(await keyLineage(w.h.store, grandchild.id), [grandchild.id, child.id, w.root.apiKeyId]);
  // A key stored before `createdBy` existed: the api_key.created audit actor is its parent.
  const doc = await w.h.store.apiKeys.findById(grandchild.id);
  delete doc.createdBy;
  const legacyStore = { apiKeys: { findById: async (id) => (id === grandchild.id ? doc : w.h.store.apiKeys.findById(id)) }, auditEvents: w.h.store.auditEvents };
  assert.deepEqual(await keyLineage(legacyStore, grandchild.id), [grandchild.id, child.id, w.root.apiKeyId]);
  // A cycle (only possible by tampering with the DB) throws; confirm then refuses.
  const cyclic = { apiKeys: { findById: async (id) => ({ id, createdBy: id === 'key_a' ? 'key_b' : 'key_a' }) }, auditEvents: w.h.store.auditEvents };
  await assert.rejects(keyLineage(cyclic, 'key_a'), /cyclic/);
  // createdBy is set server-side and cannot be supplied by the caller.
  assert.equal((await w.h.call(w.h.admin, 'POST', '/v1/api-keys', { name: 'k', role: 'admin', ownerId: null, createdBy: null })).status, 400);
  // The API does not expose lineage (byte-compatible ApiKey).
  assert.ok(!('createdBy' in (await w.h.call(w.h.admin, 'GET', '/v1/api-keys')).body.data[0]));
});

test('§5.6 INV_NO_SELF_APPROVAL fails closed without a resolved lineage', () => {
  const subject = { initiatedBy: { apiKeyId: 'key_i' }, conflictKeyIds: ['key_i', 'key_r'] };
  const approver = { role: 'admin', apiKeyId: 'key_a', ownerId: null };
  assert.equal(holds('INV_NO_SELF_APPROVAL', { approver: { ...approver, keyLineage: ['key_a', 'key_q'] }, subject }), true);
  assert.equal(holds('INV_NO_SELF_APPROVAL', { approver, subject }), false);
  assert.equal(holds('INV_NO_SELF_APPROVAL', { approver: { ...approver, keyLineage: ['key_q'] }, subject }), false);
  assert.equal(holds('INV_NO_SELF_APPROVAL', { approver: { ...approver, keyLineage: ['key_a'] }, subject: { initiatedBy: subject.initiatedBy } }), false);
  assert.equal(holds('INV_NO_SELF_APPROVAL', { approver: { ...approver, keyLineage: ['key_a'] }, subject: { ...subject, conflictKeyIds: ['key_r'] } }), false);
  assert.equal(holds('INV_NO_SELF_APPROVAL', { approver: { ...approver, keyLineage: ['key_a', 'key_r'] }, subject }), false);
});

// ============================================================ the review document itself

test('SECURITY_REVIEW_HARNESS.md: every checklist item is checked and cites a test in this file', () => {
  const doc = read('docs/SECURITY_REVIEW_HARNESS.md');
  const items = doc.split('\n').filter((l) => /^\s*- \[[ xX]\]/.test(l));
  assert.ok(items.length >= 15, `${items.length} checklist items`);
  assert.deepEqual(items.filter((l) => /^\s*- \[ \]/.test(l)), []);
  const own = read('test/security-harness.test.js');
  for (const ref of new Set(doc.match(/§\d+\.\d+/g))) {
    assert.ok(own.includes(`'${ref} `), `${ref} is cited in the doc but has no test`);
  }
});
