// T04: hackathon demo seed (DELIVERY_PLAN §5). Offline checks of the scenario built from
// fixtures/, reset idempotency on a recording collection double (the Atlas run is
// `make demo-reset`), and the demo scripts' hard "Atlas required" failure.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { canonicalJson } from '../src/crypto/canonical.js';
import { sha256hex } from '../src/crypto/ed25519.js';
import { INVARIANTS_HASH, validatePolicy } from '../src/harness/invariants.js';
import { loadFixture } from '../src/memory/embeddings.js';
import { signalsText, textSha256 } from '../src/memory/signalsText.js';
import {
  DEMO_IDS,
  HARNESS_V1_POLICY,
  SEEDED_COLLECTIONS,
  USDC,
  buildHackathonDocs,
  clearHackathon,
  collectionCounts,
  expectedCounts,
  seedHackathon,
  toBsonIntegers,
  treasuryBotKey,
} from '../src/seed/hackathon.js';
import {
  HARNESS_VERSIONS_SCHEMA,
  PASSPORTS_SCHEMA,
  SANCTIONS_SCHEMA,
  SECURITY_MEMORIES_SCHEMA,
  TRANSACTIONS_SCHEMA,
} from '../src/store/migrations.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const NOW = new Date('2026-09-26T12:34:56Z');
const EVM = /^0x[0-9a-f]{40}$/;
const byId = (list, id) => list.find((d) => d._id === id);

test('seed builds exactly the 12 scenario items with fixed ids and demo:true', () => {
  const d = buildHackathonDocs({ now: NOW });
  assert.deepEqual(Object.keys(d), [...SEEDED_COLLECTIONS]);
  assert.deepEqual(d.operators.map((x) => x._id), ['op_NORTHWIND']);
  assert.deepEqual(d.businesses.map((x) => x._id), ['biz_CIRCLEPAY']);
  assert.deepEqual(d.agents.map((x) => x._id), ['agt_TREASURYBOT']);
  assert.deepEqual(d.grants.map((x) => x._id), ['grt_TB_USDC']);
  assert.equal(d.transactions.length, 30);
  assert.deepEqual(d.security_memories.map((x) => x._id).sort(), ['mem_INV-0977', 'mem_INV-1042', 'mem_INV-1101']);
  assert.ok(d.sanctions.length >= 45 && d.sanctions.length <= 55);
  assert.deepEqual(d.sanctions_updates.map((x) => x._id), ['upd_2026-09-26']);
  assert.deepEqual(d.passports.map((x) => x._id), ['pp_TREASURYBOT']);
  assert.deepEqual(d.harness_versions.map((x) => x._id), [1]);
  for (const list of Object.values(d)) for (const doc of list) assert.equal(doc.demo, true, doc._id);
});

test('seed is deterministic for a given day', () => {
  const a = buildHackathonDocs({ now: NOW });
  const b = buildHackathonDocs({ now: new Date('2026-09-26T23:59:00Z') });
  assert.deepEqual(a, b);
});

test('principal, agent, delegation and passport are consistent', () => {
  const d = buildHackathonDocs({ now: NOW });
  const op = d.operators[0];
  assert.equal(op.status, 'verified');
  assert.equal(op.verification.method, 'fixture');
  const agent = d.agents[0];
  const key = treasuryBotKey('original');
  assert.equal(agent.operatorId, DEMO_IDS.principal);
  assert.equal(agent.publicKey, key.publicKey);
  assert.equal(agent.keyThumbprint, key.thumbprint);
  assert.notEqual(treasuryBotKey('rotated').thumbprint, key.thumbprint);
  assert.equal(agent.wallets.length, 1);
  assert.match(agent.wallets[0].address, EVM);
  assert.deepEqual(agent.signingKeyHistory.map((h) => [h.thumbprint, h.to]), [[key.thumbprint, null]]);

  const g = d.grants[0];
  assert.equal(g.agentId, agent._id);
  assert.equal(g.businessId, DEMO_IDS.business);
  assert.equal(g.operatorId, DEMO_IDS.principal);
  assert.deepEqual(g.actions, ['payments:create']);
  assert.equal(g.maxTxAmount, 25_000 * USDC);
  assert.equal(g.constraints.maxAmount, g.maxTxAmount);
  assert.equal(g.constraints.currency, 'USDC');
  assert.equal(g.dailyLimit, 100_000 * USDC);
  assert.equal(g.approvedWallet, agent.wallets[0].address);
  assert.equal(g.version, 1);
  assert.ok(g.expiresAt > NOW && g.validFrom < NOW);

  const p = d.passports[0];
  assert.equal(p.status, 'ACTIVE');
  assert.equal(p.agentId, agent._id);
  assert.equal(p.principalId, DEMO_IDS.principal);
  assert.equal(p.delegationId, g._id);
  assert.equal(p.delegationVersion, 1);
  assert.equal(p.wallet, agent.wallets[0].address);
  assert.equal(p.harnessVersion, 1);
  assert.equal(p.sanctionsDatasetVersion, '2026-09-01');
  assert.deepEqual(p.statusHistory.map((h) => h.status), ['ACTIVE']);
});

test('transactions: 30 settled USDC payments, median 2000, two known counterparties, original key', () => {
  const d = buildHackathonDocs({ now: NOW });
  const agent = d.agents[0];
  const amounts = d.transactions.map((t) => t.amount).sort((x, y) => x - y);
  assert.equal((amounts[14] + amounts[15]) / 2, 2000 * USDC);
  assert.ok(amounts[0] >= 800 * USDC && amounts.at(-1) <= 4200 * USDC);
  const cps = new Set(d.transactions.map((t) => t.counterparty.address));
  assert.equal(cps.size, 2);
  for (const t of d.transactions) {
    assert.equal(t.agentId, agent._id);
    assert.equal(t.wallet, agent.wallets[0].address);
    assert.equal(t.asset, 'USDC');
    assert.equal(t.status, 'settled');
    assert.equal(t.signingKeyThumbprint, agent.keyThumbprint);
    assert.ok(Number.isSafeInteger(t.amount));
    assert.match(t.counterparty.address, EVM);
    assert.ok(t.at < NOW && t.at > new Date(NOW - 31 * 86_400_000));
    for (const k of TRANSACTIONS_SCHEMA.required) assert.ok(k in t, `transactions.${k}`);
  }
});

test('sanctions: baseline has Lazarus with aliases and never lists TreasuryBot; staged update lists its counterparty', () => {
  const d = buildHackathonDocs({ now: NOW });
  const laz = byId(d.sanctions, 'sdn_LAZARUS');
  assert.equal(laz.name, 'Lazarus Group');
  assert.ok(laz.aliases.length >= 2);
  const listed = new Set();
  for (const s of d.sanctions) {
    assert.equal(s.datasetVersion, '2026-09-01');
    for (const k of SANCTIONS_SCHEMA.required) assert.ok(k in s, `sanctions.${k}`);
    for (const w of s.wallets) {
      assert.match(w.address, EVM);
      listed.add(w.address);
    }
  }
  const agentWallet = d.agents[0].wallets[0].address;
  const cps = [...new Set(d.transactions.map((t) => t.counterparty.address))];
  for (const a of [agentWallet, ...cps]) assert.ok(!listed.has(a), a);

  const upd = d.sanctions_updates[0];
  assert.equal(upd.status, 'staged');
  assert.equal(upd.appliedAt, null);
  assert.equal(upd.datasetVersion, '2026-09-26');
  const staged = upd.upserts.flatMap((u) => u.wallets.map((w) => w.address));
  assert.equal(staged.filter((a) => cps.includes(a)).length, 1);
  assert.ok(!staged.includes(agentWallet));
});

test('memories: precomputed fixture embeddings, VERIFIED takeover, irrelevant VERIFIED, UNVERIFIED look-alike', () => {
  // The seed never calls an embeddings provider, whatever EMBEDDINGS_MODE says.
  const saved = process.env.EMBEDDINGS_MODE;
  process.env.EMBEDDINGS_MODE = 'live';
  let d;
  try {
    d = buildHackathonDocs({ now: NOW });
  } finally {
    if (saved === undefined) delete process.env.EMBEDDINGS_MODE;
    else process.env.EMBEDDINGS_MODE = saved;
  }
  const fixture = loadFixture();
  for (const m of d.security_memories) {
    assert.equal(m.signalsText, signalsText(m.signals));
    assert.equal(m.embeddingTextSha256, textSha256(m.signalsText));
    assert.deepEqual(m.embedding, fixture.vectors[m.embeddingTextSha256].embedding);
    assert.equal(m.embedding.length, 1024);
    assert.equal(m.embeddingModel, fixture.model);
    for (const k of SECURITY_MEMORIES_SCHEMA.required) assert.ok(k in m && m[k] !== null, `security_memories.${k}`);
  }
  const takeover = byId(d.security_memories, 'mem_INV-1042');
  assert.equal(takeover.status, 'VERIFIED');
  assert.equal(takeover.outcome, 'CONFIRMED_ACCOUNT_TAKEOVER');
  assert.deepEqual([...takeover.signals].sort(), ['AMOUNT_ANOMALY', 'NEAR_CEILING', 'NEW_COUNTERPARTY', 'SIGNING_KEY_CHANGED']);
  assert.deepEqual(takeover.recommendedSteps, ['signing_key_history_check']);
  assert.equal(typeof takeover.verifiedBy, 'object');
  assert.ok(takeover.verifiedAt instanceof Date);

  const irrelevant = byId(d.security_memories, 'mem_INV-0977');
  assert.equal(irrelevant.status, 'VERIFIED');
  assert.equal(irrelevant.outcome, 'FALSE_POSITIVE');
  assert.deepEqual(irrelevant.signals, ['VELOCITY']);
  assert.notDeepEqual(irrelevant.embedding, takeover.embedding);

  const unverified = byId(d.security_memories, 'mem_INV-1101');
  assert.equal(unverified.status, 'UNVERIFIED');
  assert.equal(unverified.verifiedBy, null);
  assert.equal(unverified.outcome, null);
  assert.deepEqual(unverified.embedding, takeover.embedding);
});

test('memory fixtures reference fixtures/embeddings.json by sha256', () => {
  const dir = resolve(root, 'fixtures/memories');
  const files = readdirSync(dir).filter((f) => f.endsWith('.json'));
  assert.equal(files.length, 3);
  for (const f of files) {
    const m = JSON.parse(readFileSync(resolve(dir, f), 'utf8'));
    assert.equal(m.embeddingRef.file, 'fixtures/embeddings.json');
    assert.equal(m.embeddingRef.sha256, textSha256(signalsText(m.signals)));
  }
});

test('harness v1: valid policy, runtime invariants hash, canonical policy hash, single active version', () => {
  const [h] = buildHackathonDocs({ now: NOW }).harness_versions;
  assert.equal(h.version, 1);
  assert.equal(h.status, 'active');
  assert.equal(h.parentVersion, null);
  assert.deepEqual(validatePolicy(h.policy), []);
  assert.deepEqual(h.policy, structuredClone(HARNESS_V1_POLICY));
  assert.equal(h.invariantsHash, INVARIANTS_HASH);
  assert.equal(h.policyHash, sha256hex(canonicalJson(h.policy)));
  assert.equal(h.approvedBy.label, 'seed');
  for (const k of HARNESS_VERSIONS_SCHEMA.required) assert.ok(k in h, `harness_versions.${k}`);
  for (const k of Object.keys(h)) assert.ok(k in HARNESS_VERSIONS_SCHEMA.properties, `harness_versions has no property ${k}`);
  const p = buildHackathonDocs({ now: NOW }).passports[0];
  for (const k of PASSPORTS_SCHEMA.required) assert.ok(k in p, `passports.${k}`);
});

test('writes encode integers beyond int32 as int64 (validators require int|long)', () => {
  const d = buildHackathonDocs({ now: NOW });
  const t = toBsonIntegers(d.transactions.find((x) => x.amount > 2 ** 31));
  assert.equal(typeof t.amount, 'bigint');
  assert.ok(t.at instanceof Date);
  const g = toBsonIntegers(d.grants[0]);
  assert.equal(g.constraints.maxAmount, 25_000n * BigInt(USDC));
  const m = toBsonIntegers(d.security_memories[0]);
  assert.deepEqual(m.embedding, d.security_memories[0].embedding);
  assert.equal(toBsonIntegers(d.harness_versions[0])._id, 1);
});

// Recording double of the driver collection API used by seed/clear/count.
function recordingDb() {
  const cols = new Map();
  const matches = (doc, filter) =>
    Object.entries(filter).every(([k, v]) => {
      if (k === '$or') return v.some((f) => matches(doc, f));
      if (v && typeof v === 'object' && !Array.isArray(v) && '$in' in v) return v.$in.includes(doc[k]);
      return doc[k] === v;
    });
  const collection = (name) => {
    if (!cols.has(name)) cols.set(name, new Map());
    const m = cols.get(name);
    return {
      async bulkWrite(ops) {
        for (const { replaceOne } of ops) {
          assert.equal(replaceOne.upsert, true);
          assert.equal(replaceOne.filter._id, replaceOne.replacement._id);
          m.set(replaceOne.filter._id, structuredClone(replaceOne.replacement));
        }
      },
      async deleteMany(filter) {
        let deletedCount = 0;
        for (const [id, d] of m) {
          if (matches(d, filter)) {
            m.delete(id);
            deletedCount++;
          }
        }
        return { deletedCount };
      },
      async countDocuments(filter = {}) {
        return [...m.values()].filter((d) => matches(d, filter)).length;
      },
      async insertOne(d) {
        m.set(d._id, d);
      },
    };
  };
  return { collection };
}

test('reset twice gives identical counts; runtime state is removed; non-demo data is kept', async () => {
  const db = recordingDb();
  const reset = async () => {
    await clearHackathon(db);
    await seedHackathon(db, { now: NOW });
    return collectionCounts(db);
  };
  const first = await reset();
  assert.deepEqual(first, expectedCounts());

  // Simulate a demo run: runtime docs + an adapted harness + a demo API key + unrelated data.
  await db.collection('investigations').insertOne({ _id: 'inv_X', agentId: DEMO_IDS.agent });
  await db.collection('harness_events').insertOne({ _id: 'hev_X' });
  await db.collection('harness_versions').insertOne({ _id: 2, status: 'active' });
  await db.collection('receipts').insertOne({ _id: 'rcp_X' });
  await db.collection('watcher_state').insertOne({ _id: 'sanctions' });
  await db.collection('transactions').insertOne({ _id: 'txn_RUNTIME', agentId: DEMO_IDS.agent, source: 'pipeline' });
  await db.collection('security_memories').insertOne({ _id: 'mem_inv_X', agentId: DEMO_IDS.agent, status: 'UNVERIFIED' });
  await db.collection('sanctions').insertOne({ _id: 'sdn_MERIDIAN_OTC', datasetVersion: '2026-09-26' });
  await db.collection('api_keys').insertOne({ _id: 'key_DEMO', demo: true });
  await db.collection('api_keys').insertOne({ _id: 'key_REAL' });
  await db.collection('operators').insertOne({ _id: 'op_OTHER' });
  await db.collection('audit_events').insertOne({ _id: 'aud_1' });
  assert.notDeepEqual(await collectionCounts(db), first);

  const second = await reset();
  const third = await reset();
  assert.deepEqual(second, first);
  assert.deepEqual(third, first);
  assert.equal(await db.collection('api_keys').countDocuments({}), 1);
  assert.equal(await db.collection('operators').countDocuments({}), 2);
  assert.equal(await db.collection('audit_events').countDocuments({}), 1);
  assert.equal(await db.collection('sanctions').countDocuments({ _id: 'sdn_MERIDIAN_OTC' }), 0);
  assert.equal(await db.collection('harness_versions').countDocuments({ status: 'active' }), 1);
});

test('demo scripts never use the in-memory store', () => {
  for (const f of readdirSync(resolve(root, 'scripts')).filter((n) => /^demo.*\.js$/.test(n))) {
    assert.doesNotMatch(readFileSync(resolve(root, 'scripts', f), 'utf8'), /MemoryStore/, f);
  }
});

for (const script of ['scripts/demo.js', 'scripts/demo-reset.js', 'scripts/demo-seed.js']) {
  test(`${script} without MONGODB_URI exits 1 with "Atlas required"`, () => {
    const env = { ...process.env };
    delete env.MONGODB_URI;
    delete env.NODE_ENV;
    const r = spawnSync(process.execPath, [script], { cwd: root, env, encoding: 'utf8', timeout: 30_000 });
    assert.equal(r.status, 1, r.stderr);
    assert.match(r.stderr, /Atlas required/);
  });
}
