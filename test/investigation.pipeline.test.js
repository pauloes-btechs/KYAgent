// T07 skeleton pipeline on the MemoryStore double. There is no in-memory $vectorSearch, so the
// memory stage must fail closed (BLOCK INTERNAL_ERROR); the Atlas path is covered by
// test/atlas/memory.vector.test.js.
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { runInvestigation } from '../src/investigation/pipeline.js';
import { retrieveMemories, vectorSearchPipeline } from '../src/memory/retrieve.js';
import { USDC, buildHackathonDocs } from '../src/seed/hackathon.js';
import { AtlasRequiredError, MemoryStore } from '../src/store/memory.js';

const NOW = new Date('2026-09-26T12:00:00Z');
const fromDoc = ({ _id, ...rest }) => ({ id: _id, ...rest });
const docs = buildHackathonDocs({ now: NOW });

async function world() {
  const store = new MemoryStore();
  await store.operators.insert(fromDoc(docs.operators[0]));
  await store.agents.insert(fromDoc(docs.agents[0]));
  await store.grants.insert(fromDoc(docs.grants[0]));
  for (const t of docs.transactions) await store.transactions.insert(fromDoc(t));
  return store;
}

const tx = (over = {}) => ({
  asset: 'USDC',
  amount: 2_000 * USDC,
  counterparty: { address: '0x7a11000000000000000000000000000000c0ffee' },
  signingKeyThumbprint: docs.agents[0].keyThumbprint,
  ...over,
});

describe('memory retrieval / skeleton pipeline without Atlas', () => {
  test('retrieveMemories requires a driver Db (no in-memory emulation)', async () => {
    await assert.rejects(retrieveMemories({ db: null, signals: ['VELOCITY'] }), AtlasRequiredError);
  });

  test('the $vectorSearch stage filters VERIFIED and projects vectorSearchScore', () => {
    const [vs, proj] = vectorSearchPipeline([0.1], { k: 3, numCandidates: 100 });
    assert.deepEqual(vs.$vectorSearch, { index: 'memory_vector', path: 'embedding', queryVector: [0.1], numCandidates: 100, limit: 3, filter: { status: 'VERIFIED' } });
    assert.deepEqual(proj.$project.score, { $meta: 'vectorSearchScore' });
  });

  test('memory stage fails closed on MemoryStore: BLOCK INTERNAL_ERROR', async () => {
    const store = await world();
    const r = await runInvestigation({ store, agentId: 'agt_TREASURYBOT', delegationId: 'grt_TB_USDC', tx: tx(), now: NOW });
    assert.deepEqual(r.stages.map((s) => [s.name, s.status]), [
      ['identity', 'passed'],
      ['delegation', 'passed'],
      ['signals', r.signals.length ? 'flagged' : 'passed'],
      ['memory', 'error'],
      ['decision', 'failed'],
    ]);
    assert.equal(r.stages[3].engine, '$vectorSearch');
    assert.equal(r.riskDecision, 'BLOCK');
    assert.equal(r.reasons[0].code, 'INTERNAL_ERROR');
  });

  test('unknown agent short-circuits to BLOCK IDENTITY_DENIED', async () => {
    const store = await world();
    const r = await runInvestigation({ store, agentId: 'agt_NOPE', delegationId: 'grt_TB_USDC', tx: tx(), now: NOW });
    assert.deepEqual(r.stages.slice(1, 4).map((s) => s.status), ['skipped', 'skipped', 'skipped']);
    assert.equal(r.riskDecision, 'BLOCK');
    assert.equal(r.reasons[0].code, 'IDENTITY_DENIED');
    assert.equal(r.reasons[0].identityReasonCode, 'AGENT_NOT_FOUND');
  });

  test('over the delegation maximum records INV_DELEGATION_MAX (memory still fails closed)', async () => {
    const store = await world();
    const r = await runInvestigation({ store, agentId: 'agt_TREASURYBOT', delegationId: 'grt_TB_USDC', tx: tx({ amount: 30_000 * USDC }), now: NOW });
    assert.equal(r.stages[1].status, 'failed');
    assert.ok(r.reasons.some((x) => x.code === 'DELEGATION_MAX_EXCEEDED' && x.invariantId === 'INV_DELEGATION_MAX'));
    assert.equal(r.riskDecision, 'BLOCK');
  });
});
