// T06 Atlas acceptance: the signals stage runs its real `transactions` aggregation
// ($group + $percentile, velocity window, first-seen) through MongoStore on the hackathon seed
// history (src/seed/hackathon.js), and the canonical takeover payment yields exactly
// {NEW_COUNTERPARTY, SIGNING_KEY_CHANGED, AMOUNT_ANOMALY, NEAR_CEILING}.
// Runs only when ATLAS_TEST_URI is set; uses a unique per-run database that is dropped afterwards.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, before, describe, test } from 'node:test';
import { computeSignals, historyStatsJs } from '../../src/investigation/signals.js';
import { USDC, seedHackathon, toBsonIntegers, treasuryBotKey } from '../../src/seed/hackathon.js';

const uri = process.env.ATLAS_TEST_URI;
const skip = uri ? false : 'ATLAS_TEST_URI not set';
const NEW_CP = '0x9e110000000000000000000000000000000dead1';
const CANONICAL = ['NEW_COUNTERPARTY', 'SIGNING_KEY_CHANGED', 'AMOUNT_ANOMALY', 'NEAR_CEILING'];

describe('atlas: behavioral signals stage on the seed history', { skip, timeout: 120_000 }, () => {
  let store;
  let agent;
  let grant;
  let knownCp;
  const now = new Date();
  const original = treasuryBotKey('original').thumbprint;
  const rotated = treasuryBotKey('rotated').thumbprint;

  const payment = (over = {}) => ({
    id: 'txn_CANDIDATE',
    wallet: agent.wallets[0].address,
    asset: 'USDC',
    amount: 24_000 * USDC,
    counterparty: { address: NEW_CP, name: 'Unknown recipient' },
    signingKeyThumbprint: rotated,
    delegationId: grant.id,
    ...over,
  });
  const takenOver = () => {
    const at = new Date(now.getTime() - 2 * 3_600_000);
    return {
      ...agent,
      keyThumbprint: rotated,
      signingKeyHistory: [{ ...agent.signingKeyHistory[0], to: at }, { thumbprint: rotated, from: at, to: null }],
    };
  };

  before(async () => {
    const { MongoStore } = await import('../../src/store/mongo.js');
    store = new MongoStore(uri, `kyagent_t06_${Date.now()}_${randomBytes(3).toString('hex')}`);
    await store.init(); // applies migrations (validators + transactions indexes)
    await seedHackathon(store.db, { now });
    agent = await store.agents.findById('agt_TREASURYBOT');
    grant = await store.grants.findById('grt_TB_USDC');
    knownCp = (await store.transactions.find({ agentId: agent.id }, { limit: 1 }))[0].counterparty;
  });

  after(async () => {
    if (store?.db) await store.db.dropDatabase().catch(() => {});
    if (store) await store.close();
  });

  test('canonical takeover payment yields exactly the four signals via the aggregation', async () => {
    const r = await computeSignals({ store, agent: takenOver(), grant, tx: payment(), now });
    assert.equal(r.engine, 'aggregate');
    assert.deepEqual(r.signals, CANONICAL);
    assert.equal(r.stats.txCount, 30);
    assert.equal(r.stats.knownWallet, true);
    assert.equal(r.stats.knownCounterparty, false);
    assert.equal(r.stats.velocity1h, 0);
    assert.deepEqual(r.stats.historicalThumbprints, [original]);
    // $percentile over the seed amounts (800–4200 USDC, median 2000 USDC).
    assert.ok(Number.isSafeInteger(r.stats.p50) && Number.isSafeInteger(r.stats.p95));
    assert.ok(r.stats.p50 >= 1900 * USDC && r.stats.p50 <= 2100 * USDC, `p50=${r.stats.p50}`);
    assert.ok(r.stats.p95 >= 3400 * USDC && r.stats.p95 <= 4200 * USDC, `p95=${r.stats.p95}`);
    assert.deepEqual(r.evidence.map((e) => e.id), CANONICAL.map((s) => `signal:${s}`));
  });

  test('aggregation and JS fallback agree on the signal set for the same history', async () => {
    const cases = [
      [takenOver(), payment()],
      [agent, payment({ amount: 2100 * USDC, counterparty: knownCp, signingKeyThumbprint: original })],
      [agent, payment({ amount: 9000 * USDC, counterparty: knownCp, signingKeyThumbprint: original })],
      [agent, payment({ amount: 23_000 * USDC, counterparty: { address: NEW_CP }, signingKeyThumbprint: original })],
    ];
    for (const [a, tx] of cases) {
      const atlas = await computeSignals({ store, agent: a, grant, tx, now });
      const js = await computeSignals({ store: { db: null, transactions: store.transactions }, agent: a, grant, tx, now });
      assert.equal(js.engine, 'js');
      assert.deepEqual(atlas.signals, js.signals);
      for (const k of ['txCount', 'velocity1h', 'knownCounterparty', 'knownWallet', 'historicalThumbprints', 'spent24h']) {
        assert.deepEqual(atlas.stats[k], js.stats[k], k);
      }
    }
    const direct = await historyStatsJs(store.transactions, {
      agentId: agent.id,
      candidate: { counterparty: NEW_CP, wallet: agent.wallets[0].address, delegationId: grant.id },
      now,
    });
    assert.equal(direct.txCount, 30);
  });

  test('routine seed-pattern payment yields no signals', async () => {
    const r = await computeSignals({
      store,
      agent,
      grant,
      tx: payment({ amount: 2000 * USDC, counterparty: knownCp, signingKeyThumbprint: original }),
      now,
    });
    assert.deepEqual(r.signals, []);
  });

  test('non-settled history does not make a counterparty known', async () => {
    const col = store.db.collection('transactions');
    await col.insertOne(
      toBsonIntegers({
        _id: 'txn_T06_BLOCKED',
        agentId: agent.id,
        principalId: agent.operatorId,
        delegationId: grant.id,
        wallet: agent.wallets[0].address,
        asset: 'USDC',
        amount: 24_000 * USDC,
        counterparty: { address: NEW_CP, name: null },
        signingKeyThumbprint: rotated,
        status: 'blocked',
        investigationId: null,
        at: new Date(now.getTime() - 60_000),
        source: 'pipeline',
      }),
    );
    try {
      const r = await computeSignals({ store, agent: takenOver(), grant, tx: payment(), now });
      assert.deepEqual(r.signals, CANONICAL);
      assert.equal(r.stats.txCount, 30);
    } finally {
      await col.deleteOne({ _id: 'txn_T06_BLOCKED' });
    }
  });
});
