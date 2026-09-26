// T06: behavioral signals stage on the MemoryStore double (JS fallback engine), over the
// TreasuryBot seed history from src/seed/hackathon.js. The Atlas aggregation path is covered by
// test/atlas/signals.test.js.
import assert from 'node:assert/strict';
import { beforeEach, describe, test } from 'node:test';
import { SIGNALS_DEFAULTS, computeSignals, deriveSignals, percentileNearestRank } from '../src/investigation/signals.js';
import { USDC, buildHackathonDocs, treasuryBotKey } from '../src/seed/hackathon.js';
import { MemoryStore } from '../src/store/memory.js';

const NOW = new Date('2026-09-26T12:00:00Z');
const NEW_CP = '0x9e110000000000000000000000000000000dead1';
const fromDoc = ({ _id, ...rest }) => ({ id: _id, ...rest });

const docs = buildHackathonDocs({ now: NOW });
const seedAgent = fromDoc(docs.agents[0]);
const grant = fromDoc(docs.grants[0]);
const original = treasuryBotKey('original').thumbprint;
const rotated = treasuryBotKey('rotated').thumbprint;
const knownA = docs.transactions[0].counterparty;

/** TreasuryBot after the takeover key rotation (the attacker registered `rotated`). */
function rotatedAgent() {
  const at = new Date(NOW.getTime() - 2 * 3_600_000);
  return {
    ...seedAgent,
    keyThumbprint: rotated,
    signingKeyHistory: [
      { ...seedAgent.signingKeyHistory[0], to: at },
      { thumbprint: rotated, from: at, to: null },
    ],
  };
}

const payment = (over = {}) => ({
  id: 'txn_CANDIDATE',
  wallet: seedAgent.wallets[0].address,
  asset: 'USDC',
  amount: 24_000 * USDC,
  counterparty: { address: NEW_CP, name: 'Unknown recipient' },
  signingKeyThumbprint: rotated,
  delegationId: grant.id,
  ...over,
});

let store;
beforeEach(async () => {
  store = new MemoryStore();
  for (const t of docs.transactions) await store.transactions.insert(fromDoc(t));
});

describe('signals stage (MemoryStore, JS fallback)', () => {
  test('canonical takeover: 24 000 USDC to a new counterparty with a rotated key', async () => {
    const r = await computeSignals({ store, agent: rotatedAgent(), grant, tx: payment(), now: NOW });
    assert.equal(r.engine, 'js');
    assert.deepEqual(r.signals, ['NEW_COUNTERPARTY', 'SIGNING_KEY_CHANGED', 'AMOUNT_ANOMALY', 'NEAR_CEILING']);
    assert.deepEqual(new Set(r.signals), new Set(['NEW_COUNTERPARTY', 'SIGNING_KEY_CHANGED', 'AMOUNT_ANOMALY', 'NEAR_CEILING']));
    assert.equal(r.stats.txCount, 30);
    assert.equal(r.stats.p50, 2000 * USDC);
    assert.equal(r.stats.p95, 3950 * USDC);
    assert.equal(r.stats.velocity1h, 0);
    assert.equal(r.stats.knownCounterparty, false);
    assert.equal(r.stats.knownWallet, true);
    assert.deepEqual(r.stats.historicalThumbprints, [original]);
    assert.equal(r.stats.spent24h, 0);
    assert.equal(r.stats.dailyRemaining, 100_000 * USDC);
    assert.deepEqual(r.evidence.map((e) => e.id), r.signals.map((s) => `signal:${s}`));
    for (const e of r.evidence) {
      assert.equal(e.kind, 'signal');
      assert.equal(e.source, 'transactions');
      assert.equal(e.ref, 'txn_CANDIDATE');
    }
    const ceiling = r.evidence.find((e) => e.id === 'signal:NEAR_CEILING').data;
    assert.equal(ceiling.maxTxAmount, 25_000 * USDC);
    assert.equal(ceiling.nearMax, true);
  });

  test('a routine payment from the seed pattern yields no signals', async () => {
    const r = await computeSignals({
      store,
      agent: seedAgent,
      grant,
      tx: payment({ amount: 2100 * USDC, counterparty: knownA, signingKeyThumbprint: original }),
      now: NOW,
    });
    assert.deepEqual(r.signals, []);
    assert.deepEqual(r.evidence, []);
  });

  test('each signal fires on its own', async () => {
    const base = { amount: 2000 * USDC, counterparty: knownA, signingKeyThumbprint: original };
    const run = (tx, agent = seedAgent) => computeSignals({ store, agent, grant, tx: payment({ ...base, ...tx }), now: NOW });
    assert.deepEqual((await run({ wallet: '0x1111111111111111111111111111111111111111' })).signals, ['NEW_WALLET']);
    assert.deepEqual((await run({ counterparty: { address: NEW_CP } })).signals, ['NEW_COUNTERPARTY']);
    assert.deepEqual((await run({ signingKeyThumbprint: rotated }, rotatedAgent())).signals, ['SIGNING_KEY_CHANGED']);
    assert.deepEqual((await run({ amount: 5000 * USDC })).signals, ['AMOUNT_ANOMALY']);
    // A key that is not in agents.signingKeyHistory at all is a change even with no rotation record.
    assert.deepEqual((await run({ signingKeyThumbprint: rotated })).signals, ['SIGNING_KEY_CHANGED']);
  });

  test('AMOUNT_ANOMALY is strictly above p95; NEAR_CEILING is inclusive at 90 %', async () => {
    const base = { counterparty: knownA, signingKeyThumbprint: original };
    const run = (amount) => computeSignals({ store, agent: seedAgent, grant, tx: payment({ ...base, amount }), now: NOW });
    assert.deepEqual((await run(3950 * USDC)).signals, []);
    assert.deepEqual((await run(3950 * USDC + 1)).signals, ['AMOUNT_ANOMALY']);
    assert.deepEqual((await run(22_500 * USDC)).signals, ['AMOUNT_ANOMALY', 'NEAR_CEILING']);
    assert.deepEqual((await run(22_500 * USDC - 1)).signals, ['AMOUNT_ANOMALY']);
  });

  test('NEAR_CEILING on the remaining daily limit and VELOCITY on the last hour', async () => {
    const recent = (i, amount) => ({
      ...fromDoc(docs.transactions[29]),
      id: `txn_RECENT_${i}`,
      amount,
      at: new Date(NOW.getTime() - (i + 1) * 60_000),
    });
    for (let i = 0; i < 5; i += 1) await store.transactions.insert(recent(i, 16_000 * USDC));
    const r = await computeSignals({
      store,
      agent: seedAgent,
      grant,
      tx: payment({ amount: 2000 * USDC, counterparty: knownA, signingKeyThumbprint: original }),
      now: NOW,
    });
    assert.equal(r.stats.spent24h, 80_000 * USDC);
    assert.equal(r.stats.dailyRemaining, 20_000 * USDC);
    assert.equal(r.stats.velocity1h, 5);
    assert.deepEqual(r.signals, ['VELOCITY']);
    const big = await computeSignals({
      store,
      agent: seedAgent,
      grant,
      tx: payment({ amount: 18_000 * USDC, counterparty: knownA, signingKeyThumbprint: original }),
      now: NOW,
    });
    assert.ok(big.signals.includes('NEAR_CEILING'));
    const near = big.evidence.find((e) => e.id === 'signal:NEAR_CEILING').data;
    assert.equal(near.nearMax, false);
    assert.equal(near.nearDaily, true);
  });

  test('history excludes non-settled and future transactions', async () => {
    await store.transactions.insert({ ...fromDoc(docs.transactions[0]), id: 'txn_BLOCKED', status: 'blocked', counterparty: { address: NEW_CP, name: null } });
    await store.transactions.insert({ ...fromDoc(docs.transactions[0]), id: 'txn_FUTURE', at: new Date(NOW.getTime() + 60_000), counterparty: { address: NEW_CP, name: null } });
    const r = await computeSignals({ store, agent: rotatedAgent(), grant, tx: payment(), now: NOW });
    assert.equal(r.stats.txCount, 30);
    assert.equal(r.stats.knownCounterparty, false);
  });

  test('no history: no AMOUNT_ANOMALY baseline, wallet and counterparty are new', async () => {
    const empty = new MemoryStore();
    const r = await computeSignals({
      store: empty,
      agent: seedAgent,
      grant,
      tx: payment({ amount: 1000 * USDC, signingKeyThumbprint: original }),
      now: NOW,
    });
    assert.equal(r.stats.txCount, 0);
    assert.equal(r.stats.p95, null);
    assert.deepEqual(r.signals, ['NEW_WALLET', 'NEW_COUNTERPARTY']);
  });

  test('input validation fails closed', async () => {
    await assert.rejects(computeSignals({ store, agent: seedAgent, grant, tx: payment({ amount: 1.5 }), now: NOW }), TypeError);
    await assert.rejects(computeSignals({ store, agent: seedAgent, grant, tx: payment({ counterparty: null }), now: NOW }), TypeError);
    await assert.rejects(computeSignals({ store, agent: null, grant, tx: payment(), now: NOW }), TypeError);
    assert.throws(() => deriveSignals({ agent: seedAgent, grant, tx: {}, stats: {}, opts: SIGNALS_DEFAULTS }), TypeError);
  });

  test('percentileNearestRank', () => {
    assert.equal(percentileNearestRank([], 0.5), null);
    assert.equal(percentileNearestRank([3, 1, 2], 0.5), 2);
    assert.equal(percentileNearestRank([1, 2, 3, 4], 0.95), 4);
    assert.equal(percentileNearestRank([5], 0.95), 5);
  });
});
