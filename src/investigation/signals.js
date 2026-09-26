// Behavioral signals stage (investigation-pipeline.md §4 stage 4). Reads the agent's settled
// `transactions` history and derives the closed signal set for one candidate payment:
//
//   NEW_WALLET           source wallet never seen in the agent's settled history
//   NEW_COUNTERPARTY     counterparty address never paid by the agent before
//   SIGNING_KEY_CHANGED  signing key did not sign the history / is not the agent's established key
//                        (agents.signingKeyHistory)
//   AMOUNT_ANOMALY       amount > p95 of the settled history
//   VELOCITY             too many settled payments in the last hour
//   NEAR_CEILING         amount >= 90 % of the delegation's maxTxAmount or of the remaining daily limit
//
// Engine: on MongoStore the history statistics come from ONE aggregation on `transactions`
// (`$group` + `$percentile` p50/p95, velocity window, first-seen counterparty and wallet, 24 h
// spend). `$percentile` needs MongoDB >= 7.0 (always true on Atlas); an older server makes the
// aggregation throw and the stage fails closed — there is no silent fallback to the JS path.
// MemoryStore (unit tests, no driver Db) uses the JS fallback over the repository double with
// the same definitions; percentiles there are exact nearest-rank.
import { SIGNALS } from '../memory/signalsText.js';

export const SIGNALS_DEFAULTS = Object.freeze({
  velocityWindowMs: 3_600_000, // 1 h
  velocityMaxPerWindow: 5, // VELOCITY when this many settled payments already happened in the window
  minHistoryForAnomaly: 5, // below this, p95 is not a meaningful baseline
  dailyWindowMs: 86_400_000,
});

const PERCENTILES = Object.freeze([0.5, 0.95]);

/** Exact nearest-rank percentile over numbers (JS fallback). */
export function percentileNearestRank(values, p) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.max(1, Math.ceil(p * sorted.length));
  return sorted[rank - 1];
}

const toInt = (v) => (v === null || v === undefined ? null : Math.round(Number(v)));

function candidateOf(tx) {
  if (!tx || typeof tx !== 'object') throw new TypeError('signals: tx is required');
  const amount = Number(tx.amount);
  if (!Number.isSafeInteger(amount) || amount <= 0) throw new TypeError('signals: tx.amount must be a positive integer (minor units)');
  const counterparty = tx.counterparty?.address;
  if (typeof counterparty !== 'string' || !counterparty) throw new TypeError('signals: tx.counterparty.address is required');
  if (typeof tx.wallet !== 'string' || !tx.wallet) throw new TypeError('signals: tx.wallet is required');
  if (typeof tx.signingKeyThumbprint !== 'string' || !tx.signingKeyThumbprint) {
    throw new TypeError('signals: tx.signingKeyThumbprint is required');
  }
  return { amount, counterparty, wallet: tx.wallet, thumbprint: tx.signingKeyThumbprint, delegationId: tx.delegationId ?? null };
}

/** History statistics through a single `transactions` aggregation (MongoStore / Atlas). */
export async function historyStatsAggregate(db, { agentId, candidate, now, opts = SIGNALS_DEFAULTS }) {
  const velocityFrom = new Date(now.getTime() - opts.velocityWindowMs);
  const dayFrom = new Date(now.getTime() - opts.dailyWindowMs);
  const firstSeen = [{ $group: { _id: null, n: { $sum: 1 }, firstSeen: { $min: '$at' } } }];
  const [row] = await db
    .collection('transactions')
    .aggregate([
      { $match: { agentId, status: 'settled', at: { $lte: now } } },
      {
        $facet: {
          amounts: [
            {
              $group: {
                _id: null,
                txCount: { $sum: 1 },
                pct: { $percentile: { input: '$amount', p: [...PERCENTILES], method: 'approximate' } },
                thumbprints: { $addToSet: '$signingKeyThumbprint' },
              },
            },
          ],
          velocity: [{ $match: { at: { $gt: velocityFrom } } }, { $count: 'n' }],
          counterparty: [{ $match: { 'counterparty.address': candidate.counterparty } }, ...firstSeen],
          wallet: [{ $match: { wallet: candidate.wallet } }, ...firstSeen],
          spent24h: [
            { $match: { delegationId: candidate.delegationId, at: { $gt: dayFrom } } },
            { $group: { _id: null, total: { $sum: '$amount' } } },
          ],
        },
      },
    ])
    .toArray();
  const a = row?.amounts?.[0];
  return {
    txCount: a?.txCount ?? 0,
    p50: toInt(a?.pct?.[0]),
    p95: toInt(a?.pct?.[1]),
    velocity1h: row?.velocity?.[0]?.n ?? 0,
    knownCounterparty: (row?.counterparty?.[0]?.n ?? 0) > 0,
    counterpartyFirstSeen: row?.counterparty?.[0]?.firstSeen ?? null,
    knownWallet: (row?.wallet?.[0]?.n ?? 0) > 0,
    walletFirstSeen: row?.wallet?.[0]?.firstSeen ?? null,
    historicalThumbprints: [...(a?.thumbprints ?? [])].sort(),
    spent24h: candidate.delegationId ? Number(row?.spent24h?.[0]?.total ?? 0) : 0,
  };
}

/** The same statistics computed in JS over a repository `find` (MemoryStore double). */
export async function historyStatsJs(transactions, { agentId, candidate, now, opts = SIGNALS_DEFAULTS }) {
  const all = await transactions.find({ agentId }, { limit: 100_000 });
  const t = now.getTime();
  const history = all.filter((d) => d.status === 'settled' && d.at instanceof Date && d.at.getTime() <= t);
  const amounts = history.map((d) => Number(d.amount));
  const firstSeen = (list) => (list.length ? new Date(Math.min(...list.map((d) => d.at.getTime()))) : null);
  const cp = history.filter((d) => d.counterparty?.address === candidate.counterparty);
  const wl = history.filter((d) => d.wallet === candidate.wallet);
  const spent = candidate.delegationId
    ? history
        .filter((d) => d.delegationId === candidate.delegationId && d.at.getTime() > t - opts.dailyWindowMs)
        .reduce((s, d) => s + Number(d.amount), 0)
    : 0;
  return {
    txCount: history.length,
    p50: percentileNearestRank(amounts, PERCENTILES[0]),
    p95: percentileNearestRank(amounts, PERCENTILES[1]),
    velocity1h: history.filter((d) => d.at.getTime() > t - opts.velocityWindowMs).length,
    knownCounterparty: cp.length > 0,
    counterpartyFirstSeen: firstSeen(cp),
    knownWallet: wl.length > 0,
    walletFirstSeen: firstSeen(wl),
    historicalThumbprints: [...new Set(history.map((d) => d.signingKeyThumbprint))].sort(),
    spent24h: spent,
  };
}

/** Delegation ceilings: `maxTxAmount` (falls back to constraints.maxAmount) and `dailyLimit`. */
function ceilingsOf(grant) {
  const maxTx = grant?.maxTxAmount ?? grant?.constraints?.maxAmount ?? null;
  const daily = grant?.dailyLimit ?? null;
  return { maxTxAmount: Number.isSafeInteger(maxTx) ? maxTx : null, dailyLimit: Number.isSafeInteger(daily) ? daily : null };
}

/** SIGNING_KEY_CHANGED against agents.signingKeyHistory and the keys that signed the history. */
function keyChange(agent, thumbprint, stats) {
  const history = Array.isArray(agent?.signingKeyHistory) ? agent.signingKeyHistory : [];
  const entry = history.find((h) => h.thumbprint === thumbprint) ?? null;
  const established = stats.txCount > 0 ? stats.historicalThumbprints : history.length ? [history[0].thumbprint] : [];
  const changed = !entry || !established.includes(thumbprint);
  return {
    changed,
    data: {
      thumbprint,
      registeredInHistory: Boolean(entry),
      keyFrom: entry?.from ? new Date(entry.from).toISOString() : null,
      establishedThumbprints: established,
      signingKeyHistoryLength: history.length,
    },
  };
}

/**
 * Pure decision over precomputed stats. Signals come back in the closed-set order (SIGNALS).
 * Every comparison is integer-exact (minor units; 0.9 × X compared as 10·amount >= 9·X).
 */
export function deriveSignals({ agent, grant, tx, stats, opts = SIGNALS_DEFAULTS }) {
  const c = candidateOf(tx);
  const { maxTxAmount, dailyLimit } = ceilingsOf(grant);
  const dailyRemaining = dailyLimit === null ? null : Math.max(0, dailyLimit - stats.spent24h);
  const key = keyChange(agent, c.thumbprint, stats);
  const hasBaseline = stats.txCount >= opts.minHistoryForAnomaly && stats.p95 !== null;
  const nearMax = maxTxAmount !== null && c.amount * 10 >= maxTxAmount * 9;
  const nearDaily = dailyRemaining !== null && c.amount * 10 >= dailyRemaining * 9;

  const fired = {
    NEW_WALLET: [!stats.knownWallet, `wallet ${c.wallet} not seen in ${stats.txCount} settled payments`, { wallet: c.wallet, txCount: stats.txCount }],
    NEW_COUNTERPARTY: [
      !stats.knownCounterparty,
      `counterparty ${c.counterparty} never paid before`,
      { counterparty: c.counterparty, txCount: stats.txCount },
    ],
    SIGNING_KEY_CHANGED: [key.changed, `signing key ${c.thumbprint} is not the agent's established key`, key.data],
    AMOUNT_ANOMALY: [
      hasBaseline && c.amount > stats.p95,
      `amount ${c.amount} > p95 ${stats.p95} of ${stats.txCount} settled payments`,
      { amount: c.amount, p50: stats.p50, p95: stats.p95, txCount: stats.txCount },
    ],
    VELOCITY: [
      stats.velocity1h >= opts.velocityMaxPerWindow,
      `${stats.velocity1h} settled payments in the last ${opts.velocityWindowMs / 60_000} min`,
      { velocity1h: stats.velocity1h, max: opts.velocityMaxPerWindow, windowMs: opts.velocityWindowMs },
    ],
    NEAR_CEILING: [
      nearMax || nearDaily,
      `amount ${c.amount} >= 90% of ${nearMax ? `maxTxAmount ${maxTxAmount}` : `daily remaining ${dailyRemaining}`}`,
      { amount: c.amount, maxTxAmount, dailyLimit, spent24h: stats.spent24h, dailyRemaining, nearMax, nearDaily },
    ],
  };

  const signals = SIGNALS.filter((s) => fired[s][0]);
  const evidence = signals.map((s) => ({
    id: `signal:${s}`,
    kind: 'signal',
    source: 'transactions',
    ref: tx.id ?? tx._id ?? null,
    summary: fired[s][1],
    data: fired[s][2],
  }));
  return { signals, evidence, dailyRemaining };
}

/**
 * Run the signals stage for one candidate payment.
 * `tx` = { wallet, amount, counterparty: { address }, signingKeyThumbprint, delegationId? }.
 * Returns `{ engine, signals, stats, evidence }` (stats per investigation-pipeline.md §4).
 */
export async function computeSignals({ store, agent, grant = null, tx, now = new Date(), opts = {} }) {
  if (!store) throw new TypeError('signals: store is required');
  if (!agent?.id && !agent?._id) throw new TypeError('signals: agent is required');
  const o = { ...SIGNALS_DEFAULTS, ...opts };
  const agentId = agent.id ?? agent._id;
  const candidate = candidateOf({ ...tx, delegationId: tx.delegationId ?? grant?.id ?? grant?._id ?? null });
  const db = store.db;
  const engine = db ? 'aggregate' : 'js';
  const stats = db
    ? await historyStatsAggregate(db, { agentId, candidate, now, opts: o })
    : await historyStatsJs(store.transactions, { agentId, candidate, now, opts: o });
  const { signals, evidence, dailyRemaining } = deriveSignals({
    agent,
    grant,
    tx: { ...tx, delegationId: candidate.delegationId },
    stats,
    opts: o,
  });
  return { engine, signals, stats: { ...stats, dailyRemaining }, evidence };
}
