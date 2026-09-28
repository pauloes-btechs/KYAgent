// Adaptive step registry (docs/contracts/harness.md §3.3). Closed: extending it is a code change
// plus ADAPTIVE_STEPS in src/harness/invariants.js. Adaptive steps add evidence only; they never
// return reasons, so they cannot set or weaken a decision.
const HOUR = 3_600_000;

const toDate = (v) => (v instanceof Date ? v : v ? new Date(v) : null);

/** settled transactions signed with `thumbprint`: one aggregation on Atlas, repository scan otherwise. */
async function settledWithKey(store, agentId, thumbprint) {
  if (!thumbprint) return 0;
  if (store.db) {
    const [row] = await store.db
      .collection('transactions')
      .aggregate([{ $match: { agentId, status: 'settled', signingKeyThumbprint: thumbprint } }, { $count: 'n' }])
      .toArray();
    return row?.n ?? 0;
  }
  return (await store.transactions.find({ agentId, status: 'settled', signingKeyThumbprint: thumbprint })).length;
}

async function signingKeyHistoryCheck({ store, agent, agentId, now }) {
  if (!agent) throw new Error('signing_key_history_check: agent not loaded');
  const history = (Array.isArray(agent.signingKeyHistory) ? agent.signingKeyHistory : [])
    .map((h) => ({ thumbprint: h.thumbprint, from: toDate(h.from), to: toDate(h.to) }))
    .sort((a, b) => (a.from?.getTime() ?? 0) - (b.from?.getTime() ?? 0));
  const currentThumbprint = agent.keyThumbprint ?? null;
  const currentIdx = history.map((h) => h.thumbprint).lastIndexOf(currentThumbprint);
  const previous = currentIdx > 0 ? history[currentIdx - 1] : null;
  const rotatedAt = previous ? history[currentIdx].from : null;
  const rotatedWithinHours = rotatedAt ? Math.max(0, Math.floor((now.getTime() - rotatedAt.getTime()) / HOUR)) : null;
  const settledTxWithCurrentKey = await settledWithKey(store, agentId, currentThumbprint);
  const result = {
    currentThumbprint,
    previousThumbprint: previous?.thumbprint ?? null,
    rotatedAt: rotatedAt ? rotatedAt.toISOString() : null,
    rotatedWithinHours,
    settledTxWithCurrentKey,
  };
  const unproven = Boolean(previous) && settledTxWithCurrentKey === 0;
  return {
    status: unproven ? 'flagged' : 'passed',
    result,
    evidence: [
      {
        id: `step:signing_key_history_check:${agentId}`,
        kind: 'step',
        source: 'agents.signingKeyHistory+transactions',
        ref: agentId,
        summary: previous
          ? `signing key rotated ${rotatedWithinHours} h ago; ${settledTxWithCurrentKey} settled payments signed with the current key`
          : `no key rotation on record; ${settledTxWithCurrentKey} settled payments signed with the current key`,
        data: result,
      },
    ],
    reasons: [],
  };
}

export const ADAPTIVE_STEP_RUNNERS = Object.freeze({
  signing_key_history_check: Object.freeze({ engine: 'find+aggregate', run: signingKeyHistoryCheck }),
});
