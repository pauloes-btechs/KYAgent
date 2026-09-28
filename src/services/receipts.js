// Compliance receipts (docs/contracts/receipt.schema.json, investigation-pipeline.md §6).
// One receipt per investigation, built only from the decided investigation document (never from
// unsigned request fields). receiptHash = sha256hex(canonicalJson(receipt without receiptHash and
// anchor)); the hash is notarised by an `audit_events` entry of type `receipt.issued` whose data
// carries it, and that entry is recorded as the receipt's `anchor`.
//
// Order (fail closed): build -> audit `receipt.issued` -> insert into `receipts`. A failure of
// either write rejects; the caller records the investigation BLOCK / INTERNAL_ERROR.
import { canonicalJson } from '../crypto/canonical.js';
import { sha256hex } from '../crypto/ed25519.js';
import { INVARIANTS_HASH } from '../harness/invariants.js';
import { TRUST_RULES_VERSION } from './trust.js';

export const RECEIPT_VERSION = 'kya-receipt-v1';
export const POLICY_VERSION = `${TRUST_RULES_VERSION}+inv:${INVARIANTS_HASH}`;

/** Deterministic receipt id for an investigation (one receipt per investigation). */
export const receiptIdFor = (investigationId) => `rcp_${String(investigationId).replace(/^inv_/, '')}`;

const iso = (v) => (v instanceof Date ? v.toISOString() : v ?? null);
const stage = (inv, name) => (inv.stages ?? []).find((s) => s.name === name) ?? null;
const checked = (s) => Boolean(s) && s.status !== 'skipped' && s.status !== 'error' && !s.result?.notApplicable;
const boolOrNull = (v) => (typeof v === 'boolean' ? v : null);
const intOrNull = (v) => (Number.isSafeInteger(v) ? v : null);
const cut = (s, n) => (typeof s === 'string' && s.length > n ? s.slice(0, n) : s);
const pick = (o, keys) => Object.fromEntries(keys.filter((k) => o[k] !== undefined).map((k) => [k, o[k]]));

/** receiptHash over the receipt body (excluding `receiptHash` and `anchor`). */
export function receiptHashOf(receipt) {
  const { receiptHash: _h, anchor: _a, ...body } = receipt;
  return sha256hex(Buffer.from(canonicalJson(body), 'utf8'));
}

/** Build the receipt (with receiptHash, without anchor) for a decided investigation document. */
export function buildReceipt(inv, { issuedAt }) {
  const identity = stage(inv, 'identity');
  const delegation = stage(inv, 'delegation');
  const sanctions = stage(inv, 'sanctions');
  const memoryStage = stage(inv, 'memory');
  const idEvidence = identity?.evidence?.[0]?.data ?? {};
  const d = delegation?.result ?? {};
  const s = sanctions?.result ?? {};
  const tx = inv.transaction;
  const txOk = tx && typeof tx.wallet === 'string' && typeof tx.counterparty?.address === 'string';

  const receipt = {
    receiptVersion: RECEIPT_VERSION,
    receiptId: receiptIdFor(inv.id),
    investigationId: inv.id,
    trigger: inv.trigger,
    issuedAt: iso(issuedAt),
    traceId: inv.requestId ?? inv.triggerRef?.changeEventId ?? null,
    decision: inv.decision,
    riskDecision: inv.riskDecision,
    reasons: (inv.reasons ?? []).map((r) => pick(r, ['code', 'riskDecision', 'stage', 'invariantId', 'identityReasonCode', 'evidenceRefs'])),
    agent: { id: inv.agentId, keyThumbprint: identity?.result?.keyThumbprint ?? null, wallet: tx?.wallet ?? null },
    principal: { id: inv.principalId ?? null, status: idEvidence.operatorStatus ?? null },
    businessId: inv.businessId ?? null,
    delegation: {
      id: inv.delegationId ?? null,
      version: intOrNull(inv.delegationVersion),
      checked: checked(delegation),
      asset: d.asset ?? null,
      maxTxAmount: intOrNull(d.maxTxAmount),
      dailyLimit: intOrNull(d.dailyLimit),
      spent24h: intOrNull(d.spent24h),
      withinMax: boolOrNull(d.withinMax),
      withinDaily: boolOrNull(d.withinDaily),
      walletApproved: boolOrNull(d.walletApproved),
      assetPermitted: boolOrNull(d.assetPermitted),
    },
    transaction: txOk
      ? { asset: tx.asset, amount: intOrNull(tx.amount), wallet: tx.wallet, counterparty: { address: tx.counterparty.address, name: tx.counterparty.name ?? null } }
      : null,
    identity: {
      mode: identity?.result?.mode ?? (inv.trigger === 'api' ? 'signed' : 'state'),
      decision: identity?.result?.decision ?? 'DENY',
      reasonCode: identity?.result?.reasonCode ?? 'INTERNAL_ERROR',
      verifiedSignature: idEvidence.signature === 'valid',
    },
    sanctions: {
      checked: checked(sanctions) || Array.isArray(s.exactHits),
      datasetVersion: s.datasetVersion ?? null,
      exactHits: (s.exactHits ?? []).map((h) => pick(h, ['sanctionsId', 'address', 'name', 'programs'])),
      fuzzyHits: (s.fuzzyHits ?? []).slice(0, 10).map((h) => pick(h, ['sanctionsId', 'name', 'matched', 'scorePpm'])),
    },
    signals: [...(inv.signals ?? [])],
    memory: {
      checked: checked(memoryStage),
      engine: '$vectorSearch',
      embeddingModel: inv.memory?.embeddingModel ?? null,
      k: inv.memory?.k ?? 0,
      minScorePpm: inv.memory?.minScorePpm ?? 0,
      hits: (inv.memory?.hits ?? []).map((h) => ({ memoryId: h.memoryId, status: h.status, outcome: h.outcome, scorePpm: h.scorePpm, usedAsPrecedent: Boolean(h.usedAsPrecedent) })),
    },
    stages: (inv.stages ?? []).map((x) => ({ name: x.name, engine: x.engine, status: x.status, durationMs: x.durationMs })),
    sanctionsDatasetVersion: s.datasetVersion ?? null,
    policyVersion: POLICY_VERSION,
    invariantsHash: INVARIANTS_HASH,
    harnessVersion: inv.harnessVersion,
    delegationVersion: intOrNull(inv.delegationVersion),
    passport: inv.passport ? { id: inv.passport.id, before: inv.passport.before ?? inv.passport.fromStatus, after: inv.passport.after ?? inv.passport.toStatus } : null,
    evidence: (inv.stages ?? []).flatMap((x) => x.evidence ?? []).map((e) => ({ id: cut(e.id, 200), kind: e.kind, source: cut(e.source, 100), ref: e.ref == null ? null : cut(String(e.ref), 200), summary: cut(e.summary, 500) })),
  };
  receipt.receiptHash = receiptHashOf(receipt);
  return receipt;
}

export function receiptService({ store, audit }) {
  return {
    /**
     * Issue the receipt for a decided investigation: audit `receipt.issued` (the notarisation),
     * then persist it in `receipts`. Returns the receipt with its `anchor`. Rejects on failure.
     */
    async issue(principal, inv, { issuedAt }) {
      const receipt = buildReceipt(inv, { issuedAt });
      const ev = await audit.record(principal, 'receipt.issued', { type: 'receipt', id: receipt.receiptId }, {
        receiptId: receipt.receiptId,
        investigationId: inv.id,
        receiptHash: receipt.receiptHash,
      });
      const anchored = { ...receipt, anchor: { auditEventId: ev.id, auditSeq: ev.seq, auditHash: ev.hash } };
      // Stored exactly as hashed (issuedAt stays the ISO string) so receiptHash can be recomputed.
      await store.receipts.insert({ id: receipt.receiptId, ...anchored, agentId: inv.agentId });
      return anchored;
    },
  };
}
