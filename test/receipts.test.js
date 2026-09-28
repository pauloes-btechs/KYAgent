// T15 compliance receipts: schema conformance, receiptHash = sha256(canonicalJson(receipt)),
// `receipt.issued` notarisation, GET /v1/investigations/{id}/receipt tenant scoping, and tamper
// detection (a tampered stored receipt fails its hash while the audit chain stays valid).
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { describe, test } from 'node:test';
import { canonicalJson } from '../src/crypto/canonical.js';
import { INVARIANTS_HASH } from '../src/harness/invariants.js';
import { POLICY_VERSION, buildReceipt, receiptHashOf, receiptIdFor, receiptService } from '../src/services/receipts.js';
import { auditService } from '../src/services/audit.js';
import { TRUST_RULES_VERSION } from '../src/services/trust.js';
import { MemoryStore } from '../src/store/memory.js';
import { createBusiness, createOperator, world } from './helpers.js';

const SCHEMA = JSON.parse(readFileSync(new URL('../docs/contracts/receipt.schema.json', import.meta.url), 'utf8'));

// Minimal JSON Schema (2020-12 subset used by receipt.schema.json) validator; returns error paths.
function validateSchema(schema, value, path = '', root = schema) {
  if (schema.$ref) {
    const def = schema.$ref.replace('#/$defs/', '');
    return validateSchema(root.$defs[def], value, path, root);
  }
  const errs = [];
  const typeOf = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : Number.isInteger(v) ? 'integer' : typeof v);
  if (schema.oneOf) {
    const ok = schema.oneOf.filter((s) => validateSchema(s, value, path, root).length === 0).length;
    if (ok !== 1) errs.push(`${path}: oneOf matched ${ok}`);
    return errs;
  }
  if ('const' in schema && value !== schema.const) errs.push(`${path}: const`);
  if (schema.enum && !schema.enum.includes(value)) errs.push(`${path}: enum (${JSON.stringify(value)})`);
  if (schema.type) {
    const types = [].concat(schema.type);
    const t = typeOf(value);
    if (!types.includes(t) && !(t === 'integer' && types.includes('number'))) {
      errs.push(`${path}: type ${t} not in ${types}`);
      return errs;
    }
  }
  if (typeof value === 'string') {
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) errs.push(`${path}: pattern`);
    if (schema.maxLength !== undefined && value.length > schema.maxLength) errs.push(`${path}: maxLength`);
    if (schema.format === 'date-time' && Number.isNaN(Date.parse(value))) errs.push(`${path}: date-time`);
  }
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) errs.push(`${path}: minimum`);
    if (schema.maximum !== undefined && value > schema.maximum) errs.push(`${path}: maximum`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) errs.push(`${path}: minItems`);
    if (schema.maxItems !== undefined && value.length > schema.maxItems) errs.push(`${path}: maxItems`);
    if (schema.uniqueItems && new Set(value.map((v) => JSON.stringify(v))).size !== value.length) errs.push(`${path}: uniqueItems`);
    if (schema.items) value.forEach((v, i) => errs.push(...validateSchema(schema.items, v, `${path}/${i}`, root)));
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const k of schema.required ?? []) if (!(k in value)) errs.push(`${path}/${k}: required`);
    for (const [k, v] of Object.entries(value)) {
      const sub = schema.properties?.[k];
      if (sub) errs.push(...validateSchema(sub, v, `${path}/${k}`, root));
      else if (schema.additionalProperties === false) errs.push(`${path}/${k}: additionalProperties`);
    }
  }
  return errs;
}

const WALLET = '0x' + 'a1'.repeat(20);
const COUNTERPARTY = '0x7a11000000000000000000000000000000c0ffee';
const DECIDED_AT = new Date('2026-09-26T12:00:01.000Z');

/** A fully-populated decided investigation document (shape written by investigations.create). */
function decidedInvestigation(over = {}) {
  const stage = (name, engine, status, result, evidence = []) => ({ name, engine, status, startedAt: DECIDED_AT, durationMs: 3, result, evidence });
  return {
    id: 'inv_01JRCPT000000000000000000A',
    trigger: 'api',
    triggerRef: null,
    agentId: 'agt_1',
    principalId: 'op_1',
    businessId: 'biz_1',
    delegationId: 'grt_1',
    delegationVersion: 2,
    action: 'payments:create',
    transaction: { asset: 'USDC', amount: 1_500_000_000, wallet: WALLET, counterparty: { address: COUNTERPARTY, name: 'Known Vendor' } },
    harnessVersion: 1,
    stages: [
      stage('identity', 'find+code', 'passed', { mode: 'signed', decision: 'ALLOW', reasonCode: 'ALLOWED', keyThumbprint: 'thumb_1' }, [
        { id: 'ev_identity', kind: 'identity', source: 'agents', ref: 'agt_1', summary: 'signature valid', data: { signature: 'valid', operatorStatus: 'verified' } },
      ]),
      stage('delegation', 'find+code', 'passed', {
        asset: 'USDC', maxTxAmount: 10_000_000_000, dailyLimit: 25_000_000_000, spent24h: 0,
        withinMax: true, withinDaily: true, walletApproved: true, assetPermitted: true,
      }, [{ id: 'ev_delegation', kind: 'delegation', source: 'grants', ref: 'grt_1', summary: 'within limits' }]),
      stage('sanctions', 'find+$search', 'passed', { datasetVersion: '2026-09-01', exactHits: [], fuzzyHits: [] }, [
        { id: 'ev_sanctions', kind: 'sanctions_exact', source: 'sanctions', ref: null, summary: 'no exact hit' },
      ]),
      stage('signals', 'aggregate', 'passed', { signals: [] }),
      stage('memory', '$vectorSearch', 'passed', {}, [{ id: 'ev_mem', kind: 'memory', source: 'security_memories', ref: 'mem_INV-0977', summary: 'irrelevant' }]),
    ],
    signals: ['NEW_COUNTERPARTY'],
    memory: {
      engine: '$vectorSearch',
      embeddingModel: 'voyage-3.5-lite',
      k: 3,
      minScorePpm: 800_000,
      hits: [{ memoryId: 'mem_INV-0977', status: 'VERIFIED', outcome: 'CLEAN', scorePpm: 612_345, usedAsPrecedent: false }],
    },
    decision: 'ALLOW',
    riskDecision: 'ALLOW',
    reasons: [{ code: 'CLEAR', riskDecision: 'ALLOW', stage: 'decision', message: 'dropped from receipt' }],
    status: 'DECIDED',
    passport: null,
    requestId: 'req_trace_1',
    createdAt: DECIDED_AT,
    decidedAt: DECIDED_AT,
    ...over,
  };
}

describe('buildReceipt', () => {
  test('validates against receipt.schema.json and carries every REQ-P1-3 field', () => {
    const inv = decidedInvestigation();
    const r = buildReceipt(inv, { issuedAt: inv.decidedAt });
    assert.deepEqual(validateSchema(SCHEMA, r), []);
    assert.equal(r.receiptId, receiptIdFor(inv.id));
    assert.equal(r.decision, 'ALLOW');
    assert.equal(r.riskDecision, 'ALLOW');
    assert.equal(r.agent.id, 'agt_1');
    assert.equal(r.principal.id, 'op_1');
    assert.equal(r.issuedAt, DECIDED_AT.toISOString());
    assert.equal(r.identity.decision, 'ALLOW');
    assert.equal(r.identity.verifiedSignature, true);
    assert.equal(r.delegation.checked, true);
    assert.equal(r.delegation.withinMax, true);
    assert.equal(r.sanctions.checked, true);
    assert.deepEqual(r.signals, ['NEW_COUNTERPARTY']);
    assert.deepEqual(r.memory.hits, [{ memoryId: 'mem_INV-0977', status: 'VERIFIED', outcome: 'CLEAN', scorePpm: 612_345, usedAsPrecedent: false }]);
    assert.equal(r.sanctionsDatasetVersion, '2026-09-01');
    assert.equal(r.policyVersion, `${TRUST_RULES_VERSION}+inv:${INVARIANTS_HASH}`);
    assert.equal(r.policyVersion, POLICY_VERSION);
    assert.equal(r.invariantsHash, INVARIANTS_HASH);
    assert.equal(r.harnessVersion, 1);
    assert.equal(r.delegationVersion, 2);
    assert.equal(r.traceId, 'req_trace_1');
    assert.deepEqual(r.evidence.map((e) => e.id), ['ev_identity', 'ev_delegation', 'ev_sanctions', 'ev_mem']);
    // Stage evidence `data` (raw internals) never leaks into the receipt.
    assert.equal(JSON.stringify(r).includes('operatorStatus'), false);
    assert.equal(JSON.stringify(r).includes('dropped from receipt'), false);
  });

  test('receiptHash = sha256(canonicalJson(receipt without receiptHash/anchor)) and is deterministic', () => {
    const inv = decidedInvestigation();
    const r = buildReceipt(inv, { issuedAt: inv.decidedAt });
    const { receiptHash, ...body } = r;
    assert.equal(receiptHash, createHash('sha256').update(canonicalJson(body), 'utf8').digest('hex'));
    assert.equal(buildReceipt(inv, { issuedAt: inv.decidedAt }).receiptHash, receiptHash);
    assert.equal(receiptHashOf({ ...r, anchor: { auditEventId: 'x', auditSeq: 1, auditHash: 'f'.repeat(64) } }), receiptHash);
    assert.notEqual(receiptHashOf({ ...r, riskDecision: 'BLOCK' }), receiptHash);
  });

  test('an identity short-circuit (DENY / BLOCK, skipped stages) still yields a schema-valid receipt', () => {
    const inv = decidedInvestigation({
      decision: 'DENY',
      riskDecision: 'BLOCK',
      reasons: [{ code: 'IDENTITY_DENIED', riskDecision: 'BLOCK', stage: 'identity', identityReasonCode: 'SIGNATURE_INVALID' }],
      delegationId: null,
      delegationVersion: null,
      signals: [],
      memory: { engine: '$vectorSearch', k: 3, minScorePpm: 800_000, hits: [] },
      stages: [
        { name: 'identity', engine: 'find+code', status: 'failed', durationMs: 1, result: { mode: 'signed', decision: 'DENY', reasonCode: 'SIGNATURE_INVALID' }, evidence: [] },
        { name: 'delegation', engine: 'find+code', status: 'skipped', durationMs: 0, result: null, evidence: [] },
      ],
    });
    const r = buildReceipt(inv, { issuedAt: inv.decidedAt });
    assert.deepEqual(validateSchema(SCHEMA, r), []);
    assert.equal(r.delegation.checked, false);
    assert.equal(r.sanctionsDatasetVersion, null);
    assert.equal(r.identity.reasonCode, 'SIGNATURE_INVALID');
  });
});

describe('receiptService', () => {
  const clock = { now: () => DECIDED_AT };
  const system = { role: 'admin', apiKeyId: 'key_admin' };

  test('issue() notarises receiptHash in `receipt.issued`; tampering breaks the hash, verifyChain() stays valid', async () => {
    const store = new MemoryStore();
    const audit = auditService({ store, clock });
    const receipts = receiptService({ store, audit });
    const inv = decidedInvestigation();
    const issued = await receipts.issue(system, inv, { issuedAt: inv.decidedAt });
    assert.deepEqual(validateSchema(SCHEMA, issued), []);

    const [ev] = await store.auditEvents.range(issued.anchor.auditSeq, 1);
    assert.equal(ev.type, 'receipt.issued');
    assert.equal(ev.data.receiptHash, issued.receiptHash);
    assert.equal(ev.id, issued.anchor.auditEventId);
    assert.deepEqual(await receipts.verify(issued), { valid: true, hashMatches: true, anchorMatches: true, recomputedHash: issued.receiptHash });

    // Tamper with the stored copy: BLOCK rewritten as ALLOW would be the attacker's goal; here the reverse.
    const tampered = { ...issued, riskDecision: 'BLOCK' };
    const v1 = await receipts.verify(tampered);
    assert.equal(v1.valid, false);
    assert.equal(v1.hashMatches, false);
    assert.notEqual(v1.recomputedHash, issued.receiptHash);
    // Recomputing receiptHash after tampering is caught by the audit anchor.
    const rehashed = { ...tampered, receiptHash: receiptHashOf(tampered) };
    const v2 = await receipts.verify(rehashed);
    assert.equal(v2.hashMatches, true);
    assert.equal(v2.anchorMatches, false);
    assert.equal(v2.valid, false);
    // The audit log is untouched by receipt tampering.
    assert.equal((await audit.verifyChain()).valid, true);
  });

  test('issue() rejects (fail closed) and stores nothing when the audit write fails', async () => {
    const store = new MemoryStore();
    const audit = { record: async () => { throw new Error('audit down'); } };
    const receipts = receiptService({ store, audit });
    const inv = decidedInvestigation();
    await assert.rejects(receipts.issue(system, inv, { issuedAt: inv.decidedAt }), /audit down/);
    assert.equal(await store.receipts.findById(receiptIdFor(inv.id)), null);
  });
});

describe('GET /v1/investigations/{id}/receipt', () => {
  async function investigate(w) {
    const context = { amount: 1_500_000_000, currency: 'USDC', counterparty: COUNTERPARTY };
    const res = await w.t.call(w.business.key, 'POST', '/v1/investigations', w.signed({ context }), { headers: { 'x-request-id': 'req_receipt_trace' } });
    assert.ok(res.body?.id?.startsWith('inv_'), res.text);
    return res.body;
  }

  test('every decision gets a schema-valid, notarised receipt readable by its tenants only', async (t) => {
    const w = await world();
    t.after(() => w.t.close());
    const inv = await investigate(w);
    assert.ok(inv.receiptId, 'the investigation references its receipt');

    const res = await w.t.call(w.business.key, 'GET', `/v1/investigations/${inv.id}/receipt`);
    assert.equal(res.status, 200, res.text);
    assert.equal(res.headers.get('x-kya-receipt-integrity'), 'valid');
    const r = res.body;
    assert.deepEqual(validateSchema(SCHEMA, r), []);
    assert.equal(r.investigationId, inv.id);
    assert.equal(r.receiptHash, inv.receiptHash);
    assert.equal(r.riskDecision, inv.riskDecision);
    assert.equal(r.agent.id, w.agent.agent.id);
    assert.equal(r.principal.id, w.operator.op.id);
    assert.equal(r.businessId, w.business.biz.id);
    assert.equal(r.traceId, 'req_receipt_trace');
    assert.equal(r.policyVersion, POLICY_VERSION);
    assert.ok(r.anchor.auditSeq >= 1);

    // Notarised: the `receipt.issued` audit event carries the same receiptHash.
    const audits = (await w.t.call(w.t.admin, 'GET', `/v1/audit-events?type=receipt.issued&subjectId=${r.receiptId}`)).body.data;
    assert.equal(audits.length, 1);
    assert.equal(audits[0].data.receiptHash, r.receiptHash);

    // Operator of the agent and admin can read it; other tenants get 404 (no existence oracle).
    assert.equal((await w.t.call(w.operator.key, 'GET', `/v1/investigations/${inv.id}/receipt`)).status, 200);
    assert.equal((await w.t.call(w.t.admin, 'GET', `/v1/investigations/${inv.id}/receipt`)).status, 200);
    const otherBiz = await createBusiness(w.t, 'Initech');
    const otherOp = await createOperator(w.t, { legalName: 'Umbrella' });
    for (const key of [otherBiz.key, otherOp.key]) {
      const denied = await w.t.call(key, 'GET', `/v1/investigations/${inv.id}/receipt`);
      assert.equal(denied.status, 404);
      assert.equal(denied.body.error.code, 'NOT_FOUND');
    }
    assert.equal((await w.t.call(w.business.key, 'GET', '/v1/investigations/inv_01JZZZZZZZZZZZZZZZZZZZZZZZ/receipt')).status, 404);
    assert.equal((await w.t.call(null, 'GET', `/v1/investigations/${inv.id}/receipt`)).status, 401);
  });

  test('tampering with the stored receipt makes receiptHash mismatch while verifyChain() stays valid', async (t) => {
    const w = await world();
    t.after(() => w.t.close());
    const inv = await investigate(w);
    const stored = w.t.store.receipts._col.docs.get(inv.receiptId);
    assert.ok(stored);
    const flipped = stored.riskDecision === 'BLOCK' ? 'ALLOW' : 'BLOCK';
    stored.riskDecision = flipped;

    const res = await w.t.call(w.business.key, 'GET', `/v1/investigations/${inv.id}/receipt`);
    assert.equal(res.status, 200);
    assert.equal(res.body.riskDecision, flipped, 'the receipt is returned as stored, never silently repaired');
    assert.equal(res.headers.get('x-kya-receipt-integrity'), 'mismatch');
    assert.notEqual(receiptHashOf(res.body), res.body.receiptHash);

    const integrity = await w.t.call(w.t.admin, 'GET', '/v1/audit-events/integrity');
    assert.equal(integrity.status, 200);
    assert.equal(integrity.body.valid, true);
  });
});
