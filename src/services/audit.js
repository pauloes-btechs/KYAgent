// Append-only, hash-chained audit log (REQ-008, data-schema.md `audit_events`).
// Every security-relevant state change (registration, issuance, verification,
// revocation, ...) appends one event. The store exposes no update/delete path;
// each event carries `prevHash` + `hash` so any later edit, deletion or
// reordering of stored events is detectable by `verifyChain()`.
//
// Events hold ids and non-secret metadata only: never API-key secrets or hashes,
// credential JWS, signatures, private keys or verification context values.
import { ID_PREFIX } from '../contracts.js';
import { canonicalJson } from '../crypto/canonical.js';
import { sha256hex } from '../crypto/ed25519.js';
import { ConflictError } from '../errors.js';
import { newId } from '../ids.js';
import { auditEventOut, pageOut } from './serialize.js';
import { pageQuery } from './util.js';

export const AUDIT_EVENT_TYPES = Object.freeze([
  'operator.created',
  'operator.verification_completed',
  'operator.suspended',
  'business.created',
  'api_key.created',
  'api_key.revoked',
  'agent.registered',
  'agent.suspended',
  'agent.reactivated',
  'agent.revoked',
  'grant.created',
  'grant.revoked',
  'credential.issued',
  'credential.revoked',
  'verification.decided',
  'passport.issued',
  'passport.status_changed',
  'investigation.decided',
]);

export const GENESIS_HASH = '0'.repeat(64);
const MAX_APPEND_ATTEMPTS = 5;
const SCAN_BATCH = 500;

/** Actor derived from the authenticated principal (never the raw API key). */
export function actorOf(principal) {
  if (!principal) return { role: 'system', apiKeyId: null, ownerId: null };
  return {
    role: principal.role,
    apiKeyId: principal.apiKeyId ?? null,
    ownerId: principal.operatorId ?? principal.businessId ?? null,
  };
}

/** The exact bytes that are hashed; `hash` itself is excluded. */
export function auditHash(e) {
  const payload = {
    v: 1,
    id: e.id,
    seq: e.seq,
    type: e.type,
    occurredAt: e.occurredAt.toISOString(),
    actor: e.actor,
    subjectType: e.subjectType,
    subjectId: e.subjectId,
    requestId: e.requestId,
    data: e.data,
    prevHash: e.prevHash,
  };
  return sha256hex(Buffer.from(canonicalJson(payload), 'utf8'));
}

/** Drop undefined values; Dates become ISO strings so data is canonical-JSON safe. */
function cleanData(data) {
  const out = {};
  for (const [k, v] of Object.entries(data ?? {})) {
    if (v === undefined) continue;
    out[k] = v instanceof Date ? v.toISOString() : v;
  }
  return out;
}

export function auditService({ store, clock }) {
  // Serializes appends within this process so the chain stays linear; the store's
  // unique `seq` constraint catches races with other processes (retried below).
  let queue = Promise.resolve();

  async function appendOnce(base) {
    const tail = await store.auditEvents.last();
    const event = {
      ...base,
      seq: tail ? tail.seq + 1 : 1,
      prevHash: tail ? tail.hash : GENESIS_HASH,
    };
    event.hash = auditHash(event);
    await store.auditEvents.append(event);
    return event;
  }

  async function append(base) {
    for (let attempt = 1; ; attempt++) {
      try {
        return await appendOnce(base);
      } catch (err) {
        if (!(err instanceof ConflictError) || attempt >= MAX_APPEND_ATTEMPTS) throw err;
      }
    }
  }

  /**
   * Append one event. Rejects if the event could not be persisted; callers must
   * treat that as a failure of the operation (fail closed), never ignore it.
   */
  function record(principal, type, subject, data) {
    if (!AUDIT_EVENT_TYPES.includes(type)) return Promise.reject(new Error(`unknown audit event type ${type}`));
    const base = {
      id: newId(ID_PREFIX.auditEvent),
      type,
      occurredAt: clock.now(),
      actor: actorOf(principal),
      subjectType: subject.type,
      subjectId: subject.id,
      requestId: principal?.requestId ?? null,
      data: cleanData(data),
    };
    const run = queue.then(() => append(base));
    queue = run.catch(() => {});
    return run;
  }

  return {
    record,

    /**
     * Record, and if the audit write fails run `compensate` (best effort) to undo
     * the effect of an unaudited grant of capability, then rethrow.
     */
    async recordOrCompensate(principal, type, subject, data, compensate) {
      try {
        return await record(principal, type, subject, data);
      } catch (err) {
        await Promise.resolve()
          .then(compensate)
          .catch(() => {});
        throw err;
      }
    },

    async list(principal, q) {
      const filter = { type: q.type, subjectId: q.subjectId };
      return pageOut(await store.auditEvents.list(pageQuery(q, filter)), auditEventOut);
    },

    /** Recompute the whole chain. Returns the first broken sequence number, if any. */
    async verifyChain() {
      let expectedSeq = 1;
      let prevHash = GENESIS_HASH;
      for (;;) {
        const batch = await store.auditEvents.range(expectedSeq, SCAN_BATCH);
        for (const e of batch) {
          if (e.seq !== expectedSeq || e.prevHash !== prevHash || auditHash(e) !== e.hash) {
            return { valid: false, count: expectedSeq - 1, headHash: prevHash, brokenAtSeq: expectedSeq };
          }
          prevHash = e.hash;
          expectedSeq++;
        }
        if (batch.length < SCAN_BATCH) break;
      }
      const tail = await store.auditEvents.last();
      if (tail && tail.seq !== expectedSeq - 1) {
        return { valid: false, count: expectedSeq - 1, headHash: prevHash, brokenAtSeq: expectedSeq };
      }
      return { valid: true, count: expectedSeq - 1, headHash: prevHash, brokenAtSeq: null };
    },
  };
}
