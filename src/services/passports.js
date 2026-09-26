// Agent passports (docs/contracts/passport.md). This module is the only writer of the
// `passports` collection. Every status change is one conditional
// `updateIf({ _id, status: from }, { $set, $push: { statusHistory } })` plus an audit event.
//
// INV_NO_SELF_PASSPORT_MODIFICATION (harness.md §1): only the in-process `system` actor
// (pipeline / sanctions watcher) or an `admin` may transition a passport. `operator` and
// `business` principals — including the passport's own principal — get 403 FORBIDDEN.
// There is no default actor: callers must pass SYSTEM_ACTOR or an authenticated principal.
import { ApiError } from '../errors.js';
import { holds } from '../harness/invariants.js';
import { newId } from '../ids.js';
import { actorOf } from './audit.js';
import { forbidden, invalidState, notFound } from './util.js';

export const PASSPORT_ID_PREFIX = 'pp';
export const PASSPORT_STATUSES = Object.freeze(['ACTIVE', 'REVIEW', 'RE_SCREENING', 'SUSPENDED', 'REVOKED']);

/** The in-process system actor. No HTTP principal carries `role: 'system'`. */
export const SYSTEM_ACTOR = Object.freeze({ role: 'system' });

const SYS = Object.freeze(['system']);
const SYS_ADMIN = Object.freeze(['system', 'admin']);
const ADMIN = Object.freeze(['admin']);

/** passport.md §3: legal transitions and the actors allowed to perform them. Anything else is illegal. */
export const PASSPORT_TRANSITIONS = Object.freeze(
  [
    ['ACTIVE', 'REVIEW', SYS_ADMIN],
    ['REVIEW', 'ACTIVE', ADMIN],
    ['ACTIVE', 'RE_SCREENING', SYS],
    ['REVIEW', 'RE_SCREENING', SYS],
    ['RE_SCREENING', 'ACTIVE', SYS],
    ['RE_SCREENING', 'REVIEW', SYS],
    ['RE_SCREENING', 'SUSPENDED', SYS],
    ['ACTIVE', 'SUSPENDED', SYS_ADMIN],
    ['REVIEW', 'SUSPENDED', SYS_ADMIN],
    ['SUSPENDED', 'REVOKED', ADMIN],
    ['ACTIVE', 'REVOKED', SYS],
    ['REVIEW', 'REVOKED', SYS],
    ['RE_SCREENING', 'REVOKED', SYS],
  ].map(([from, to, actors]) => Object.freeze({ from, to, actors })),
);

const MAX_REASON = 500;

/** True when `from -> to` is a legal transition for `role`. */
export function isLegalTransition(from, to, role) {
  return PASSPORT_TRANSITIONS.some((t) => t.from === from && t.to === to && t.actors.includes(role));
}

/** Enforce INV_NO_SELF_PASSPORT_MODIFICATION; returns the normalized actor ref. */
function authorizedActor(principal) {
  if (!principal || typeof principal !== 'object') throw new TypeError('passport actor is required');
  const actor = actorOf(principal);
  if (!holds('INV_NO_SELF_PASSPORT_MODIFICATION', { actor })) throw forbidden();
  return actor;
}

function checkReason(reason) {
  if (typeof reason !== 'string' || reason.trim() === '' || reason.length > MAX_REASON) {
    throw new ApiError('VALIDATION_ERROR', 'A reason is required', [{ path: '/reason', message: `must be a non-empty string <= ${MAX_REASON} chars` }]);
  }
}

const iso = (d) => (d instanceof Date ? d.toISOString() : d ?? null);

export const passportOut = (p) => ({
  id: p.id,
  agentId: p.agentId,
  principalId: p.principalId,
  delegationId: p.delegationId,
  delegationVersion: p.delegationVersion,
  wallet: p.wallet,
  status: p.status,
  statusReason: p.statusReason ?? null,
  credentialId: p.credentialId ?? null,
  lastInvestigationId: p.lastInvestigationId ?? null,
  sanctionsDatasetVersion: p.sanctionsDatasetVersion,
  harnessVersion: p.harnessVersion,
  issuedAt: iso(p.issuedAt),
  expiresAt: iso(p.expiresAt),
  updatedAt: iso(p.updatedAt),
  statusHistory: (p.statusHistory ?? []).map((h) => ({
    status: h.status,
    at: iso(h.at),
    actor: h.actor ?? null,
    reason: h.reason ?? null,
    investigationId: h.investigationId ?? null,
  })),
});

/** Business view: public fields only (passport.md §4). */
export const passportPublicOut = (p) => ({
  agentId: p.agentId,
  principalId: p.principalId,
  status: p.status,
  harnessVersion: p.harnessVersion,
  sanctionsDatasetVersion: p.sanctionsDatasetVersion,
  updatedAt: iso(p.updatedAt),
});

export function passportService({ store, clock, audit }) {
  async function findByAgent(agentId) {
    if (typeof agentId !== 'string') return null;
    const [p] = await store.passports.find({ agentId }, { limit: 1 });
    return p ?? null;
  }

  return {
    findByAgent,

    /**
     * `— -> ACTIVE` (issuance). Actor: system or admin. The agent may hold at most one
     * passport (unique `agentId`).
     */
    async issue(principal, { id, agentId, principalId, delegationId, delegationVersion, wallet, sanctionsDatasetVersion, harnessVersion, expiresAt, credentialId = null, reason = 'issued' }) {
      const actor = authorizedActor(principal);
      checkReason(reason);
      if (await findByAgent(agentId)) throw invalidState('Agent already has a passport');
      const now = clock.now();
      const doc = {
        id: id ?? newId(PASSPORT_ID_PREFIX),
        agentId,
        principalId,
        delegationId,
        delegationVersion,
        wallet: typeof wallet === 'string' ? wallet.toLowerCase() : wallet,
        status: 'ACTIVE',
        statusReason: null,
        credentialId,
        lastInvestigationId: null,
        sanctionsDatasetVersion,
        harnessVersion,
        issuedAt: now,
        expiresAt,
        updatedAt: now,
        statusHistory: [{ status: 'ACTIVE', at: now, actor, reason, investigationId: null }],
      };
      await store.passports.insert(doc);
      await audit.record(principal, 'passport.issued', { type: 'passport', id: doc.id }, {
        agentId,
        principalId,
        delegationId,
        delegationVersion,
        status: 'ACTIVE',
      });
      return doc;
    },

    /**
     * Move passport `id` from one of `from` to `to`. Only pairs that are legal for the actor's
     * role are attempted; the write is conditional on the current status, so a concurrent
     * change makes this fail with 409 instead of overwriting it.
     */
    async transition(id, from, to, reason, principal, { investigationId = null } = {}) {
      const actor = authorizedActor(principal);
      checkReason(reason);
      if (!PASSPORT_STATUSES.includes(to)) throw invalidState(`Unknown passport status ${to}`);
      if (!Array.isArray(from) || from.length === 0) throw invalidState('No source status given');
      const legalFrom = from.filter((f) => isLegalTransition(f, to, actor.role));
      if (legalFrom.length === 0) throw invalidState(`Illegal passport transition to ${to}`);

      const now = clock.now();
      const patch = { status: to, statusReason: reason, updatedAt: now };
      if (investigationId) patch.lastInvestigationId = investigationId;
      const entry = { status: to, at: now, actor, reason, investigationId };
      const updated = await store.passports.updateIf(id, legalFrom, patch, { statusHistory: entry });
      if (!updated) {
        const current = await store.passports.findById(id);
        if (!current) throw notFound();
        throw invalidState(`Passport is ${current.status}`);
      }
      const history = updated.statusHistory ?? [];
      const fromStatus = history.length >= 2 ? history[history.length - 2].status : null;
      await audit.record(principal, 'passport.status_changed', { type: 'passport', id }, {
        agentId: updated.agentId,
        fromStatus,
        toStatus: to,
        reason,
        investigationId: investigationId ?? undefined,
      });
      return updated;
    },

    /** Record the latest credential carrying `kya_passport` (no status change, no history entry). */
    async linkCredential(id, credentialId) {
      return store.passports.updateIf(id, null, { credentialId, updatedAt: clock.now() });
    },

    /** Read by agent id: admin (all), operator (own agents), business (agents it delegates to; public view). */
    async get(principal, agentId) {
      const p = await findByAgent(agentId);
      if (!p) throw notFound();
      if (principal.role === 'admin') return passportOut(p);
      if (principal.role === 'operator') {
        if (p.principalId !== principal.operatorId) throw notFound();
        return passportOut(p);
      }
      if (principal.role === 'business') {
        const grants = await store.grants.list({ filter: { agentId: p.agentId, businessId: principal.businessId }, limit: 1 });
        if (!grants.data.length) throw notFound();
        return passportPublicOut(p);
      }
      throw notFound();
    },
  };
}
