import { ID_PREFIX } from '../contracts.js';
import { validationError } from '../errors.js';
import { newId } from '../ids.js';
import { schemas } from '../validate.js';
import { grantOut, pageOut } from './serialize.js';
import { ensureValid, invalidState, notFound, pageQuery } from './util.js';

const MAX_GRANT_LIFETIME_MS = 365 * 24 * 3600 * 1000;

export function grantService({ store, clock, audit }) {
  function visibleTo(principal, grant) {
    if (principal.role === 'admin') return true;
    if (principal.role === 'business') return grant.businessId === principal.businessId;
    if (principal.role === 'operator') return grant.operatorId === principal.operatorId;
    return false;
  }

  return {
    async create(principal, body) {
      ensureValid(schemas.createGrant, body);
      const now = clock.now();
      const expiresAt = new Date(body.expiresAt);
      if (!(expiresAt > now) || expiresAt - now > MAX_GRANT_LIFETIME_MS) {
        throw validationError([{ path: '/expiresAt', message: 'must be in the future and at most 365 days ahead' }]);
      }
      const agent = await store.agents.findById(body.agentId);
      if (!agent) throw notFound();
      if (agent.status !== 'active') throw invalidState(`Agent is ${agent.status}`);
      const doc = {
        id: newId(ID_PREFIX.grant),
        businessId: principal.businessId,
        agentId: agent.id,
        operatorId: agent.operatorId,
        actions: [...body.actions],
        constraints: { ...(body.constraints ?? {}) },
        status: 'active',
        expiresAt,
        createdAt: now,
        revokedAt: null,
        statusReason: null,
      };
      await store.grants.insert(doc);
      await audit.recordOrCompensate(
        principal,
        'grant.created',
        { type: 'grant', id: doc.id },
        {
          businessId: doc.businessId,
          agentId: doc.agentId,
          operatorId: doc.operatorId,
          actions: doc.actions,
          constraints: doc.constraints,
          expiresAt: doc.expiresAt,
        },
        () => store.grants.revoke(doc.id, { revokedAt: clock.now(), statusReason: 'audit log unavailable' }),
      );
      return grantOut(doc);
    },

    async list(principal, q) {
      const filter = { agentId: q.agentId, status: q.status };
      if (principal.role === 'business') filter.businessId = principal.businessId;
      if (principal.role === 'operator') filter.operatorId = principal.operatorId;
      return pageOut(await store.grants.list(pageQuery(q, filter)), grantOut);
    },

    async get(principal, id) {
      const grant = await store.grants.findById(id);
      if (!grant || !visibleTo(principal, grant)) throw notFound();
      return grantOut(grant);
    },

    async revoke(principal, id, body) {
      ensureValid(schemas.reason, body);
      const grant = await store.grants.findById(id);
      if (!grant || !visibleTo(principal, grant)) throw notFound();
      const updated = await store.grants.revoke(id, { revokedAt: clock.now(), statusReason: body.reason });
      if (!updated) throw invalidState('Grant is already revoked');
      await audit.record(principal, 'grant.revoked', { type: 'grant', id }, {
        businessId: updated.businessId,
        agentId: updated.agentId,
        reason: body.reason,
      });
      return grantOut(updated);
    },
  };
}
