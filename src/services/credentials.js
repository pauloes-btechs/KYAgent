import { ID_PREFIX } from '../contracts.js';
import { signCredential } from '../crypto/credentials.js';
import { ApiError, validationError } from '../errors.js';
import { newId } from '../ids.js';
import { schemas } from '../validate.js';
import { credentialOut, pageOut } from './serialize.js';
import { ensureValid, invalidState, notFound, pageQuery } from './util.js';

export function credentialService({ store, clock, config, audit }) {
  function visibleTo(principal, cred) {
    if (principal.role === 'admin') return true;
    if (principal.role === 'operator') return cred.operatorId === principal.operatorId;
    if (principal.role === 'business') return cred.businessId === principal.businessId;
    return false;
  }

  return {
    /** Issue a signed, expiring, scoped, key-bound credential (crypto-and-signing.md §4.1). */
    async issue(principal, agentId, body) {
      ensureValid(schemas.issueCredential, body);
      const ttl = body.ttlSeconds ?? config.credentialDefaultTtlSeconds;
      if (ttl > config.credentialMaxTtlSeconds) {
        throw validationError([{ path: '/ttlSeconds', message: `must be <= ${config.credentialMaxTtlSeconds}` }]);
      }
      const agent = await store.agents.findById(agentId);
      if (!agent || agent.operatorId !== principal.operatorId) throw notFound();
      const operator = await store.operators.findById(agent.operatorId);
      if (!operator || operator.status !== 'verified') throw new ApiError('OPERATOR_NOT_VERIFIED');
      if (agent.status !== 'active') throw invalidState(`Agent is ${agent.status}`);
      const grant = await store.grants.findById(body.grantId);
      if (!grant || grant.agentId !== agent.id) throw notFound();
      const now = clock.now();
      if (grant.status !== 'active') throw invalidState('Grant is revoked');
      if (!(grant.expiresAt > now)) throw invalidState('Grant has expired');

      const iat = Math.floor(now.getTime() / 1000);
      const exp = Math.min(iat + ttl, Math.floor(grant.expiresAt.getTime() / 1000));
      if (exp <= iat) throw invalidState('Grant expires too soon to issue a credential');

      const record = {
        id: newId(ID_PREFIX.credential),
        agentId: agent.id,
        operatorId: agent.operatorId,
        businessId: grant.businessId,
        grantId: grant.id,
        actions: [...grant.actions],
        status: 'active',
        issuedAt: now,
        expiresAt: new Date(exp * 1000),
        revokedAt: null,
        statusReason: null,
      };
      const claims = {
        iss: config.issuer,
        sub: agent.id,
        aud: grant.businessId,
        iat,
        nbf: iat,
        exp,
        jti: record.id,
        kya_operator: agent.operatorId,
        kya_grant: grant.id,
        kya_actions: [...grant.actions],
        kya_constraints: { ...grant.constraints },
        cnf: { jkt: agent.keyThumbprint },
      };
      await store.credentials.insert(record);
      // Audit before signing: if the log write fails the JWS is never released and
      // the record is revoked (fail closed).
      await audit.recordOrCompensate(
        principal,
        'credential.issued',
        { type: 'credential', id: record.id },
        {
          agentId: record.agentId,
          operatorId: record.operatorId,
          businessId: record.businessId,
          grantId: record.grantId,
          actions: record.actions,
          expiresAt: record.expiresAt,
        },
        () => store.credentials.revoke(record.id, { revokedAt: clock.now(), statusReason: 'audit log unavailable' }),
      );
      const credential = signCredential(claims, { privateKey: config.signingKey, kid: config.kid });
      return { credential, record: credentialOut(record) };
    },

    async list(principal, q) {
      const filter = { agentId: q.agentId, grantId: q.grantId };
      if (principal.role === 'operator') filter.operatorId = principal.operatorId;
      if (principal.role === 'business') filter.businessId = principal.businessId;
      return pageOut(await store.credentials.list(pageQuery(q, filter)), credentialOut);
    },

    async get(principal, id) {
      const cred = await store.credentials.findById(id);
      if (!cred || !visibleTo(principal, cred)) throw notFound();
      return credentialOut(cred);
    },

    async revoke(principal, id, body) {
      ensureValid(schemas.reason, body);
      const cred = await store.credentials.findById(id);
      if (!cred || !visibleTo(principal, cred)) throw notFound();
      const updated = await store.credentials.revoke(id, { revokedAt: clock.now(), statusReason: body.reason });
      if (!updated) throw invalidState('Credential is already revoked');
      await audit.record(principal, 'credential.revoked', { type: 'credential', id }, {
        agentId: updated.agentId,
        businessId: updated.businessId,
        grantId: updated.grantId,
        reason: body.reason,
      });
      return credentialOut(updated);
    },
  };
}
