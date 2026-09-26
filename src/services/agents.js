import { ID_PREFIX } from '../contracts.js';
import { buildRegisterMessage } from '../crypto/canonical.js';
import { keyThumbprint, parsePublicKey, verifySignature } from '../crypto/ed25519.js';
import { ApiError, ConflictError, validationError } from '../errors.js';
import { newId } from '../ids.js';
import { schemas } from '../validate.js';
import { agentOut, pageOut } from './serialize.js';
import { ensureValid, invalidState, notFound, pageQuery } from './util.js';

export function agentService({ store, clock }) {
  /** Admin: any agent. Operator: own agents only (others look non-existent). */
  async function loadOwned(principal, id) {
    const agent = await store.agents.findById(id);
    if (!agent) throw notFound();
    if (principal.role === 'operator' && agent.operatorId !== principal.operatorId) throw notFound();
    return agent;
  }

  async function transition(principal, id, fromStatuses, patch, errorMessage) {
    const agent = await loadOwned(principal, id);
    const updated = await store.agents.setStatus(id, fromStatuses, { ...patch, updatedAt: clock.now() });
    if (!updated) throw invalidState(`${errorMessage} (agent is ${agent.status})`);
    return agentOut(updated);
  }

  return {
    async register(principal, body) {
      ensureValid(schemas.createAgent, body);
      const operator = await store.operators.findById(principal.operatorId);
      if (!operator || operator.status !== 'verified') {
        throw new ApiError('OPERATOR_NOT_VERIFIED', 'Operator must be verified before registering agents');
      }
      const keyObject = parsePublicKey(body.publicKey);
      if (!keyObject) throw validationError([{ path: '/publicKey', message: 'is not a valid Ed25519 public key' }]);
      const message = buildRegisterMessage(operator.id, body.publicKey);
      if (!verifySignature(keyObject, message, body.proofOfPossession)) {
        throw validationError([{ path: '/proofOfPossession', message: 'does not verify with publicKey' }]);
      }
      const now = clock.now();
      const doc = {
        id: newId(ID_PREFIX.agent),
        operatorId: operator.id,
        name: body.name,
        description: body.description ?? null,
        publicKey: body.publicKey,
        keyThumbprint: keyThumbprint(body.publicKey),
        status: 'active',
        statusReason: null,
        createdAt: now,
        updatedAt: now,
        revokedAt: null,
      };
      try {
        await store.agents.insert(doc);
      } catch (err) {
        if (err instanceof ConflictError) throw new ApiError('CONFLICT', 'Public key is already registered');
        throw err;
      }
      return agentOut(doc);
    },

    async list(principal, q) {
      const operatorId = principal.role === 'operator' ? principal.operatorId : q.operatorId;
      return pageOut(await store.agents.list(pageQuery(q, { operatorId, status: q.status })), agentOut);
    },

    /** Businesses may read any agent's public identity (REQ-001 lookup). */
    async get(principal, id) {
      if (principal.role === 'business') {
        const agent = await store.agents.findById(id);
        if (!agent) throw notFound();
        return agentOut(agent);
      }
      return agentOut(await loadOwned(principal, id));
    },

    suspend(principal, id, body) {
      ensureValid(schemas.reason, body);
      return transition(principal, id, ['active'], { status: 'suspended', statusReason: body.reason }, 'Only active agents can be suspended');
    },

    reactivate(principal, id) {
      return transition(principal, id, ['suspended'], { status: 'active', statusReason: null }, 'Only suspended agents can be reactivated');
    },

    revoke(principal, id, body) {
      ensureValid(schemas.reason, body);
      const now = clock.now();
      return transition(
        principal,
        id,
        ['active', 'suspended'],
        { status: 'revoked', statusReason: body.reason, revokedAt: now },
        'Agent is already revoked',
      );
    },
  };
}
