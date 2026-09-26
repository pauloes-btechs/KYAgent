import { ID_PREFIX } from '../contracts.js';
import { newId } from '../ids.js';
import { schemas } from '../validate.js';
import { runOperatorVerification } from './kyc.js';
import { businessOut, operatorOut, operatorPublicOut, pageOut } from './serialize.js';
import { ensureValid, invalidState, notFound, pageQuery } from './util.js';

export function businessService({ store, clock }) {
  return {
    async create(principal, body) {
      ensureValid(schemas.createBusiness, body);
      const doc = { id: newId(ID_PREFIX.business), name: body.name, status: 'active', createdAt: clock.now() };
      await store.businesses.insert(doc);
      return businessOut(doc);
    },
    async list(principal, q) {
      return pageOut(await store.businesses.list(pageQuery(q, {})), businessOut);
    },
    async get(principal, id) {
      if (principal.role === 'business' && principal.businessId !== id) throw notFound();
      const b = await store.businesses.findById(id);
      if (!b) throw notFound();
      return businessOut(b);
    },
  };
}

export function operatorService({ store, clock, config }) {
  return {
    async create(principal, body) {
      ensureValid(schemas.createOperator, body);
      const now = clock.now();
      const doc = {
        id: newId(ID_PREFIX.operator),
        type: body.type,
        legalName: body.legalName,
        contactEmail: body.contactEmail.toLowerCase(),
        country: body.country,
        status: 'pending',
        verification: null,
        statusReason: null,
        createdAt: now,
        updatedAt: now,
      };
      await store.operators.insert(doc);
      return operatorOut(doc);
    },

    async list(principal, q) {
      return pageOut(await store.operators.list(pageQuery(q, { status: q.status })), operatorOut);
    },

    async get(principal, id) {
      if (principal.role === 'operator' && principal.operatorId !== id) throw notFound();
      const op = await store.operators.findById(id);
      if (!op) throw notFound();
      return principal.role === 'business' ? operatorPublicOut(op) : operatorOut(op);
    },

    async verify(principal, id) {
      const op = await store.operators.findById(id);
      if (!op) throw notFound();
      if (op.status !== 'pending' && op.status !== 'rejected') throw invalidState(`Operator is ${op.status}`);
      const now = clock.now();
      const result = runOperatorVerification(op, config.sanctionsMode, now);
      const updated = await store.operators.update(id, ['pending', 'rejected'], { ...result, updatedAt: now });
      if (!updated) throw invalidState('Operator state changed concurrently');
      return operatorOut(updated);
    },

    async suspend(principal, id, body) {
      ensureValid(schemas.reason, body);
      const op = await store.operators.findById(id);
      if (!op) throw notFound();
      const now = clock.now();
      const updated = await store.operators.update(id, ['verified'], { status: 'suspended', statusReason: body.reason, updatedAt: now });
      if (!updated) throw invalidState(`Only verified operators can be suspended (operator is ${op.status})`);
      return operatorOut(updated);
    },
  };
}
