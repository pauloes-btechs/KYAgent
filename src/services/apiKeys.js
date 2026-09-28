import { generateApiKey, hashApiKeySecret, parseApiKey, secretMatches } from '../crypto/apiKeys.js';
import { ApiError, validationError } from '../errors.js';
import { decodeCursor } from '../store/pagination.js';
import { schemas } from '../validate.js';
import { apiKeyOut, pageOut } from './serialize.js';
import { ensureValid, invalidState, notFound, pageQuery } from './util.js';

const TOUCH_INTERVAL_MS = 60_000;
const MAX_LINEAGE_DEPTH = 32;
const MAX_OWNED_KEYS = 1000;
const unauthenticated = () => new ApiError('UNAUTHENTICATED', 'Missing or invalid API key');

export function apiKeyService({ store, clock, config, audit }) {
  return {
    async create(principal, body) {
      ensureValid(schemas.createApiKey, body);
      const ownerId = body.ownerId ?? null;
      if (body.role === 'admin') {
        if (ownerId !== null) throw validationError([{ path: '/ownerId', message: 'must be null for admin keys' }]);
      } else {
        if (ownerId === null) throw validationError([{ path: '/ownerId', message: `is required for ${body.role} keys` }]);
        const owner =
          body.role === 'operator' ? await store.operators.findById(ownerId) : await store.businesses.findById(ownerId);
        if (!owner) throw notFound();
      }
      const { keyId, secret, plaintext } = generateApiKey();
      const doc = {
        id: keyId,
        name: body.name,
        role: body.role,
        ownerId,
        secretHash: hashApiKeySecret(config.pepper, secret),
        status: 'active',
        // Lineage for INV_NO_SELF_APPROVAL: whoever holds the minting key also received this key's secret.
        createdBy: principal?.apiKeyId ?? null,
        createdAt: clock.now(),
        lastUsedAt: null,
        revokedAt: null,
      };
      await store.apiKeys.insert(doc);
      // Never log the secret or its hash; revoke the key if the event cannot be recorded.
      await audit.recordOrCompensate(
        principal,
        'api_key.created',
        { type: 'api_key', id: doc.id },
        { role: doc.role, ownerId: doc.ownerId, name: doc.name },
        () => store.apiKeys.revoke(doc.id, { revokedAt: clock.now() }),
      );
      return { apiKey: apiKeyOut(doc), secret: plaintext };
    },

    async list(principal, q) {
      return pageOut(await store.apiKeys.list(pageQuery(q, { ownerId: q.ownerId })), apiKeyOut);
    },

    async revoke(principal, id) {
      const existing = await store.apiKeys.findById(id);
      if (!existing) throw notFound();
      const updated = await store.apiKeys.revoke(id, { revokedAt: clock.now() });
      if (!updated) throw invalidState('API key is already revoked');
      await audit.record(principal, 'api_key.revoked', { type: 'api_key', id }, { role: updated.role, ownerId: updated.ownerId });
      return apiKeyOut(updated);
    },

    /** Bearer header -> Principal. Every failure yields the same 401 (no oracle). */
    async authenticate(authorizationHeader) {
      if (typeof authorizationHeader !== 'string' || !authorizationHeader.startsWith('Bearer ')) throw unauthenticated();
      const parsed = parseApiKey(authorizationHeader.slice(7).trim());
      if (!parsed) throw unauthenticated();
      const key = await store.apiKeys.findById(parsed.keyId);
      // Hash even when the key is unknown so timing does not reveal key existence.
      const ok = secretMatches(config.pepper, parsed.secret, key?.secretHash ?? '');
      if (!key || !ok || key.status !== 'active') throw unauthenticated();

      let principal;
      if (key.role === 'admin') {
        principal = { role: 'admin', apiKeyId: key.id };
      } else if (key.role === 'operator') {
        const op = await store.operators.findById(key.ownerId);
        if (!op || op.status === 'suspended' || op.status === 'rejected') throw unauthenticated();
        principal = { role: 'operator', apiKeyId: key.id, operatorId: op.id };
      } else if (key.role === 'business') {
        const biz = await store.businesses.findById(key.ownerId);
        if (!biz || biz.status !== 'active') throw unauthenticated();
        principal = { role: 'business', apiKeyId: key.id, businessId: biz.id };
      } else {
        throw unauthenticated();
      }

      const now = clock.now();
      if (!key.lastUsedAt || now - key.lastUsedAt >= TOUCH_INTERVAL_MS) {
        store.apiKeys.touch(key.id, now).catch(() => {}); // best effort
      }
      return principal;
    },

    /** Insert the hash of KYA_BOOTSTRAP_ADMIN_API_KEY if that key id does not exist yet. */
    async bootstrapAdmin(plaintext) {
      const parsed = parseApiKey(plaintext);
      if (!parsed) return false;
      if (await store.apiKeys.findById(parsed.keyId)) return false;
      await store.apiKeys.insert({
        id: parsed.keyId,
        name: 'bootstrap admin',
        role: 'admin',
        ownerId: null,
        secretHash: hashApiKeySecret(config.pepper, parsed.secret),
        status: 'active',
        createdBy: null, // provisioned out-of-band: a lineage root
        createdAt: clock.now(),
        lastUsedAt: null,
        revokedAt: null,
      });
      return true;
    },
  };
}

/**
 * Key lineage for INV_NO_SELF_APPROVAL: `[apiKeyId, parent, …, root]`. The holder of any key in the
 * chain received (or could mint) every key below it, so two keys whose lineages intersect are
 * controlled by the same holder. The parent is `createdBy`; keys stored before that field existed
 * fall back to the actor of their hash-chained `api_key.created` audit event. Keys provisioned
 * out-of-band (bootstrap env key, seed/demo scripts) have neither and are roots. Keys are never
 * deleted, so a missing record only occurs for ids that were never stored. A cycle or a chain
 * deeper than MAX_LINEAGE_DEPTH throws (callers fail closed).
 */
export async function keyLineage(store, apiKeyId) {
  const chain = [];
  let id = apiKeyId;
  while (typeof id === 'string' && id) {
    if (chain.includes(id) || chain.length >= MAX_LINEAGE_DEPTH) throw new Error('API key lineage is cyclic or too deep');
    chain.push(id);
    const key = await store.apiKeys.findById(id);
    if (!key) break;
    if (key.createdBy !== undefined) {
      id = key.createdBy;
    } else {
      const created = await store.auditEvents.list({ filter: { type: 'api_key.created', subjectType: 'api_key', subjectId: id }, limit: 1 });
      id = created.data[0]?.actor?.apiKeyId ?? null;
    }
  }
  return chain;
}

/** Ids of every API key (any status) owned by `ownerIds`. Throws past MAX_OWNED_KEYS (fail closed). */
export async function ownedKeyIds(store, ownerIds) {
  const ids = [];
  for (const ownerId of new Set(ownerIds.filter((o) => typeof o === 'string' && o))) {
    let cursor = null;
    do {
      const page = await store.apiKeys.list({ filter: { ownerId }, limit: 100, cursor: cursor && decodeCursor(cursor) });
      ids.push(...page.data.map((k) => k.id));
      if (ids.length > MAX_OWNED_KEYS) throw new Error('too many API keys owned by the case parties');
      cursor = page.nextCursor;
    } while (cursor);
  }
  return ids;
}
