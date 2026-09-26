import { generateApiKey, hashApiKeySecret, parseApiKey, secretMatches } from '../crypto/apiKeys.js';
import { ApiError, validationError } from '../errors.js';
import { schemas } from '../validate.js';
import { apiKeyOut, pageOut } from './serialize.js';
import { ensureValid, invalidState, notFound, pageQuery } from './util.js';

const TOUCH_INTERVAL_MS = 60_000;
const unauthenticated = () => new ApiError('UNAUTHENTICATED', 'Missing or invalid API key');

export function apiKeyService({ store, clock, config }) {
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
        createdAt: clock.now(),
        lastUsedAt: null,
        revokedAt: null,
      };
      await store.apiKeys.insert(doc);
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
        createdAt: clock.now(),
        lastUsedAt: null,
        revokedAt: null,
      });
      return true;
    },
  };
}
