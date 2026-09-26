// In-memory Store (dev/test). Enforces the same uniqueness constraints and
// state-transition preconditions as the MongoDB store (data-schema.md).
import { ConflictError } from '../errors.js';
import { encodeCursor } from './pagination.js';

const clone = (v) => (v == null ? v : structuredClone(v));

class Collection {
  constructor({ timeField = 'createdAt', unique = [] } = {}) {
    this.docs = new Map();
    this.timeField = timeField;
    this.unique = unique;
  }

  async insert(doc) {
    if (this.docs.has(doc.id)) throw new ConflictError();
    for (const field of this.unique) {
      for (const existing of this.docs.values()) {
        if (existing[field] === doc[field]) throw new ConflictError(`duplicate ${field}`);
      }
    }
    this.docs.set(doc.id, clone(doc));
    return clone(doc);
  }

  async findById(id) {
    return clone(this.docs.get(id) ?? null);
  }

  /** Sorted by time desc, id desc. `cursor` is a decoded { t, id } or null. */
  async list({ filter = {}, limit = 50, cursor = null } = {}) {
    const tf = this.timeField;
    let items = [...this.docs.values()].filter((d) =>
      Object.entries(filter).every(([k, v]) => v === undefined || d[k] === v),
    );
    items.sort((a, b) => b[tf] - a[tf] || (a.id < b.id ? 1 : a.id > b.id ? -1 : 0));
    if (cursor) {
      items = items.filter((d) => d[tf].getTime() < cursor.t || (d[tf].getTime() === cursor.t && d.id < cursor.id));
    }
    const page = items.slice(0, limit);
    const last = page[page.length - 1];
    const nextCursor = items.length > limit && last ? encodeCursor(last[tf].getTime(), last.id) : null;
    return { data: page.map(clone), nextCursor };
  }

  /** Atomic conditional update: only applies when current status is in `fromStatuses`. */
  async updateIf(id, fromStatuses, patch) {
    const doc = this.docs.get(id);
    if (!doc || (fromStatuses && !fromStatuses.includes(doc.status))) return null;
    Object.assign(doc, clone(patch));
    return clone(doc);
  }
}

export class MemoryStore {
  constructor() {
    this.kind = 'memory';
    const apiKeys = new Collection();
    const agents = new Collection({ unique: ['publicKey', 'keyThumbprint'] });
    const grants = new Collection();
    const credentials = new Collection({ timeField: 'issuedAt' });
    const events = new Collection({ timeField: 'evaluatedAt' });
    const nonceMap = new Map();
    this._nonces = nonceMap;

    this.apiKeys = {
      insert: (d) => apiKeys.insert(d),
      findById: (id) => apiKeys.findById(id),
      list: (q) => apiKeys.list(q),
      revoke: (id, patch) => apiKeys.updateIf(id, ['active'], { ...patch, status: 'revoked' }),
      touch: (id, at) => apiKeys.updateIf(id, null, { lastUsedAt: at }),
    };
    const businesses = new Collection();
    this.businesses = {
      insert: (d) => businesses.insert(d),
      findById: (id) => businesses.findById(id),
      list: (q) => businesses.list(q),
    };
    const operators = new Collection();
    this.operators = {
      insert: (d) => operators.insert(d),
      findById: (id) => operators.findById(id),
      list: (q) => operators.list(q),
      update: (id, fromStatuses, patch) => operators.updateIf(id, fromStatuses, patch),
    };
    this.agents = {
      insert: (d) => agents.insert(d),
      findById: (id) => agents.findById(id),
      list: (q) => agents.list(q),
      setStatus: (id, fromStatuses, patch) => agents.updateIf(id, fromStatuses, patch),
    };
    this.grants = {
      insert: (d) => grants.insert(d),
      findById: (id) => grants.findById(id),
      list: (q) => grants.list(q),
      /** Active, unexpired grants from businessId to agentId, createdAt ascending. */
      findActiveFor: async (agentId, businessId, now) =>
        [...grants.docs.values()]
          .filter((g) => g.agentId === agentId && g.businessId === businessId && g.status === 'active' && g.expiresAt > now)
          .sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1))
          .map(clone),
      revoke: (id, patch) => grants.updateIf(id, ['active'], { ...patch, status: 'revoked' }),
    };
    this.credentials = {
      insert: (d) => credentials.insert(d),
      findById: (id) => credentials.findById(id),
      list: (q) => credentials.list(q),
      revoke: (id, patch) => credentials.updateIf(id, ['active'], { ...patch, status: 'revoked' }),
    };
    this.nonces = {
      /** Returns false if (agentId, nonce) is already recorded and not yet expired. */
      insertOnce: async (agentId, nonce, expiresAt, now) => {
        const key = `${agentId}:${nonce}`;
        const existing = nonceMap.get(key);
        if (existing !== undefined && existing > now.getTime()) return false;
        nonceMap.set(key, expiresAt.getTime());
        if (nonceMap.size > 10000) {
          for (const [k, exp] of nonceMap) if (exp <= now.getTime()) nonceMap.delete(k);
        }
        return true;
      },
    };
    this.verificationEvents = {
      insert: (d) => events.insert(d),
      list: (q) => events.list(q),
    };
    // Append-only: no update/delete methods exist. `seq` must extend the chain by
    // exactly one (the in-memory analogue of Mongo's unique `seq` index).
    const auditLog = [];
    const audit = new Collection({ timeField: 'occurredAt' });
    this.auditEvents = {
      append: async (d) => {
        const expected = auditLog.length ? auditLog[auditLog.length - 1].seq + 1 : 1;
        if (d.seq !== expected) throw new ConflictError('audit sequence conflict');
        await audit.insert(d);
        auditLog.push(clone(d));
        return clone(d);
      },
      last: async () => clone(auditLog[auditLog.length - 1] ?? null),
      /** Events with seq >= fromSeq, ascending, at most `limit`. */
      range: async (fromSeq, limit) => auditLog.filter((e) => e.seq >= fromSeq).slice(0, limit).map(clone),
      list: (q) => audit.list(q),
    };
    this._auditLog = auditLog;
  }

  async init() {}
  async close() {}
  async ping() {
    return true;
  }
}
