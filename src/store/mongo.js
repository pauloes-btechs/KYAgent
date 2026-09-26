// MongoDB Store (data-schema.md). Requires the optional `mongodb` driver:
//   npm install mongodb
// The driver is imported lazily so the default (in-memory) setup has zero dependencies.
import { ConflictError } from '../errors.js';
import { encodeCursor } from './pagination.js';

const toDoc = ({ id, ...rest }) => ({ _id: id, ...rest });
const fromDoc = (doc) => {
  if (!doc) return null;
  const { _id, ...rest } = doc;
  return { id: _id, ...rest };
};

function isDuplicateKey(err) {
  return err && (err.code === 11000 || err.code === 11001);
}

function repo(col, timeField = 'createdAt') {
  return {
    async insert(d) {
      try {
        await col.insertOne(toDoc(d));
      } catch (err) {
        if (isDuplicateKey(err)) throw new ConflictError();
        throw err;
      }
      return d;
    },
    async findById(id) {
      return fromDoc(await col.findOne({ _id: id }));
    },
    async list({ filter = {}, limit = 50, cursor = null } = {}) {
      const q = {};
      for (const [k, v] of Object.entries(filter)) if (v !== undefined) q[k] = v;
      if (cursor) {
        const t = new Date(cursor.t);
        q.$or = [{ [timeField]: { $lt: t } }, { [timeField]: t, _id: { $lt: cursor.id } }];
      }
      const docs = await col.find(q).sort({ [timeField]: -1, _id: -1 }).limit(limit + 1).toArray();
      const page = docs.slice(0, limit).map(fromDoc);
      const last = page[page.length - 1];
      return { data: page, nextCursor: docs.length > limit && last ? encodeCursor(last[timeField].getTime(), last.id) : null };
    },
    async updateIf(id, fromStatuses, patch) {
      const q = { _id: id };
      if (fromStatuses) q.status = { $in: fromStatuses };
      const res = await col.findOneAndUpdate(q, { $set: patch }, { returnDocument: 'after', includeResultMetadata: false });
      // Driver v5 returns { value }, v6 returns the document.
      const doc = res && Object.prototype.hasOwnProperty.call(res, 'value') && Object.prototype.hasOwnProperty.call(res, 'ok') ? res.value : res;
      return fromDoc(doc);
    },
  };
}

export class MongoStore {
  constructor(uri, dbName) {
    this.kind = 'mongo';
    this._uri = uri;
    this._dbName = dbName;
  }

  async init() {
    let mongodb;
    try {
      mongodb = await import('mongodb');
    } catch {
      throw new Error('MONGODB_URI is set but the "mongodb" package is not installed (run: npm install mongodb)');
    }
    this._client = new mongodb.MongoClient(this._uri, { serverSelectionTimeoutMS: 5000 });
    await this._client.connect();
    const db = this._client.db(this._dbName);
    this._db = db;
    const c = (n) => db.collection(n);

    await Promise.all([
      c('api_keys').createIndex({ role: 1, ownerId: 1 }),
      c('operators').createIndex({ status: 1 }),
      c('operators').createIndex({ contactEmail: 1 }),
      c('agents').createIndex({ publicKey: 1 }, { unique: true }),
      c('agents').createIndex({ keyThumbprint: 1 }, { unique: true }),
      c('agents').createIndex({ operatorId: 1, createdAt: -1 }),
      c('grants').createIndex({ agentId: 1, businessId: 1, status: 1, createdAt: 1 }),
      c('grants').createIndex({ businessId: 1, createdAt: -1 }),
      c('grants').createIndex({ operatorId: 1, createdAt: -1 }),
      c('credentials').createIndex({ agentId: 1, issuedAt: -1 }),
      c('credentials').createIndex({ businessId: 1, issuedAt: -1 }),
      c('credentials').createIndex({ grantId: 1 }),
      c('nonces').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
      c('verification_events').createIndex({ businessId: 1, evaluatedAt: -1 }),
      c('verification_events').createIndex({ agentId: 1, evaluatedAt: -1 }),
    ]);

    const apiKeys = repo(c('api_keys'));
    this.apiKeys = {
      ...apiKeys,
      revoke: (id, patch) => apiKeys.updateIf(id, ['active'], { ...patch, status: 'revoked' }),
      touch: (id, at) => apiKeys.updateIf(id, null, { lastUsedAt: at }),
    };
    this.businesses = repo(c('businesses'));
    const operators = repo(c('operators'));
    this.operators = { ...operators, update: operators.updateIf };
    const agents = repo(c('agents'));
    this.agents = { ...agents, setStatus: agents.updateIf };
    const grantsCol = c('grants');
    const grants = repo(grantsCol);
    this.grants = {
      ...grants,
      findActiveFor: async (agentId, businessId, now) =>
        (await grantsCol
          .find({ agentId, businessId, status: 'active', expiresAt: { $gt: now } })
          .sort({ createdAt: 1, _id: 1 })
          .limit(100)
          .toArray()).map(fromDoc),
      revoke: (id, patch) => grants.updateIf(id, ['active'], { ...patch, status: 'revoked' }),
    };
    const credentials = repo(c('credentials'), 'issuedAt');
    this.credentials = {
      ...credentials,
      revoke: (id, patch) => credentials.updateIf(id, ['active'], { ...patch, status: 'revoked' }),
    };
    const noncesCol = c('nonces');
    this.nonces = {
      insertOnce: async (agentId, nonce, expiresAt, now) => {
        const _id = `${agentId}:${nonce}`;
        // TTL deletion is lazy; treat an expired leftover as free by removing it first.
        await noncesCol.deleteOne({ _id, expiresAt: { $lte: now } });
        try {
          await noncesCol.insertOne({ _id, agentId, expiresAt });
          return true;
        } catch (err) {
          if (isDuplicateKey(err)) return false;
          throw err;
        }
      },
    };
    this.verificationEvents = repo(c('verification_events'), 'evaluatedAt');
  }

  async ping() {
    await this._db.command({ ping: 1 });
    return true;
  }

  async close() {
    await this._client?.close();
  }
}
