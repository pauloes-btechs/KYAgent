// MongoDB Store (data-schema.md, mongo-collections.md). The `mongodb` driver is a declared
// dependency; it is imported lazily so MemoryStore-only unit tests never load it.
import { ConflictError } from '../errors.js';
import { runMigrations } from './migrations.js';
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

// Plain CRUD over the investigation-harness collections (mongo-collections.md §3). Search,
// vector and change-stream access is built on `store.db` by the owning modules.
function harnessRepo(col, timeField) {
  const base = repo(col, timeField);
  return {
    ...base,
    find: async (filter = {}, { sort = { _id: 1 }, limit = 1000 } = {}) =>
      (await col.find(filter).sort(sort).limit(limit).toArray()).map(fromDoc),
    upsert: async (d) => {
      const { _id, ...rest } = toDoc(d);
      await col.replaceOne({ _id }, rest, { upsert: true });
      return d;
    },
  };
}

// NamespaceNotFound: the probe collection is missing but $listSearchIndexes itself is supported.
const SEARCH_PROBE_OK_CODES = new Set([26]);

/**
 * Atlas feature detection. Change streams need a replica set (`hello.setName`) or mongos;
 * Atlas Search / Vector Search need a `listSearchIndexes` probe that the server accepts.
 */
export async function detectCapabilities(db, probeCollection = 'operators') {
  let changeStreams = false;
  try {
    const hello = await db.admin().command({ hello: 1 });
    changeStreams = typeof hello.setName === 'string' || hello.msg === 'isdbgrid';
  } catch {
    changeStreams = false;
  }
  let atlasSearch = false;
  try {
    await db.collection(probeCollection).listSearchIndexes().toArray();
    atlasSearch = true;
  } catch (err) {
    atlasSearch = SEARCH_PROBE_OK_CODES.has(err?.code);
  }
  return Object.freeze({ atlasSearch, changeStreams });
}

export class MongoStore {
  constructor(uri, dbName) {
    this.kind = 'mongo';
    this._uri = uri;
    this._dbName = dbName;
    this.capabilities = Object.freeze({ atlasSearch: false, changeStreams: false });
  }

  /** The connected driver `Db`, for the Search / Vector Search / Change Stream modules. */
  get db() {
    return this._db;
  }

  async init() {
    let mongodb;
    try {
      mongodb = await import('mongodb');
    } catch {
      throw new Error('MONGODB_URI is set but the "mongodb" package is not installed (run: npm ci)');
    }
    this._client = new mongodb.MongoClient(this._uri, { serverSelectionTimeoutMS: 5000 });
    await this._client.connect();
    const db = this._client.db(this._dbName);
    this._db = db;
    const c = (n) => db.collection(n);

    // Schema (indexes, unique constraints) is owned by versioned migrations;
    // pending ones are applied on startup so the API never runs without them.
    this.migrations = await runMigrations(db);
    this.capabilities = await detectCapabilities(db);

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
    // Append-only: only insert and reads are exposed. Duplicate `seq` (a concurrent
    // writer extended the chain first) surfaces as ConflictError and is retried.
    const auditCol = c('audit_events');
    const audit = repo(auditCol, 'occurredAt');
    this.auditEvents = {
      append: audit.insert,
      last: async () => fromDoc(await auditCol.find({}).sort({ seq: -1 }).limit(1).next()),
      range: async (fromSeq, limit) =>
        (await auditCol.find({ seq: { $gte: fromSeq } }).sort({ seq: 1 }).limit(limit).toArray()).map(fromDoc),
      list: audit.list,
    };

    // Investigation harness collections (mongo-collections.md §3).
    this.transactions = harnessRepo(c('transactions'), 'at');
    const sanctionsCol = c('sanctions');
    this.sanctions = {
      ...harnessRepo(sanctionsCol, 'updatedAt'),
      /** Exact, index-backed wallet match (the sanctions invariant); not Atlas Search. */
      findByWallet: async (address) =>
        (await sanctionsCol.find({ 'wallets.address': address }).sort({ _id: 1 }).toArray()).map(fromDoc),
    };
    this.sanctionsUpdates = harnessRepo(c('sanctions_updates'), 'stagedAt');
    this.investigations = harnessRepo(c('investigations'));
    this.securityMemories = harnessRepo(c('security_memories'));
    this.passports = harnessRepo(c('passports'), 'issuedAt');
    this.receipts = harnessRepo(c('receipts'), 'issuedAt');
    this.harnessVersions = harnessRepo(c('harness_versions'));
    this.harnessEvents = harnessRepo(c('harness_events'), 'at');
    this.watcherState = harnessRepo(c('watcher_state'), 'updatedAt');
  }

  async ping() {
    await this._db.command({ ping: 1 });
    return true;
  }

  async close() {
    await this._client?.close();
  }
}
