// Versioned MongoDB schema migrations (data-schema.md). Each migration runs at most
// once per database and is recorded in `schema_migrations`; every step is also
// idempotent (createIndex is a no-op when the index exists), so a crash between
// "apply" and "record" is safe to re-run. Migrations are append-only: never edit
// or reorder a released entry — add a new one.

export const MIGRATIONS_COLLECTION = 'schema_migrations';

export const MIGRATIONS = [
  {
    id: '001_initial_indexes',
    description: 'Indexes and uniqueness constraints for all collections',
    async up(db) {
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
    },
  },
  {
    id: '002_audit_events_indexes',
    description: 'Append-only audit log: unique sequence and query indexes',
    async up(db) {
      const c = db.collection('audit_events');
      await Promise.all([
        c.createIndex({ seq: 1 }, { unique: true }),
        c.createIndex({ occurredAt: -1, _id: -1 }),
        c.createIndex({ subjectId: 1, occurredAt: -1 }),
        c.createIndex({ type: 1, occurredAt: -1 }),
      ]);
    },
  },
  {
    id: '003_businesses_name_index',
    description: 'Lookup index for businesses by name (used by the seed script)',
    async up(db) {
      await db.collection('businesses').createIndex({ name: 1 });
    },
  },
  {
    id: '004_principals_view_delegation_fields',
    description: 'principals read-only view over operators; agent wallet index (mongo-collections.md §2)',
    async up(db) {
      await ensureView(db, 'principals', 'operators', PRINCIPALS_PIPELINE);
      await db.collection('agents').createIndex({ 'wallets.address': 1 });
    },
  },
  {
    id: '005_transactions',
    description: 'USDC transaction history: validator and signal/daily-limit indexes',
    async up(db) {
      await ensureValidatedCollection(db, 'transactions', TRANSACTIONS_SCHEMA);
      const c = db.collection('transactions');
      await Promise.all([
        c.createIndex({ agentId: 1, at: -1 }),
        c.createIndex({ 'counterparty.address': 1 }),
        c.createIndex({ agentId: 1, 'counterparty.address': 1 }),
        c.createIndex({ delegationId: 1, status: 1, at: -1 }),
      ]);
    },
  },
  {
    id: '006_sanctions',
    description: 'Sanctions list + staged updates; exact-wallet invariant index',
    async up(db) {
      await ensureValidatedCollection(db, 'sanctions', SANCTIONS_SCHEMA);
      await ensureValidatedCollection(db, 'sanctions_updates', null);
      await Promise.all([
        // INV_SANCTIONS_EXACT_BLOCK: exact match via find() on this B-tree index, never $search.
        db.collection('sanctions').createIndex({ 'wallets.address': 1 }),
        db.collection('sanctions').createIndex({ datasetVersion: 1 }),
        db.collection('sanctions_updates').createIndex({ status: 1, datasetVersion: 1 }),
      ]);
    },
  },
  {
    id: '007_investigations_passports_receipts',
    description: 'Investigations, passports and receipts: validators and indexes',
    async up(db) {
      await ensureValidatedCollection(db, 'investigations', INVESTIGATIONS_SCHEMA);
      await ensureValidatedCollection(db, 'passports', PASSPORTS_SCHEMA);
      await ensureValidatedCollection(db, 'receipts', RECEIPTS_SCHEMA);
      const c = (n) => db.collection(n);
      await Promise.all([
        c('investigations').createIndex({ agentId: 1, createdAt: -1 }),
        c('investigations').createIndex({ businessId: 1, createdAt: -1 }),
        c('investigations').createIndex({ status: 1, createdAt: -1 }),
        c('investigations').createIndex({ trigger: 1, createdAt: -1 }),
        c('passports').createIndex({ agentId: 1 }, { unique: true }),
        c('passports').createIndex({ status: 1 }),
        c('passports').createIndex({ wallet: 1 }),
        c('receipts').createIndex({ investigationId: 1 }, { unique: true }),
        c('receipts').createIndex({ agentId: 1, issuedAt: -1 }),
        c('receipts').createIndex({ receiptHash: 1 }),
      ]);
    },
  },
  {
    id: '008_security_memories_harness',
    description: 'Security memories, harness versions (no invariants key) and harness events',
    async up(db) {
      await ensureValidatedCollection(db, 'security_memories', SECURITY_MEMORIES_SCHEMA);
      await ensureValidatedCollection(db, 'harness_versions', HARNESS_VERSIONS_SCHEMA);
      await ensureValidatedCollection(db, 'harness_events', null);
      await ensureValidatedCollection(db, 'watcher_state', null);
      const c = (n) => db.collection(n);
      await Promise.all([
        c('security_memories').createIndex({ status: 1, createdAt: -1 }),
        c('security_memories').createIndex({ sourceInvestigationId: 1 }, { unique: true }),
        c('harness_versions').createIndex(
          { status: 1 },
          { unique: true, partialFilterExpression: { status: 'active' }, name: 'status_1_single_active' },
        ),
        c('harness_events').createIndex({ at: -1 }),
        c('harness_events').createIndex({ toVersion: 1 }),
      ]);
    },
  },
];

// ---------------------------------------------------------------------------
// Collection / view helpers. Validators and views need the real driver `Db`
// (createCollection + collMod); the fakeDb used by deploy.test.js only records
// createIndex calls, so these are skipped there. Search / Vector Search indexes
// are NOT created here — see src/store/searchIndexes.js.

const NAMESPACE_EXISTS = 48;
const isNamespaceExists = (err) => err && (err.code === NAMESPACE_EXISTS || err.codeName === 'NamespaceExists');

async function ensureView(db, name, viewOn, pipeline) {
  if (typeof db.createCollection !== 'function') return;
  try {
    await db.createCollection(name, { viewOn, pipeline });
  } catch (err) {
    if (!isNamespaceExists(err)) throw err;
    await db.command({ collMod: name, viewOn, pipeline });
  }
}

/** Create `name` (with a strict $jsonSchema validator when given) or update the validator in place. */
async function ensureValidatedCollection(db, name, schema) {
  if (typeof db.createCollection !== 'function') return;
  const opts = schema ? { validator: { $jsonSchema: schema }, validationLevel: 'strict', validationAction: 'error' } : {};
  try {
    await db.createCollection(name, opts);
  } catch (err) {
    if (!isNamespaceExists(err)) throw err;
    if (schema) await db.command({ collMod: name, ...opts });
  }
}

// ---------------------------------------------------------------------------
// Schemas (mongo-collections.md §3, harness.md §3.1/§4). MongoDB $jsonSchema has
// no `const`, `$ref` or `integer`: they are expressed as single-value `enum`,
// inlined definitions and bsonType int|long.

export const PRINCIPALS_PIPELINE = [
  {
    $project: {
      _id: 1, principalId: '$_id', type: 1, legalName: 1, country: 1, status: 1,
      verification: 1, createdAt: 1, updatedAt: 1,
    },
  },
];

const INT = ['int', 'long'];
const NUMBER = ['int', 'long', 'double', 'decimal'];
const int = (minimum, maximum) => ({
  bsonType: INT,
  ...(minimum !== undefined && { minimum }),
  ...(maximum !== undefined && { maximum }),
});
const str = { bsonType: 'string' };
const strOrNull = { bsonType: ['string', 'null'] };
const EVM_ADDRESS = '^0x[0-9a-f]{40}$';
const SLUG = { bsonType: 'string', pattern: '^[a-z0-9_]{1,64}$' };
const OUTCOMES = ['CONFIRMED_ACCOUNT_TAKEOVER', 'SANCTIONS_MATCH', 'FALSE_POSITIVE', 'CLEAN'];
const SIGNAL = { enum: ['NEW_WALLET', 'NEW_COUNTERPARTY', 'SIGNING_KEY_CHANGED', 'AMOUNT_ANOMALY', 'VELOCITY', 'NEAR_CEILING'] };
const signalList = { bsonType: 'array', minItems: 1, uniqueItems: true, items: SIGNAL };

export const TRANSACTIONS_SCHEMA = {
  bsonType: 'object',
  required: ['_id', 'agentId', 'wallet', 'asset', 'amount', 'counterparty', 'signingKeyThumbprint', 'status', 'at'],
  properties: {
    _id: str,
    agentId: str,
    wallet: { bsonType: 'string', pattern: EVM_ADDRESS },
    asset: { enum: ['USDC'] },
    amount: int(1),
    counterparty: {
      bsonType: 'object',
      required: ['address'],
      properties: { address: { bsonType: 'string', pattern: EVM_ADDRESS }, name: strOrNull },
    },
    signingKeyThumbprint: str,
    status: { enum: ['settled', 'blocked', 'review'] },
    at: { bsonType: 'date' },
    source: { enum: ['fixture', 'pipeline', 'chain'] },
  },
};

export const SANCTIONS_SCHEMA = {
  bsonType: 'object',
  required: ['_id', 'name', 'aliases', 'type', 'wallets', 'datasetVersion'],
  properties: {
    _id: str,
    name: str,
    aliases: { bsonType: 'array', items: str },
    type: { enum: ['entity', 'individual'] },
    programs: { bsonType: 'array', items: str },
    wallets: {
      bsonType: 'array',
      items: {
        bsonType: 'object',
        required: ['address'],
        properties: { chain: str, address: { bsonType: 'string', pattern: EVM_ADDRESS } },
      },
    },
    datasetVersion: str,
    source: { enum: ['fixture', 'ofac'] },
  },
};

export const INVESTIGATIONS_SCHEMA = {
  bsonType: 'object',
  required: ['_id', 'trigger', 'agentId', 'harnessVersion', 'stages', 'riskDecision', 'reasons', 'status', 'createdAt'],
  properties: {
    _id: str,
    trigger: { enum: ['api', 'sanctions_change', 'manual'] },
    agentId: str,
    harnessVersion: int(1),
    stages: { bsonType: 'array' },
    decision: { enum: ['ALLOW', 'DENY'] },
    riskDecision: { enum: ['ALLOW', 'REVIEW', 'BLOCK'] },
    reasons: { bsonType: 'array' },
    status: { enum: ['DECIDED', 'AWAITING_REVIEW', 'CONFIRMED'] },
    outcome: { enum: [...OUTCOMES, null] },
    createdAt: { bsonType: 'date' },
  },
};

export const PASSPORTS_SCHEMA = {
  bsonType: 'object',
  required: ['_id', 'agentId', 'principalId', 'delegationId', 'delegationVersion', 'status', 'harnessVersion', 'statusHistory', 'issuedAt'],
  properties: {
    _id: str,
    agentId: str,
    principalId: str,
    delegationId: str,
    delegationVersion: int(1),
    status: { enum: ['ACTIVE', 'REVIEW', 'RE_SCREENING', 'SUSPENDED', 'REVOKED'] },
    harnessVersion: int(1),
    statusHistory: { bsonType: 'array' },
    issuedAt: { bsonType: 'date' },
  },
};

export const RECEIPTS_SCHEMA = {
  bsonType: 'object',
  required: ['_id', 'investigationId', 'riskDecision', 'receiptHash', 'issuedAt'],
  properties: {
    _id: str,
    investigationId: str,
    riskDecision: { enum: ['ALLOW', 'REVIEW', 'BLOCK'] },
    receiptHash: { bsonType: 'string', pattern: '^[0-9a-f]{64}$' },
  },
};

export const EMBEDDING_DIMENSIONS = 1024;

export const SECURITY_MEMORIES_SCHEMA = {
  bsonType: 'object',
  required: ['_id', 'title', 'status', 'signals', 'signalsText', 'embedding', 'embeddingModel', 'createdAt'],
  properties: {
    _id: str,
    title: str,
    status: { enum: ['UNVERIFIED', 'VERIFIED', 'REJECTED'] },
    signals: { bsonType: 'array' },
    signalsText: str,
    embedding: {
      bsonType: 'array',
      minItems: EMBEDDING_DIMENSIONS,
      maxItems: EMBEDDING_DIMENSIONS,
      items: { bsonType: NUMBER },
    },
    embeddingModel: str,
    createdAt: { bsonType: 'date' },
  },
  // INV_UNVERIFIED_MEMORY_NOT_PRECEDENT: a VERIFIED memory must carry who verified it, when, and the outcome.
  oneOf: [
    { properties: { status: { enum: ['UNVERIFIED', 'REJECTED'] } } },
    {
      required: ['verifiedBy', 'verifiedAt', 'outcome'],
      properties: {
        status: { enum: ['VERIFIED'] },
        verifiedBy: { bsonType: 'object' },
        verifiedAt: { bsonType: 'date' },
        outcome: { enum: OUTCOMES },
      },
    },
  ],
};

/** harness.md §3.1 translated to $jsonSchema. additionalProperties:false rejects `invariants`, `skipInvariants`, … */
export const HARNESS_POLICY_SCHEMA = {
  bsonType: 'object',
  additionalProperties: false,
  required: ['steps', 'memoryRetrieval', 'contextAssembly', 'evidenceRequests', 'escalation'],
  properties: {
    steps: {
      bsonType: 'array', minItems: 6, maxItems: 12, uniqueItems: true,
      items: { enum: ['identity', 'delegation', 'sanctions', 'signals', 'memory', 'policy', 'signing_key_history_check'] },
    },
    memoryRetrieval: {
      bsonType: 'object', additionalProperties: false,
      required: ['k', 'numCandidates', 'minScorePpm', 'filter'],
      properties: {
        k: int(1, 10),
        numCandidates: int(10, 200),
        minScorePpm: int(1, 1000000),
        filter: {
          bsonType: 'object', additionalProperties: false, required: ['status'],
          properties: { status: { enum: ['VERIFIED'] } },
        },
      },
    },
    sanctionsFuzzy: {
      bsonType: 'object', additionalProperties: false, required: ['minScorePpm', 'limit'],
      properties: { minScorePpm: int(1), limit: int(1, 10) },
    },
    contextAssembly: {
      bsonType: 'object', additionalProperties: false,
      required: ['maxMemories', 'includeSignalStats', 'includeSanctionsEvidence'],
      properties: {
        maxMemories: int(0, 10),
        includeSignalStats: { bsonType: 'bool' },
        includeSanctionsEvidence: { bsonType: 'bool' },
      },
    },
    evidenceRequests: {
      bsonType: 'array', maxItems: 10,
      items: {
        bsonType: 'object', additionalProperties: false, required: ['id', 'stage', 'description'],
        properties: { id: SLUG, stage: SLUG, description: { bsonType: 'string', maxLength: 300 } },
      },
    },
    escalation: {
      bsonType: 'array', maxItems: 20,
      items: {
        bsonType: 'object', additionalProperties: false, required: ['id', 'when', 'then'],
        properties: {
          id: SLUG,
          when: {
            bsonType: 'object', additionalProperties: false, minProperties: 1,
            properties: {
              precedentOutcomeIn: { bsonType: 'array', minItems: 1, uniqueItems: true, items: { enum: OUTCOMES } },
              signalsAll: signalList,
              signalsAnyMin: {
                bsonType: 'object', additionalProperties: false, required: ['of', 'min'],
                properties: { of: signalList, min: int(1) },
              },
              sanctionsFuzzyHit: { enum: [true] },
            },
          },
          then: {
            bsonType: 'object', additionalProperties: false, required: ['riskDecision', 'reasonCode'],
            properties: {
              riskDecision: { enum: ['REVIEW'] },
              reasonCode: { enum: ['MEMORY_PRECEDENT_TAKEOVER', 'BEHAVIOR_ESCALATION', 'SANCTIONS_FUZZY_MATCH'] },
            },
          },
        },
      },
    },
  },
};

export const HARNESS_VERSIONS_SCHEMA = {
  bsonType: 'object',
  additionalProperties: false,
  required: ['_id', 'version', 'status', 'invariantsHash', 'policy', 'policyHash', 'createdAt', 'approvedBy'],
  properties: {
    _id: int(1),
    version: int(1),
    status: { enum: ['active', 'superseded'] },
    parentVersion: { bsonType: [...INT, 'null'] },
    invariantsHash: { bsonType: 'string', pattern: '^[0-9a-f]{64}$' },
    policy: HARNESS_POLICY_SCHEMA,
    policyHash: { bsonType: 'string', pattern: '^[0-9a-f]{64}$' },
    createdAt: { bsonType: 'date' },
    approvedBy: {
      bsonType: 'object', additionalProperties: false, required: ['role'],
      properties: {
        role: { enum: ['admin', 'system'] },
        apiKeyId: strOrNull,
        ownerId: strOrNull,
        label: { enum: ['seed'] },
      },
    },
    sourceEventId: strOrNull,
    demo: { enum: [true] },
  },
};

/**
 * Apply pending migrations in order. Returns { applied, skipped } id lists.
 * `migrations` is injectable for tests.
 */
export async function runMigrations(db, { migrations = MIGRATIONS, now = () => new Date() } = {}) {
  const ids = migrations.map((m) => m.id);
  if (new Set(ids).size !== ids.length) throw new Error('duplicate migration id');
  const log = db.collection(MIGRATIONS_COLLECTION);
  const done = new Set((await log.find({}).toArray()).map((d) => d._id));
  const applied = [];
  const skipped = [];
  for (const m of migrations) {
    if (done.has(m.id)) {
      skipped.push(m.id);
      continue;
    }
    await m.up(db);
    try {
      await log.insertOne({ _id: m.id, description: m.description, appliedAt: now() });
    } catch (err) {
      // A concurrent runner recorded it first; the migration itself is idempotent.
      if (!(err && (err.code === 11000 || err.code === 11001))) throw err;
    }
    applied.push(m.id);
  }
  return { applied, skipped };
}
