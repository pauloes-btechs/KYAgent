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
];

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
