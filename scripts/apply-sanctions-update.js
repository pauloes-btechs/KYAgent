// Applies a staged sanctions dataset delta (default `upd_2026-09-26`, Demo 4) to Atlas:
// upserts every entry of `sanctions_updates.<id>.upserts` into `sanctions` with the update's
// `datasetVersion` (a real write, so the sanctions change stream fires), then marks the update
// `staged → applied` and appends a `sanctions.updated` audit event.
//
//   node scripts/apply-sanctions-update.js [upd_2026-09-26 | 2026-09-26]
//
// Requires MONGODB_URI (MONGODB_DB, default kyagent). Idempotent: an already-applied update is
// reported and nothing is written. The URI is never printed.
import { pathToFileURL } from 'node:url';
import { SYSTEM_ACTOR } from '../src/services/passports.js';

export const DEFAULT_UPDATE_ID = 'upd_2026-09-26';
const EVM_ADDRESS_RE = /^0x[0-9a-f]{40}$/;

export const updateIdOf = (arg) => (!arg ? DEFAULT_UPDATE_ID : arg.startsWith('upd_') ? arg : `upd_${arg}`);

/**
 * Apply update `updateId` on a connected MongoStore. Returns
 * `{ status: 'applied' | 'already_applied', updateId, datasetVersion, sanctionsIds }`.
 */
export async function applySanctionsUpdate(store, updateId, { audit, clock = { now: () => new Date() } } = {}) {
  const db = store.db;
  if (!db) throw new Error('apply-sanctions-update requires MongoDB Atlas (MONGODB_URI)');
  const upd = await db.collection('sanctions_updates').findOne({ _id: updateId });
  if (!upd) throw new Error(`sanctions update ${updateId} not found (run make demo-reset or npm run demo:seed)`);
  const sanctionsIds = (upd.upserts ?? []).map((u) => u._id);
  if (upd.status === 'applied') return { status: 'already_applied', updateId, datasetVersion: upd.datasetVersion, sanctionsIds };
  if (upd.status !== 'staged') throw new Error(`sanctions update ${updateId} is ${upd.status}, expected staged`);

  const now = clock.now();
  // Upsert first, then flip the status: a crash in between leaves the update `staged` and a
  // re-run re-applies it (the watcher is idempotent per change event).
  for (const u of upd.upserts ?? []) {
    const wallets = (u.wallets ?? []).map((w) => {
      const address = String(w.address ?? '').toLowerCase();
      if (!EVM_ADDRESS_RE.test(address)) throw new Error(`${u._id}: invalid wallet address`);
      return { chain: w.chain ?? 'evm', address };
    });
    const { _id, ...rest } = u;
    await db.collection('sanctions').replaceOne(
      { _id },
      { ...rest, aliases: rest.aliases ?? [], wallets, datasetVersion: upd.datasetVersion, source: rest.source ?? 'fixture', updatedAt: now, sourceUpdateId: updateId },
      { upsert: true },
    );
  }
  const res = await db.collection('sanctions_updates').updateOne({ _id: updateId, status: 'staged' }, { $set: { status: 'applied', appliedAt: now } });
  if (res.matchedCount === 0) return { status: 'already_applied', updateId, datasetVersion: upd.datasetVersion, sanctionsIds };
  if (audit) {
    await audit.record(SYSTEM_ACTOR, 'sanctions.updated', { type: 'sanctions_update', id: updateId }, { datasetVersion: upd.datasetVersion, sanctionsIds });
  }
  return { status: 'applied', updateId, datasetVersion: upd.datasetVersion, sanctionsIds };
}

async function main() {
  const fail = (msg) => {
    process.stderr.write(`${msg}\n`);
    process.exit(1);
  };
  if (!process.env.MONGODB_URI) fail('Atlas required: set MONGODB_URI to the MongoDB Atlas connection string');
  const updateId = updateIdOf(process.argv[2]);
  const { MongoStore } = await import('../src/store/mongo.js');
  const { auditService } = await import('../src/services/audit.js');
  const store = new MongoStore(process.env.MONGODB_URI, process.env.MONGODB_DB || 'kyagent');
  try {
    await store.init();
    const clock = { now: () => new Date() };
    const r = await applySanctionsUpdate(store, updateId, { audit: auditService({ store, clock }), clock });
    process.stdout.write(`apply-sanctions-update: ${r.updateId} ${r.status} (dataset ${r.datasetVersion}; ${r.sanctionsIds.join(', ')})\n`);
  } catch (err) {
    process.stderr.write(`apply-sanctions-update failed: ${err.message}\n`);
    process.exitCode = 1;
  } finally {
    await store.close().catch(() => {});
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
