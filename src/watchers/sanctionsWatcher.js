// Sanctions watcher: continuous KYA over MongoDB Change Streams (investigation-pipeline.md §7,
// passport.md §3, DELIVERY_PLAN T11 / Demo 4).
//
//   db.sanctions.watch([{ $match: { operationType: { $in: ['insert','update','replace'] } } }],
//                      { fullDocument: 'updateLookup', resumeAfter: watcher_state.resumeToken })
//
// Per change event:
//   1. affected agents = agents.wallets.address ∈ doc.wallets.address
//                      ∪ transactions.counterparty.address ∈ doc.wallets.address (distinct agentId)
//   2. per agent: passport ACTIVE|REVIEW → RE_SCREENING (system actor)
//   3. run the pipeline with trigger 'sanctions_change' over the agent wallet plus its recent
//      counterparties ∪ the counterparties that matched in step 1 (so the sanctioned address is
//      always in scope, whatever its age)
//   4. passport RE_SCREENING → SUSPENDED | REVIEW | ACTIVE by riskDecision BLOCK | REVIEW | ALLOW
//   5. only then persist the resume token in `watcher_state` (at-least-once delivery).
//
// Idempotency (an event can be delivered again after a crash): the passport transitions are
// conditional (`updateIf` on the current status); the investigation id is derived from
// (changeEventId, agentId), so a replay finds the investigation it already wrote.
//
// Failure handling: an event whose processing throws is retried in place (`maxAttempts`, backoff)
// without advancing the stream. When the attempts are exhausted it is dead-lettered: the error
// is recorded in `watcher_state.deadLetters` and every affected passport still RE_SCREENING is
// failed closed to SUSPENDED (INTERNAL_ERROR); then the token advances so later sanctions changes
// are not blocked. If even the dead-letter write fails, the stream is closed and reopened from
// the last persisted token, so the event is delivered again — it is never silently skipped.
//
// Addresses: `sanctions.wallets.address` and `transactions.counterparty.address` are enforced
// lowercase by their collection validators (migrations.js EVM_ADDRESS) and seeded agents'
// wallets are lowercased by src/seed/hackathon.js, so an exact `$in` on lowercased values is the
// complete match.
//
// Atlas only: requires `store.db` and `store.capabilities.changeStreams` (src/server.js starts it).
import { canonicalJson } from '../crypto/canonical.js';
import { sha256hex } from '../crypto/ed25519.js';
import { ConflictError } from '../errors.js';
import { loadActiveHarness } from '../harness/policy.js';
import { runInvestigation } from '../investigation/pipeline.js';
import { isLegalTransition, passportService, SYSTEM_ACTOR } from '../services/passports.js';
import { receiptIdFor, receiptService } from '../services/receipts.js';

export const WATCHER_ID = 'sanctions';
export const WATCHED_COLLECTION = 'sanctions';
export const WATCHER_STATE_COLLECTION = 'watcher_state';
export const RESCREEN_WINDOW_DAYS = 90;
export const CHANGE_STREAM_PIPELINE = Object.freeze([
  Object.freeze({ $match: Object.freeze({ operationType: Object.freeze({ $in: Object.freeze(['insert', 'update', 'replace']) }) }) }),
]);
/** investigation-pipeline.md §6: sanctions_change passport effect by riskDecision. */
export const PASSPORT_BY_DECISION = Object.freeze({ BLOCK: 'SUSPENDED', REVIEW: 'REVIEW', ALLOW: 'ACTIVE' });

const DAY = 86_400_000;
const MAX_DEAD_LETTERS = 50;
const MAX_COUNTERPARTIES = 500;
const EVM_ADDRESS_RE = /^0x[0-9a-f]{40}$/;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const noopLogger = { debug() {}, info() {}, warn() {}, error() {} };

/** Stable id of a change event, derived from its resume token. */
export function changeEventId(token) {
  const raw = typeof token?._data === 'string' ? token._data : canonicalJson(token ?? null);
  return `chg_${sha256hex(Buffer.from(raw, 'utf8')).slice(0, 32)}`;
}

/** Deterministic investigation id per (change event, agent): a replay finds the same document. */
export function investigationIdFor(eventId, agentId) {
  return `inv_${sha256hex(Buffer.from(`${eventId}:${agentId}`, 'utf8')).slice(0, 26).toUpperCase()}`;
}

/** Lowercased, well-formed wallet addresses listed by a sanctions document. */
export function sanctionedAddresses(doc) {
  const out = new Set();
  for (const w of doc?.wallets ?? []) {
    const a = typeof w?.address === 'string' ? w.address.trim().toLowerCase() : null;
    if (a && EVM_ADDRESS_RE.test(a)) out.add(a);
  }
  return [...out];
}

/**
 * Affected agents for a set of sanctioned addresses. Returns Map agentId →
 * { viaWallet: address[], viaCounterparty: [{ address, name }] }.
 */
export async function findAffectedAgents(db, addresses) {
  const affected = new Map();
  if (!addresses.length) return affected;
  const entry = (agentId) => {
    if (!affected.has(agentId)) affected.set(agentId, { viaWallet: [], viaCounterparty: [] });
    return affected.get(agentId);
  };
  const agents = await db
    .collection('agents')
    .find({ 'wallets.address': { $in: addresses } }, { projection: { wallets: 1 } })
    .toArray();
  for (const a of agents) {
    for (const w of a.wallets ?? []) if (addresses.includes(w.address)) entry(a._id).viaWallet.push(w.address);
  }
  const counterparties = await db
    .collection('transactions')
    .aggregate([
      { $match: { 'counterparty.address': { $in: addresses } } },
      { $sort: { at: -1 } },
      { $group: { _id: { agentId: '$agentId', address: '$counterparty.address' }, name: { $first: '$counterparty.name' } } },
      { $sort: { '_id.agentId': 1, '_id.address': 1 } },
    ])
    .toArray();
  for (const c of counterparties) entry(c._id.agentId).viaCounterparty.push({ address: c._id.address, name: c.name ?? null });
  return new Map([...affected.entries()].sort(([a], [b]) => a.localeCompare(b)));
}

/** Distinct counterparties of the agent's last RESCREEN_WINDOW_DAYS of transactions (date filter in the query). */
async function recentCounterparties(store, agentId, now) {
  const since = new Date(now.getTime() - RESCREEN_WINDOW_DAYS * DAY);
  if (store.db) {
    const rows = await store.db
      .collection('transactions')
      .aggregate([
        { $match: { agentId, at: { $gte: since } } },
        { $sort: { at: -1 } },
        { $group: { _id: '$counterparty.address', name: { $first: '$counterparty.name' } } },
        { $sort: { _id: 1 } },
        { $limit: MAX_COUNTERPARTIES },
      ])
      .toArray();
    return rows.map((r) => ({ address: r._id, name: r.name ?? null }));
  }
  // MemoryStore CRUD double (unit tests).
  const byAddress = new Map();
  const txs = (await store.transactions.find({ agentId })).filter((t) => new Date(t.at) >= since).sort((a, b) => new Date(b.at) - new Date(a.at));
  for (const t of txs) if (!byAddress.has(t.counterparty?.address)) byAddress.set(t.counterparty?.address, t.counterparty?.name ?? null);
  return [...byAddress.entries()]
    .filter(([a]) => a)
    .sort(([a], [b]) => a.localeCompare(b))
    .slice(0, MAX_COUNTERPARTIES)
    .map(([address, name]) => ({ address, name }));
}

/**
 * Re-screen one agent after a sanctions change (steps 2–4). Works on any store (the pipeline's
 * `$search` stage needs Atlas when counterparty names are present). `hooks.onStep(step, ctx)` is a
 * test seam to inject failures between steps.
 */
export function rescreenService({ store, clock, audit, events = null, logger = noopLogger, hooks = {} }) {
  const passports = passportService({ store, clock, audit });
  const receipts = receiptService({ store, audit });
  const publish = (type, data) => events?.publish(type, data);
  const step = async (name, ctx) => hooks.onStep?.(name, ctx);

  async function transition(passport, from, to, reason, investigationId = null) {
    const updated = await passports.transition(passport.id, from, to, reason, SYSTEM_ACTOR, { investigationId });
    const history = updated.statusHistory ?? [];
    const fromStatus = history.length >= 2 ? history[history.length - 2].status : null;
    publish('passport.status_changed', { passportId: updated.id, agentId: updated.agentId, from: fromStatus, to, investigationId });
    return updated;
  }

  /** Fail closed after a dead-lettered event: RE_SCREENING → SUSPENDED (INTERNAL_ERROR). */
  async function failClosed(agentId, triggerRef) {
    const p = await passports.findByAgent(agentId);
    if (!p || p.status !== 'RE_SCREENING') return null;
    const updated = await transition(p, ['RE_SCREENING'], 'SUSPENDED', 'INTERNAL_ERROR');
    publish('passport_suspended', { agentId, passportId: p.id, investigationId: null, reasonCode: 'INTERNAL_ERROR', ...triggerRef });
    return updated;
  }

  async function rescreenAgent({ agentId, triggerRef, matched = { viaWallet: [], viaCounterparty: [] } }) {
    const ctx = { agentId, triggerRef };
    let passport = await passports.findByAgent(agentId);
    const invId = investigationIdFor(triggerRef.changeEventId, agentId);
    let inv = await store.investigations.findById(invId);

    // Step 2: → RE_SCREENING (or resume a re-screen interrupted mid-way).
    if (passport) {
      if (passport.status === 'ACTIVE' || passport.status === 'REVIEW') {
        passport = await transition(passport, ['ACTIVE', 'REVIEW'], 'RE_SCREENING', `sanctions change ${triggerRef.sanctionsId} (dataset ${triggerRef.datasetVersion})`);
        publish('rescreen_started', { agentId, passportId: passport.id, resumed: false, ...triggerRef });
      } else if (passport.status === 'RE_SCREENING') {
        publish('rescreen_started', { agentId, passportId: passport.id, resumed: true, ...triggerRef });
      } else if (!inv) {
        // SUSPENDED / REVOKED for another reason: already blocked, nothing to re-evaluate.
        logger.info('sanctions watcher: passport already blocked, re-screen skipped', { agentId, status: passport.status });
        return { agentId, skipped: passport.status, investigationId: null, passportStatus: passport.status };
      }
    }
    await step('rescreen_started', ctx);

    // Step 3: the sanctions_change investigation (written once per change event and agent).
    if (!inv) inv = await investigate({ id: invId, agentId, passport, triggerRef, matched });
    await step('investigation_recorded', { ...ctx, investigationId: inv.id });

    // Step 4: passport by riskDecision.
    const target = PASSPORT_BY_DECISION[inv.riskDecision] ?? 'SUSPENDED';
    if (passport && passport.status === 'RE_SCREENING') {
      passport = await transition(passport, ['RE_SCREENING'], target, inv.reasons?.[0]?.code ?? inv.riskDecision, inv.id);
      if (target === 'SUSPENDED') {
        publish('passport_suspended', { agentId, passportId: passport.id, investigationId: inv.id, reasonCode: inv.reasons?.[0]?.code ?? null, ...triggerRef });
      }
    }
    return { agentId, investigationId: inv.id, riskDecision: inv.riskDecision, passportStatus: passport?.status ?? null };
  }

  async function investigate({ id, agentId, passport, triggerRef, matched }) {
    const now = clock.now();
    const agent = await store.agents.findById(agentId);
    const harness = await loadActiveHarness(store);
    const delegationId = passport?.delegationId ?? null;
    const grant = delegationId ? await store.grants.findById(delegationId) : null;
    const wallet = passport?.wallet ?? agent?.wallets?.[0]?.address ?? null;

    const byAddress = new Map((await recentCounterparties(store, agentId, now)).map((c) => [c.address, c]));
    for (const c of matched.viaCounterparty) if (!byAddress.has(c.address)) byAddress.set(c.address, c);
    const counterparties = [...byAddress.values()];
    const primary = matched.viaCounterparty[0] ?? (matched.viaWallet[0] ? { address: matched.viaWallet[0], name: null } : counterparties[0] ?? null);
    const transaction = {
      asset: grant?.asset ?? grant?.constraints?.currency ?? 'USDC',
      amount: null,
      wallet,
      counterparty: { address: primary?.address ?? null, name: primary?.name ?? null },
    };

    const r = await runInvestigation({
      store,
      agentId,
      delegationId,
      policy: harness.policy,
      trigger: 'sanctions_change',
      now,
      invariantsMatch: harness.invariantsMatch,
      harness,
      // Every counterparty (and its name, via `$search`) is screened: the primary one plus the rest.
      tx: {
        id,
        asset: transaction.asset,
        amount: null,
        wallet,
        counterparty: transaction.counterparty,
        counterparties: counterparties.filter((c) => c.address !== transaction.counterparty.address),
        signingKeyThumbprint: agent?.keyThumbprint ?? null,
      },
    });

    const doc = {
      id,
      trigger: 'sanctions_change',
      triggerRef,
      initiatedBy: { role: 'system', apiKeyId: null, ownerId: null },
      agentId,
      principalId: agent?.operatorId ?? passport?.principalId ?? null,
      businessId: grant?.businessId ?? null,
      delegationId,
      delegationVersion: grant?.version ?? null,
      action: null,
      transaction,
      screenedCounterparties: counterparties,
      harnessVersion: harness.version,
      stages: r.stages,
      signals: r.signals,
      memory: r.memory ?? { engine: '$vectorSearch', k: harness.policy.memoryRetrieval.k, minScorePpm: harness.policy.memoryRetrieval.minScorePpm, hits: [] },
      decision: r.decision,
      riskDecision: r.riskDecision,
      reasons: r.reasons,
      status: r.riskDecision === 'REVIEW' ? 'AWAITING_REVIEW' : 'DECIDED',
      outcome: null,
      confirmedBy: null,
      confirmedAt: null,
      passport: passport ? { id: passport.id, fromStatus: 'RE_SCREENING', toStatus: PASSPORT_BY_DECISION[r.riskDecision] ?? 'SUSPENDED' } : null,
      receiptId: null,
      receiptHash: null,
      requestId: null,
      createdAt: now,
      decidedAt: clock.now(),
    };
    // An unauditable decision must not stand: a failed audit write throws and the event is retried.
    await audit.record(SYSTEM_ACTOR, 'investigation.decided', { type: 'investigation', id }, {
      agentId,
      trigger: doc.trigger,
      riskDecision: doc.riskDecision,
      reasonCode: doc.reasons[0]?.code ?? null,
      delegationId,
      sanctionsId: triggerRef.sanctionsId,
      datasetVersion: triggerRef.datasetVersion,
      changeEventId: triggerRef.changeEventId,
    });
    // Receipt before the investigation (investigation-pipeline.md §6). A redelivered event reuses
    // the receipt already issued for this deterministic investigation id; a failure throws and
    // the event is retried like any other unrecorded decision.
    const issued = await store.receipts.findById(receiptIdFor(id));
    const receipt = issued ? (({ id: _id, agentId: _agentId, ...r }) => r)(issued) : await receipts.issue(SYSTEM_ACTOR, doc, { issuedAt: doc.decidedAt });
    Object.assign(doc, { receipt, receiptId: receipt.receiptId, receiptHash: receipt.receiptHash });
    try {
      await store.investigations.insert(doc);
    } catch (err) {
      if (!(err instanceof ConflictError)) throw err;
      const existing = await store.investigations.findById(id);
      if (!existing) throw err;
      return existing;
    }
    publish('investigation.decided', { investigationId: id, agentId, trigger: doc.trigger, riskDecision: doc.riskDecision });
    return doc;
  }

  return { rescreenAgent, failClosed, passports };
}

export class SanctionsWatcher {
  /**
   * @param {{ store, clock?, audit, events?, logger?, maxAttempts?, retryDelayMs?, maxAwaitTimeMS?,
   *           reopenDelayMs?, idleCheckpointMs?, hooks? }} opts
   */
  constructor({ store, clock = { now: () => new Date() }, audit, events = null, logger = noopLogger, maxAttempts = 3, retryDelayMs = 500, maxAwaitTimeMS = 1000, reopenDelayMs = 1000, idleCheckpointMs = 30_000, hooks = {} }) {
    if (!audit) throw new TypeError('SanctionsWatcher: audit service is required');
    this.store = store;
    this.clock = clock;
    this.events = events;
    this.logger = logger;
    this.maxAttempts = maxAttempts;
    this.retryDelayMs = retryDelayMs;
    this.maxAwaitTimeMS = maxAwaitTimeMS;
    this.reopenDelayMs = reopenDelayMs;
    this.idleCheckpointMs = idleCheckpointMs;
    this.hooks = hooks;
    this.rescreen = rescreenService({ store, clock, audit, events, logger, hooks });
    this.stats = { processed: 0, deadLettered: 0, lastEventAt: null, lastChangeEventId: null };
    this._running = false;
    this._killed = false;
    this._stream = null;
    this._loop = null;
  }

  get running() {
    return this._running;
  }

  _state() {
    return this.store.db.collection(WATCHER_STATE_COLLECTION);
  }

  async _setState(set, extra = {}) {
    await this._state().updateOne({ _id: WATCHER_ID }, { $set: { ...set, updatedAt: this.clock.now() }, ...extra }, { upsert: true });
  }

  /** Open the change stream from the persisted token (or the persisted start time). */
  async _open() {
    const db = this.store.db;
    const state = await this._state().findOne({ _id: WATCHER_ID });
    const opts = { fullDocument: 'updateLookup', maxAwaitTimeMS: this.maxAwaitTimeMS };
    let from;
    if (state?.resumeToken) {
      opts.resumeAfter = state.resumeToken;
      from = 'resumeToken';
    } else {
      // First start: pin the start to a cluster time persisted *before* reading, so a crash
      // before the first token is saved still replays everything from this point.
      let at = state?.startAtOperationTime ?? null;
      if (!at) {
        const hello = await db.command({ hello: 1 });
        at = hello.operationTime ?? hello.$clusterTime?.clusterTime ?? null;
        if (!at) throw new Error('sanctions watcher: cluster time unavailable (change streams need a replica set)');
        await this._setState({ resumeToken: null, startAtOperationTime: at, lastEventAt: null, lastDatasetVersion: null });
      }
      opts.startAtOperationTime = at;
      from = 'startAtOperationTime';
    }
    const stream = db.collection(WATCHED_COLLECTION).watch([...CHANGE_STREAM_PIPELINE], opts);
    // Surface open errors (e.g. an expired resume token) here instead of on the first read.
    await stream.tryNext().then(
      (first) => {
        stream._kyaFirst = first;
      },
      async (err) => {
        await stream.close().catch(() => {});
        throw err;
      },
    );
    this.logger.info('sanctions watcher: change stream open', { from });
    return stream;
  }

  /**
   * Start watching. Resolves once the change stream is open; rejects (and stops) if the first
   * open fails. Later stream errors are retried by reopening from the persisted token.
   */
  async start() {
    if (!this.store?.db || !this.store.capabilities?.changeStreams) throw new Error('sanctions watcher requires MongoDB change streams (Atlas replica set)');
    if (this._running) return;
    this._running = true;
    this._killed = false;
    let opened;
    const firstOpen = new Promise((resolve, reject) => {
      opened = { resolve, reject };
    });
    this._loop = this._run(opened);
    try {
      await firstOpen;
    } catch (err) {
      this._running = false;
      await this._loop.catch(() => {});
      throw err;
    }
  }

  /** Graceful stop: finishes the event in progress (and saves its token), then closes the stream. */
  async stop() {
    this._running = false;
    await this._loop?.catch(() => {});
    this._loop = null;
  }

  /**
   * Abrupt stop (crash simulation / fatal shutdown): closes the stream immediately and never
   * persists a token for the event in progress. The next start replays it.
   */
  kill() {
    this._killed = true;
    this._running = false;
    const s = this._stream;
    this._stream = null;
    s?.close().catch(() => {});
  }

  async _run(opened) {
    let first = true;
    while (this._running) {
      let stream = null;
      try {
        stream = await this._open();
        this._stream = stream;
        if (first) {
          first = false;
          opened.resolve();
        }
        let lastCheckpoint = Date.now();
        let pending = stream._kyaFirst;
        while (this._running) {
          const change = pending ?? (await stream.tryNext());
          pending = null;
          if (!this._running) return;
          if (!change) {
            // Idle: every delivered event is processed, so the post-batch token is safe to keep.
            if (stream.resumeToken && Date.now() - lastCheckpoint >= this.idleCheckpointMs) {
              await this._setState({ resumeToken: stream.resumeToken });
              lastCheckpoint = Date.now();
            }
            continue;
          }
          const outcome = await this._process(change);
          if (this._killed) return;
          await this._setState(
            {
              resumeToken: change._id,
              lastEventAt: this.clock.now(),
              lastDatasetVersion: change.fullDocument?.datasetVersion ?? null,
              lastChangeEventId: outcome.changeEventId,
            },
            outcome.deadLetter ? { $push: { deadLetters: { $each: [outcome.deadLetter], $slice: -MAX_DEAD_LETTERS } } } : {},
          );
          lastCheckpoint = Date.now();
          this.stats.lastEventAt = this.clock.now();
          this.stats.lastChangeEventId = outcome.changeEventId;
        }
      } catch (err) {
        if (first) {
          opened.reject(err);
          return;
        }
        if (!this._running) return;
        this.logger.error('sanctions watcher: stream error, reopening from the persisted token', { error: err?.message, code: err?.code ?? null });
        await sleep(this.reopenDelayMs);
      } finally {
        if (this._stream === stream) this._stream = null;
        await stream?.close().catch(() => {});
      }
    }
  }

  /**
   * Process one change with bounded retries. Returns `{ changeEventId, deadLetter? }`; throws only
   * when the watcher is killed/stopped mid-retry or the fail-closed path itself fails.
   */
  async _process(change) {
    const eventId = changeEventId(change._id);
    let affected = null;
    let lastErr = null;
    for (let attempt = 1; attempt <= this.maxAttempts; attempt++) {
      try {
        await this.handleChange(change, {
          eventId,
          onAffected: (a) => {
            affected = a;
          },
        });
        this.stats.processed += 1;
        return { changeEventId: eventId };
      } catch (err) {
        lastErr = err;
        if (!this._running) throw err;
        this.logger.warn('sanctions watcher: event processing failed', { changeEventId: eventId, attempt, maxAttempts: this.maxAttempts, error: err?.message });
        if (attempt < this.maxAttempts) await sleep(this.retryDelayMs * attempt);
        if (!this._running) throw err;
      }
    }
    // Dead letter: fail closed on every affected passport still being re-screened.
    const doc = change.fullDocument ?? null;
    const triggerRef = { sanctionsId: doc?._id ?? change.documentKey?._id ?? null, datasetVersion: doc?.datasetVersion ?? null, changeEventId: eventId };
    const failedClosed = [];
    for (const agentId of affected ? [...affected.keys()] : []) {
      if (await this.rescreen.failClosed(agentId, triggerRef)) failedClosed.push(agentId);
    }
    this.stats.deadLettered += 1;
    this.logger.error('sanctions watcher: event dead-lettered', { changeEventId: eventId, sanctionsId: triggerRef.sanctionsId, attempts: this.maxAttempts, failedClosed });
    return {
      changeEventId: eventId,
      deadLetter: {
        changeEventId: eventId,
        resumeToken: change._id,
        sanctionsId: triggerRef.sanctionsId,
        datasetVersion: triggerRef.datasetVersion,
        operationType: change.operationType,
        attempts: this.maxAttempts,
        error: String(lastErr?.message ?? lastErr).slice(0, 500),
        affectedAgentIds: affected ? [...affected.keys()] : null,
        failedClosedAgentIds: failedClosed,
        at: this.clock.now(),
      },
    };
  }

  /** Steps 1–4 for one change event. Throws on failure (the caller retries / dead-letters). */
  async handleChange(change, { eventId = changeEventId(change._id), onAffected } = {}) {
    const doc = change.fullDocument ?? null;
    const addresses = sanctionedAddresses(doc);
    const affected = await findAffectedAgents(this.store.db, addresses);
    onAffected?.(affected);
    const triggerRef = { sanctionsId: doc?._id ?? change.documentKey?._id ?? null, datasetVersion: doc?.datasetVersion ?? null, changeEventId: eventId };
    const affectedAgentIds = [...affected.keys()];
    const detected = { ...triggerRef, operationType: change.operationType, affectedAgentIds };
    this.events?.publish('sanctions.change_detected', detected);
    this.events?.publish('change_detected', detected);
    this.logger.info('sanctions watcher: change detected', detected);

    const results = [];
    for (const [agentId, matched] of affected) {
      this.events?.publish('affected_agent', { agentId, ...triggerRef, viaWallet: matched.viaWallet, viaCounterparty: matched.viaCounterparty.map((c) => c.address) });
      results.push(await this.rescreen.rescreenAgent({ agentId, triggerRef, matched }));
    }
    return { changeEventId: eventId, affectedAgentIds, results };
  }
}

/** Legal passport target for every riskDecision (sanity check used by tests and at load). */
for (const to of Object.values(PASSPORT_BY_DECISION)) {
  if (!isLegalTransition('RE_SCREENING', to, 'system')) throw new Error(`RE_SCREENING -> ${to} is not a legal system transition`);
}
