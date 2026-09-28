// Hackathon judging scenario (DELIVERY_PLAN §5): the 12 demo documents/sets, built
// deterministically from fixtures/ and written to MongoDB Atlas by `make demo-reset`.
// Every document carries `demo: true` and a fixed id. Times are laid out relative to the
// reset day (UTC midnight) so the delegation is always unexpired and the history is always
// "the last 30 days"; everything else (ids, amounts, addresses, keys, vectors) is constant.
//
// Embeddings are read from the precomputed fixtures/embeddings.json (no network call and no
// dependency on EMBEDDINGS_MODE), so the stored vectors are identical on every reset.
import { readFileSync, readdirSync } from 'node:fs';
import { canonicalJson } from '../crypto/canonical.js';
import { keyThumbprint, sha256hex } from '../crypto/ed25519.js';
import { INVARIANTS_HASH, validatePolicy } from '../harness/invariants.js';
import { assertEmbedding, loadFixture } from '../memory/embeddings.js';
import { signalsText, textSha256 } from '../memory/signalsText.js';
import { agentKeyFromSeed } from '../sdk/agentSigner.js';

const FIXTURES = new URL('../../fixtures/', import.meta.url);
const readJson = (rel) => JSON.parse(readFileSync(new URL(rel, FIXTURES), 'utf8'));

export const DEMO_IDS = Object.freeze({
  principal: 'op_NORTHWIND',
  business: 'biz_CIRCLEPAY',
  agent: 'agt_TREASURYBOT',
  delegation: 'grt_TB_USDC',
  passport: 'pp_TREASURYBOT',
  sanctionsUpdate: 'upd_2026-09-26',
  harnessVersion: 1,
});

export const USDC = 1_000_000; // minor units per USDC (6 decimals)
const DAY = 86_400_000;
const HOUR = 3_600_000;
const EVM_ADDRESS_RE = /^0x[0-9a-f]{40}$/;
export const EMBEDDINGS_FIXTURE_FILE = 'fixtures/embeddings.json';

/**
 * Demo-only TreasuryBot keys. The Ed25519 seeds are sha256 of these PUBLIC labels, so anyone can
 * derive them: that is intended (the demo must sign requests reproducibly). Never reuse for a
 * real agent. `original` is registered and signed the whole history; `rotated` is the takeover key.
 */
export const TREASURYBOT_KEY_LABELS = Object.freeze({
  original: 'kyagent-demo/treasurybot/signing-key/original',
  rotated: 'kyagent-demo/treasurybot/signing-key/rotated',
});

export function treasuryBotKey(which = 'original') {
  const label = TREASURYBOT_KEY_LABELS[which];
  if (!label) throw new Error(`unknown TreasuryBot key ${which}`);
  const key = agentKeyFromSeed(sha256hex(label));
  return { ...key, thumbprint: keyThumbprint(key.publicKey) };
}

/** Adaptive policy v1 (harness.md §3.2). */
export const HARNESS_V1_POLICY = Object.freeze({
  steps: ['identity', 'delegation', 'sanctions', 'signals', 'memory', 'policy'],
  memoryRetrieval: { k: 3, numCandidates: 100, minScorePpm: 780000, filter: { status: 'VERIFIED' } },
  contextAssembly: { maxMemories: 3, includeSignalStats: true, includeSanctionsEvidence: true },
  evidenceRequests: [],
  escalation: [
    {
      id: 'precedent_takeover',
      when: { precedentOutcomeIn: ['CONFIRMED_ACCOUNT_TAKEOVER'] },
      then: { riskDecision: 'REVIEW', reasonCode: 'MEMORY_PRECEDENT_TAKEOVER' },
    },
  ],
});

/** Collections written by the seed, in insertion order. */
export const SEEDED_COLLECTIONS = Object.freeze([
  'operators',
  'businesses',
  'agents',
  'grants',
  'transactions',
  'security_memories',
  'sanctions',
  'sanctions_updates',
  'passports',
  'harness_versions',
]);

/** Runtime collections emptied by reset (harness_versions is then restored to v1 only). */
export const RUNTIME_COLLECTIONS = Object.freeze(['investigations', 'harness_events', 'watcher_state', 'passports', 'receipts', 'harness_versions']);

const utcDay = (d) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
const datasetDate = (v) => {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) throw new Error(`bad datasetVersion ${v}`);
  return new Date(`${v}T00:00:00.000Z`);
};

function address(a, where) {
  if (typeof a !== 'string' || !EVM_ADDRESS_RE.test(a)) throw new Error(`${where}: not a lowercased EVM address`);
  return a;
}

function memoryDoc(m, anchor, fixture) {
  const text = signalsText(m.signals);
  const sha = textSha256(text);
  if (m.embeddingRef?.file !== EMBEDDINGS_FIXTURE_FILE || m.embeddingRef?.sha256 !== sha) {
    throw new Error(`${m._id}: embeddingRef does not match sha256(signalsText(signals))`);
  }
  const entry = Object.hasOwn(fixture.vectors, sha) ? fixture.vectors[sha] : null;
  if (!entry || entry.text !== text) throw new Error(`${m._id}: no precomputed embedding for its signalsText`);
  const at = (daysAgo) => (daysAgo === null ? null : new Date(anchor - daysAgo * DAY));
  return {
    _id: m._id,
    title: m.title,
    summary: m.summary,
    status: m.status,
    outcome: m.outcome,
    signals: [...m.signals],
    signalsText: text,
    embedding: assertEmbedding([...entry.embedding]),
    embeddingModel: fixture.model,
    embeddingTextSha256: sha,
    recommendedSteps: [...m.recommendedSteps],
    sourceInvestigationId: m.sourceInvestigationId,
    agentId: m.agentId,
    principalId: m.principalId,
    verifiedBy: m.verifiedBy ? { ...m.verifiedBy } : null,
    verifiedAt: at(m.verifiedDaysAgo),
    createdAt: at(m.createdDaysAgo),
    demo: true,
  };
}

/**
 * Build every demo document. Pure: same `now` (same UTC day) ⇒ deep-equal output.
 * Returns `{ [collection]: doc[] }` for SEEDED_COLLECTIONS.
 */
export function buildHackathonDocs({ now = new Date() } = {}) {
  const anchor = utcDay(now).getTime();
  const ago = (days, hours = 0) => new Date(anchor - days * DAY + hours * HOUR);
  const ids = DEMO_IDS;

  const txFixture = readJson('transactions/treasurybot.json');
  const baseline = readJson('sanctions/baseline-2026-09-01.json');
  const update = readJson('sanctions/update-2026-09-26.json');
  const embeddings = loadFixture();

  const wallet = address(txFixture.wallet, 'TreasuryBot wallet');
  const original = treasuryBotKey('original');
  const counterparties = Object.fromEntries(
    Object.entries(txFixture.counterparties).map(([k, c]) => [k, { address: address(c.address, `counterparty ${k}`), name: c.name }]),
  );

  // 1. principal (operator)
  const principalCreated = ago(180);
  const operators = [
    {
      _id: ids.principal,
      type: 'organization',
      legalName: 'Northwind Treasury Ltd',
      contactEmail: 'treasury-ops@northwind.example',
      country: 'GB',
      status: 'verified',
      verification: { method: 'fixture', kycResult: 'pass', sanctionsMode: 'fixture', sanctionsResult: 'clear', checkedAt: ago(179) },
      statusReason: null,
      createdAt: principalCreated,
      updatedAt: ago(179),
      demo: true,
    },
  ];

  // 2. relying party
  const businesses = [{ _id: ids.business, name: 'CirclePay Merchant (demo)', status: 'active', createdAt: ago(180), demo: true }];

  // 3. agent with wallet and signing-key history
  const agentCreated = ago(120);
  const agents = [
    {
      _id: ids.agent,
      operatorId: ids.principal,
      name: 'TreasuryBot',
      description: 'Autonomous USDC treasury agent for Northwind (demo)',
      publicKey: original.publicKey,
      keyThumbprint: original.thumbprint,
      status: 'active',
      statusReason: null,
      createdAt: agentCreated,
      updatedAt: agentCreated,
      revokedAt: null,
      wallets: [{ chain: 'evm', address: wallet, addedAt: agentCreated }],
      signingKeyHistory: [{ thumbprint: original.thumbprint, from: agentCreated, to: null }],
      demo: true,
    },
  ];

  // 4. delegation (grant)
  const maxTxAmount = 25_000 * USDC;
  const grantCreated = ago(60);
  const grants = [
    {
      _id: ids.delegation,
      businessId: ids.business,
      agentId: ids.agent,
      operatorId: ids.principal,
      actions: ['payments:create'],
      constraints: { maxAmount: maxTxAmount, currency: 'USDC' },
      permittedTools: ['usdc.transfer'],
      asset: 'USDC',
      approvedWallet: wallet,
      maxTxAmount,
      dailyLimit: 100_000 * USDC,
      validFrom: grantCreated,
      expiresAt: ago(-30),
      status: 'active',
      version: 1,
      createdAt: grantCreated,
      revokedAt: null,
      statusReason: null,
      demo: true,
    },
  ];

  // 5. clean transaction history
  const transactions = txFixture.transactions.map((t) => {
    const cp = counterparties[t.counterparty];
    if (!cp) throw new Error(`${t._id}: unknown counterparty ${t.counterparty}`);
    const amount = t.amountUsdc * USDC;
    if (!Number.isSafeInteger(amount) || amount <= 0) throw new Error(`${t._id}: bad amount`);
    return {
      _id: t._id,
      agentId: txFixture.agentId,
      principalId: txFixture.principalId,
      delegationId: txFixture.delegationId,
      wallet,
      asset: txFixture.asset,
      amount,
      counterparty: { ...cp },
      signingKeyThumbprint: treasuryBotKey(txFixture.signingKey).thumbprint,
      status: 'settled',
      investigationId: null,
      at: ago(t.daysAgo, t.hourUtc),
      source: 'fixture',
      demo: true,
    };
  });

  // 6-8. security memories (VERIFIED takeover, irrelevant VERIFIED, UNVERIFIED look-alike)
  const memDir = new URL('memories/', FIXTURES);
  const security_memories = readdirSync(memDir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => memoryDoc(readJson(`memories/${f}`), anchor, embeddings));

  // 9. baseline sanctions dataset
  const sanctionsUpdatedAt = datasetDate(baseline.datasetVersion);
  const sanctions = baseline.entries.map((e) => ({
    _id: e._id,
    name: e.name,
    aliases: [...e.aliases],
    type: e.type,
    programs: [...e.programs],
    wallets: e.wallets.map((w, i) => ({ chain: w.chain, address: address(w.address, `${e._id}.wallets[${i}]`) })),
    datasetVersion: baseline.datasetVersion,
    source: 'fixture',
    updatedAt: sanctionsUpdatedAt,
    demo: true,
  }));

  // 10. staged (NOT applied) sanctions update
  const sanctions_updates = [
    {
      _id: update._id,
      datasetVersion: update.datasetVersion,
      status: 'staged',
      stagedAt: datasetDate(update.datasetVersion),
      appliedAt: null,
      upserts: update.upserts.map((u) => ({
        _id: u._id,
        name: u.name,
        aliases: [...u.aliases],
        type: u.type,
        programs: [...u.programs],
        wallets: u.wallets.map((w, i) => ({ chain: w.chain, address: address(w.address, `${u._id}.wallets[${i}]`) })),
        source: 'fixture',
        demo: true,
      })),
      demo: true,
    },
  ];

  // 11. passport
  const passportIssued = grantCreated;
  const passports = [
    {
      _id: ids.passport,
      agentId: ids.agent,
      principalId: ids.principal,
      delegationId: ids.delegation,
      delegationVersion: 1,
      wallet,
      status: 'ACTIVE',
      statusReason: null,
      credentialId: null,
      lastInvestigationId: null,
      sanctionsDatasetVersion: baseline.datasetVersion,
      harnessVersion: ids.harnessVersion,
      issuedAt: passportIssued,
      expiresAt: grants[0].expiresAt,
      updatedAt: passportIssued,
      statusHistory: [
        { status: 'ACTIVE', at: passportIssued, actor: { role: 'system', apiKeyId: null, ownerId: null }, reason: 'demo seed', investigationId: null },
      ],
      demo: true,
    },
  ];

  // 12. harness v1
  const policy = structuredClone(HARNESS_V1_POLICY);
  const policyErrors = validatePolicy(policy);
  if (policyErrors.length) throw new Error(`harness v1 policy invalid: ${JSON.stringify(policyErrors)}`);
  const harness_versions = [
    {
      _id: ids.harnessVersion,
      version: ids.harnessVersion,
      status: 'active',
      parentVersion: null,
      invariantsHash: INVARIANTS_HASH,
      policy,
      policyHash: sha256hex(canonicalJson(policy)),
      createdAt: new Date(anchor),
      approvedBy: { role: 'system', apiKeyId: null, ownerId: null, label: 'seed' },
      sourceEventId: null,
      demo: true,
    },
  ];

  const docs = {
    operators,
    businesses,
    agents,
    grants,
    transactions,
    security_memories,
    sanctions,
    sanctions_updates,
    passports,
    harness_versions,
  };
  assertScenario(docs, { wallet, counterparties });
  return docs;
}

/** Scenario invariants the demos depend on; a fixture edit that breaks one fails loudly. */
function assertScenario(docs, { wallet, counterparties }) {
  for (const [c, list] of Object.entries(docs)) {
    const seen = new Set();
    for (const d of list) {
      if (d.demo !== true) throw new Error(`${c}/${d._id}: missing demo:true`);
      if (seen.has(d._id)) throw new Error(`${c}: duplicate _id ${d._id}`);
      seen.add(d._id);
    }
  }
  const listed = new Set(docs.sanctions.flatMap((s) => s.wallets.map((w) => w.address)));
  for (const a of [wallet, ...Object.values(counterparties).map((c) => c.address)]) {
    if (listed.has(a)) throw new Error(`baseline sanctions must not list TreasuryBot's wallet or counterparties (${a})`);
  }
  const staged = new Set(docs.sanctions_updates.flatMap((u) => u.upserts.flatMap((s) => s.wallets.map((w) => w.address))));
  const txCounterparties = new Set(docs.transactions.map((t) => t.counterparty.address));
  if (![...staged].some((a) => txCounterparties.has(a))) {
    throw new Error("the staged sanctions update must list one of TreasuryBot's existing counterparties");
  }
}

/** Fixed ids per collection (time-independent), used by reset to find demo docs. */
export function demoIds(docs = buildHackathonDocs()) {
  const out = Object.fromEntries(Object.entries(docs).map(([c, list]) => [c, list.map((d) => d._id)]));
  // Sanctions entries created when the staged update is applied.
  out.sanctions = [...out.sanctions, ...docs.sanctions_updates.flatMap((u) => u.upserts.map((s) => s._id))];
  return out;
}

/** Expected document counts after a reset (see collectionCounts). */
export function expectedCounts(docs = buildHackathonDocs()) {
  const counts = Object.fromEntries(COUNT_SPEC.map(([c]) => [c, 0]));
  for (const c of SEEDED_COLLECTIONS) counts[c] = docs[c].length;
  return counts;
}

// [collection, filter]: what `collectionCounts` measures. Shared collections count only
// demo-scoped docs; runtime collections count everything.
const COUNT_SPEC = [
  ['operators', { demo: true }],
  ['businesses', { demo: true }],
  ['agents', { demo: true }],
  ['grants', { agentId: DEMO_IDS.agent }],
  ['transactions', { agentId: DEMO_IDS.agent }],
  ['security_memories', { demo: true }],
  ['sanctions', { demo: true }],
  ['sanctions_updates', { demo: true }],
  ['passports', {}],
  ['harness_versions', {}],
  ['investigations', {}],
  ['harness_events', {}],
  ['watcher_state', {}],
  ['receipts', {}],
  ['credentials', { agentId: DEMO_IDS.agent }],
  ['api_keys', { demo: true }],
];

export async function collectionCounts(db) {
  const out = {};
  for (const [c, filter] of COUNT_SPEC) out[c] = await db.collection(c).countDocuments(filter);
  return out;
}

/**
 * Remove the demo scenario and everything the demo produced at runtime:
 * - `demo: true` docs and the fixed demo ids in the shared collections;
 * - runtime docs scoped to TreasuryBot (pipeline transactions and memory candidates, grants,
 *   credentials, verification events, nonces) and the demo API keys installed by scripts/demo.js;
 * - every document of RUNTIME_COLLECTIONS (emptied with deleteMany so the migration-owned
 *   validators and indexes stay in place).
 * `audit_events` is never touched: it is the append-only hash chain.
 */
export async function clearHackathon(db) {
  const ids = demoIds();
  const agent = DEMO_IDS.agent;
  const byDemo = (c) => ({ $or: [{ demo: true }, { _id: { $in: ids[c] ?? [] } }] });
  const plan = [
    ['operators', byDemo('operators')],
    ['businesses', byDemo('businesses')],
    ['agents', byDemo('agents')],
    ['grants', { $or: [{ demo: true }, { _id: { $in: ids.grants } }, { agentId: agent }] }],
    ['transactions', { $or: [{ demo: true }, { _id: { $in: ids.transactions } }, { agentId: agent }] }],
    ['security_memories', { $or: [{ demo: true }, { _id: { $in: ids.security_memories } }, { agentId: agent }] }],
    ['sanctions', byDemo('sanctions')],
    ['sanctions_updates', byDemo('sanctions_updates')],
    ['credentials', { agentId: agent }],
    ['verification_events', { agentId: agent }],
    ['nonces', { agentId: agent }],
    ['api_keys', { demo: true }],
    ...RUNTIME_COLLECTIONS.map((c) => [c, {}]),
  ];
  const deleted = {};
  for (const [c, filter] of plan) {
    const res = await db.collection(c).deleteMany(filter);
    deleted[c] = (deleted[c] ?? 0) + (res?.deletedCount ?? 0);
  }
  return deleted;
}

const INT32_MIN = -(2 ** 31);
const INT32_MAX = 2 ** 31 - 1;

/**
 * BSON encoding for writes: integers outside int32 (USDC minor units, e.g. 2 400 USDC =
 * 2400000000) become BigInt so the driver stores them as int64 (`long`, as the validators
 * require) instead of double. Reads promote them back to numbers (driver default).
 */
export function toBsonIntegers(value) {
  if (typeof value === 'number') {
    return Number.isSafeInteger(value) && (value < INT32_MIN || value > INT32_MAX) ? BigInt(value) : value;
  }
  if (Array.isArray(value)) return value.map(toBsonIntegers);
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, toBsonIntegers(v)]));
  }
  return value;
}

/** Upsert every demo document (idempotent). Returns the per-collection counts written. */
export async function seedHackathon(db, { now = new Date(), docs = buildHackathonDocs({ now }) } = {}) {
  const written = {};
  for (const c of SEEDED_COLLECTIONS) {
    const list = docs[c];
    if (list.length) {
      await db.collection(c).bulkWrite(
        list.map((d) => ({ replaceOne: { filter: { _id: d._id }, replacement: toBsonIntegers(d), upsert: true } })),
        { ordered: true },
      );
    }
    written[c] = list.length;
  }
  return written;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Demo 3 (REQ-P0-3): a payment that resembles the VERIFIED takeover mem_INV-1042 without being
 * identical — rotated signing key, never-seen counterparty, amount above p95 but below the 90 %
 * ceiling (so NEAR_CEILING does not fire). Expected: REVIEW / MEMORY_PRECEDENT_TAKEOVER.
 */
export const DEMO3_CASE = Object.freeze({
  action: 'payments:create',
  context: Object.freeze({
    amount: 21_000 * USDC,
    currency: 'USDC',
    counterparty: '0x7a11000000000000000000000000000000c0ffee',
    counterpartyName: 'Unfamiliar OTC desk',
  }),
  expectedSignals: Object.freeze(['AMOUNT_ANOMALY', 'NEW_COUNTERPARTY', 'SIGNING_KEY_CHANGED']),
  expected: Object.freeze({ riskDecision: 'REVIEW', reasonCode: 'MEMORY_PRECEDENT_TAKEOVER', memoryId: 'mem_INV-1042' }),
});

// Demo 1/2 pay TreasuryBot's established counterparty A (fixtures/transactions/treasurybot.json)
// with the original, registered key: no behavioural signal fires for Demo 1.
const KNOWN_COUNTERPARTY = Object.freeze({ ...readJson('transactions/treasurybot.json').counterparties.A });

/**
 * Demo 1 (REQ-P1-1): clean payment well inside the delegation (1 500 USDC, below the 2 000 USDC
 * median) to a known counterparty. Expected: ALLOW / CLEAR, passport ACTIVE.
 */
export const DEMO1_CASE = Object.freeze({
  action: 'payments:create',
  context: Object.freeze({
    amount: 1_500 * USDC,
    currency: 'USDC',
    counterparty: KNOWN_COUNTERPARTY.address,
    counterpartyName: KNOWN_COUNTERPARTY.name,
  }),
  expected: Object.freeze({ riskDecision: 'ALLOW', reasonCode: 'CLEAR' }),
});

/**
 * Demo 2 (REQ-P1-2): the same verified agent and counterparty, 30 000 USDC over the 25 000 USDC
 * delegation maximum. Expected: BLOCK / DELEGATION_MAX_EXCEEDED wrapping the /v1/verify
 * CONSTRAINT_VIOLATION; the identity stage still passes (identity VERIFIED, action UNAUTHORIZED).
 */
export const DEMO2_CASE = Object.freeze({
  action: 'payments:create',
  context: Object.freeze({ ...DEMO1_CASE.context, amount: 30_000 * USDC }),
  expected: Object.freeze({ riskDecision: 'BLOCK', reasonCode: 'DELEGATION_MAX_EXCEEDED', identityReasonCode: 'CONSTRAINT_VIOLATION' }),
});

/**
 * The takeover precondition of Demo 3: TreasuryBot's registered signing key is replaced by the
 * `rotated` key (2 h before `now`), recorded in `signingKeyHistory`. Idempotent; undone by reset.
 */
export async function rotateTreasuryBotKey(db, { now = new Date() } = {}) {
  const rotated = treasuryBotKey('rotated');
  const agents = db.collection('agents');
  const agent = await agents.findOne({ _id: DEMO_IDS.agent });
  if (!agent) throw new Error(`${DEMO_IDS.agent} is not seeded (run make demo-reset)`);
  if (agent.keyThumbprint === rotated.thumbprint) return { rotated: false, thumbprint: rotated.thumbprint };
  const rotatedAt = new Date(now.getTime() - 2 * HOUR);
  const history = (agent.signingKeyHistory ?? []).map((h) => (h.to ? h : { ...h, to: rotatedAt }));
  await agents.updateOne(
    { _id: DEMO_IDS.agent },
    {
      $set: {
        publicKey: rotated.publicKey,
        keyThumbprint: rotated.thumbprint,
        signingKeyHistory: [...history, { thumbprint: rotated.thumbprint, from: rotatedAt, to: null }],
        updatedAt: now,
      },
    },
  );
  return { rotated: true, thumbprint: rotated.thumbprint };
}

/**
 * Prove both Atlas indexes answer real queries over the seeded data: `$search` finds the
 * Lazarus entity by name, and `$vectorSearch` (filter VERIFIED) ranks mem_INV-1042 first and
 * never returns the UNVERIFIED look-alike. Returns `{ search, vector }` evidence.
 */
export async function probeSearch(db, docs = buildHackathonDocs()) {
  const lazarus = docs.sanctions.find((s) => s._id === 'sdn_LAZARUS');
  const takeover = docs.security_memories.find((m) => m._id === 'mem_INV-1042');
  const search = await db
    .collection('sanctions')
    .aggregate([
      { $search: { index: 'sanctions_search', text: { query: lazarus.name, path: ['name', 'aliases'] } } },
      { $limit: 5 },
      { $project: { _id: 1 } },
    ])
    .toArray();
  const vector = await db
    .collection('security_memories')
    .aggregate([
      {
        $vectorSearch: {
          index: 'memory_vector',
          path: 'embedding',
          queryVector: takeover.embedding,
          numCandidates: HARNESS_V1_POLICY.memoryRetrieval.numCandidates,
          limit: HARNESS_V1_POLICY.memoryRetrieval.k,
          filter: { status: 'VERIFIED' },
        },
      },
      { $project: { _id: 1, status: 1 } },
    ])
    .toArray();
  const ok =
    search.some((d) => d._id === lazarus._id) &&
    vector[0]?._id === takeover._id &&
    vector.every((d) => d.status === 'VERIFIED');
  return { ok, search: search.map((d) => d._id), vector: vector.map((d) => d._id) };
}

/** Poll probeSearch until it passes (freshly written docs take a moment to be indexed). */
export async function waitForSearchReady(db, { docs = buildHackathonDocs(), timeoutMs = 120_000, intervalMs = 2_000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  let last;
  for (;;) {
    try {
      last = await probeSearch(db, docs);
      if (last.ok) return last;
    } catch (err) {
      last = { ok: false, error: err.message };
    }
    if (Date.now() >= deadline) {
      throw new Error(`search indexes did not answer over the seeded data within ${timeoutMs} ms: ${JSON.stringify(last)}`);
    }
    await sleep(intervalMs);
  }
}
