// Investigation evidence panels and the Continuous KYA strip (DELIVERY_PLAN T16, REQ-P1-5).
// Pure module: no DOM access. Rendering goes through an injected element factory
// `h(tag, attrs, ...children)` (app.js passes its textContent-only `el`), so the same
// code renders in the browser and in node tests. Values are shown verbatim from the
// contract payloads (Investigation, Receipt, HarnessVersion, stream events); nothing
// is invented — a missing value renders as '—'.

export const PANEL_HEADINGS = Object.freeze({
  signals: 'Current signals',
  memory: 'MongoDB security memory (Vector Search)',
  harness: (v) => `Harness v${v ?? '—'}`,
  decision: 'Decision + receipt',
});

export const PROVENANCE_NOTE = 'Additional provenance investigation invoked because of verified prior incidents';

const RISK = new Set(['ALLOW', 'REVIEW', 'BLOCK']);
const dash = (v) => (v === null || v === undefined || v === '' ? '—' : String(v));
const arr = (v) => (Array.isArray(v) ? v : []);

/** Map a stored receipt (receipt.schema.json) to the Investigation fields the panels read. */
export function fromReceipt(r) {
  if (!r || typeof r !== 'object') return null;
  return {
    id: r.investigationId,
    trigger: r.trigger,
    agentId: r.agent?.id ?? null,
    transaction: r.transaction ?? null,
    harnessVersion: r.harnessVersion,
    stages: arr(r.stages),
    signals: arr(r.signals),
    memory: { engine: r.memory?.engine, k: r.memory?.k, minScorePpm: r.memory?.minScorePpm, checked: r.memory?.checked, hits: arr(r.memory?.hits) },
    decision: r.decision,
    riskDecision: r.riskDecision,
    reasons: arr(r.reasons),
    passport: r.passport ?? null,
    receiptId: r.receiptId,
    receiptHash: r.receiptHash,
    decidedAt: r.issuedAt,
  };
}

/** Steps in harness version `version` that its parent version did not have. */
export function addedSteps(versions, version) {
  const list = arr(versions);
  const v = list.find((x) => x.version === version);
  if (!v || v.parentVersion === null || v.parentVersion === undefined) return [];
  const parent = list.find((x) => x.version === v.parentVersion);
  if (!parent) return [];
  const before = new Set(arr(parent.policy?.steps));
  return arr(v.policy?.steps).filter((s) => !before.has(s));
}

export function formatScore(hit) {
  if (typeof hit?.score === 'number' && Number.isFinite(hit.score)) return hit.score.toFixed(4);
  if (Number.isInteger(hit?.scorePpm)) return (hit.scorePpm / 1e6).toFixed(4);
  return '—';
}

export function riskStamp(h, d) {
  const known = RISK.has(d);
  return h('span', { class: `stamp ${known ? d : 'BLOCK'}`, text: known ? d : 'UNKNOWN' });
}

function panel(h, key, heading, ...body) {
  return h('section', { class: `panel evidence ${key}`, 'aria-labelledby': `ev-${key}-h` }, h('h2', { id: `ev-${key}-h`, text: heading }), ...body);
}

function facts(h, pairs) {
  return h('dl', {}, pairs.map(([k, v]) => [h('dt', { text: k }), h('dd', {}, v === null || v === undefined ? '—' : v)]));
}

const mono = (h, v) => h('span', { class: 'mono', text: dash(v), title: dash(v) });

function signalsPanel(h, inv) {
  const signals = arr(inv.signals);
  const stage = arr(inv.stages).find((s) => s.name === 'signals');
  const tx = inv.transaction;
  return panel(
    h,
    'signals',
    PANEL_HEADINGS.signals,
    signals.length
      ? h('ul', { class: 'codes' }, signals.map((s) => h('li', {}, h('span', { class: 'code flag', text: String(s) }))))
      : h('p', { class: 'muted', text: 'No behavioural signals raised for this action.' }),
    facts(h, [
      ['Agent', mono(h, inv.agentId)],
      ['Trigger', mono(h, inv.trigger)],
      ['Amount (minor units)', mono(h, tx?.amount)],
      ['Counterparty', tx ? h('span', {}, mono(h, tx.counterparty?.address), tx.counterparty?.name ? ` ${tx.counterparty.name}` : '') : '—'],
      ['Signals stage', stage ? `${stage.status} · ${stage.engine}` : '—'],
    ]),
  );
}

function memoryPanel(h, inv) {
  const mem = inv.memory ?? {};
  const hits = arr(mem.hits);
  const body = hits.length
    ? h(
        'table',
        {},
        h('caption', { class: 'muted', text: `Retrieved through Vector Search (${dash(mem.engine)}, k=${dash(mem.k)}, min score ${Number.isInteger(mem.minScorePpm) ? (mem.minScorePpm / 1e6).toFixed(2) : '—'})` }),
        h('thead', {}, h('tr', {}, ['Memory id', 'Title', 'Outcome', 'Retrieval', 'Score', 'Status', 'Precedent'].map((c) => h('th', { scope: 'col', text: c })))),
        h(
          'tbody',
          {},
          hits.map((m) =>
            h(
              'tr',
              {},
              h('td', {}, mono(h, m.memoryId)),
              h('td', { text: dash(m.title) }),
              h('td', {}, mono(h, m.outcome)),
              h('td', { text: 'Retrieved through Vector Search' }),
              h('td', { class: 'mono', text: formatScore(m) }),
              h('td', {}, m.status === 'VERIFIED' ? h('span', { class: 'badge verified', text: 'VERIFIED' }) : h('span', { class: 'badge unverified', text: `${dash(m.status)} — never precedent` })),
              h('td', { text: m.usedAsPrecedent === true ? 'yes' : m.usedAsPrecedent === false ? 'no' : '—' }),
            ),
          ),
        ),
      )
    : h('p', { class: 'muted', text: mem.checked === false ? 'Memory stage skipped for this investigation.' : 'No verified prior incidents matched (unverified memory is never used as precedent).' });
  return panel(h, 'memory', PANEL_HEADINGS.memory, body);
}

function harnessPanel(h, inv, versions) {
  const added = addedSteps(versions, inv.harnessVersion);
  const stages = arr(inv.stages);
  const ranAdded = stages.some((s) => added.includes(s.name) && s.status !== 'skipped');
  const verifiedPrecedent = arr(inv.memory?.hits).some((m) => m.status === 'VERIFIED');
  return panel(
    h,
    'harness',
    PANEL_HEADINGS.harness(inv.harnessVersion),
    ranAdded && verifiedPrecedent ? h('p', { class: 'callout', role: 'note', text: PROVENANCE_NOTE }) : null,
    stages.length
      ? h(
          'table',
          {},
          h('thead', {}, h('tr', {}, ['Stage', 'Engine', 'Status', 'ms'].map((c) => h('th', { scope: 'col', text: c })))),
          h(
            'tbody',
            {},
            stages.map((s) =>
              h(
                'tr',
                { class: added.includes(s.name) ? 'added-step' : '' },
                h('td', {}, mono(h, s.name), added.includes(s.name) ? h('span', { class: 'badge added', text: `added in v${inv.harnessVersion}` }) : null),
                h('td', {}, mono(h, s.engine)),
                h('td', { class: `st ${/^[a-z]+$/.test(s.status) ? s.status : ''}`, text: dash(s.status) }),
                h('td', { class: 'mono', text: dash(s.durationMs) }),
              ),
            ),
          ),
        )
      : h('p', { class: 'muted', text: 'No stage results recorded.' }),
    versions === null
      ? h('p', { class: 'muted', role: 'alert', text: 'Harness versions could not be loaded; added steps are unknown.' })
      : added.length
        ? null
        : h('p', { class: 'muted', text: 'No step added relative to the parent harness version.' }),
  );
}

function decisionPanel(h, inv, onReceipt) {
  const reasons = arr(inv.reasons);
  const p = inv.passport;
  return panel(
    h,
    'decision',
    PANEL_HEADINGS.decision,
    h('p', { class: 'verdict' }, riskStamp(h, inv.riskDecision), ' ', h('span', { class: 'muted', text: `identity ${dash(inv.decision)}` })),
    facts(h, [
      ['Reasons', reasons.length ? h('span', {}, reasons.map((r) => h('div', {}, mono(h, r.code), r.invariantId ? [' ', mono(h, r.invariantId)] : null, r.message ? ` — ${r.message}` : ''))) : '—'],
      ['Passport', p ? h('span', {}, mono(h, p.before), ' → ', mono(h, p.after)) : '—'],
      ['Investigation', mono(h, inv.id)],
      ['Receipt', mono(h, inv.receiptId)],
      ['Receipt hash', mono(h, inv.receiptHash)],
      ['Decided', dash(inv.decidedAt)],
    ]),
    inv.id && onReceipt ? h('button', { type: 'button', class: 'secondary', text: 'Open receipt', onclick: () => onReceipt(inv.id) }) : null,
  );
}

/** The four evidence panels for one investigation. */
export function renderInvestigation(h, inv, { versions = null, onReceipt } = {}) {
  return h('div', { class: 'evidence-grid' }, signalsPanel(h, inv), memoryPanel(h, inv), harnessPanel(h, inv, versions), decisionPanel(h, inv, onReceipt));
}

// ------------------------------------------------------------------ Continuous KYA strip

export const KYA_STEPS = Object.freeze([
  { type: 'change_detected', label: 'MongoDB Change Detected' },
  { type: 'affected_agent', label: 'Affected Agent Found' },
  { type: 'rescreen_started', label: 'Re-screen Started' },
  { type: 'passport_suspended', label: 'Passport Suspended' },
]);

export function kyaStripInit() {
  return { steps: KYA_STEPS.map((s) => ({ ...s, done: false, detail: null, at: null })), agentId: null };
}

function stepDetail(type, d) {
  if (type === 'change_detected') return `${dash(d.sanctionsId)} · dataset ${dash(d.datasetVersion)} · ${arr(d.affectedAgentIds).length} affected`;
  if (type === 'passport_suspended') return `${dash(d.agentId)} · ${dash(d.reasonCode)}`;
  return dash(d.agentId);
}

/** Apply one stream event `{ type, data }`; returns a new strip state (unknown types leave it unchanged). */
export function kyaStripApply(state, event) {
  let type = event?.type;
  const data = event?.data ?? {};
  if (type === 'passport.status_changed' && data.to === 'SUSPENDED') type = 'passport_suspended';
  const idx = KYA_STEPS.findIndex((s) => s.type === type);
  if (idx < 0) return state;
  const base = type === 'change_detected' ? kyaStripInit() : state;
  const steps = base.steps.map((s, i) => (i === idx ? { ...s, done: true, detail: stepDetail(type, data), at: data.at ?? null } : s));
  return { steps, agentId: data.agentId ?? base.agentId };
}

export function renderKyaStrip(h, state) {
  return h(
    'ol',
    { class: 'kya-steps' },
    state.steps.map((s, i) =>
      h(
        'li',
        { class: `kya-step ${s.done ? 'done' : 'waiting'}${s.type === 'passport_suspended' && s.done ? ' critical' : ''}`, 'aria-current': s.done && !state.steps[i + 1]?.done ? 'step' : undefined },
        h('span', { class: 'kya-label', text: s.label }),
        h('span', { class: 'kya-detail mono', text: s.done ? s.detail : 'waiting' }),
      ),
    ),
  );
}

/** Incremental text/event-stream parser: push(chunk) calls onEvent({ type, data }) per complete frame. */
export function createSseParser(onEvent) {
  let buf = '';
  return (chunk) => {
    buf += chunk.replace(/\r\n?/g, '\n');
    let end;
    while ((end = buf.indexOf('\n\n')) >= 0) {
      const frame = buf.slice(0, end);
      buf = buf.slice(end + 2);
      let type = 'message';
      const data = [];
      for (const line of frame.split('\n')) {
        if (line.startsWith('event:')) type = line.slice(6).trim();
        else if (line.startsWith('data:')) data.push(line.slice(5).replace(/^ /, ''));
      }
      if (!data.length) continue;
      try {
        onEvent({ type, data: JSON.parse(data.join('\n')) });
      } catch {
        // malformed frame: ignore rather than render untrusted text
      }
    }
  };
}
