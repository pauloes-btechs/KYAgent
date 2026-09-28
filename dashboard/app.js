// KYAgent dashboard — a thin view over the public API (no privileged backdoor).
// Security notes:
//  * The API key lives only in this module's memory: never localStorage, cookies or URLs.
//  * All server data is rendered with textContent (never innerHTML): agent names,
//    reasons etc. are untrusted.
//  * Deny by default: actions are shown only for roles the RBAC matrix allows, and
//    any error hides data rather than guessing.

import { denyCountsByReason, trustAssessment } from '/dashboard/trust.js';
import { createSseParser, fromReceipt, kyaStripApply, kyaStripInit, renderInvestigation, renderKyaStrip, riskStamp } from '/dashboard/investigations.js';

const IDLE_MS = 30 * 60 * 1000;
const state = { key: null, role: null, keyPrefix: null, idleTimer: null, stream: null, strip: kyaStripInit(), live: [], onLive: null };
const $ = (id) => document.getElementById(id);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

function toast(message) {
  const t = $('toast');
  t.textContent = message;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3500);
}

// ------------------------------------------------------------------ API client
class ApiFailure extends Error {
  constructor(status, body) {
    super(body?.error?.message || `Request failed (${status})`);
    this.status = status;
    this.code = body?.error?.code;
    this.body = body;
  }
}

async function api(method, path, body) {
  return (await apiResponse(method, path, body)).json;
}

async function apiResponse(method, path, body) {
  if (!state.key) throw new ApiFailure(401);
  const headers = { Authorization: `Bearer ${state.key}` };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: 'no-store', credentials: 'omit' });
  let json = null;
  try {
    json = await res.json();
  } catch {
    json = null;
  }
  if (res.status === 401 && state.role) {
    signOut('Your API key was rejected. It may have been revoked.');
    throw new ApiFailure(401, json);
  }
  if (!res.ok && !(path === '/v1/verify' && json && json.decision)) throw new ApiFailure(res.status, json);
  return { json, headers: res.headers };
}

async function probe(path) {
  const res = await fetch(path, { headers: { Authorization: `Bearer ${state.key}` }, cache: 'no-store', credentials: 'omit' });
  return res.status;
}

// ------------------------------------------------------------------ auth
async function signIn(key) {
  state.key = key;
  const admin = await probe('/v1/api-keys?limit=1');
  if (admin === 401) throw new Error('That API key was not accepted.');
  let role = null;
  if (admin === 200) role = 'admin';
  else if ((await probe('/v1/agents?limit=1')) === 200) role = 'operator';
  else if ((await probe('/v1/grants?limit=1')) === 200) role = 'business';
  if (!role) throw new Error('Could not determine the role for this key.');
  state.role = role;
  state.keyPrefix = key.slice(0, 34);
  try {
    const health = await (await fetch('/healthz', { cache: 'no-store' })).json();
    $('env-chip').hidden = health.store !== 'memory';
  } catch {
    $('env-chip').hidden = true;
  }
  $('role-chip').textContent = `${role} · ${state.keyPrefix}`;
  $('signin').hidden = true;
  $('shell').hidden = false;
  buildNav();
  bumpIdle();
  if (role === 'admin') startKyaStream();
  if (!location.hash || !routeFor(location.hash)) location.hash = `#/${navItems()[0].route}`;
  else render();
}

function signOut(message) {
  state.key = null;
  state.role = null;
  clearTimeout(state.idleTimer);
  stopKyaStream();
  $('apikey').value = '';
  $('shell').hidden = true;
  $('signin').hidden = false;
  $('content').replaceChildren();
  $('signin-error').textContent = message || '';
}

function bumpIdle() {
  clearTimeout(state.idleTimer);
  if (state.key) state.idleTimer = setTimeout(() => signOut('Signed out after 30 minutes of inactivity.'), IDLE_MS);
}

// ------------------------------------------------------------------ navigation
const NAV = [
  { group: 'Identity', route: 'operators', label: 'Operators', roles: ['admin'], view: operatorsView },
  { group: 'Identity', route: 'agents', label: 'Agents', roles: ['admin', 'operator'], view: agentsView },
  { group: 'Identity', route: 'lookup', label: 'Agent lookup', roles: ['business'], view: lookupView },
  { group: 'Authorization', route: 'grants', label: 'Grants', roles: ['admin', 'operator', 'business'], view: grantsView },
  { group: 'Authorization', route: 'credentials', label: 'Credentials', roles: ['admin', 'operator', 'business'], view: credentialsView },
  { group: 'Decisions', route: 'investigations', label: 'Investigations', roles: ['admin', 'business'], view: investigationsView },
  { group: 'Decisions', route: 'verifications', label: 'Verifications (audit log)', roles: ['admin', 'business'], view: verificationsView },
  { group: 'Admin', route: 'api-keys', label: 'API keys', roles: ['admin'], view: apiKeysView },
];

const navItems = () => NAV.filter((n) => n.roles.includes(state.role));
const routeFor = (hash) => navItems().find((n) => `#/${n.route}` === hash.split('?')[0]);

function buildNav() {
  const nav = $('nav');
  nav.replaceChildren();
  let group = null;
  for (const item of navItems()) {
    if (item.group !== group) {
      group = item.group;
      nav.append(el('h2', { text: group }));
    }
    nav.append(el('a', { href: `#/${item.route}`, 'data-route': item.route, text: item.label }));
  }
}

function render() {
  if (!state.key) return;
  const item = routeFor(location.hash) || navItems()[0];
  for (const a of $('nav').querySelectorAll('a')) {
    if (a.dataset.route === item.route) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  $('page-title').textContent = item.label;
  const main = $('content');
  main.replaceChildren();
  state.onLive = null;
  item.view(main);
}

// ------------------------------------------------------------------ building blocks
const fmtTime = (iso) => (iso ? new Date(iso).toLocaleString() : '—');
const mono = (v) => el('span', { class: 'mono', text: v ?? '—', title: v ?? '' });
const status = (s) => el('span', { class: `status ${/^[a-z]+$/.test(s) ? s : ''}`, text: s });
const stamp = (d) => el('span', { class: `stamp ${d === 'ALLOW' ? 'ALLOW' : 'DENY'}`, text: d === 'ALLOW' ? 'ALLOW' : 'DENY' });

function header(main, title, desc) {
  main.append(el('h1', { text: title }), el('p', { class: 'desc', text: desc }));
}

async function confirmDestructive(verb, id) {
  const reason = window.prompt(`${verb} ${id}\nThis cannot be undone. Reason (required):`);
  if (!reason || !reason.trim()) return null;
  const typed = window.prompt(`Type the id to confirm:\n${id}`);
  if (typed !== id) {
    toast('Confirmation did not match; nothing was changed.');
    return null;
  }
  return reason.trim().slice(0, 500);
}

function actionButton(label, onClick, cls = 'secondary') {
  return el('button', {
    type: 'button',
    class: cls,
    text: label,
    onclick: async (e) => {
      e.stopPropagation();
      try {
        await onClick();
      } catch (err) {
        toast(err.message);
      }
    },
  });
}

/**
 * Generic list page over a paginated endpoint.
 * columns: [{ label, cell(row) -> Node|string }]
 */
function listView(main, { path, columns, filters = [], rowActions, onRow, onLoaded, emptyText = 'Nothing here yet.' }) {
  const params = new URLSearchParams();
  const tableWrap = el('div');
  const detail = el('div');
  let cursor = null;
  let rows = [];

  const filterBar = el('div', { class: 'filters' });
  for (const f of filters) {
    const input =
      f.options
        ? el('select', { 'aria-label': f.label }, el('option', { value: '', text: `${f.label}: any` }), f.options.map((o) => el('option', { value: o, text: o })))
        : el('input', { placeholder: f.label, 'aria-label': f.label, maxlength: 64 });
    input.addEventListener('change', () => {
      if (input.value) params.set(f.name, input.value.trim());
      else params.delete(f.name);
      load(true);
    });
    filterBar.append(input);
  }
  if (filters.length) main.append(filterBar);
  main.append(tableWrap, detail);

  async function load(reset) {
    if (reset) {
      cursor = null;
      rows = [];
      tableWrap.replaceChildren(el('div', { class: 'loading', text: 'Loading…' }));
      detail.replaceChildren();
    }
    const qs = new URLSearchParams(params);
    qs.set('limit', '50');
    if (cursor) qs.set('cursor', cursor);
    let page;
    try {
      page = await api('GET', `${path}${path.includes('?') ? '&' : '?'}${qs}`);
    } catch (err) {
      tableWrap.replaceChildren(el('div', { class: 'empty', role: 'alert', text: `Could not load: ${err.message}` }));
      return;
    }
    rows = rows.concat(page.data);
    cursor = page.nextCursor;
    draw();
    if (onLoaded) onLoaded(rows);
  }

  function draw() {
    if (!rows.length) {
      tableWrap.replaceChildren(el('div', { class: 'empty', text: emptyText }));
      return;
    }
    const cols = rowActions ? [...columns, { label: 'Actions', cell: (r) => el('div', { class: 'actions' }, rowActions(r, () => load(true))) }] : columns;
    const table = el(
      'table',
      {},
      el('thead', {}, el('tr', {}, cols.map((c) => el('th', { scope: 'col', text: c.label })))),
      el(
        'tbody',
        {},
        rows.map((r) =>
          el(
            'tr',
            {
              class: onRow ? 'clickable' : '',
              tabindex: onRow ? 0 : undefined,
              onclick: onRow ? () => onRow(r, detail) : undefined,
              onkeydown: onRow
                ? (e) => {
                    if (e.target === e.currentTarget && (e.key === 'Enter' || e.key === ' ')) {
                      e.preventDefault();
                      onRow(r, detail);
                    }
                  }
                : undefined,
            },
            cols.map((c) => el('td', {}, c.cell(r))),
          ),
        ),
      ),
    );
    tableWrap.replaceChildren(table);
    if (cursor) tableWrap.append(el('button', { type: 'button', class: 'secondary more', text: 'Load more', onclick: () => load(false) }));
  }

  load(true);
}

function factSheet(title, pairs) {
  return el('section', { class: 'panel' }, el('h2', { text: title }), el('dl', {}, pairs.map(([k, v]) => [el('dt', { text: k }), el('dd', {}, v ?? '—')])));
}

// Operator records per view (agents inherit risk from their operator). Errors are cached as null => untrusted.
function operatorCache() {
  const cache = new Map();
  return (id) => {
    if (!cache.has(id)) cache.set(id, api('GET', `/v1/operators/${encodeURIComponent(id)}`).catch(() => null));
    return cache.get(id);
  };
}

function trustBadge(t) {
  return el('span', { class: `trust ${t.level}`, title: t.verdict }, el('strong', { text: String(t.score) }), ` ${t.level}`);
}

function trustCell(agent, getOperator) {
  const cell = el('span', { class: 'muted', text: '…', 'aria-busy': 'true' });
  getOperator(agent.operatorId).then((operator) => {
    cell.removeAttribute('aria-busy');
    cell.className = '';
    cell.replaceChildren(trustBadge(trustAssessment({ agent, operator })));
  });
  return cell;
}

function trustPanel(t) {
  return el(
    'section',
    { class: 'panel', 'aria-labelledby': 'trust-h' },
    el('h2', { id: 'trust-h', text: 'Trust score' }),
    el('p', {}, trustBadge(t), ' ', el('span', { class: t.level === 'untrusted' ? 'stamp DENY' : t.level === 'high' ? 'stamp ALLOW' : 'stamp WARN', text: t.verdict })),
    el(
      'table',
      {},
      el('caption', { class: 'muted', text: 'Informational, derived from agent/operator status and the audit log. The authoritative decision is POST /v1/verify.' }),
      el('thead', {}, el('tr', {}, ['Factor', 'Impact', 'Detail'].map((h) => el('th', { scope: 'col', text: h })))),
      el('tbody', {}, t.factors.map((f) => el('tr', {}, el('td', { text: f.label }), el('td', { class: 'mono', text: f.impact === 0 ? '0' : String(f.impact) }), el('td', { text: f.detail })))),
    ),
  );
}

async function agentDetail(agent, detail, getOperator) {
  detail.replaceChildren(el('div', { class: 'loading', role: 'status', text: 'Loading agent…' }));
  let operator;
  let verifications = null;
  try {
    const fresh = await api('GET', `/v1/agents/${encodeURIComponent(agent.id)}`);
    agent = fresh;
    operator = await getOperator(agent.operatorId);
    if (state.role === 'admin') {
      verifications = (await api('GET', `/v1/verifications?agentId=${encodeURIComponent(agent.id)}&limit=100`)).data;
    }
  } catch (err) {
    detail.replaceChildren(el('div', { class: 'empty', role: 'alert', text: `Could not load agent: ${err.message}` }));
    return;
  }
  const t = trustAssessment({ agent, operator, verifications });
  const grants = el('div');
  const creds = el('div');
  detail.replaceChildren(
    factSheet(`Agent ${agent.name}`, [
      ['Agent', mono(agent.id)],
      ['Status', status(agent.status)],
      ['Status reason', agent.statusReason],
      ['Operator', operator ? el('span', {}, `${operator.legalName} `, mono(operator.id), ' ', status(operator.status)) : mono(agent.operatorId)],
      ['Public key', mono(agent.publicKey)],
      ['Key thumbprint', mono(agent.keyThumbprint)],
      ['Created', fmtTime(agent.createdAt)],
      ['Revoked', fmtTime(agent.revokedAt)],
    ]),
    trustPanel(t),
    el('h2', { class: 'section', text: 'Grants to this agent' }),
    grants,
    el('h2', { class: 'section', text: 'Credentials' }),
    creds,
  );
  listView(grants, {
    path: `/v1/grants?agentId=${encodeURIComponent(agent.id)}`,
    emptyText: 'No grants for this agent.',
    columns: [
      { label: 'ID', cell: (g) => mono(g.id) },
      { label: 'Business', cell: (g) => mono(g.businessId) },
      { label: 'Actions', cell: (g) => mono(g.actions.join(', ')) },
      { label: 'Status', cell: (g) => status(g.status) },
      { label: 'Expires', cell: (g) => fmtTime(g.expiresAt) },
    ],
  });
  listView(creds, {
    path: `/v1/credentials?agentId=${encodeURIComponent(agent.id)}`,
    emptyText: 'No credentials issued to this agent.',
    columns: [
      { label: 'ID (jti)', cell: (c) => mono(c.id) },
      { label: 'Audience', cell: (c) => mono(c.businessId) },
      { label: 'Status', cell: (c) => status(c.status) },
      { label: 'Expires', cell: (c) => fmtTime(c.expiresAt) },
    ],
  });
  detail.querySelector('h2')?.setAttribute('tabindex', '-1');
  detail.querySelector('h2')?.focus();
}

// ------------------------------------------------------------------ views
function operatorsView(main) {
  header(main, 'Operators', 'People and organisations accountable for agents. MVP verification is a mock KYC + sanctions screen.');
  listView(main, {
    path: '/v1/operators',
    filters: [{ name: 'status', label: 'Status', options: ['pending', 'verified', 'rejected', 'suspended'] }],
    columns: [
      { label: 'Legal name', cell: (o) => o.legalName },
      { label: 'ID', cell: (o) => mono(o.id) },
      { label: 'Type', cell: (o) => o.type },
      { label: 'Country', cell: (o) => o.country },
      { label: 'Status', cell: (o) => status(o.status) },
      { label: 'KYC / sanctions', cell: (o) => (o.verification ? `${o.verification.kycResult} / ${o.verification.sanctionsResult}` : '—') },
    ],
    rowActions: (o, reload) => [
      (o.status === 'pending' || o.status === 'rejected') &&
        actionButton(o.status === 'rejected' ? 'Re-run verification' : 'Run verification', async () => {
          const r = await api('POST', `/v1/operators/${o.id}/verification`);
          toast(`Operator is now ${r.status}`);
          reload();
        }),
      o.status === 'verified' &&
        actionButton('Suspend', async () => {
          const reason = await confirmDestructive('Suspend operator', o.id);
          if (!reason) return;
          await api('POST', `/v1/operators/${o.id}/suspend`, { reason });
          toast('Operator suspended');
          reload();
        }, 'danger'),
    ],
  });
}

function agentsView(main) {
  header(main, 'Agents', 'Registered agents, their Ed25519 key thumbprints and trust scores. Select a row for details. Revocation takes effect on the next verification.');
  const getOperator = operatorCache();
  listView(main, {
    onRow: (a, detail) => agentDetail(a, detail, getOperator),
    path: '/v1/agents',
    filters: [
      { name: 'status', label: 'Status', options: ['active', 'suspended', 'revoked'] },
      ...(state.role === 'admin' ? [{ name: 'operatorId', label: 'Operator id' }] : []),
    ],
    columns: [
      { label: 'Name', cell: (a) => a.name },
      { label: 'ID', cell: (a) => mono(a.id) },
      { label: 'Operator', cell: (a) => mono(a.operatorId) },
      { label: 'Status', cell: (a) => status(a.status) },
      { label: 'Trust', cell: (a) => trustCell(a, getOperator) },
      { label: 'Key thumbprint', cell: (a) => mono(a.keyThumbprint) },
      { label: 'Created', cell: (a) => fmtTime(a.createdAt) },
    ],
    rowActions: (a, reload) => [
      a.status === 'active' &&
        actionButton('Suspend', async () => {
          const reason = window.prompt(`Suspend ${a.id}. Reason (required):`);
          if (!reason || !reason.trim()) return;
          await api('POST', `/v1/agents/${a.id}/suspend`, { reason: reason.trim().slice(0, 500) });
          toast('Agent suspended');
          reload();
        }),
      a.status === 'suspended' &&
        actionButton('Reactivate', async () => {
          await api('POST', `/v1/agents/${a.id}/reactivate`);
          toast('Agent reactivated');
          reload();
        }),
      a.status !== 'revoked' &&
        actionButton('Revoke', async () => {
          const reason = await confirmDestructive('Revoke agent', a.id);
          if (!reason) return;
          await api('POST', `/v1/agents/${a.id}/revoke`, { reason });
          toast('Agent revoked');
          reload();
        }, 'danger'),
    ],
  });
}

function lookupView(main) {
  header(main, 'Agent lookup', 'Check who an agent is and who is accountable for it. Informational — the authoritative decision is POST /v1/verify.');
  const input = el('input', { placeholder: 'agt_…', 'aria-label': 'Agent id', maxlength: 64, class: 'mono' });
  const out = el('div');
  const form = el('form', { class: 'filters' }, input, el('button', { type: 'submit', class: 'primary', text: 'Look up' }));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    out.replaceChildren(el('div', { class: 'loading', text: 'Loading…' }));
    try {
      const agent = await api('GET', `/v1/agents/${encodeURIComponent(input.value.trim())}`);
      const op = await api('GET', `/v1/operators/${encodeURIComponent(agent.operatorId)}`);
      const history = await api('GET', `/v1/verifications?agentId=${encodeURIComponent(agent.id)}&limit=100`).then((p) => p.data, () => null);
      const t = trustAssessment({ agent, operator: op, verifications: history });
      out.replaceChildren(
        trustPanel(t),
        factSheet('Identity', [
          ['Agent', mono(agent.id)],
          ['Name', agent.name],
          ['Status', status(agent.status)],
          ['Key thumbprint', mono(agent.keyThumbprint)],
          ['Public key', mono(agent.publicKey)],
          ['Operator', el('span', {}, `${op.legalName} `, mono(op.id), ' ', status(op.status), ` ${op.country} · ${op.type}`)],
        ]),
      );
    } catch (err) {
      out.replaceChildren(el('div', { class: 'empty', role: 'alert', text: err.status === 404 || err.status === 400 ? 'No agent with this id is visible to you.' : `Could not load: ${err.message}` }));
    }
  });
  main.append(form, out);
}

function grantsView(main) {
  header(main, 'Grants', 'Scoped permissions a business has given an agent: actions, constraints and expiry.');
  listView(main, {
    path: '/v1/grants',
    filters: [
      { name: 'status', label: 'Status', options: ['active', 'revoked'] },
      { name: 'agentId', label: 'Agent id' },
    ],
    columns: [
      { label: 'ID', cell: (g) => mono(g.id) },
      { label: 'Agent', cell: (g) => mono(g.agentId) },
      { label: 'Business', cell: (g) => mono(g.businessId) },
      { label: 'Actions', cell: (g) => mono(g.actions.join(', ')) },
      { label: 'Constraints', cell: (g) => mono(Object.keys(g.constraints).length ? JSON.stringify(g.constraints) : '—') },
      { label: 'Status', cell: (g) => status(g.status) },
      { label: 'Expires', cell: (g) => fmtTime(g.expiresAt) },
    ],
    rowActions:
      state.role === 'operator'
        ? undefined
        : (g, reload) => [
            g.status === 'active' &&
              actionButton('Revoke', async () => {
                const reason = await confirmDestructive('Revoke grant', g.id);
                if (!reason) return;
                await api('POST', `/v1/grants/${g.id}/revoke`, { reason });
                toast('Grant revoked');
                reload();
              }, 'danger'),
          ],
  });
}

function credentialsView(main) {
  header(main, 'Credentials', 'Signed, expiring credentials issued to agents. The JWS itself is never stored or shown again.');
  listView(main, {
    path: '/v1/credentials',
    filters: [
      { name: 'agentId', label: 'Agent id' },
      { name: 'grantId', label: 'Grant id' },
    ],
    columns: [
      { label: 'ID (jti)', cell: (c) => mono(c.id) },
      { label: 'Agent', cell: (c) => mono(c.agentId) },
      { label: 'Audience', cell: (c) => mono(c.businessId) },
      { label: 'Grant', cell: (c) => mono(c.grantId) },
      { label: 'Actions', cell: (c) => mono(c.actions.join(', ')) },
      { label: 'Status', cell: (c) => status(c.status) },
      { label: 'Expires', cell: (c) => fmtTime(c.expiresAt) },
    ],
    rowActions: (c, reload) => [
      c.status === 'active' &&
        actionButton('Revoke', async () => {
          const reason = await confirmDestructive('Revoke credential', c.id);
          if (!reason) return;
          await api('POST', `/v1/credentials/${c.id}/revoke`, { reason });
          toast('Credential revoked');
          reload();
        }, 'danger'),
    ],
  });
}

function verificationsView(main) {
  header(main, 'Verifications', 'Audit log of every ALLOW / DENY decision, newest first. Each DENY carries the first failed check.');
  const summary = el('div');
  main.append(summary);
  listView(main, {
    onLoaded: (rows) => {
      const counts = denyCountsByReason(rows);
      summary.replaceChildren(
        counts.length
          ? el(
              'table',
              { class: 'summary' },
              el('caption', { class: 'muted', text: `DENY count by reason (${rows.length} loaded decisions)` }),
              el('thead', {}, el('tr', {}, el('th', { scope: 'col', text: 'Reason code' }), el('th', { scope: 'col', text: 'DENY count' }))),
              el('tbody', {}, counts.map((c) => el('tr', {}, el('td', {}, mono(c.code)), el('td', { class: 'mono', text: String(c.count) })))),
            )
          : '',
      );
    },
    path: '/v1/verifications',
    filters: [
      { name: 'decision', label: 'Decision', options: ['ALLOW', 'DENY'] },
      { name: 'agentId', label: 'Agent id' },
    ],
    emptyText: 'No decisions recorded yet.',
    columns: [
      { label: 'Evaluated', cell: (v) => fmtTime(v.evaluatedAt) },
      { label: 'Decision', cell: (v) => stamp(v.decision) },
      { label: 'Reason', cell: (v) => mono(v.reasons[0]?.code) },
      { label: 'Agent', cell: (v) => mono(v.agentId) },
      { label: 'Action', cell: (v) => mono(v.action) },
      ...(state.role === 'admin' ? [{ label: 'Business', cell: (v) => mono(v.businessId) }] : []),
    ],
    onRow: (v, detail) =>
      detail.replaceChildren(
        factSheet('Verification detail', [
          ['Verification', mono(v.verificationId)],
          ['Decision', stamp(v.decision)],
          ['Reasons', el('span', {}, v.reasons.map((r) => el('div', {}, mono(r.code), ` — ${r.message}`)))],
          ['Agent', mono(v.agentId)],
          ['Operator', mono(v.operatorId)],
          ['Action', mono(v.action)],
          ['Grant', mono(v.grantId)],
          ['Credential', mono(v.credentialId)],
          ['Business', mono(v.businessId)],
          ['Request id', mono(v.requestId)],
          ['Evaluated at', v.evaluatedAt],
        ]),
      ),
  });
}

function apiKeysView(main) {
  header(main, 'API keys', 'Keys are stored as HMAC-SHA256 hashes; the plaintext is shown only once, at creation (via the API).');
  listView(main, {
    path: '/v1/api-keys',
    columns: [
      { label: 'Name', cell: (k) => k.name },
      { label: 'Prefix', cell: (k) => mono(k.displayPrefix) },
      { label: 'Role', cell: (k) => k.role },
      { label: 'Owner', cell: (k) => mono(k.ownerId) },
      { label: 'Status', cell: (k) => status(k.status) },
      { label: 'Last used', cell: (k) => fmtTime(k.lastUsedAt) },
    ],
    rowActions: (k, reload) => [
      k.status === 'active' &&
        actionButton('Revoke', async () => {
          const reason = await confirmDestructive('Revoke API key', k.id);
          if (!reason) return;
          await api('POST', `/v1/api-keys/${k.id}/revoke`);
          toast('API key revoked');
          reload();
        }, 'danger'),
    ],
  });
}

// ------------------------------------------------------------------ investigations + continuous KYA
function investigationsView(main) {
  header(main, 'Investigations', 'Evidence behind a risk decision: current signals, MongoDB security memory retrieved via Vector Search, the harness version that ran, and the decision with its compliance receipt.');
  const out = el('div', { 'aria-live': 'polite' });
  const receiptOut = el('div');
  let versions;

  async function show(inv) {
    if (versions === undefined) versions = await api('GET', '/v1/harness/versions').then((r) => r.data, () => null);
    out.replaceChildren(renderInvestigation(el, inv, { versions, onReceipt: openReceipt }));
    receiptOut.replaceChildren();
  }

  async function openReceipt(id) {
    receiptOut.replaceChildren(el('div', { class: 'loading', role: 'status', text: 'Loading receipt…' }));
    try {
      const { json, headers } = await apiResponse('GET', `/v1/investigations/${encodeURIComponent(id)}/receipt`);
      const integrity = headers.get('X-KYA-Receipt-Integrity');
      receiptOut.replaceChildren(
        factSheet('Compliance receipt', [
          ['Receipt', mono(json.receiptId)],
          ['Receipt hash', mono(json.receiptHash)],
          ['Integrity', el('span', { class: `stamp ${integrity === 'valid' ? 'ALLOW' : 'DENY'}`, text: integrity === 'valid' ? 'valid' : integrity === 'mismatch' ? 'mismatch' : 'unknown' })],
          ['Audit anchor', json.anchor ? el('span', {}, mono(json.anchor.auditEventId), ` seq ${json.anchor.auditSeq}`) : '—'],
          ['Policy version', mono(json.policyVersion)],
          ['Sanctions dataset', mono(json.sanctionsDatasetVersion)],
        ]),
        el('pre', { class: 'json mono', tabindex: 0, 'aria-label': 'Receipt JSON', text: JSON.stringify(json, null, 2) }),
      );
      receiptOut.querySelector('h2')?.setAttribute('tabindex', '-1');
      receiptOut.querySelector('h2')?.focus();
    } catch (err) {
      receiptOut.replaceChildren(el('div', { class: 'empty', role: 'alert', text: err.status === 404 || err.status === 400 ? 'No receipt with this investigation id is visible to you.' : `Could not load receipt: ${err.message}` }));
    }
  }

  async function loadById(id) {
    out.replaceChildren(el('div', { class: 'loading', role: 'status', text: 'Loading investigation…' }));
    try {
      const { json } = await apiResponse('GET', `/v1/investigations/${encodeURIComponent(id)}/receipt`);
      await show(fromReceipt(json));
    } catch (err) {
      out.replaceChildren(el('div', { class: 'empty', role: 'alert', text: err.status === 404 || err.status === 400 ? 'No investigation with this id is visible to you.' : `Could not load: ${err.message}` }));
    }
  }

  const idInput = el('input', { placeholder: 'inv_…', 'aria-label': 'Investigation id', maxlength: 80, class: 'mono', required: true });
  const byId = el('form', { class: 'filters' }, idInput, el('button', { type: 'submit', class: 'primary', text: 'Load evidence' }));
  byId.addEventListener('submit', (e) => {
    e.preventDefault();
    loadById(idInput.value.trim());
  });

  // A signed InvestigationRequest produced on the agent host; the dashboard never holds agent keys.
  const reqInput = el('textarea', { id: 'inv-req', rows: 5, class: 'mono', spellcheck: 'false', placeholder: 'InvestigationRequest JSON: agentId, action, resource, context, signedRequest' });
  const submit = el(
    'form',
    { class: 'stack' },
    el('label', { for: 'inv-req', text: 'Signed investigation request (JSON, signed on the agent host)' }),
    reqInput,
    el('div', {}, el('button', { type: 'submit', class: 'secondary', text: 'Run investigation' })),
  );
  submit.addEventListener('submit', async (e) => {
    e.preventDefault();
    let body;
    try {
      body = JSON.parse(reqInput.value);
    } catch {
      out.replaceChildren(el('div', { class: 'empty', role: 'alert', text: 'Request is not valid JSON.' }));
      return;
    }
    out.replaceChildren(el('div', { class: 'loading', role: 'status', text: 'Running investigation pipeline…' }));
    try {
      await show(await api('POST', '/v1/investigations', body));
    } catch (err) {
      // 500 fail-closed responses still carry a BLOCK investigation body.
      if (err.body && err.body.riskDecision) await show(err.body);
      else out.replaceChildren(el('div', { class: 'empty', role: 'alert', text: `Investigation failed: ${err.code ? `${err.code} — ` : ''}${err.message}` }));
    }
  });

  main.append(byId, el('details', {}, el('summary', { text: 'Run a new investigation' }), submit));

  if (state.role === 'admin') {
    const live = el('div');
    const drawLive = () =>
      live.replaceChildren(
        state.live.length
          ? el(
              'table',
              {},
              el('caption', { class: 'muted', text: 'Decided investigations received on the event stream (this session)' }),
              el('thead', {}, el('tr', {}, ['At', 'Risk', 'Agent', 'Trigger', 'Investigation', ''].map((c) => el('th', { scope: 'col', text: c })))),
              el(
                'tbody',
                {},
                state.live.map((d) =>
                  el(
                    'tr',
                    {},
                    el('td', { text: fmtTime(d.at) }),
                    el('td', {}, riskStamp(el, d.riskDecision)),
                    el('td', {}, mono(d.agentId)),
                    el('td', {}, mono(d.trigger)),
                    el('td', {}, mono(d.investigationId)),
                    el('td', {}, el('button', { type: 'button', class: 'secondary', text: 'Open', onclick: () => loadById(d.investigationId) })),
                  ),
                ),
              ),
            )
          : el('div', { class: 'empty', text: 'No investigations decided since sign-in. Live events appear here.' }),
      );
    state.onLive = drawLive;
    drawLive();
    main.append(el('h2', { class: 'section', text: 'Live decisions' }), live);
  }
  main.append(out, receiptOut);
}

function drawStrip(connText) {
  $('kya-strip').hidden = false;
  if (connText) $('kya-conn').textContent = connText;
  $('kya-steps').replaceChildren(renderKyaStrip(el, state.strip));
}

// Admin only. Uses fetch rather than EventSource, which cannot send the Authorization header.
function startKyaStream() {
  stopKyaStream();
  const ctrl = new AbortController();
  state.stream = ctrl;
  drawStrip('Connecting…');
  const onEvent = (evt) => {
    state.strip = kyaStripApply(state.strip, evt);
    if (evt.type === 'investigation.decided') {
      state.live = [evt.data, ...state.live].slice(0, 20);
      state.onLive?.();
    }
    drawStrip();
  };
  (async () => {
    while (!ctrl.signal.aborted) {
      try {
        const res = await fetch('/v1/events/stream', { headers: { Authorization: `Bearer ${state.key}`, Accept: 'text/event-stream' }, cache: 'no-store', credentials: 'omit', signal: ctrl.signal });
        if (res.status === 401) {
          signOut('Your API key was rejected. It may have been revoked.');
          return;
        }
        if (!res.ok || !res.body) throw new Error(`stream unavailable (${res.status})`);
        drawStrip('Live');
        const push = createSseParser(onEvent);
        const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          push(value);
        }
        throw new Error('stream closed');
      } catch (err) {
        if (ctrl.signal.aborted) return;
        drawStrip(`Disconnected (${err.message}) — retrying in 3 s`);
        await new Promise((r) => setTimeout(r, 3000));
      }
    }
  })();
}

function stopKyaStream() {
  state.stream?.abort();
  state.stream = null;
  state.strip = kyaStripInit();
  state.live = [];
  $('kya-strip').hidden = true;
}

// ------------------------------------------------------------------ wiring
$('signin-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('signin-error').textContent = '';
  const key = $('apikey').value.trim();
  $('apikey').value = '';
  try {
    await signIn(key);
  } catch (err) {
    state.key = null;
    state.role = null;
    $('signin-error').textContent = err.message;
  }
});
$('toggle-key').addEventListener('click', () => {
  const input = $('apikey');
  const show = input.type === 'password';
  input.type = show ? 'text' : 'password';
  $('toggle-key').textContent = show ? 'Hide' : 'Show';
  $('toggle-key').setAttribute('aria-pressed', String(show));
});
$('signout').addEventListener('click', () => signOut());
window.addEventListener('hashchange', render);
for (const evt of ['click', 'keydown']) document.addEventListener(evt, bumpIdle);
