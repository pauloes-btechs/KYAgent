// HTTP adapter (node:http, zero dependencies). Routes are thin: auth + RBAC role
// gate here, ownership checks in services (ARCHITECTURE §5, §6).
import { readFileSync } from 'node:fs';
import http from 'node:http';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { RESOURCE_ID_RE } from './contracts.js';
import { jwks } from './crypto/credentials.js';
import { ApiError, validationError } from './errors.js';
import { newId } from './ids.js';
import { createLogger } from './logger.js';
import { agentService } from './services/agents.js';
import { apiKeyService } from './services/apiKeys.js';
import { AUDIT_EVENT_TYPES, auditService } from './services/audit.js';
import { credentialService } from './services/credentials.js';
import { grantService } from './services/grants.js';
import { businessService, operatorService } from './services/operators.js';
import { verificationService } from './services/verification.js';
import { decodeCursor } from './store/pagination.js';

export const systemClock = { now: () => new Date() };

const REQUEST_ID_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const DASHBOARD_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'dashboard');
const DASHBOARD_FILES = {
  'index.html': 'text/html; charset=utf-8',
  'app.js': 'text/javascript; charset=utf-8',
  'styles.css': 'text/css; charset=utf-8',
};
const DASHBOARD_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; " +
  "base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const ALL = ['admin', 'operator', 'business'];
const q = {
  str64: { type: 'string', max: 64 },
  operatorStatus: { enum: ['pending', 'verified', 'rejected', 'suspended'] },
  agentStatus: { enum: ['active', 'suspended', 'revoked'] },
  grantStatus: { enum: ['active', 'revoked'] },
  decision: { enum: ['ALLOW', 'DENY'] },
  auditType: { enum: AUDIT_EVENT_TYPES },
};

function loadDashboard() {
  const files = {};
  for (const [name, type] of Object.entries(DASHBOARD_FILES)) {
    try {
      files[name] = { body: readFileSync(join(DASHBOARD_DIR, name)), type };
    } catch {
      // dashboard is optional for the API
    }
  }
  return files;
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let tooLarge = Number(req.headers['content-length'] ?? 0) > limit;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (tooLarge || size > limit) {
        tooLarge = true;
        chunks.length = 0;
        if (size > limit * 16) req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve({ raw: tooLarge ? null : Buffer.concat(chunks), tooLarge }));
    req.on('close', () => resolve({ raw: null, tooLarge: true }));
    req.on('error', reject);
  });
}

const isJsonContentType = (ct) => typeof ct === 'string' && /^application\/json\s*(;|$)/i.test(ct);

function parseJson(raw) {
  try {
    return { ok: true, body: JSON.parse(raw.toString('utf8')) };
  } catch {
    return { ok: false };
  }
}

function parseQuery(url, spec = {}) {
  const out = { limit: 50, cursor: null };
  const limit = url.searchParams.get('limit');
  if (limit !== null) {
    if (!/^\d{1,3}$/.test(limit) || Number(limit) < 1 || Number(limit) > 100) {
      throw validationError([{ path: '/query/limit', message: 'must be an integer between 1 and 100' }], 'Query is invalid');
    }
    out.limit = Number(limit);
  }
  const cursor = url.searchParams.get('cursor');
  if (cursor !== null) {
    out.cursor = decodeCursor(cursor);
    if (!out.cursor) throw validationError([{ path: '/query/cursor', message: 'is invalid' }], 'Query is invalid');
  }
  for (const [name, rule] of Object.entries(spec)) {
    const v = url.searchParams.get(name);
    if (v === null) continue;
    if ((rule.enum && !rule.enum.includes(v)) || (rule.max && v.length > rule.max)) {
      throw validationError([{ path: `/query/${name}`, message: 'is invalid' }], 'Query is invalid');
    }
    out[name] = v;
  }
  return out;
}

export function buildApp({ config, store, clock = systemClock, logger = createLogger(config.logLevel) }) {
  const audit = auditService({ store, clock });
  const deps = { store, clock, config, audit };
  const services = {
    audit,
    apiKeys: apiKeyService(deps),
    businesses: businessService(deps),
    operators: operatorService(deps),
    agents: agentService(deps),
    grants: grantService(deps),
    credentials: credentialService(deps),
    verification: verificationService(deps),
  };
  const s = services;
  const dashboard = loadDashboard();

  // body: 'json' = required JSON object body, 'none' = body ignored, 'verify' = decision semantics
  const routes = [
    { m: 'POST', p: '/v1/businesses', roles: ['admin'], body: 'json', status: 201, h: (c) => s.businesses.create(c.principal, c.body) },
    { m: 'GET', p: '/v1/businesses', roles: ['admin'], h: (c) => s.businesses.list(c.principal, c.query) },
    { m: 'GET', p: '/v1/businesses/:id', roles: ['admin', 'business'], h: (c) => s.businesses.get(c.principal, c.id) },

    { m: 'POST', p: '/v1/operators', roles: ['admin'], body: 'json', status: 201, h: (c) => s.operators.create(c.principal, c.body) },
    { m: 'GET', p: '/v1/operators', roles: ['admin'], query: { status: q.operatorStatus }, h: (c) => s.operators.list(c.principal, c.query) },
    { m: 'GET', p: '/v1/operators/:id', roles: ALL, h: (c) => s.operators.get(c.principal, c.id) },
    { m: 'POST', p: '/v1/operators/:id/verification', roles: ['admin'], h: (c) => s.operators.verify(c.principal, c.id) },
    { m: 'POST', p: '/v1/operators/:id/suspend', roles: ['admin'], body: 'json', h: (c) => s.operators.suspend(c.principal, c.id, c.body) },

    { m: 'POST', p: '/v1/api-keys', roles: ['admin'], body: 'json', status: 201, noStore: true, h: (c) => s.apiKeys.create(c.principal, c.body) },
    { m: 'GET', p: '/v1/api-keys', roles: ['admin'], query: { ownerId: q.str64 }, h: (c) => s.apiKeys.list(c.principal, c.query) },
    { m: 'POST', p: '/v1/api-keys/:id/revoke', roles: ['admin'], h: (c) => s.apiKeys.revoke(c.principal, c.id) },

    { m: 'POST', p: '/v1/agents', roles: ['operator'], body: 'json', status: 201, h: (c) => s.agents.register(c.principal, c.body) },
    { m: 'GET', p: '/v1/agents', roles: ['admin', 'operator'], query: { operatorId: q.str64, status: q.agentStatus }, h: (c) => s.agents.list(c.principal, c.query) },
    { m: 'GET', p: '/v1/agents/:id', roles: ALL, h: (c) => s.agents.get(c.principal, c.id) },
    { m: 'POST', p: '/v1/agents/:id/suspend', roles: ['admin', 'operator'], body: 'json', h: (c) => s.agents.suspend(c.principal, c.id, c.body) },
    { m: 'POST', p: '/v1/agents/:id/reactivate', roles: ['admin', 'operator'], h: (c) => s.agents.reactivate(c.principal, c.id) },
    { m: 'POST', p: '/v1/agents/:id/revoke', roles: ['admin', 'operator'], body: 'json', h: (c) => s.agents.revoke(c.principal, c.id, c.body) },
    { m: 'POST', p: '/v1/agents/:id/credentials', roles: ['operator'], body: 'json', status: 201, noStore: true, h: (c) => s.credentials.issue(c.principal, c.id, c.body) },

    { m: 'POST', p: '/v1/grants', roles: ['business'], body: 'json', status: 201, h: (c) => s.grants.create(c.principal, c.body) },
    { m: 'GET', p: '/v1/grants', roles: ALL, query: { agentId: q.str64, status: q.grantStatus }, h: (c) => s.grants.list(c.principal, c.query) },
    { m: 'GET', p: '/v1/grants/:id', roles: ALL, h: (c) => s.grants.get(c.principal, c.id) },
    { m: 'POST', p: '/v1/grants/:id/revoke', roles: ['admin', 'business'], body: 'json', h: (c) => s.grants.revoke(c.principal, c.id, c.body) },

    { m: 'GET', p: '/v1/credentials', roles: ALL, query: { agentId: q.str64, grantId: q.str64 }, h: (c) => s.credentials.list(c.principal, c.query) },
    { m: 'GET', p: '/v1/credentials/:id', roles: ALL, h: (c) => s.credentials.get(c.principal, c.id) },
    { m: 'POST', p: '/v1/credentials/:id/revoke', roles: ALL, body: 'json', h: (c) => s.credentials.revoke(c.principal, c.id, c.body) },

    { m: 'POST', p: '/v1/verify', roles: ['business'], body: 'verify', h: null },
    { m: 'GET', p: '/v1/audit-events', roles: ['admin'], query: { type: q.auditType, subjectId: q.str64 }, h: (c) => s.audit.list(c.principal, c.query) },
    { m: 'GET', p: '/v1/audit-events/integrity', roles: ['admin'], h: () => s.audit.verifyChain() },
    { m: 'GET', p: '/v1/verifications', roles: ['admin', 'business'], query: { agentId: q.str64, decision: q.decision }, h: (c) => s.verification.list(c.principal, c.query) },
  ].map((r) => ({ ...r, segs: r.p.split('/') }));

  function match(method, pathname) {
    const segs = pathname.split('/');
    for (const r of routes) {
      if (r.m !== method || r.segs.length !== segs.length) continue;
      let id;
      let ok = true;
      for (let i = 0; i < segs.length; i++) {
        // ids are [a-z0-9_A-Z] only, so no percent-decoding is needed; bad ids fail RESOURCE_ID_RE.
        if (r.segs[i] === ':id') id = segs[i];
        else if (r.segs[i] !== segs[i]) {
          ok = false;
          break;
        }
      }
      if (ok) return { route: r, id };
    }
    return null;
  }

  function send(res, status, body, requestId, extraHeaders = {}) {
    const payload = Buffer.from(JSON.stringify(body), 'utf8');
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': payload.length,
      'X-Request-Id': requestId,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      ...extraHeaders,
    });
    res.end(payload);
  }

  function sendError(res, err, requestId) {
    const headers = err.code === 'UNAUTHENTICATED' ? { 'WWW-Authenticate': 'Bearer' } : {};
    send(res, err.status, err.toBody(requestId), requestId, headers);
  }

  function serveDashboard(res, pathname, requestId) {
    const name = pathname.replace(/^\/dashboard\/?/, '') || 'index.html';
    const file = Object.hasOwn(dashboard, name) ? dashboard[name] : null;
    if (!file) return sendError(res, new ApiError('NOT_FOUND'), requestId);
    res.writeHead(200, {
      'Content-Type': file.type,
      'Content-Length': file.body.length,
      'Content-Security-Policy': DASHBOARD_CSP,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-cache',
      'X-Request-Id': requestId,
    });
    res.end(file.body);
  }

  async function handle(req, res) {
    const incomingId = req.headers['x-request-id'];
    const requestId = typeof incomingId === 'string' && REQUEST_ID_RE.test(incomingId) ? incomingId : newId('req');
    const started = Date.now();
    let url;
    try {
      url = new URL(req.url, 'http://localhost');
    } catch {
      return sendError(res, new ApiError('NOT_FOUND'), requestId);
    }
    const { pathname } = url;
    try {
      // --- public endpoints
      if (req.method === 'GET' && pathname === '/healthz') {
        try {
          await store.ping();
        } catch {
          throw new ApiError('SERVICE_UNAVAILABLE');
        }
        return send(res, 200, { status: 'ok', store: store.kind }, requestId);
      }
      if (req.method === 'GET' && pathname === '/.well-known/jwks.json') {
        return send(res, 200, jwks({ publicKey: config.signingPublicKey, kid: config.kid }), requestId, {
          'Cache-Control': 'public, max-age=300',
        });
      }
      if (req.method === 'GET' && pathname === '/') {
        res.writeHead(302, { Location: '/dashboard/', 'X-Request-Id': requestId });
        return res.end();
      }
      if (req.method === 'GET' && (pathname === '/dashboard' || pathname.startsWith('/dashboard/'))) {
        return serveDashboard(res, pathname, requestId);
      }

      // --- API
      const found = match(req.method, pathname);
      if (!found) throw new ApiError('NOT_FOUND');
      const { route, id } = found;
      const bodyPromise = readBody(req, config.maxBodyBytes);
      bodyPromise.catch(() => {});

      // requestId travels with the principal so audit events can be correlated with logs.
      const principal = { ...(await services.apiKeys.authenticate(req.headers.authorization)), requestId };
      if (!route.roles.includes(principal.role)) throw new ApiError('FORBIDDEN');

      const { raw, tooLarge } = await bodyPromise;

      if (route.body === 'verify') {
        let parsed = { ok: false };
        if (!tooLarge && isJsonContentType(req.headers['content-type']) && raw) parsed = parseJson(raw);
        const result = await services.verification.verify(principal, parsed, requestId);
        return send(res, result.status, result.body, requestId);
      }

      if (id !== undefined && !RESOURCE_ID_RE.test(id)) {
        throw validationError([{ path: '/params/id', message: 'must be a resource id' }], 'Path parameter is invalid');
      }
      const query = parseQuery(url, route.query);
      let body;
      if (tooLarge) throw new ApiError('PAYLOAD_TOO_LARGE');
      if (route.body === 'json') {
        if (!isJsonContentType(req.headers['content-type'])) throw new ApiError('UNSUPPORTED_MEDIA_TYPE');
        const parsed = raw && raw.length ? parseJson(raw) : { ok: false };
        if (!parsed.ok) throw validationError([{ path: '', message: 'must be valid JSON' }], 'Malformed JSON body');
        body = parsed.body;
      }
      const result = await route.h({ principal, id, query, body, requestId });
      return send(res, route.status ?? 200, result, requestId, route.noStore ? { 'Cache-Control': 'no-store' } : {});
    } catch (err) {
      if (err instanceof ApiError) return sendError(res, err, requestId);
      logger.error('unhandled error', { requestId, error: err?.message, stack: err?.stack });
      return sendError(res, new ApiError('INTERNAL_ERROR'), requestId);
    } finally {
      logger.info('request', { requestId, method: req.method, path: pathname, status: res.statusCode, ms: Date.now() - started });
    }
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500);
      res.end();
    });
  });

  return {
    server,
    services,
    store,
    config,
    async init() {
      await store.init();
      if (config.bootstrapAdminApiKey) {
        const inserted = await services.apiKeys.bootstrapAdmin(config.bootstrapAdminApiKey);
        if (inserted) logger.info('bootstrap admin API key installed (hash only)');
      }
    },
    listen(port = config.port, host = config.host) {
      return new Promise((resolve) => server.listen(port, host, () => resolve(server.address())));
    },
    async close() {
      const closed = new Promise((resolve) => server.close(() => resolve()));
      server.closeAllConnections?.();
      await closed;
      await store.close();
    },
  };
}
