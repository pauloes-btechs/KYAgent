// REQ-013: input validation and a consistent structured error envelope / HTTP status mapping.
import assert from 'node:assert/strict';
import test from 'node:test';
import { ERROR_CODES } from '../src/contracts.js';
import { ApiError, ConflictError, MAX_ERROR_DETAILS, StoreUnavailableError, toApiError } from '../src/errors.js';
import { createBusiness, createOperator, startApp, world } from './helpers.js';

const REQUEST_ID_RE = /^[A-Za-z0-9_.-]{1,64}$/;

/** Asserts the error-model.md envelope and that X-Request-Id matches the body. */
function assertError(res, status, code) {
  assert.equal(res.status, status, res.text);
  assert.match(res.headers.get('content-type'), /^application\/json/);
  assert.deepEqual(Object.keys(res.body), ['error']);
  const { error } = res.body;
  assert.equal(error.code, code);
  assert.equal(ERROR_CODES[code], status);
  assert.equal(typeof error.message, 'string');
  assert.ok(error.message.length > 0);
  assert.match(error.requestId, REQUEST_ID_RE);
  assert.equal(res.headers.get('x-request-id'), error.requestId);
  if (code !== 'VALIDATION_ERROR') assert.equal(error.details, undefined);
  return error;
}

test('toApiError maps every thrown value to a stable code and status', () => {
  const api = new ApiError('NOT_FOUND');
  assert.equal(toApiError(api), api);
  assert.equal(toApiError(new ConflictError()).status, 409);
  assert.equal(toApiError(new StoreUnavailableError()).code, 'SERVICE_UNAVAILABLE');
  const mongoDown = Object.assign(new Error('connect ECONNREFUSED 10.0.0.5:27017'), { name: 'MongoServerSelectionError' });
  assert.equal(toApiError(mongoDown).status, 503);
  assert.equal(toApiError(new TypeError('boom')).code, 'INTERNAL_ERROR');
  assert.equal(toApiError(undefined).status, 500);
  assert.equal(toApiError(new Error('secret-ish')).message, 'Internal error');
  assert.throws(() => new ApiError('NOPE'), TypeError);
});

test('validation details are capped and only carry path/message', () => {
  const details = Array.from({ length: 100 }, (_, i) => ({ path: `/x${i}`, message: 'is not allowed', extra: 'leak' }));
  const body = new ApiError('VALIDATION_ERROR', 'bad', details).toBody('req_1');
  assert.equal(body.error.details.length, MAX_ERROR_DETAILS);
  assert.deepEqual(Object.keys(body.error.details[0]), ['path', 'message']);
  assert.equal(new ApiError('CONFLICT', 'dup', details).toBody('req_1').error.details, undefined);
});

test('HTTP errors: every documented status uses the same envelope', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const { t, business, operator } = w;

  assertError(await t.call(null, 'GET', '/v1/agents'), 401, 'UNAUTHENTICATED');
  const unauth = await t.call('kya_bogus_key', 'GET', '/v1/agents');
  assertError(unauth, 401, 'UNAUTHENTICATED');
  assert.equal(unauth.headers.get('www-authenticate'), 'Bearer');
  assertError(await t.call(business.key, 'GET', '/v1/agents'), 403, 'FORBIDDEN');
  assertError(await t.call(t.admin, 'GET', '/v1/nope'), 404, 'NOT_FOUND');
  assertError(await t.call(t.admin, 'DELETE', '/v1/agents'), 404, 'NOT_FOUND');
  assertError(await t.call(t.admin, 'GET', '/v1/agents/agt_01J8ZQ4Y5N3V6K2M7P9R0S1T2V'), 404, 'NOT_FOUND');
  assertError(
    await t.call(t.admin, 'POST', '/v1/businesses', undefined, { raw: '{"name":"x"}', headers: { 'content-type': 'text/plain' } }),
    415,
    'UNSUPPORTED_MEDIA_TYPE',
  );
  assertError(await t.call(t.admin, 'POST', '/v1/businesses', { name: 'x'.repeat(70000) }), 413, 'PAYLOAD_TOO_LARGE');

  // 409 CONFLICT (duplicate public key) and INVALID_STATE (revoke twice)
  const dup = await t.call(operator.key, 'POST', '/v1/agents', {
    name: 'clone',
    publicKey: w.agent.agent.publicKey,
    proofOfPossession: (await import('../src/sdk/agentSigner.js')).proofOfPossession(w.agent.privateKey, operator.op.id, w.agent.agent.publicKey),
  });
  assertError(dup, 409, 'CONFLICT');
  assert.equal((await t.call(business.key, 'POST', `/v1/grants/${w.grant.id}/revoke`, { reason: 'x' })).status, 200);
  assertError(await t.call(business.key, 'POST', `/v1/grants/${w.grant.id}/revoke`, { reason: 'x' }), 409, 'INVALID_STATE');

  // 409 OPERATOR_NOT_VERIFIED
  const pending = await createOperator(t, { legalName: 'Pending Co', verify: false });
  assertError(await t.call(pending.key, 'POST', '/v1/agents', { name: 'a', publicKey: 'A'.repeat(43), proofOfPossession: 'A'.repeat(86) }), 409, 'OPERATOR_NOT_VERIFIED');

  // client-supplied request ids are echoed, invalid ones replaced
  const echoed = await t.call(t.admin, 'GET', '/v1/nope', undefined, { headers: { 'x-request-id': 'trace-123' } });
  assert.equal(assertError(echoed, 404, 'NOT_FOUND').requestId, 'trace-123');
  const replaced = await t.call(t.admin, 'GET', '/v1/nope', undefined, { headers: { 'x-request-id': 'bad id\twith spaces' } });
  assert.match(assertError(replaced, 404, 'NOT_FOUND').requestId, /^req_/);
});

test('body validation returns VALIDATION_ERROR with JSON Pointer details', async (tc) => {
  const t = await startApp();
  tc.after(t.close);
  const post = (body, opts) => t.call(t.admin, 'POST', '/v1/operators', body, opts);

  const malformed = assertError(await post(undefined, { raw: '{"type":', headers: { 'content-type': 'application/json' } }), 400, 'VALIDATION_ERROR');
  assert.deepEqual(malformed.details, [{ path: '', message: 'must be valid JSON' }]);
  assertError(await post(undefined, { raw: '', headers: { 'content-type': 'application/json' } }), 400, 'VALIDATION_ERROR');

  for (const body of [[], 'str', 42, null]) {
    const err = assertError(await post(body), 400, 'VALIDATION_ERROR');
    assert.deepEqual(err.details, [{ path: '', message: 'must be an object' }]);
  }

  const err = assertError(
    await post({ type: 'robot', legalName: '', contactEmail: 'nope', country: 'gb', isAdmin: true }),
    400,
    'VALIDATION_ERROR',
  );
  const paths = err.details.map((d) => d.path).sort();
  assert.deepEqual(paths, ['/contactEmail', '/country', '/isAdmin', '/legalName', '/type']);
  for (const d of err.details) assert.equal(typeof d.message, 'string');

  const missing = assertError(await post({}), 400, 'VALIDATION_ERROR');
  assert.deepEqual(missing.details.map((d) => d.path).sort(), ['/contactEmail', '/country', '/legalName', '/type']);

  // prototype-pollution keys are rejected as unknown fields, not merged
  const proto = assertError(await post(undefined, { raw: '{"__proto__":{"admin":true}}', headers: { 'content-type': 'application/json' } }), 400, 'VALIDATION_ERROR');
  assert.ok(proto.details.some((d) => d.path === '/__proto__'));
  assert.equal({}.admin, undefined);
  const ctor = assertError(await post({ constructor: 1, toString: 'x' }), 400, 'VALIDATION_ERROR');
  assert.ok(ctor.details.some((d) => d.path === '/constructor' && d.message === 'is not allowed'));

  // many unknown fields: details are capped
  const many = Object.fromEntries(Array.from({ length: 200 }, (_, i) => [`f${i}`, 1]));
  assert.equal(assertError(await post(many), 400, 'VALIDATION_ERROR').details.length, MAX_ERROR_DETAILS);
});

test('path and query validation', async (tc) => {
  const t = await startApp();
  tc.after(t.close);
  const biz = await createBusiness(t);

  const badId = assertError(await t.call(t.admin, 'GET', '/v1/operators/not-an-id'), 400, 'VALIDATION_ERROR');
  assert.deepEqual(badId.details, [{ path: '/params/id', message: 'must be a resource id' }]);
  // unauthenticated callers never reach input validation
  assertError(await t.call(null, 'GET', '/v1/operators/not-an-id'), 401, 'UNAUTHENTICATED');

  const q = async (qs, key = t.admin, path = '/v1/operators') => t.call(key, 'GET', `${path}?${qs}`);
  assert.equal((await q('limit=1&status=pending')).status, 200);
  for (const [qs, path] of [
    ['limit=0', '/query/limit'],
    ['limit=101', '/query/limit'],
    ['limit=1.5', '/query/limit'],
    ['limit=-1', '/query/limit'],
    ['cursor=%%%', '/query/cursor'],
    ['cursor=abc', '/query/cursor'],
    ['status=bogus', '/query/status'],
    ['status=pending&status=verified', '/query/status'],
    ['limit=1&limit=2', '/query/limit'],
    ['sort=name', '/query/sort'],
    ['operatorId=op_x', '/query/operatorId'],
  ]) {
    const err = assertError(await q(qs), 400, 'VALIDATION_ERROR');
    assert.ok(err.details.some((d) => d.path === path), `${qs}: ${JSON.stringify(err.details)}`);
  }
  // all query problems are reported at once
  const multi = assertError(await q('limit=0&status=bogus&x=1'), 400, 'VALIDATION_ERROR');
  assert.deepEqual(multi.details.map((d) => d.path).sort(), ['/query/limit', '/query/status', '/query/x']);
  // length caps on free-text filters
  assertError(await q(`ownerId=${'a'.repeat(65)}`, t.admin, '/v1/api-keys'), 400, 'VALIDATION_ERROR');
  assertError(await q('ownerId=', t.admin, '/v1/api-keys'), 400, 'VALIDATION_ERROR');
  // non-list routes accept no query parameters
  assertError(await t.call(biz.key, 'GET', `/v1/businesses/${biz.biz.id}?limit=1`), 400, 'VALIDATION_ERROR');
  assert.equal((await t.call(biz.key, 'GET', `/v1/businesses/${biz.biz.id}`)).status, 200);
});

test('store failures: 503 when unreachable, 500 otherwise, never leaking internals', async (tc) => {
  const t = await startApp();
  tc.after(t.close);
  const original = t.store.operators.list;
  t.store.operators.list = async () => {
    throw Object.assign(new Error('connect ECONNREFUSED 10.1.2.3:27017'), { name: 'MongoServerSelectionError' });
  };
  const down = await t.call(t.admin, 'GET', '/v1/operators');
  assertError(down, 503, 'SERVICE_UNAVAILABLE');
  assert.ok(!down.text.includes('10.1.2.3'));

  t.store.operators.list = async () => {
    throw new Error('internal detail /srv/secret/path');
  };
  const boom = await t.call(t.admin, 'GET', '/v1/operators');
  assertError(boom, 500, 'INTERNAL_ERROR');
  assert.ok(!boom.text.includes('/srv/secret/path'));
  assert.ok(!boom.text.includes('at '));

  t.store.operators.list = original;
  assert.equal((await t.call(t.admin, 'GET', '/v1/operators')).status, 200);
});

test('/v1/verify keeps decision semantics for invalid input (no 400)', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  for (const opts of [
    { raw: '{bad json', headers: { 'content-type': 'application/json' } },
    { raw: '{}', headers: { 'content-type': 'text/plain' } },
  ]) {
    const res = await w.t.call(w.business.key, 'POST', '/v1/verify', undefined, opts);
    assert.equal(res.status, 200);
    assert.equal(res.body.decision, 'DENY');
    assert.equal(res.body.reasons[0].code, 'MALFORMED_REQUEST');
  }
  const res = await w.t.call(w.business.key, 'POST', '/v1/verify', { ...w.signed(), extra: 1 });
  assert.equal(res.status, 200);
  assert.equal(res.body.reasons[0].code, 'MALFORMED_REQUEST');
  // callers that are not authenticated still get an HTTP error, not a decision
  assertError(await w.t.call(null, 'POST', '/v1/verify', w.signed()), 401, 'UNAUTHENTICATED');
  assertError(await w.t.call(w.operator.key, 'POST', '/v1/verify', w.signed()), 403, 'FORBIDDEN');
});
