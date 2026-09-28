// T11: GET /v1/events/stream (SSE, admin only, one stream per key) on the in-process event hub.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createEventHub, STREAM_EVENT_TYPES } from '../src/events.js';
import { createBusiness, createOperator, startApp } from './helpers.js';

/** Open an SSE stream; `until(re)` reads until the accumulated text matches. */
async function openStream(base, key) {
  const ac = new AbortController();
  const res = await fetch(`${base}/v1/events/stream`, { headers: { authorization: `Bearer ${key}` }, signal: ac.signal });
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let text = '';
  let done = false;
  const until = async (re, timeoutMs = 3000) => {
    const deadline = Date.now() + timeoutMs;
    while (!re.test(text)) {
      if (done) throw new Error(`stream ended before ${re}: ${text}`);
      if (Date.now() > deadline) throw new Error(`timeout waiting for ${re}: ${text}`);
      const r = await reader.read();
      if (r.done) done = true;
      else text += decoder.decode(r.value, { stream: true });
    }
    return text;
  };
  const ended = async (timeoutMs = 3000) => {
    const deadline = Date.now() + timeoutMs;
    while (!done) {
      if (Date.now() > deadline) return false;
      const r = await reader.read();
      if (r.done) done = true;
    }
    return true;
  };
  return { res, until, ended, abort: () => ac.abort(), get text() { return text; } };
}

test('events/stream: 401 without a key, 403 for operator and business keys, 400 on query parameters', async (t) => {
  const h = await startApp();
  t.after(() => h.close());
  assert.equal((await h.call(null, 'GET', '/v1/events/stream')).status, 401);
  const op = await createOperator(h);
  const biz = await createBusiness(h);
  assert.equal((await h.call(op.key, 'GET', '/v1/events/stream')).status, 403);
  assert.equal((await h.call(biz.key, 'GET', '/v1/events/stream')).status, 403);
  const bad = await h.call(h.admin, 'GET', '/v1/events/stream?limit=1');
  assert.equal(bad.status, 400);
  assert.equal(bad.body.error.code, 'VALIDATION_ERROR');
});

test('events/stream: admin receives published events as SSE frames', async (t) => {
  const h = await startApp();
  t.after(() => h.close());
  const s = await openStream(h.base, h.admin);
  t.after(() => s.abort());
  assert.equal(s.res.status, 200);
  assert.match(s.res.headers.get('content-type'), /^text\/event-stream/);
  assert.equal(s.res.headers.get('cache-control'), 'no-store');
  await s.until(/: connected\n\n/);
  h.app.events.publish('change_detected', { sanctionsId: 'sdn_X', datasetVersion: '2026-09-26', affectedAgentIds: ['agt_A'] });
  h.app.events.publish('passport.status_changed', { passportId: 'pp_A', agentId: 'agt_A', from: 'ACTIVE', to: 'RE_SCREENING', investigationId: null });
  const text = await s.until(/event: passport\.status_changed\ndata: .*\n\n/);
  const frames = [...text.matchAll(/event: (\S+)\ndata: (.*)\n\n/g)].map((m) => [m[1], JSON.parse(m[2])]);
  assert.deepEqual(frames.map(([e]) => e), ['change_detected', 'passport.status_changed']);
  assert.equal(frames[0][1].type, 'change_detected');
  assert.equal(frames[0][1].sanctionsId, 'sdn_X');
  assert.match(frames[0][1].at, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(frames[1][1].to, 'RE_SCREENING');
});

test('events/stream: one stream per key — a second stream for the same key closes the first', async (t) => {
  const h = await startApp();
  t.after(() => h.close());
  const first = await openStream(h.base, h.admin);
  await first.until(/: connected/);
  const second = await openStream(h.base, h.admin);
  t.after(() => second.abort());
  await second.until(/: connected/);
  assert.equal(await first.ended(), true);
  h.app.events.publish('rescreen_started', { agentId: 'agt_A' });
  await second.until(/event: rescreen_started/);
});

test('event hub: closed type set, subscriber isolation, unsubscribe', () => {
  const hub = createEventHub({ clock: { now: () => new Date('2026-09-26T00:00:00Z') } });
  assert.throws(() => hub.publish('passport.deleted', {}), /unknown stream event type/);
  for (const type of ['sanctions.change_detected', 'passport.status_changed', 'investigation.decided', 'harness.adapted']) assert.ok(STREAM_EVENT_TYPES.includes(type));
  const got = [];
  hub.subscribe(() => {
    throw new Error('broken subscriber');
  });
  const off = hub.subscribe((e) => got.push(e));
  hub.publish('affected_agent', { agentId: 'agt_A' });
  off();
  hub.publish('affected_agent', { agentId: 'agt_B' });
  assert.deepEqual(got, [{ type: 'affected_agent', data: { type: 'affected_agent', at: '2026-09-26T00:00:00.000Z', agentId: 'agt_A' } }]);
});
