// REQ-017: the published docs (OpenAPI, README, integration guides) must match the running API.
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { REASON_CODES } from '../src/contracts.js';
import * as sdk from '../src/sdk/agentSigner.js';
import * as businessVerifier from '../src/sdk/businessVerifier.js';
import { startApp } from './helpers.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => readFileSync(resolve(root, p), 'utf8');
const openapi = read('docs/contracts/openapi.yaml');
const DOCS = ['README.md', 'docs/guides/business-integration.md', 'docs/guides/operator-integration.md'];

// "/v1/agents/{id}" -> { get, post, … } from the paths section of openapi.yaml.
function specOperations() {
  const paths = openapi.slice(openapi.indexOf('\npaths:'), openapi.indexOf('\ncomponents:'));
  const ops = new Set();
  let current = null;
  for (const line of paths.split('\n')) {
    const p = line.match(/^ {2}(\/\S*):\s*$/);
    if (p) current = p[1];
    const m = line.match(/^ {4}(get|post|put|patch|delete):\s*$/);
    if (m && current) ops.add(`${m[1].toUpperCase()} ${current}`);
  }
  return ops;
}

function appOperations() {
  const src = read('src/app.js');
  const ops = new Set([...src.matchAll(/\{ m: '(\w+)', p: '([^']+)'/g)].map((m) => `${m[1]} ${m[2].replace(/:id\b/g, '{id}')}`));
  for (const p of ['/healthz', '/.well-known/jwks.json', '/openapi.yaml']) ops.add(`GET ${p}`);
  return ops;
}

test('openapi.yaml documents exactly the implemented endpoints', () => {
  assert.deepEqual([...specOperations()].sort(), [...appOperations()].sort());
});

test('GET /openapi.yaml serves the spec publicly and verbatim', async (t) => {
  const h = await startApp();
  t.after(() => h.close());
  const res = await h.call(null, 'GET', '/openapi.yaml');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /^application\/yaml/);
  assert.equal(res.text, openapi);
  assert.match(res.text, /^openapi: 3\.1\.0/);
});

test('README and guides: relative links resolve', () => {
  for (const doc of DOCS) {
    for (const [, target] of read(doc).matchAll(/\]\(([^)#\s]+)(?:#[^)]*)?\)/g)) {
      if (/^[a-z]+:/i.test(target)) continue;
      assert.ok(existsSync(resolve(root, dirname(doc), target)), `${doc} links to missing ${target}`);
    }
  }
  const readme = read('README.md');
  assert.ok(readme.includes('docs/guides/business-integration.md'));
  assert.ok(readme.includes('docs/guides/operator-integration.md'));
  assert.ok(readme.includes('docs/contracts/openapi.yaml'));
});

test('guides only mention endpoints that exist', () => {
  const ops = specOperations();
  for (const doc of DOCS) {
    for (const [, method, path] of read(doc).matchAll(/\b(GET|POST) (\/[\w./{}-]+)/g)) {
      const normalized = path.replace(/\.$/, '').replace(/\{\w+\}/g, '{id}');
      assert.ok(ops.has(`${method} ${normalized}`), `${doc}: ${method} ${path} is not in openapi.yaml`);
    }
  }
});

test('business guide lists every verification reason code', () => {
  const guide = read('docs/guides/business-integration.md');
  for (const code of REASON_CODES) assert.ok(guide.includes(`\`${code}\``), `missing ${code}`);
});

test('SDK functions named in the docs exist', () => {
  const modules = { agentSigner: sdk, businessVerifier };
  for (const doc of DOCS) {
    for (const [, names, mod] of read(doc).matchAll(/import \{([^}]+)\} from '\.\/src\/sdk\/(\w+)\.js'/g)) {
      assert.ok(modules[mod], `${doc}: unknown SDK module ${mod}`);
      for (const name of names.split(',').map((s) => s.trim())) assert.equal(typeof modules[mod][name], 'function', `${doc}: ${name}`);
    }
  }
});
