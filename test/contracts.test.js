// Runtime constants must match the binding contract in docs/contracts/.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { ERROR_CODES, ID_PREFIX, REASON_CODES, REASON_MESSAGES } from '../src/contracts.js';

const typesTs = readFileSync(new URL('../docs/contracts/types.ts', import.meta.url), 'utf8');
const openapi = readFileSync(new URL('../docs/contracts/openapi.yaml', import.meta.url), 'utf8');

test('REASON_CODES match docs/contracts/types.ts and openapi.yaml', () => {
  const block = typesTs.match(/REASON_CODES = \[([\s\S]*?)\] as const/)[1];
  const fromTypes = [...block.matchAll(/'([A-Z_]+)'/g)].map((m) => m[1]);
  assert.deepEqual([...REASON_CODES], fromTypes);
  const enumBlock = openapi.match(/ReasonCode:\s*\n\s*type: string\s*\n\s*enum: \[([\s\S]*?)\]/)[1];
  assert.deepEqual([...REASON_CODES], enumBlock.split(',').map((s) => s.trim()));
  for (const code of REASON_CODES) assert.ok(REASON_MESSAGES[code], `message for ${code}`);
});

test('ERROR_CODES and ID_PREFIX match docs/contracts/types.ts', () => {
  const block = typesTs.match(/ERROR_CODES = \{([\s\S]*?)\} as const/)[1];
  const fromTypes = Object.fromEntries([...block.matchAll(/([A-Z_]+): (\d+)/g)].map((m) => [m[1], Number(m[2])]));
  assert.deepEqual({ ...ERROR_CODES }, fromTypes);
  const prefixBlock = typesTs.match(/ID_PREFIX = \{([\s\S]*?)\} as const/)[1];
  const prefixes = Object.fromEntries([...prefixBlock.matchAll(/(\w+): '(\w+)'/g)].map((m) => [m[1], m[2]]));
  assert.deepEqual({ ...ID_PREFIX }, prefixes);
});
