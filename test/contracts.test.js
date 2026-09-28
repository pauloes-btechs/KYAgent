// Runtime constants must match the binding contract in docs/contracts/.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { ERROR_CODES, ID_PREFIX, REASON_CODES, REASON_MESSAGES, RISK_DECISIONS, RISK_REASON_CODES } from '../src/contracts.js';

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

test('RISK_DECISIONS and RISK_REASON_CODES match types.ts, openapi.yaml and decision-vocabulary.md', () => {
  const list = (re, src) => [...src.match(re)[1].matchAll(/'([A-Z_]+)'/g)].map((m) => m[1]);
  assert.deepEqual([...RISK_DECISIONS], list(/RISK_DECISIONS = \[([\s\S]*?)\] as const/, typesTs));
  assert.deepEqual([...RISK_REASON_CODES], list(/RISK_REASON_CODES = \[([\s\S]*?)\] as const/, typesTs));
  const oaDecisions = openapi.match(/RiskDecision: \{ type: string, enum: \[([^\]]*)\] \}/)[1].split(',').map((s) => s.trim());
  assert.deepEqual([...RISK_DECISIONS], oaDecisions);
  const oaCodes = openapi.match(/RiskReasonCode:\s*\n\s*type: string\s*\n\s*enum: \[([\s\S]*?)\]/)[1].split(',').map((s) => s.trim());
  assert.deepEqual([...RISK_REASON_CODES], oaCodes);
  // decision-vocabulary.md §4 table: same codes, same order, each with its verdict.
  const vocab = readFileSync(new URL('../docs/contracts/decision-vocabulary.md', import.meta.url), 'utf8');
  const rows = [...vocab.split('## 4.')[1].split('## 5.')[0].matchAll(/^\| `([A-Z_]+)` \| (ALLOW|REVIEW|BLOCK) \|/gm)].map((m) => [m[1], m[2]]);
  assert.deepEqual(rows.map(([c]) => c), [...RISK_REASON_CODES]);
  for (const [, d] of rows) assert.ok(RISK_DECISIONS.includes(d));
  assert.ok(Object.isFrozen(RISK_DECISIONS) && Object.isFrozen(RISK_REASON_CODES));
  // The /v1/verify vocabulary is untouched: Decision stays ALLOW|DENY, no risk code leaks into REASON_CODES.
  assert.match(typesTs, /export type Decision = 'ALLOW' \| 'DENY';/);
  assert.match(openapi, /Decision: \{ type: string, enum: \[ALLOW, DENY\] \}/);
  for (const code of RISK_REASON_CODES) if (code !== 'INTERNAL_ERROR') assert.ok(!REASON_CODES.includes(code), code);
});

test('ERROR_CODES and ID_PREFIX match docs/contracts/types.ts', () => {
  const block = typesTs.match(/ERROR_CODES = \{([\s\S]*?)\} as const/)[1];
  const fromTypes = Object.fromEntries([...block.matchAll(/([A-Z_]+): (\d+)/g)].map((m) => [m[1], Number(m[2])]));
  assert.deepEqual({ ...ERROR_CODES }, fromTypes);
  const prefixBlock = typesTs.match(/ID_PREFIX = \{([\s\S]*?)\} as const/)[1];
  const prefixes = Object.fromEntries([...prefixBlock.matchAll(/(\w+): '(\w+)'/g)].map((m) => [m[1], m[2]]));
  assert.deepEqual({ ...ID_PREFIX }, prefixes);
});
