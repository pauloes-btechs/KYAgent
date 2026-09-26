import { REGISTER_VERSION, SIG_VERSION } from '../contracts.js';
import { sha256hex } from './ed25519.js';

export const MAX_CONTEXT_DEPTH = 32;

export class CanonicalJsonError extends Error {}

/** Canonical JSON per crypto-and-signing.md §3.1 (sorted keys, integers only). */
export function canonicalJson(value, depth = 0) {
  if (depth > MAX_CONTEXT_DEPTH) throw new CanonicalJsonError('context nested too deeply');
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'string':
      return JSON.stringify(value);
    case 'number':
      if (!Number.isSafeInteger(value)) throw new CanonicalJsonError('only safe integers are allowed');
      return String(value);
    case 'object': {
      if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v, depth + 1)).join(',')}]`;
      const keys = Object.keys(value).sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k], depth + 1)}`).join(',')}}`;
    }
    default:
      throw new CanonicalJsonError(`unsupported JSON type ${typeof value}`);
  }
}

export function contextSha256(context) {
  return sha256hex(Buffer.from(canonicalJson(context ?? {}), 'utf8'));
}

/** KYA-SIG-V1 signing string (crypto-and-signing.md §3.2). */
export function buildSigningString({ agentId, audience, action, resource, contextSha256: ctxHash, timestamp, nonce }) {
  return [SIG_VERSION, agentId, audience, action, resource ?? '', ctxHash, String(timestamp), nonce].join('\n');
}

/** Proof-of-possession message (crypto-and-signing.md §2). */
export function buildRegisterMessage(operatorId, publicKey) {
  return `${REGISTER_VERSION}\n${operatorId}\n${publicKey}`;
}
