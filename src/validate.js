// Minimal strict JSON-schema subset validator for the request schemas in openapi.yaml.
// Returns a list of { path, message } (JSON Pointer paths); empty list = valid.
import { ACTION_PATTERN_RE, ACTION_RE, B64U_43_RE, B64U_86_RE, NONCE_RE, RESOURCE_ID_RE } from './contracts.js';

const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function validate(schema, value, path = '') {
  const errors = [];
  check(schema, value, path, errors);
  return errors;
}

const typeOf = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v);

function check(s, v, path, errors) {
  if (s.nullable && v === null) return;
  const t = typeOf(v);
  switch (s.type) {
    case 'object': {
      if (t !== 'object') return errors.push({ path, message: 'must be an object' });
      for (const key of s.required ?? []) {
        if (!Object.prototype.hasOwnProperty.call(v, key)) errors.push({ path: `${path}/${key}`, message: 'is required' });
      }
      for (const [key, val] of Object.entries(v)) {
        const sub = s.properties?.[key];
        if (!sub) {
          if (s.additionalProperties === false) errors.push({ path: `${path}/${key}`, message: 'is not allowed' });
          continue;
        }
        check(sub, val, `${path}/${key}`, errors);
      }
      return;
    }
    case 'array': {
      if (t !== 'array') return errors.push({ path, message: 'must be an array' });
      if (s.minItems !== undefined && v.length < s.minItems) errors.push({ path, message: `must have at least ${s.minItems} items` });
      if (s.maxItems !== undefined && v.length > s.maxItems) return errors.push({ path, message: `must have at most ${s.maxItems} items` });
      if (s.uniqueItems && new Set(v.map((x) => JSON.stringify(x))).size !== v.length) {
        errors.push({ path, message: 'must not contain duplicate items' });
      }
      v.forEach((item, i) => check(s.items, item, `${path}/${i}`, errors));
      return;
    }
    case 'string': {
      if (t !== 'string') return errors.push({ path, message: 'must be a string' });
      if (s.minLength !== undefined && v.length < s.minLength) return errors.push({ path, message: `must be at least ${s.minLength} characters` });
      if (s.maxLength !== undefined && v.length > s.maxLength) return errors.push({ path, message: `must be at most ${s.maxLength} characters` });
      if (s.enum && !s.enum.includes(v)) return errors.push({ path, message: `must be one of ${s.enum.join(', ')}` });
      if (s.pattern && !s.pattern.test(v)) return errors.push({ path, message: s.patternMessage ?? 'has an invalid format' });
      if (s.format === 'date-time' && (!ISO_RE.test(v) || Number.isNaN(Date.parse(v)))) {
        return errors.push({ path, message: 'must be an ISO 8601 date-time' });
      }
      if (s.format === 'email' && !EMAIL_RE.test(v)) return errors.push({ path, message: 'must be an email address' });
      return;
    }
    case 'integer': {
      if (!Number.isSafeInteger(v)) return errors.push({ path, message: 'must be an integer' });
      if (s.minimum !== undefined && v < s.minimum) return errors.push({ path, message: `must be >= ${s.minimum}` });
      if (s.maximum !== undefined && v > s.maximum) return errors.push({ path, message: `must be <= ${s.maximum}` });
      return;
    }
    case 'const':
      if (v !== s.value) errors.push({ path, message: `must be ${JSON.stringify(s.value)}` });
      return;
    case 'any-object':
      if (t !== 'object') errors.push({ path, message: 'must be an object' });
      return;
    default:
      throw new Error(`unsupported schema type ${s.type}`);
  }
}

// ---------------------------------------------------------------- schemas
const str = (opts = {}) => ({ type: 'string', ...opts });
const resourceId = str({ pattern: RESOURCE_ID_RE, patternMessage: 'must be a resource id' });
const actionPattern = str({
  maxLength: 128,
  pattern: ACTION_PATTERN_RE,
  patternMessage: 'must be an action pattern like "orders:create" or "orders:*" (a bare * is not allowed)',
});
const noNewline = /^[^\n\r]*$/;

export const schemas = {
  reason: { type: 'object', additionalProperties: false, required: ['reason'], properties: { reason: str({ minLength: 1, maxLength: 500 }) } },
  createBusiness: { type: 'object', additionalProperties: false, required: ['name'], properties: { name: str({ minLength: 1, maxLength: 200 }) } },
  createOperator: {
    type: 'object',
    additionalProperties: false,
    required: ['type', 'legalName', 'contactEmail', 'country'],
    properties: {
      type: str({ enum: ['individual', 'organization'] }),
      legalName: str({ minLength: 1, maxLength: 200 }),
      contactEmail: str({ maxLength: 254, format: 'email' }),
      country: str({ pattern: /^[A-Z]{2}$/, patternMessage: 'must be an ISO 3166-1 alpha-2 code' }),
    },
  },
  createApiKey: {
    type: 'object',
    additionalProperties: false,
    required: ['name', 'role'],
    properties: {
      name: str({ minLength: 1, maxLength: 100 }),
      role: str({ enum: ['admin', 'operator', 'business'] }),
      ownerId: str({ maxLength: 64, nullable: true }),
    },
  },
  createAgent: {
    type: 'object',
    additionalProperties: false,
    required: ['name', 'publicKey', 'proofOfPossession'],
    properties: {
      name: str({ minLength: 1, maxLength: 100 }),
      description: str({ maxLength: 1000 }),
      publicKey: str({ pattern: B64U_43_RE, patternMessage: 'must be a base64url Ed25519 public key (43 chars)' }),
      proofOfPossession: str({ pattern: B64U_86_RE, patternMessage: 'must be a base64url Ed25519 signature (86 chars)' }),
    },
  },
  grantConstraints: {
    type: 'object',
    additionalProperties: false,
    properties: {
      maxAmount: { type: 'integer', minimum: 0, maximum: Number.MAX_SAFE_INTEGER },
      currency: str({ pattern: /^[A-Z]{3}$/, patternMessage: 'must be an ISO 4217 code' }),
      resources: {
        type: 'array',
        minItems: 1,
        maxItems: 100,
        uniqueItems: true,
        items: str({ minLength: 1, maxLength: 256, pattern: /^[^\n\r]+$/ }),
      },
    },
  },
  issueCredential: {
    type: 'object',
    additionalProperties: false,
    required: ['grantId'],
    properties: { grantId: resourceId, ttlSeconds: { type: 'integer', minimum: 60, maximum: 86400 } },
  },
  signedRequest: {
    type: 'object',
    additionalProperties: false,
    required: ['version', 'agentId', 'audience', 'action', 'resource', 'contextSha256', 'timestamp', 'nonce', 'signature'],
    properties: {
      version: { type: 'const', value: 'KYA-SIG-V1' },
      agentId: str({ minLength: 1, maxLength: 64, pattern: noNewline }),
      audience: str({ minLength: 1, maxLength: 64, pattern: noNewline }),
      action: str({ maxLength: 128, pattern: ACTION_RE }),
      resource: str({ maxLength: 256, pattern: noNewline }),
      contextSha256: str({ pattern: /^[0-9a-f]{64}$/ }),
      timestamp: { type: 'integer', minimum: 0, maximum: 9999999999 },
      nonce: str({ pattern: NONCE_RE }),
      signature: str({ pattern: B64U_86_RE }),
    },
  },
};

schemas.createGrant = {
  type: 'object',
  additionalProperties: false,
  required: ['agentId', 'actions', 'expiresAt'],
  properties: {
    agentId: resourceId,
    actions: { type: 'array', minItems: 1, maxItems: 50, uniqueItems: true, items: actionPattern },
    constraints: schemas.grantConstraints,
    expiresAt: str({ format: 'date-time' }),
  },
};

schemas.verifyRequest = {
  type: 'object',
  additionalProperties: false,
  required: ['agentId', 'action', 'signedRequest'],
  properties: {
    agentId: str({ maxLength: 64 }),
    action: str({ maxLength: 128, pattern: ACTION_RE }),
    resource: str({ maxLength: 256, pattern: noNewline }),
    context: { type: 'any-object' },
    credential: str({ maxLength: 8192 }),
    signedRequest: schemas.signedRequest,
  },
};
