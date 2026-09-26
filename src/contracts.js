// Runtime constants mirroring docs/contracts/types.ts (the source of truth).
// test/contracts.test.js asserts these stay in sync with the TypeScript contract.

export const ID_PREFIX = Object.freeze({
  operator: 'op',
  business: 'biz',
  agent: 'agt',
  grant: 'grt',
  credential: 'crd',
  apiKey: 'key',
  verification: 'vrf',
  auditEvent: 'aud',
});

export const ROLES = Object.freeze(['admin', 'operator', 'business']);

export const OPERATOR_STATUSES = Object.freeze(['pending', 'verified', 'rejected', 'suspended']);

export const REASON_CODES = Object.freeze([
  'ALLOWED',
  'MALFORMED_REQUEST',
  'AUDIENCE_MISMATCH',
  'AGENT_NOT_FOUND',
  'AGENT_REVOKED',
  'AGENT_SUSPENDED',
  'OPERATOR_NOT_VERIFIED',
  'OPERATOR_SUSPENDED',
  'TIMESTAMP_OUT_OF_WINDOW',
  'SIGNATURE_INVALID',
  'NONCE_REPLAYED',
  'CREDENTIAL_INVALID',
  'CREDENTIAL_NOT_YET_VALID',
  'CREDENTIAL_EXPIRED',
  'CREDENTIAL_SUBJECT_MISMATCH',
  'CREDENTIAL_AUDIENCE_MISMATCH',
  'CREDENTIAL_KEY_MISMATCH',
  'CREDENTIAL_REVOKED',
  'GRANT_REVOKED',
  'GRANT_EXPIRED',
  'NO_GRANT',
  'ACTION_NOT_PERMITTED',
  'CONSTRAINT_VIOLATION',
  'INTERNAL_ERROR',
]);

export const REASON_MESSAGES = Object.freeze({
  ALLOWED: 'All checks passed',
  MALFORMED_REQUEST: 'Request is malformed or unsigned fields disagree with signed fields',
  AUDIENCE_MISMATCH: 'Signed audience does not match the calling business',
  AGENT_NOT_FOUND: 'Unknown agent',
  AGENT_REVOKED: 'Agent has been revoked',
  AGENT_SUSPENDED: 'Agent is suspended',
  OPERATOR_NOT_VERIFIED: 'Agent operator is not verified',
  OPERATOR_SUSPENDED: 'Agent operator is suspended',
  TIMESTAMP_OUT_OF_WINDOW: 'Signed timestamp is outside the allowed window',
  SIGNATURE_INVALID: 'Signature does not verify with the agent key',
  NONCE_REPLAYED: 'Nonce has already been used by this agent',
  CREDENTIAL_INVALID: 'Credential is invalid',
  CREDENTIAL_NOT_YET_VALID: 'Credential is not yet valid',
  CREDENTIAL_EXPIRED: 'Credential has expired',
  CREDENTIAL_SUBJECT_MISMATCH: 'Credential subject does not match the agent',
  CREDENTIAL_AUDIENCE_MISMATCH: 'Credential audience does not match the calling business',
  CREDENTIAL_KEY_MISMATCH: 'Credential is bound to a different agent key',
  CREDENTIAL_REVOKED: 'Credential has been revoked',
  GRANT_REVOKED: 'Underlying grant has been revoked',
  GRANT_EXPIRED: 'Underlying grant has expired',
  NO_GRANT: 'No active grant from this business to the agent',
  ACTION_NOT_PERMITTED: 'Action is outside the granted scope',
  CONSTRAINT_VIOLATION: 'Grant constraints are not satisfied',
  INTERNAL_ERROR: 'Verification could not be completed; denied by default',
});

export const ERROR_CODES = Object.freeze({
  VALIDATION_ERROR: 400,
  UNAUTHENTICATED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  INVALID_STATE: 409,
  OPERATOR_NOT_VERIFIED: 409,
  PAYLOAD_TOO_LARGE: 413,
  UNSUPPORTED_MEDIA_TYPE: 415,
  INTERNAL_ERROR: 500,
  SERVICE_UNAVAILABLE: 503,
});

export const RESOURCE_ID_RE = /^[a-z]{2,3}_[0-9A-HJKMNP-TV-Z]{26}$/;
export const ACTION_RE = /^[a-z0-9_-]+(:[a-z0-9_-]+)*$/;
export const ACTION_PATTERN_RE = /^[a-z0-9_-]+(:[a-z0-9_-]+)*(:\*)?$/;
export const B64U_43_RE = /^[A-Za-z0-9_-]{43}$/;
export const B64U_86_RE = /^[A-Za-z0-9_-]{86}$/;
export const NONCE_RE = /^[A-Za-z0-9_-]{16,128}$/;
export const SIG_VERSION = 'KYA-SIG-V1';
export const REGISTER_VERSION = 'KYA-REGISTER-V1';
export const CREDENTIAL_TYP = 'kya-credential+jwt';
