/**
 * KYAgent shared contract types (source of truth).
 *
 * `src/contracts/types.ts` MUST be a byte-for-byte copy of this file.
 * Wire format: JSON, camelCase fields, timestamps as ISO 8601 UTC strings
 * (e.g. "2026-09-26T12:00:00.000Z") unless stated otherwise.
 * Keep in sync with openapi.yaml, data-schema.md and error-model.md.
 */

// ---------------------------------------------------------------------------
// Identifiers — prefix + "_" + 26-char Crockford base32 (ULID) e.g. "agt_01J8..."
// ---------------------------------------------------------------------------

export const ID_PREFIX = {
  operator: 'op',
  business: 'biz',
  agent: 'agt',
  grant: 'grt',
  credential: 'crd',
  apiKey: 'key',
  verification: 'vrf',
  auditEvent: 'aud',
} as const;

export type OperatorId = string; // op_...
export type BusinessId = string; // biz_...
export type AgentId = string; // agt_...
export type GrantId = string; // grt_...
export type CredentialId = string; // crd_... (also the JWS `jti`)
export type ApiKeyId = string; // key_...
export type VerificationId = string; // vrf_...
export type IsoDateTime = string;

// ---------------------------------------------------------------------------
// Auth / RBAC
// ---------------------------------------------------------------------------

export const ROLES = ['admin', 'operator', 'business'] as const;
export type Role = (typeof ROLES)[number];

/** Resolved caller identity, attached to each authenticated request. */
export type Principal =
  | { role: 'admin'; apiKeyId: ApiKeyId }
  | { role: 'operator'; apiKeyId: ApiKeyId; operatorId: OperatorId }
  | { role: 'business'; apiKeyId: ApiKeyId; businessId: BusinessId };

export type ApiKeyStatus = 'active' | 'revoked';

export interface ApiKey {
  id: ApiKeyId;
  name: string;
  role: Role;
  /** operatorId for role=operator, businessId for role=business, null for admin. */
  ownerId: string | null;
  status: ApiKeyStatus;
  /** "kya_" + id — the non-secret part of the plaintext key, for display only. */
  displayPrefix: string;
  createdAt: IsoDateTime;
  lastUsedAt: IsoDateTime | null;
  revokedAt: IsoDateTime | null;
}

export interface CreateApiKeyRequest {
  name: string;
  role: Role;
  ownerId?: string | null;
}

export interface CreateApiKeyResponse {
  apiKey: ApiKey;
  /** Plaintext key. Returned exactly once; never stored or retrievable again. */
  secret: string;
}

// ---------------------------------------------------------------------------
// Businesses (relying parties)
// ---------------------------------------------------------------------------

export type BusinessStatus = 'active' | 'suspended';

export interface Business {
  id: BusinessId;
  name: string;
  status: BusinessStatus;
  createdAt: IsoDateTime;
}

export interface CreateBusinessRequest {
  name: string;
}

// ---------------------------------------------------------------------------
// Operators
// ---------------------------------------------------------------------------

export const OPERATOR_STATUSES = ['pending', 'verified', 'rejected', 'suspended'] as const;
export type OperatorStatus = (typeof OPERATOR_STATUSES)[number];
export type OperatorType = 'individual' | 'organization';

export type SanctionsMode = 'mock' | 'off';
export type SanctionsResult = 'clear' | 'hit' | 'skipped';
export type KycResult = 'pass' | 'fail';

export interface OperatorVerification {
  /** Always "mock" in MVP. */
  method: 'mock';
  kycResult: KycResult;
  sanctionsMode: SanctionsMode;
  sanctionsResult: SanctionsResult;
  checkedAt: IsoDateTime;
}

export interface Operator {
  id: OperatorId;
  type: OperatorType;
  legalName: string;
  contactEmail: string;
  /** ISO 3166-1 alpha-2, uppercase. */
  country: string;
  status: OperatorStatus;
  verification: OperatorVerification | null;
  statusReason: string | null;
  createdAt: IsoDateTime;
  updatedAt: IsoDateTime;
}

/** Subset returned to non-owner, non-admin callers (businesses). */
export interface OperatorPublicProfile {
  id: OperatorId;
  type: OperatorType;
  legalName: string;
  country: string;
  status: OperatorStatus;
}

export interface CreateOperatorRequest {
  type: OperatorType;
  legalName: string;
  contactEmail: string;
  country: string;
}

export interface SuspendRequest {
  reason: string;
}

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------

export type AgentStatus = 'active' | 'suspended' | 'revoked';

export interface Agent {
  id: AgentId;
  operatorId: OperatorId;
  name: string;
  description: string | null;
  /** Ed25519 raw 32-byte public key, base64url without padding (43 chars). */
  publicKey: string;
  /** RFC 7638 JWK SHA-256 thumbprint of the public key, base64url. */
  keyThumbprint: string;
  status: AgentStatus;
  statusReason: string | null;
  createdAt: IsoDateTime;
  updatedAt: IsoDateTime;
  revokedAt: IsoDateTime | null;
}

/** REQ-019: advisory, rule-based trust score (GET /v1/agents/{id}/trust-score). */
export type TrustLevel = 'high' | 'medium' | 'low' | 'untrusted';

export interface TrustFactor {
  code: 'operator_verification' | 'agent_age' | 'revocation_history' | 'scope_breadth';
  label: string;
  points: number;
  maxPoints: number;
  detail: string;
  inputs: Record<string, unknown>;
}

export interface TrustScore {
  agentId: AgentId;
  operatorId: OperatorId;
  rulesVersion: 'kya-trust-v1';
  score: number;
  maxScore: 100;
  level: TrustLevel;
  /** Hard-gate failures (agent not active / operator not verified); non-empty => score 0. */
  gates: string[];
  factors: TrustFactor[];
  computedAt: IsoDateTime;
  advisory: string;
}

export interface CreateAgentRequest {
  name: string;
  description?: string;
  publicKey: string;
  /**
   * base64url Ed25519 signature by the agent private key over
   * "KYA-REGISTER-V1\n{operatorId}\n{publicKey}" (see crypto-and-signing.md).
   */
  proofOfPossession: string;
}

// ---------------------------------------------------------------------------
// Grants (business → agent authorizations)
// ---------------------------------------------------------------------------

export type GrantStatus = 'active' | 'revoked';

/**
 * Action pattern: segments [a-z0-9_-]+ joined by ':'; may end in ':*'.
 * Regex: ^[a-z0-9_-]+(:[a-z0-9_-]+)*(:\*)?$
 */
export type ActionPattern = string;
/** Concrete action: ^[a-z0-9_-]+(:[a-z0-9_-]+)*$ */
export type Action = string;

export interface GrantConstraints {
  /** Integer, minor currency units. Requires integer context.amount <= maxAmount. */
  maxAmount?: number;
  /** ISO 4217 uppercase. Requires context.currency === currency. */
  currency?: string;
  /** Allowed resource identifiers. Requires resource ∈ resources. */
  resources?: string[];
}

export interface Grant {
  id: GrantId;
  businessId: BusinessId;
  agentId: AgentId;
  /** Denormalized from the agent at creation. */
  operatorId: OperatorId;
  actions: ActionPattern[];
  constraints: GrantConstraints;
  status: GrantStatus;
  expiresAt: IsoDateTime;
  createdAt: IsoDateTime;
  revokedAt: IsoDateTime | null;
  statusReason: string | null;
}

export interface CreateGrantRequest {
  agentId: AgentId;
  actions: ActionPattern[];
  constraints?: GrantConstraints;
  /** Must be in the future and <= now + 365 days. */
  expiresAt: IsoDateTime;
}

// ---------------------------------------------------------------------------
// Credentials (signed JWS issued to agents)
// ---------------------------------------------------------------------------

export type CredentialStatus = 'active' | 'revoked';

export interface CredentialRecord {
  id: CredentialId;
  agentId: AgentId;
  operatorId: OperatorId;
  businessId: BusinessId;
  grantId: GrantId;
  actions: ActionPattern[];
  status: CredentialStatus;
  issuedAt: IsoDateTime;
  expiresAt: IsoDateTime;
  revokedAt: IsoDateTime | null;
  statusReason: string | null;
}

export interface IssueCredentialRequest {
  grantId: GrantId;
  /** Default KYA_CREDENTIAL_DEFAULT_TTL_SECONDS; must be 60..KYA_CREDENTIAL_MAX_TTL_SECONDS. */
  ttlSeconds?: number;
}

export interface IssueCredentialResponse {
  /** Compact JWS. Never persisted server-side. */
  credential: string;
  record: CredentialRecord;
}

/** JWS protected header of a credential. */
export interface CredentialJwsHeader {
  alg: 'EdDSA';
  typ: 'kya-credential+jwt';
  kid: string;
}

/** JWS payload of a credential. Times are NumericDate (unix seconds). */
export interface CredentialClaims {
  iss: string; // KYA_ISSUER
  sub: AgentId;
  aud: BusinessId;
  iat: number;
  nbf: number;
  exp: number;
  jti: CredentialId;
  kya_operator: OperatorId;
  kya_grant: GrantId;
  kya_actions: ActionPattern[];
  kya_constraints: GrantConstraints;
  cnf: { jkt: string }; // agent key thumbprint (RFC 7638)
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/**
 * JSON value allowed in signed context. Floats are NOT allowed (integers only)
 * so canonical JSON is identical across languages.
 */
export type ContextValue =
  | string
  | number
  | boolean
  | null
  | ContextValue[]
  | { [key: string]: ContextValue };

export interface SignedRequest {
  version: 'KYA-SIG-V1';
  agentId: AgentId;
  /** Business id the agent is talking to. */
  audience: BusinessId;
  action: Action;
  /** Empty string when not applicable. */
  resource: string;
  /** Lowercase hex SHA-256 of canonical JSON of `context` ("{}" when absent). */
  contextSha256: string;
  /** Unix seconds (integer). */
  timestamp: number;
  /** 16..128 chars of [A-Za-z0-9_-]. */
  nonce: string;
  /** base64url Ed25519 signature over the canonical signing string. */
  signature: string;
}

export interface VerifyRequest {
  agentId: AgentId;
  action: Action;
  resource?: string;
  context?: { [key: string]: ContextValue };
  /** Optional compact JWS credential presented by the agent. */
  credential?: string;
  signedRequest: SignedRequest;
}

export type Decision = 'ALLOW' | 'DENY';

export const REASON_CODES = [
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
] as const;
export type ReasonCode = (typeof REASON_CODES)[number];

export interface DecisionReason {
  code: ReasonCode;
  /** Human-readable, non-sensitive. Clients MUST branch on `code`, not `message`. */
  message: string;
}

export interface VerifyResponse {
  verificationId: VerificationId;
  decision: Decision;
  /** ALLOW => [{code:"ALLOWED"}]; DENY => exactly one reason (first failed check). */
  reasons: DecisionReason[];
  agentId: AgentId | null;
  operatorId: OperatorId | null;
  action: Action | null;
  grantId: GrantId | null;
  credentialId: CredentialId | null;
  evaluatedAt: IsoDateTime;
}

export interface VerificationEvent extends VerifyResponse {
  businessId: BusinessId;
  requestId: string;
}

// ---------------------------------------------------------------------------
// Audit log (REQ-008) — append-only, hash-chained
// ---------------------------------------------------------------------------

export type AuditEventType =
  | 'operator.created'
  | 'operator.verification_completed'
  | 'operator.suspended'
  | 'business.created'
  | 'api_key.created'
  | 'api_key.revoked'
  | 'agent.registered'
  | 'agent.suspended'
  | 'agent.reactivated'
  | 'agent.revoked'
  | 'grant.created'
  | 'grant.revoked'
  | 'credential.issued'
  | 'credential.revoked'
  | 'verification.decided';

export interface AuditEvent {
  id: string; // aud_...
  /** Contiguous from 1; unique. */
  seq: number;
  type: AuditEventType;
  occurredAt: IsoDateTime;
  actor: { role: Role | 'system'; apiKeyId: string | null; ownerId: string | null };
  subjectType: 'operator' | 'business' | 'api_key' | 'agent' | 'grant' | 'credential' | 'verification';
  subjectId: string;
  requestId: string | null;
  /** Ids and non-secret metadata only. */
  data: Record<string, unknown>;
  /** Hash of the previous event (64 zeros for seq 1). */
  prevHash: string;
  /** SHA-256 hex of canonical JSON of all fields above except `hash`. */
  hash: string;
}

// ---------------------------------------------------------------------------
// Errors (non-decision HTTP errors)
// ---------------------------------------------------------------------------

export const ERROR_CODES = {
  VALIDATION_ERROR: 400,
  UNAUTHENTICATED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  INVALID_STATE: 409,
  OPERATOR_NOT_VERIFIED: 409,
  PAYLOAD_TOO_LARGE: 413,
  UNSUPPORTED_MEDIA_TYPE: 415,
  RATE_LIMITED: 429,
  INTERNAL_ERROR: 500,
  SERVICE_UNAVAILABLE: 503,
} as const;
export type ErrorCode = keyof typeof ERROR_CODES;

export interface ErrorBody {
  error: {
    code: ErrorCode;
    message: string;
    requestId: string;
    /** Field-level problems for VALIDATION_ERROR: [{ path: "/actions/0", message }]. */
    details?: Array<{ path: string; message: string }>;
  };
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

export interface Page<T> {
  data: T[];
  /** Opaque cursor; null when no more results. */
  nextCursor: string | null;
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

export interface Clock {
  now(): Date;
}

export interface HealthResponse {
  status: 'ok';
  store: 'memory' | 'mongo';
}
