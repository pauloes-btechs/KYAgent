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

// ===========================================================================
// Investigation harness (T01 contract freeze — ARCHITECTURE.md §9)
// Additive only: nothing above this line changes. `Decision`, `REASON_CODES`
// and `VerifyResponse` keep describing /v1/verify byte-for-byte.
// Companions: mongo-collections.md, investigation-pipeline.md, harness.md,
// decision-vocabulary.md, passport.md, receipt.schema.json, search-indexes.json.
// ===========================================================================

/** Id prefixes of harness documents (runtime ids: prefix + "_" + ULID; seeds use fixed ids). */
export const INVESTIGATION_ID_PREFIXES = {
  investigation: 'inv',
  receipt: 'rcp',
  passport: 'pp',
  memory: 'mem',
  transaction: 'txn',
  sanctionsEntity: 'sdn',
  sanctionsUpdate: 'upd',
  harnessEvent: 'hev',
} as const;

export type PrincipalId = OperatorId; // principal := operator (alias, no rename)
export type DelegationId = GrantId; // delegation := grant (alias, no rename)
export type InvestigationId = string; // inv_...
export type ReceiptId = string; // rcp_...
export type PassportId = string; // pp_...
export type MemoryId = string; // mem_...
/** Lowercased EVM address, ^0x[0-9a-f]{40}$. */
export type EvmAddress = string;

// ---------------------------------------------------------------------------
// Risk decision vocabulary (decision-vocabulary.md)
// ---------------------------------------------------------------------------

export const RISK_DECISIONS = ['ALLOW', 'REVIEW', 'BLOCK'] as const;
export type RiskDecision = (typeof RISK_DECISIONS)[number];

export const RISK_REASON_CODES = [
  'CLEAR',
  'IDENTITY_DENIED',
  'DELEGATION_DENIED',
  'DELEGATION_MAX_EXCEEDED',
  'DAILY_LIMIT_EXCEEDED',
  'WALLET_NOT_APPROVED',
  'ASSET_NOT_PERMITTED',
  'SANCTIONS_EXACT_MATCH',
  'SANCTIONS_FUZZY_MATCH',
  'PASSPORT_SUSPENDED',
  'PASSPORT_REVOKED',
  'PASSPORT_UNDER_REVIEW',
  'PASSPORT_RE_SCREENING',
  'MEMORY_PRECEDENT_TAKEOVER',
  'BEHAVIOR_ESCALATION',
  'HARNESS_INVARIANTS_MISMATCH',
  'INTERNAL_ERROR',
] as const;
export type RiskReasonCode = (typeof RISK_REASON_CODES)[number];

export const INVARIANT_IDS = [
  'INV_SANCTIONS_EXACT_BLOCK',
  'INV_DELEGATION_MAX',
  'INV_DAILY_LIMIT',
  'INV_NO_SELF_APPROVAL',
  'INV_NO_SELF_PASSPORT_MODIFICATION',
  'INV_UNVERIFIED_MEMORY_NOT_PRECEDENT',
] as const;
export type InvariantId = (typeof INVARIANT_IDS)[number];

export const PIPELINE_STAGES = ['identity', 'delegation', 'sanctions', 'signals', 'memory', 'policy', 'decision'] as const;
export type PipelineStageName = (typeof PIPELINE_STAGES)[number];
/** Closed registry of adaptive steps (harness.md §3.3). */
export const ADAPTIVE_STEPS = ['signing_key_history_check'] as const;
export type AdaptiveStepId = (typeof ADAPTIVE_STEPS)[number];

export const SIGNALS = ['NEW_WALLET', 'NEW_COUNTERPARTY', 'SIGNING_KEY_CHANGED', 'AMOUNT_ANOMALY', 'VELOCITY', 'NEAR_CEILING'] as const;
export type Signal = (typeof SIGNALS)[number];

export const OUTCOMES = ['CLEAN', 'CONFIRMED_ACCOUNT_TAKEOVER', 'FALSE_POSITIVE', 'SANCTIONS_MATCH'] as const;
export type Outcome = (typeof OUTCOMES)[number];

export interface RiskReason {
  code: RiskReasonCode;
  /** Verdict this reason alone implies. */
  riskDecision: RiskDecision;
  /** Human-readable; clients MUST branch on `code`. */
  message: string;
  /** Pipeline stage or adaptive step id that produced it. */
  stage: PipelineStageName | AdaptiveStepId;
  invariantId?: InvariantId;
  /** /v1/verify reason code for IDENTITY_DENIED / DELEGATION_DENIED / DELEGATION_MAX_EXCEEDED. */
  identityReasonCode?: ReasonCode;
  evidenceRefs?: string[];
}

// ---------------------------------------------------------------------------
// Investigations (investigation-pipeline.md)
// ---------------------------------------------------------------------------

export type InvestigationTrigger = 'api' | 'sanctions_change' | 'manual';
export type InvestigationStatus = 'DECIDED' | 'AWAITING_REVIEW' | 'CONFIRMED';
export type StageEngine =
  | 'code'
  | 'find'
  | 'aggregate'
  | '$search'
  | '$vectorSearch'
  | 'find+$search'
  | 'find+code'
  | 'find+aggregate';
export type StageStatus = 'passed' | 'failed' | 'flagged' | 'skipped' | 'error';

/** Signed `context` of an investigated payment (integers only; amount in USDC minor units, 6 decimals). */
export interface PaymentContext {
  amount: number;
  currency: 'USDC';
  counterparty: EvmAddress;
  counterpartyName?: string;
  /** Defaults to the agent's first wallet. */
  wallet?: EvmAddress;
}

/** POST /v1/investigations body: a VerifyRequest whose signed context is a PaymentContext. */
export interface InvestigationRequest extends VerifyRequest {
  context: PaymentContext & { [key: string]: ContextValue };
}

export interface EvidenceItem {
  id: string;
  kind: 'identity' | 'delegation' | 'sanctions_exact' | 'sanctions_fuzzy' | 'signal' | 'memory' | 'invariant' | 'policy' | 'passport' | 'step';
  /** Collection or module, e.g. "sanctions", "security_memories". */
  source: string;
  ref: string | null;
  summary: string;
  data: Record<string, unknown>;
}

export interface StageResult {
  name: PipelineStageName | AdaptiveStepId;
  engine: StageEngine;
  status: StageStatus;
  startedAt: IsoDateTime;
  durationMs: number;
  result: Record<string, unknown>;
  evidence: EvidenceItem[];
  reasons: RiskReason[];
}

/** `result` of the `policy` stage (investigation-pipeline.md §4 row 6). */
export interface PolicyStageResult {
  harnessVersion: number | null;
  /** Runtime INVARIANTS_HASH. */
  invariantsHash: string;
  /** invariantsHash stored on the active harness version (mismatch ⇒ BLOCK HARNESS_INVARIANTS_MISMATCH). */
  harnessInvariantsHash: string | null;
  policyHash: string;
  /** `held` is null when the invariant does not apply to this run (e.g. no amount on a re-screen). */
  invariants: Array<{ id: InvariantId; applicable: boolean; held: boolean | null; droppedUnverified?: number }>;
  passportStatus: PassportStatus | null;
  escalationsFired: string[];
}

export interface MemoryHit {
  memoryId: MemoryId;
  title: string;
  /** Always VERIFIED (INV_UNVERIFIED_MEMORY_NOT_PRECEDENT). */
  status: 'VERIFIED';
  outcome: Outcome;
  /** $meta vectorSearchScore (API only; hashed forms use scorePpm). */
  score: number;
  scorePpm: number;
  signals: Signal[];
  recommendedSteps: AdaptiveStepId[];
  usedAsPrecedent: boolean;
}

export interface InvestigationTransaction {
  asset: 'USDC';
  /** Minor units; null for sanctions_change re-screens. */
  amount: number | null;
  wallet: EvmAddress;
  counterparty: { address: EvmAddress; name: string | null };
}

export interface Investigation {
  id: InvestigationId;
  trigger: InvestigationTrigger;
  status: InvestigationStatus;
  agentId: AgentId;
  principalId: PrincipalId | null;
  businessId: BusinessId | null;
  delegationId: DelegationId | null;
  delegationVersion: number | null;
  action: Action | null;
  transaction: InvestigationTransaction | null;
  harnessVersion: number;
  stages: StageResult[];
  signals: Signal[];
  memory: { engine: '$vectorSearch'; k: number; minScorePpm: number; hits: MemoryHit[] };
  /** Identity-layer verdict (same vocabulary as /v1/verify). */
  decision: Decision;
  riskDecision: RiskDecision;
  /** Sorted by precedence; reasons[0] is primary. ALLOW => [{ code: 'CLEAR' }]. */
  reasons: RiskReason[];
  outcome: Outcome | null;
  passport: { id: PassportId; before: PassportStatus; after: PassportStatus } | null;
  receiptId: ReceiptId;
  receiptHash: string;
  /** Embedded copy of the issued receipt (null only when issuing it failed ⇒ BLOCK INTERNAL_ERROR). */
  receipt?: Receipt | null;
  requestId: string | null;
  createdAt: IsoDateTime;
  decidedAt: IsoDateTime;
  confirmedAt: IsoDateTime | null;
}

export interface ConfirmInvestigationRequest {
  outcome: Outcome;
  note?: string;
  /** Human approval of the proposed harness adaptation; false => proposal recorded as rejected. */
  approveAdaptation: boolean;
}

export interface ConfirmInvestigationResponse {
  investigation: Investigation;
  memory: { id: MemoryId; status: 'VERIFIED' | 'REJECTED' };
  adaptation: {
    proposed: boolean;
    applied: boolean;
    eventId: string | null;
    fromVersion: number;
    toVersion: number | null;
    diff: JsonPatchOp[];
  };
}

// ---------------------------------------------------------------------------
// Passports (passport.md)
// ---------------------------------------------------------------------------

export const PASSPORT_STATUSES = ['ACTIVE', 'REVIEW', 'RE_SCREENING', 'SUSPENDED', 'REVOKED'] as const;
export type PassportStatus = (typeof PASSPORT_STATUSES)[number];

export interface ActorRef {
  role: Role | 'system';
  apiKeyId: ApiKeyId | null;
  ownerId: string | null;
}

export interface PassportStatusChange {
  status: PassportStatus;
  at: IsoDateTime;
  actor: ActorRef;
  reason: string | null;
  investigationId: InvestigationId | null;
}

export interface Passport {
  id: PassportId;
  agentId: AgentId;
  principalId: PrincipalId;
  delegationId: DelegationId;
  delegationVersion: number;
  wallet: EvmAddress;
  status: PassportStatus;
  statusReason: string | null;
  credentialId: CredentialId | null;
  lastInvestigationId: InvestigationId | null;
  sanctionsDatasetVersion: string;
  harnessVersion: number;
  issuedAt: IsoDateTime;
  expiresAt: IsoDateTime;
  updatedAt: IsoDateTime;
  statusHistory: PassportStatusChange[];
}

/** Business view of a passport (public fields only). */
export type PassportPublicView = Pick<Passport, 'agentId' | 'principalId' | 'status' | 'harnessVersion' | 'sanctionsDatasetVersion' | 'updatedAt'>;

export interface PassportTransitionRequest {
  to: PassportStatus;
  reason: string;
}

/** Optional claims added to CredentialClaims when a passport exists (passport.md §5). */
export interface PassportCredentialClaims extends CredentialClaims {
  kya_passport?: PassportId;
  kya_delegation_v?: number;
  kya_harness_v?: number;
}

// ---------------------------------------------------------------------------
// Harness (harness.md)
// ---------------------------------------------------------------------------

export interface HarnessPolicy {
  /** Core stages in fixed order, adaptive steps between 'memory' and 'policy'; 'decision' implicit. */
  steps: Array<Exclude<PipelineStageName, 'decision'> | AdaptiveStepId>;
  memoryRetrieval: { k: number; numCandidates: number; minScorePpm: number; filter: { status: 'VERIFIED' } };
  sanctionsFuzzy?: { minScorePpm: number; limit: number };
  contextAssembly: { maxMemories: number; includeSignalStats: boolean; includeSanctionsEvidence: boolean };
  evidenceRequests: Array<{ id: string; stage: string; description: string }>;
  escalation: Array<{
    id: string;
    when: {
      precedentOutcomeIn?: Outcome[];
      signalsAll?: Signal[];
      signalsAnyMin?: { of: Signal[]; min: number };
      sanctionsFuzzyHit?: true;
    };
    then: { riskDecision: 'REVIEW'; reasonCode: 'MEMORY_PRECEDENT_TAKEOVER' | 'BEHAVIOR_ESCALATION' | 'SANCTIONS_FUZZY_MATCH' };
  }>;
}

/** RFC 6902 subset; paths restricted to the adaptable keys (harness.md §2). */
export interface JsonPatchOp {
  op: 'add' | 'remove' | 'replace';
  path: string;
  value?: unknown;
}

export interface HarnessVersion {
  version: number;
  status: 'active' | 'superseded';
  parentVersion: number | null;
  invariantsHash: string;
  policy: HarnessPolicy;
  policyHash: string;
  createdAt: IsoDateTime;
  approvedBy: ActorRef & { label?: 'seed' };
  sourceEventId: string | null;
}

export interface HarnessEvent {
  id: string; // hev_...
  type: 'adaptation.applied' | 'adaptation.rejected';
  fromVersion: number;
  toVersion: number | null;
  diff: JsonPatchOp[];
  oldPolicy: HarnessPolicy;
  newPolicy: HarnessPolicy | null;
  oldPolicyHash: string;
  newPolicyHash: string | null;
  invariantsHash: string;
  evidence: Array<{ type: 'investigation' | 'memory'; id: string }>;
  proposer: { kind: 'template' | 'llm'; llmMode: 'fixture' | 'live'; model: string | null };
  approvedBy: ActorRef;
  approvedAt: IsoDateTime;
  at: IsoDateTime;
  auditEventId: string;
}

// ---------------------------------------------------------------------------
// Receipts (receipt.schema.json is normative; this is its TypeScript view)
// ---------------------------------------------------------------------------

export interface Receipt {
  receiptVersion: 'kya-receipt-v1';
  receiptId: ReceiptId;
  investigationId: InvestigationId;
  trigger: InvestigationTrigger;
  issuedAt: IsoDateTime;
  traceId: string | null;
  decision: Decision;
  riskDecision: RiskDecision;
  reasons: Array<Omit<RiskReason, 'message'>>;
  agent: { id: AgentId; keyThumbprint: string | null; wallet: EvmAddress | null };
  principal: { id: PrincipalId | null; status: string | null };
  businessId: BusinessId | null;
  delegation: {
    id: DelegationId | null;
    version: number | null;
    checked: boolean;
    asset?: string | null;
    maxTxAmount?: number | null;
    dailyLimit?: number | null;
    spent24h?: number | null;
    withinMax?: boolean | null;
    withinDaily?: boolean | null;
    walletApproved?: boolean | null;
    assetPermitted?: boolean | null;
  };
  transaction: InvestigationTransaction | null;
  identity: { mode: 'signed' | 'state'; decision: Decision; reasonCode: ReasonCode; verifiedSignature?: boolean };
  sanctions: {
    checked: boolean;
    datasetVersion: string | null;
    exactHits: Array<{ sanctionsId: string; address: EvmAddress; name: string; programs?: string[] }>;
    fuzzyHits: Array<{ sanctionsId: string; name: string; matched: string; scorePpm: number }>;
  };
  signals: Signal[];
  memory: {
    checked: boolean;
    engine: '$vectorSearch';
    embeddingModel: string | null;
    k: number;
    minScorePpm: number;
    hits: Array<{ memoryId: MemoryId; status: 'VERIFIED'; outcome: Outcome; scorePpm: number; usedAsPrecedent?: boolean }>;
  };
  stages: Array<{ name: string; engine: StageEngine; status: StageStatus; durationMs: number }>;
  sanctionsDatasetVersion: string | null;
  /** TRUST_RULES_VERSION + '+inv:' + INVARIANTS_HASH */
  policyVersion: string;
  invariantsHash: string;
  harnessVersion: number;
  delegationVersion: number | null;
  passport: { id: PassportId; before: PassportStatus; after: PassportStatus } | null;
  evidence: Array<Pick<EvidenceItem, 'id' | 'kind' | 'source' | 'ref' | 'summary'>>;
  /** sha256hex(canonicalJson(receipt without receiptHash and anchor)). */
  receiptHash: string;
  anchor?: { auditEventId: string; auditSeq: number; auditHash: string };
}

// ---------------------------------------------------------------------------
// Live events (GET /v1/events/stream, text/event-stream)
// ---------------------------------------------------------------------------

export type HarnessStreamEvent =
  | { type: 'sanctions.change_detected'; at: IsoDateTime; sanctionsId: string; datasetVersion: string; affectedAgentIds: AgentId[] }
  | { type: 'passport.status_changed'; at: IsoDateTime; passportId: PassportId; agentId: AgentId; from: PassportStatus | null; to: PassportStatus; investigationId: InvestigationId | null }
  | { type: 'investigation.decided'; at: IsoDateTime; investigationId: InvestigationId; agentId: AgentId; trigger: InvestigationTrigger; riskDecision: RiskDecision }
  | { type: 'harness.adapted'; at: IsoDateTime; fromVersion: number; toVersion: number; eventId: string };

/**
 * Audit event types added to the closed AuditEventType set by the implementing
 * tasks (T08/T10/T11/T13/T15), together with test/audit.test.js.
 */
export const HARNESS_AUDIT_EVENT_TYPES = [
  'investigation.decided',
  'investigation.confirmed',
  'receipt.issued',
  'passport.issued',
  'passport.status_changed',
  'memory.promoted',
  'memory.rejected',
  'harness.adapted',
  'harness.adaptation_rejected',
  'sanctions.updated',
] as const;
export type HarnessAuditEventType = (typeof HARNESS_AUDIT_EVENT_TYPES)[number];
