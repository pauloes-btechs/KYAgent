import { ERROR_CODES } from './contracts.js';

const DEFAULT_MESSAGES = {
  VALIDATION_ERROR: 'Request is invalid',
  UNAUTHENTICATED: 'Missing or invalid API key',
  FORBIDDEN: 'Not allowed for this role',
  NOT_FOUND: 'Resource not found',
  CONFLICT: 'Resource already exists',
  INVALID_STATE: 'Operation not allowed in the current state',
  OPERATOR_NOT_VERIFIED: 'Operator is not verified',
  PAYLOAD_TOO_LARGE: 'Request body is too large',
  UNSUPPORTED_MEDIA_TYPE: 'Content-Type must be application/json',
  INTERNAL_ERROR: 'Internal error',
  SERVICE_UNAVAILABLE: 'Service unavailable',
};

/** Upper bound on `details` entries so a hostile body cannot amplify the error response. */
export const MAX_ERROR_DETAILS = 20;

/** HTTP error in the error-model.md envelope. `message` must never contain secrets. */
export class ApiError extends Error {
  constructor(code, message, details) {
    super(message ?? DEFAULT_MESSAGES[code] ?? 'Error');
    if (!(code in ERROR_CODES)) throw new TypeError(`unknown error code ${code}`);
    this.code = code;
    this.status = ERROR_CODES[code];
    this.details = details;
  }

  toBody(requestId) {
    const error = { code: this.code, message: this.message, requestId };
    if (this.code === 'VALIDATION_ERROR' && this.details?.length) {
      error.details = this.details.slice(0, MAX_ERROR_DETAILS).map(({ path, message }) => ({ path, message }));
    }
    return { error };
  }
}

export const validationError = (details, message = 'Request body is invalid') =>
  new ApiError('VALIDATION_ERROR', message, details);

/** Thrown by stores on unique-index violations. */
export class ConflictError extends Error {
  constructor(message = 'duplicate key') {
    super(message);
    this.name = 'ConflictError';
  }
}

/** Thrown when the backing store cannot be reached at request time. */
export class StoreUnavailableError extends Error {
  constructor(message = 'store unavailable') {
    super(message);
    this.name = 'StoreUnavailableError';
  }
}

// Driver errors that mean "store unreachable" rather than a bug. Matched by name so the optional
// mongodb driver never has to be imported here.
const STORE_UNAVAILABLE_NAMES = new Set([
  'StoreUnavailableError',
  'MongoNetworkError',
  'MongoNetworkTimeoutError',
  'MongoServerSelectionError',
  'MongoTopologyClosedError',
  'MongoNotConnectedError',
  'MongoPoolClosedError',
]);

/**
 * Maps any thrown value to an ApiError with a stable code/status. Unknown errors become a generic
 * INTERNAL_ERROR; their message and stack are never exposed to the client.
 */
export function toApiError(err) {
  if (err instanceof ApiError) return err;
  if (err instanceof ConflictError) return new ApiError('CONFLICT');
  if (err && STORE_UNAVAILABLE_NAMES.has(err.name)) return new ApiError('SERVICE_UNAVAILABLE');
  return new ApiError('INTERNAL_ERROR');
}
