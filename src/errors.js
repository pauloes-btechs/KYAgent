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
    if (this.code === 'VALIDATION_ERROR' && this.details?.length) error.details = this.details;
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
