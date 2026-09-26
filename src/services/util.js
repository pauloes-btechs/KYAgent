import { ApiError, validationError } from '../errors.js';
import { validate } from '../validate.js';

export function ensureValid(schema, body) {
  const details = validate(schema, body);
  if (details.length) throw validationError(details);
  return body;
}

export const notFound = () => new ApiError('NOT_FOUND');
export const invalidState = (message) => new ApiError('INVALID_STATE', message);
export const forbidden = () => new ApiError('FORBIDDEN');

/** Pagination options already parsed by the route layer: { limit, cursor }. */
export const pageQuery = (q, filter) => ({ filter, limit: q.limit, cursor: q.cursor });
