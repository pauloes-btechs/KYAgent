// Opaque cursors: base64url(JSON [timeMs, id]) of the last returned item.

export function encodeCursor(timeMs, id) {
  return Buffer.from(JSON.stringify([timeMs, id]), 'utf8').toString('base64url');
}

/** Returns { t, id } or null when the cursor is not one we issued. */
export function decodeCursor(cursor) {
  if (typeof cursor !== 'string' || cursor.length > 200 || !/^[A-Za-z0-9_-]+$/.test(cursor)) return null;
  try {
    const v = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'));
    if (Array.isArray(v) && v.length === 2 && Number.isSafeInteger(v[0]) && typeof v[1] === 'string' && v[1].length <= 64) {
      return { t: v[0], id: v[1] };
    }
  } catch {
    // fall through
  }
  return null;
}
