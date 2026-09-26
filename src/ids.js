import { randomBytes } from 'node:crypto';

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/** 26-char Crockford base32 ULID: 48-bit ms timestamp + 80 random bits. */
export function ulid(timeMs = Date.now()) {
  let t = Math.floor(timeMs);
  let time = '';
  for (let i = 0; i < 10; i++) {
    time = CROCKFORD[t % 32] + time;
    t = Math.floor(t / 32);
  }
  const bytes = randomBytes(10);
  // 80 bits -> 16 base32 chars (5 bits each)
  let bits = 0n;
  for (const b of bytes) bits = (bits << 8n) | BigInt(b);
  let rand = '';
  for (let i = 0; i < 16; i++) {
    rand = CROCKFORD[Number(bits & 31n)] + rand;
    bits >>= 5n;
  }
  return time + rand;
}

export function newId(prefix, timeMs) {
  return `${prefix}_${ulid(timeMs)}`;
}
