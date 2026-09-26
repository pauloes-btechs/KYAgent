// Prints 32 random bytes (base64url) for KYA_API_KEY_PEPPER. Never commit the output.
import { randomBytes } from 'node:crypto';

process.stdout.write(`${randomBytes(32).toString('base64url')}\n`);
