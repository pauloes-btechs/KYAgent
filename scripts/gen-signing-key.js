// Prints a fresh Ed25519 server signing key (base64 PKCS#8 DER) for KYA_SIGNING_PRIVATE_KEY.
// Put the output in your secret store or an untracked .env — never commit it.
import { generateKeyPairSync } from 'node:crypto';

const { privateKey } = generateKeyPairSync('ed25519');
process.stdout.write(`${privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64')}\n`);
