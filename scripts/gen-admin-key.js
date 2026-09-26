// Prints a fresh admin API key for KYA_BOOTSTRAP_ADMIN_API_KEY. Only its HMAC hash
// is stored by the server. Never commit the output.
import { generateApiKey } from '../src/crypto/apiKeys.js';

process.stdout.write(`${generateApiKey().plaintext}\n`);
