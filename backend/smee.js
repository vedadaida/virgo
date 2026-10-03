import SmeeClient from 'smee-client';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

// Fix for corporate SSL proxy environments
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.join(__dirname, '../.env') });

const smee = new SmeeClient({
  source: process.env.SMEE_URL,
  target: 'http://localhost:5000/api/webhook',
  logger: console
});

const events = smee.start();
console.log(`[Smee] Forwarding from ${process.env.SMEE_URL} -> http://localhost:5000/api/webhook`);

process.on('SIGINT', () => {
    events.close();
    process.exit();
});
