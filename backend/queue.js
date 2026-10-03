// backend/queue.js
import { Queue } from 'bullmq';
import IORedis from 'ioredis';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, '../.env') });

const redisUrl = process.env.REDIS_URL;
const isLocal = redisUrl.includes('127.0.0.1') || redisUrl.includes('localhost');

export const connection = new IORedis(redisUrl, {
    maxRetriesPerRequest: null,
    enableReadyCheck: false,
    tls: isLocal ? undefined : { rejectUnauthorized: false }
});

connection.on('error', (err) => {
    console.warn('[Redis] Connection warning:', err.message);
});

export const SCAN_QUEUE_NAME = 'security-scan-queue';
export const scanQueue = new Queue(SCAN_QUEUE_NAME, { connection });
