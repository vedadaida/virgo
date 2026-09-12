// queue-test.js
import { Queue, Worker } from 'bullmq';
import IORedis from 'ioredis';
import dotenv from 'dotenv';

dotenv.config();

const connection = new IORedis(process.env.REDIS_URL, {
  maxRetriesPerRequest: null,
});

async function testQueue() {
  const queueName = 'test-queue';
  const myQueue = new Queue(queueName, { connection });

  console.log('[Queue] Adding job...');
  await myQueue.add('my-job', { foo: 'bar' });
  console.log('[Queue] Job added.');

  const worker = new Worker(queueName, async job => {
    console.log(`[Worker] Processing job: ${job.name}, data:`, job.data);
  }, { connection });

  worker.on('completed', job => {
    console.log(`[Worker] Job ${job.id} completed!`);
    process.exit(0);
  });
}

testQueue().catch(console.error);
