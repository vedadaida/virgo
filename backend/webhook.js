import express from 'express';
import crypto from 'crypto';
import { processGithubPR } from './worker.js';

const router = express.Router();

router.post('/', async (req, res) => {
    try {
        const signature = req.headers['x-hub-signature-256'];
        const secret = process.env.GITHUB_WEBHOOK_SECRET;

        if (secret) {
            if (!signature) {
                console.warn('[Webhook] Rejected: Missing X-Hub-Signature-256 header');
                return res.status(401).send('Missing X-Hub-Signature-256 header');
            }

            const rawBody = req.rawBody || Buffer.from(JSON.stringify(req.body));
            const expectedSig = 'sha256=' + crypto.createHmac('sha256', secret).update(rawBody).digest('hex');

            const sigBuf = Buffer.from(signature);
            const expBuf = Buffer.from(expectedSig);

            if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
                console.warn('[Webhook] Rejected: Invalid X-Hub-Signature-256');
                return res.status(401).send('Invalid signature');
            }
            console.log('[Webhook] Signature verified successfully');
        } else {
            console.warn('[Webhook] Warning: GITHUB_WEBHOOK_SECRET not set in environment. Verification skipped.');
        }

        const event = req.headers['x-github-event'];
        console.log('[Webhook] Received GitHub event: ' + event);

        if (event === 'ping') {
            return res.status(200).send('Pong! Webhook verified.');
        }

        if (event === 'pull_request') {
            const action = req.body.action;
            if (action === 'opened' || action === 'synchronize' || action === 'reopened') {
                const prNumber  = req.body.pull_request.number;
                const repoUrl   = req.body.repository.clone_url;
                const repoName  = req.body.repository.full_name;
                const branch    = req.body.pull_request.head.ref;
                const commitSha = req.body.pull_request.head.sha;

                console.log('[Webhook] Running PR scan directly for ' + repoName + ' PR #' + prNumber);

                // Run scan in background so webhook responds immediately to GitHub
                processGithubPR({
                    id: 'direct-' + Date.now(),
                    data: { repoUrl, repoName, prNumber, branch, commitSha }
                }).then(result => {
                    console.log('[Webhook] PR scan completed:', result);
                }).catch(err => {
                    console.error('[Webhook] PR scan failed:', err.message);
                });
            }
        }

        res.status(200).send('Webhook received and queued');
    } catch (error) {
        console.error('[Webhook] Error:', error);
        res.status(500).send('Internal Server Error');
    }
});

export default router;
