import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import db from './db.js';
import webhookRouter from './webhook.js';
import { processLocalScan } from './worker.js'; 

dotenv.config();
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

process.on('uncaughtException', (err) => console.error('[Server UncaughtException]:', err));
process.on('unhandledRejection', (reason) => console.error('[Server UnhandledRejection]:', reason));

const app = express();
app.use(cors());
app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf;
    }
}));
app.use('/api/webhook', webhookRouter);

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

app.get('/api/repos', async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM repos ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/scan', async (req, res) => {
    const { repoName, targetFile } = req.body;
    if (!repoName) return res.status(400).json({ error: 'repoName is required' });
    try {
        let repoRes = await db.query('SELECT id FROM repos WHERE name = $1', [repoName]);
        let repoId;
        if (repoRes.rows.length === 0) {
            repoRes = await db.query('INSERT INTO repos (name) VALUES ($1) RETURNING id', [repoName]);
        }
        repoId = repoRes.rows[0].id;

        const scanRes = await db.query(
            'INSERT INTO scans (repo_id, status, pr_number) VALUES ($1, $2, $3) RETURNING id', 
            [repoId, 'PENDING', null]
        );
        const scanId = scanRes.rows[0].id;

        const scanTarget = targetFile || 'vulnerable.js';

        // Run local scan in background directly (bypasses Redis)
        processLocalScan({ 
            id: 'local-' + scanId, 
            data: { scanId, repoId, repoName, filePath: scanTarget } 
        })
            .then(scanResult => console.log('[Server] Local scan completed:', scanResult))
            .catch(err => console.error('[Server] Local scan failed:', err.message));

        res.json({ message: 'Scan initiated', scanId, jobId: 'local-' + scanId });
    } catch (err) {
        console.error('[Server] Error triggering scan:', err);
        res.status(500).json({ error: 'Failed to trigger scan' });
    }
});

app.get('/api/scans/:id', async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM scans WHERE id = $1', [req.params.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Scan not found' });
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

function formatFinding(f) {
    return {
        id: f.id,
        name: f.rule_id,
        repository: f.repo_name || 'Repository',
        prNumber: f.pr_number || null,
        file: f.file_path,
        line: f.line_number,
        severity: (f.severity || 'medium').toLowerCase(),
        status: 'OPEN',
        context: f.code_context,
        aiExplanation: f.explanation,
        suggestedFix: f.suggested_fix,
        upvotes: parseInt(f.upvotes || 0, 10),
        downvotes: parseInt(f.downvotes || 0, 10)
    };
}

app.get('/api/findings', async (req, res) => {
    try {
        const result = await db.query(`
            SELECT f.*, 
                   r.name as repo_name,
                   s.pr_number,
                   COALESCE(SUM(CASE WHEN fb.vote = 'UP' THEN 1 ELSE 0 END), 0) as upvotes,
                   COALESCE(SUM(CASE WHEN fb.vote = 'DOWN' THEN 1 ELSE 0 END), 0) as downvotes
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            JOIN repos r ON s.repo_id = r.id
            LEFT JOIN feedback fb ON f.id = fb.finding_id
            GROUP BY f.id, r.name, s.pr_number
            ORDER BY f.created_at DESC
        `);
        res.json(result.rows.map(formatFinding));
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

app.get('/api/repos/:repoId/findings', async (req, res) => {
    try {
        const { repoId } = req.params;
        const result = await db.query(`
            SELECT f.*, 
                   r.name as repo_name,
                   s.pr_number,
                   COALESCE(SUM(CASE WHEN fb.vote = 'UP' THEN 1 ELSE 0 END), 0) as upvotes,
                   COALESCE(SUM(CASE WHEN fb.vote = 'DOWN' THEN 1 ELSE 0 END), 0) as downvotes
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            JOIN repos r ON s.repo_id = r.id
            LEFT JOIN feedback fb ON f.id = fb.finding_id
            WHERE s.repo_id = $1
            GROUP BY f.id, r.name, s.pr_number
            ORDER BY f.created_at DESC
        `, [repoId]);
        res.json(result.rows.map(formatFinding));
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/findings/:id/feedback', async (req, res) => {
    const { vote } = req.body;
    if (vote !== 'UP' && vote !== 'DOWN') return res.status(400).json({ error: 'Invalid vote' });
    try {
        await db.query('INSERT INTO feedback (finding_id, vote) VALUES ($1, $2)', [req.params.id, vote]);
        res.json({ message: 'Feedback recorded' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`[Server] VIRGO Backend running on http://localhost:${PORT}`);
});
