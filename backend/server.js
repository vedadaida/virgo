// backend/server.js
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { query } from './db.js';
import { scanQueue } from './queue.js';
import './worker.js'; // Starts the BullMQ worker in-process

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, '../.env') });
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// 1. Health Check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'VIRGO Backend & Worker are active' });
});

// 2. List all Repositories
app.get('/api/repos', async (req, res) => {
    try {
        const result = await query('SELECT * FROM repos ORDER BY created_at DESC');
        const formatted = result.rows.map(r => ({
            id: String(r.id),
            name: r.name,
            branch: 'main',
            language: 'JavaScript',
            createdAt: r.created_at
        }));
        res.json(formatted);
    } catch (err) {
        console.error('[API] Error fetching repos:', err);
        res.status(500).json({ error: 'Database error fetching repos' });
    }
});

// 3. Trigger a Scan
app.post(['/api/scan', '/api/scans'], async (req, res) => {
    try {
        const repoName = req.body.repoName || 'OWASP/NodeGoat-Local';
        const targetFile = req.body.targetFile || 'vulnerable.js';

        // 3a. Ensure repository exists in DB
        const repoRes = await query(
            `INSERT INTO repos (name) 
             VALUES ($1) 
             ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name 
             RETURNING id`,
            [repoName]
        );
        const repoId = repoRes.rows[0].id;

        // 3b. Create a scan entry in DB
        const scanRes = await query(
            `INSERT INTO scans (repo_id, status) 
             VALUES ($1, 'QUEUED') 
             RETURNING id, status, created_at`,
            [repoId]
        );
        const scanId = scanRes.rows[0].id;

        // 3c. Add job to BullMQ queue
        const job = await scanQueue.add('code-scan', {
            scanId,
            repoId,
            repoName,
            targetFile
        });

        console.log(`[API] Enqueued Scan Job #${job.id} for Scan #${scanId} (${repoName})`);

        res.status(202).json({
            scanId,
            repoId: String(repoId),
            jobId: job.id,
            status: 'QUEUED',
            message: 'Security scan enqueued successfully.'
        });
    } catch (err) {
        console.error('[API] Error triggering scan:', err);
        res.status(500).json({ error: 'Failed to enqueue scan', details: err.message });
    }
});

// 4. Check Scan Status
app.get('/api/scans/:id', async (req, res) => {
    try {
        const scanRes = await query('SELECT * FROM scans WHERE id = $1', [req.params.id]);
        if (scanRes.rows.length === 0) {
            return res.status(404).json({ error: 'Scan not found' });
        }
        res.json(scanRes.rows[0]);
    } catch (err) {
        console.error('[API] Error checking scan status:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

// 5. Get Findings (for all repos or specific repo)
app.get(['/api/findings', '/api/repos/:repoId/findings'], async (req, res) => {
    try {
        const repoId = req.params.repoId || req.query.repoId;

        let sql = `
            SELECT 
                f.id,
                f.severity,
                f.rule_id,
                f.file_path,
                f.line_number,
                f.message,
                f.code_context,
                f.explanation,
                f.suggested_fix,
                f.created_at,
                r.id as repo_id,
                r.name as repo_name,
                fb.vote as latest_feedback
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            JOIN repos r ON s.repo_id = r.id
            LEFT JOIN LATERAL (
                SELECT vote 
                FROM feedback 
                WHERE finding_id = f.id 
                ORDER BY created_at DESC 
                LIMIT 1
            ) fb ON true
        `;

        const params = [];
        if (repoId && repoId !== 'all') {
            sql += ` WHERE r.id = $1`;
            params.push(repoId);
        }

        sql += ` ORDER BY f.created_at DESC`;

        const result = await query(sql, params);

        const mappedFindings = result.rows.map(row => ({
            id: String(row.id),
            severity: (row.severity || 'medium').toLowerCase(),
            name: row.rule_id,
            repository: row.repo_name,
            file: row.file_path,
            line: row.line_number,
            status: 'OPEN',
            context: row.code_context,
            aiExplanation: row.explanation,
            suggestedFix: row.suggested_fix,
            feedback: row.latest_feedback ? row.latest_feedback.toLowerCase() : null
        }));

        res.json(mappedFindings);
    } catch (err) {
        console.error('[API] Error fetching findings:', err);
        res.status(500).json({ error: 'Database error fetching findings' });
    }
});

// 6. Submit Feedback on a Finding (Thumbs up / down)
app.post('/api/findings/:id/feedback', async (req, res) => {
    try {
        const findingId = req.params.id;
        const rawVote = req.body.vote; // 'up' or 'down'
        const comment = req.body.comment || null;

        if (!rawVote || !['up', 'down', 'UP', 'DOWN'].includes(rawVote)) {
            return res.status(400).json({ error: "Vote must be 'up' or 'down'" });
        }

        const vote = rawVote.toUpperCase();

        await query(
            `INSERT INTO feedback (finding_id, vote, comment) VALUES ($1, $2, $3)`,
            [findingId, vote, comment]
        );

        console.log(`[API] Recorded feedback for Finding #${findingId}: ${vote}`);

        res.json({
            success: true,
            findingId: String(findingId),
            feedback: vote.toLowerCase()
        });
    } catch (err) {
        console.error('[API] Error saving feedback:', err);
        res.status(500).json({ error: 'Database error saving feedback' });
    }
});

app.listen(PORT, () => {
    console.log(`[Server] VIRGO Backend running on http://localhost:${PORT}`);
});
