// scripts/register-repos.js
import { Octokit } from 'octokit';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import db from '../backend/db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.join(__dirname, '..');

// Load environment variables from project root .env
dotenv.config({ path: path.join(rootDir, '.env') });

// Allow local proxy / TLS handling consistent with worker.js and server.js
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const token = process.env.GITHUB_TOKEN;
const smeeUrl = process.env.SMEE_URL;
const webhookSecret = process.env.GITHUB_WEBHOOK_SECRET;

async function registerRepos() {
    console.log('='.repeat(65));
    console.log('       VIRGO — One-Off GitHub Repository Registration');
    console.log('='.repeat(65));

    if (!token) {
        console.error('[Error] GITHUB_TOKEN is not defined in .env');
        process.exit(1);
    }
    if (!smeeUrl) {
        console.error('[Error] SMEE_URL is not defined in .env');
        process.exit(1);
    }
    if (!webhookSecret) {
        console.error('[Error] GITHUB_WEBHOOK_SECRET is not defined in .env');
        process.exit(1);
    }

    const octokit = new Octokit({ auth: token });

    // Track summary statistics
    const stats = {
        dbAdded: [],
        dbExisting: [],
        webhookCreated: [],
        webhookExisting: [],
        webhookErrors: []
    };

    try {
        console.log('\n[1/3] Fetching repositories owned by authenticated account...');
        const repos = await octokit.paginate(octokit.rest.repos.listForAuthenticatedUser, {
            affiliation: 'owner',
            per_page: 100
        });

        console.log(`Found ${repos.length} repository(ies) on account.\n`);
        console.log('[2/3] Processing repositories (DB record + Smee webhook)...');

        for (const repo of repos) {
            const repoFullName = repo.full_name;
            const [owner, repoName] = repoFullName.split('/');

            process.stdout.write(`\n-> ${repoFullName}: `);

            // 1. Database Check & Insert (Idempotent)
            try {
                const existingRepoRes = await db.query('SELECT id FROM repos WHERE name = $1', [repoFullName]);
                if (existingRepoRes.rows.length === 0) {
                    await db.query('INSERT INTO repos (name) VALUES ($1)', [repoFullName]);
                    stats.dbAdded.push(repoFullName);
                    process.stdout.write('[DB: Added] ');
                } else {
                    stats.dbExisting.push(repoFullName);
                    process.stdout.write('[DB: Exists] ');
                }
            } catch (dbErr) {
                console.error(`\n   [DB Error on ${repoFullName}]: ${dbErr.message}`);
                continue;
            }

            // 2. Webhook Check & Creation (Idempotent)
            try {
                const existingHooks = await octokit.rest.repos.listWebhooks({
                    owner,
                    repo: repoName,
                    per_page: 100
                });

                const smeeHook = existingHooks.data.find(h => h.config && h.config.url === smeeUrl);

                if (smeeHook) {
                    stats.webhookExisting.push(repoFullName);
                    process.stdout.write(`[Webhook: Already configured (#${smeeHook.id})]`);
                } else {
                    const newHook = await octokit.rest.repos.createWebhook({
                        owner,
                        repo: repoName,
                        config: {
                            url: smeeUrl,
                            content_type: 'json',
                            secret: webhookSecret,
                            insecure_ssl: '0'
                        },
                        events: ['pull_request'],
                        active: true
                    });
                    stats.webhookCreated.push(repoFullName);
                    process.stdout.write(`[Webhook: Created (#${newHook.data.id})]`);
                }
            } catch (hookErr) {
                stats.webhookErrors.push({ repo: repoFullName, error: hookErr.message });
                process.stdout.write(`[Webhook Error: ${hookErr.message}]`);
            }
        }

        // 3. Print Final Report
        console.log('\n\n' + '='.repeat(65));
        console.log('                       REGISTRATION SUMMARY');
        console.log('='.repeat(65));

        console.log(`\n📦 DATABASE RECORDS:`);
        console.log(`   - Newly added to DB  (${stats.dbAdded.length}):`);
        if (stats.dbAdded.length > 0) {
            stats.dbAdded.forEach(r => console.log(`       + ${r}`));
        } else {
            console.log(`       (none)`);
        }

        console.log(`   - Already existed in DB (${stats.dbExisting.length}):`);
        if (stats.dbExisting.length > 0) {
            stats.dbExisting.forEach(r => console.log(`       ✓ ${r}`));
        } else {
            console.log(`       (none)`);
        }

        console.log(`\n🔗 GITHUB WEBHOOKS:`);
        console.log(`   - Newly created webhooks (${stats.webhookCreated.length}):`);
        if (stats.webhookCreated.length > 0) {
            stats.webhookCreated.forEach(r => console.log(`       + ${r}`));
        } else {
            console.log(`       (none)`);
        }

        console.log(`   - Webhook already present (${stats.webhookExisting.length}):`);
        if (stats.webhookExisting.length > 0) {
            stats.webhookExisting.forEach(r => console.log(`       ✓ ${r}`));
        } else {
            console.log(`       (none)`);
        }

        if (stats.webhookErrors.length > 0) {
            console.log(`   - Webhook errors encountered (${stats.webhookErrors.length}):`);
            stats.webhookErrors.forEach(err => console.log(`       ✕ ${err.repo}: ${err.error}`));
        }

        console.log('\n' + '='.repeat(65));
        console.log('All eligible repositories are now registered with VIRGO.');
        console.log('='.repeat(65));

    } catch (err) {
        console.error('\n[Fatal Error during registration]:', err.message);
    } finally {
        // Cleanly close database connection pool
        await db.end();
        process.exit(0);
    }
}

registerRepos();
