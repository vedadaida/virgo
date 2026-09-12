// db-init.js
import pg from 'pg';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load .env from the same directory as the script
dotenv.config({ path: path.join(__dirname, '.env') });

const { Client } = pg;
const rawUrl = process.env.DATABASE_URL;

async function init() {
    if (!rawUrl) {
        console.error("[DB] Error: DATABASE_URL not found in .env");
        process.exit(1);
    }

    try {
        console.log("[DB] Connecting to Neon PostgreSQL...");
        const client = new Client({
            connectionString: rawUrl,
            ssl: { rejectUnauthorized: false }
        });

        await client.connect();
        console.log("[DB] Connected successfully.");

        const schema = `
        CREATE TABLE IF NOT EXISTS repos (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            repo_id INT REFERENCES repos(id) ON DELETE CASCADE,
            status VARCHAR(50) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS findings (
            id SERIAL PRIMARY KEY,
            scan_id INT REFERENCES scans(id) ON DELETE CASCADE,
            file_path VARCHAR(512) NOT NULL,
            line_number INT NOT NULL,
            rule_id VARCHAR(255) NOT NULL,
            message TEXT NOT NULL,
            code_context TEXT NOT NULL,
            explanation TEXT NOT NULL,
            severity VARCHAR(50) NOT NULL,
            suggested_fix TEXT NOT NULL,
            finding_hash VARCHAR(64) UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS feedback (
            id SERIAL PRIMARY KEY,
            finding_id INT REFERENCES findings(id) ON DELETE CASCADE,
            vote VARCHAR(10) NOT NULL,
            comment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        `;

        console.log("[DB] Initializing tables...");
        await client.query(schema);
        console.log("[DB] Tables created or already exist.");

        const res = await client.query(`
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public';
        `);
        console.log("[DB] Tables currently in database:", res.rows.map(r => r.table_name).join(', '));
        await client.end();

    } catch (err) {
        console.error("[DB] Error:", err.message);
    }
}

init();
