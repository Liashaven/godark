import mysql from 'mysql2/promise';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
let pool;

function databaseConfig() {
  const raw = process.env.DATABASE_URL;
  if (!raw) throw new Error('DATABASE_URL is not configured');
  const url = new URL(raw);
  if (url.protocol !== 'mysql:' && url.protocol !== 'mysql2:') {
    throw new Error('DATABASE_URL must use the MySQL protocol');
  }
  const database = decodeURIComponent(url.pathname.replace(/^\//, ''));
  if (!url.hostname || !database) throw new Error('DATABASE_URL is missing its host or database name');
  const tlsEnabled = process.env.DATABASE_TLS !== 'false';
  return {
    host: url.hostname,
    port: url.port ? Number(url.port) : 3306,
    user: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    database,
    waitForConnections: true,
    connectionLimit: 6,
    queueLimit: 0,
    charset: 'utf8mb4',
    timezone: 'Z',
    supportBigNumbers: true,
    bigNumberStrings: true,
    ssl: tlsEnabled ? { rejectUnauthorized: true } : undefined
  };
}

export function getPool() {
  if (!pool) pool = mysql.createPool(databaseConfig());
  return pool;
}

export async function closePool() {
  if (pool) {
    const current = pool;
    pool = undefined;
    await current.end();
  }
}

export async function runMigrations(db = getPool()) {
  const connection = await db.getConnection();
  let lockAcquired = false;
  try {
    const [lockRows] = await connection.query("SELECT GET_LOCK('godark_schema_migrations', 15) AS acquired");
    lockAcquired = Number(lockRows[0]?.acquired) === 1;
    if (!lockAcquired) throw new Error('Could not acquire the GoDark migration lock');

    await connection.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      version VARCHAR(120) NOT NULL PRIMARY KEY,
      applied_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

    const migrationDir = path.join(projectRoot, 'migrations');
    const files = (await readdir(migrationDir)).filter((name) => /^\d+_[a-z0-9_-]+\.sql$/i.test(name)).sort();
    for (const file of files) {
      const [rows] = await connection.execute('SELECT version FROM schema_migrations WHERE version = ?', [file]);
      if (rows.length) continue;
      const sql = await readFile(path.join(migrationDir, file), 'utf8');
      const statements = sql.split(';').map((statement) => statement.trim()).filter(Boolean);
      for (const statement of statements) await connection.query(statement);
      await connection.execute('INSERT INTO schema_migrations (version) VALUES (?)', [file]);
      console.info(`Applied database migration ${file}`);
    }
  } finally {
    if (lockAcquired) {
      try { await connection.query("SELECT RELEASE_LOCK('godark_schema_migrations')"); } catch {}
    }
    connection.release();
  }
}
