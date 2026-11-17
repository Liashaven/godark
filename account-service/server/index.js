import http from 'node:http';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { getPool, runMigrations, closePool } from './db.js';
import { handleApiRequest } from './api.js';
import { pruneExpired } from './retention.js';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const publicRoot = path.join(projectRoot, 'public');
const routeFiles = new Map([
  ['/', 'index.html'],
  ['/privacy', 'privacy.html'],
  ['/terms', 'terms.html'],
  ['/account', 'account.html'],
  ['/manus-routes.json', 'manus-routes.json'],
  ['/style.css', 'style.css'],
  ['/account.js', 'account.js'],
  ['/favicon.svg', 'favicon.svg']
]);
// `/manus-storage/*` is a platform-reserved stable asset path and is intercepted before this server.
const contentTypes = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
  ['.svg', 'image/svg+xml']
]);
let runtimeReady = false;

function commonHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
}

function json(res, status, data) {
  commonHeaders(res);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store, private' });
  res.end(JSON.stringify(data));
}

async function sendFile(req, res, filename, status = 200, noStore = false) {
  try {
    const content = await readFile(filename);
    const ext = path.extname(filename).toLowerCase();
    commonHeaders(res);
    res.writeHead(status, {
      'Content-Type': contentTypes.get(ext) || 'application/octet-stream',
      'Cache-Control': noStore ? 'no-store, private' : 'no-cache'
    });
    res.end(req.method === 'HEAD' ? undefined : content);
  } catch {
    json(res, 500, { error: 'ASSET_UNAVAILABLE', message: 'Page asset is unavailable.' });
  }
}

function safeAssetPath(pathname) {
  if (!pathname.startsWith('/assets/')) return null;
  const name = pathname.slice('/assets/'.length);
  if (!name || name.includes('/') || name.includes('..') || !/^[A-Za-z0-9._-]+$/.test(name)) return null;
  const fullPath = path.resolve(publicRoot, 'assets', name);
  if (!fullPath.startsWith(`${path.resolve(publicRoot, 'assets')}${path.sep}`)) return null;
  return fullPath;
}

async function handleStatic(req, res, pathname) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    commonHeaders(res);
    res.writeHead(405, { 'Allow': 'GET, HEAD', 'Cache-Control': 'no-store' });
    res.end('Method not allowed');
    return;
  }
  const mapped = routeFiles.get(pathname);
  if (mapped) {
    const noStore = pathname === '/account';
    await sendFile(req, res, path.join(publicRoot, mapped), 200, noStore);
    return;
  }
  const asset = safeAssetPath(pathname);
  if (asset) {
    await sendFile(req, res, asset, 200, false);
    return;
  }
  await sendFile(req, res, path.join(publicRoot, '404.html'), 404, true);
}

function requestHandler(db) {
  return async (req, res) => {
    const url = new URL(req.url || '/', 'http://godark.invalid');
    if (url.pathname === '/healthz') {
      if (!runtimeReady) return json(res, 503, { ok: false });
      return json(res, 200, { ok: true });
    }
    if (url.pathname.startsWith('/api/')) {
      commonHeaders(res);
      await handleApiRequest(db, req, res, url);
      return;
    }
    await handleStatic(req, res, url.pathname);
  };
}

async function main() {
  const db = getPool();
  await runMigrations(db);
  await pruneExpired(db);
  runtimeReady = true;
  const port = Number.parseInt(process.env.PORT || '3000', 10);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('PORT must be between 1024 and 65535');
  const server = http.createServer(requestHandler(db));
  server.requestTimeout = 15_000;
  server.headersTimeout = 20_000;
  server.keepAliveTimeout = 5_000;
  server.listen(port, '0.0.0.0', () => console.info(`GoDark server listening on port ${port}`));

  const shutdown = () => {
    runtimeReady = false;
    server.close(() => closePool().finally(() => process.exit(0)));
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
}

main().catch(async (error) => {
  console.error('GoDark server could not start:', error?.name || 'Error');
  await closePool().catch(() => {});
  process.exitCode = 1;
});
