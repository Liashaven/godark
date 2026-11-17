import { randomBytes, scrypt as scryptCallback, createHash, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);
export const SESSION_COOKIE = 'godark_web_session';
const SESSION_DAYS = 30;
const SCRYPT_OPTIONS = { N: 32768, r: 8, p: 1, maxmem: 128 * 1024 * 1024 };

export function digestToken(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export function equalHex(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string' || !/^[a-f0-9]{64}$/i.test(left) || !/^[a-f0-9]{64}$/i.test(right)) return false;
  const a = Buffer.from(left, 'hex');
  const b = Buffer.from(right, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

export async function hashPassword(password) {
  const salt = randomBytes(16);
  const derived = await scrypt(password, salt, 64, SCRYPT_OPTIONS);
  return `scrypt$32768$8$1$${salt.toString('hex')}$${Buffer.from(derived).toString('hex')}`;
}

export async function verifyPassword(password, encoded) {
  if (typeof encoded !== 'string') return false;
  const parts = encoded.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt' || parts[1] !== '32768' || parts[2] !== '8' || parts[3] !== '1') return false;
  if (!/^[a-f0-9]{32}$/i.test(parts[4]) || !/^[a-f0-9]{128}$/i.test(parts[5])) return false;
  const derived = await scrypt(password, Buffer.from(parts[4], 'hex'), 64, SCRYPT_OPTIONS);
  const expected = Buffer.from(parts[5], 'hex');
  const actual = Buffer.from(derived);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function readCookies(header = '') {
  const result = Object.create(null);
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index < 1) continue;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (key && value) result[key] = value;
  }
  return result;
}

export function sessionCookie(token) {
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${SESSION_DAYS * 24 * 60 * 60}`;
}

export function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0`;
}

export async function createSession(db, userId, clientType = 'web') {
  const rawToken = randomBytes(32).toString('base64url');
  const rawCsrf = randomBytes(24).toString('base64url');
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000);
  const tokenHash = digestToken(rawToken);
  await db.execute(
    'INSERT INTO account_sessions (token_hash, csrf_hash, user_id, client_type, expires_at) VALUES (?, ?, ?, ?, ?)',
    [tokenHash, digestToken(rawCsrf), userId, clientType, expiresAt]
  );
  return { rawToken, rawCsrf, tokenHash, expiresAt };
}

export async function authenticate(db, req, { requireCsrf = false } = {}) {
  const authorization = req.headers.authorization || '';
  const bearer = /^Bearer\s+([A-Za-z0-9_-]{32,})$/i.exec(authorization)?.[1] || '';
  const cookieToken = readCookies(req.headers.cookie)[SESSION_COOKIE] || '';
  const token = bearer || cookieToken;
  if (!token || token.length > 256) return null;
  const tokenHash = digestToken(token);
  const [rows] = await db.execute(
    `SELECT s.token_hash, s.csrf_hash, s.client_type, s.expires_at,
            a.id, a.email, a.display_name, a.created_at, a.last_login_at,
            c.analytics_opt_in, c.diagnostics_opt_in
       FROM account_sessions s
       JOIN accounts a ON a.id = s.user_id
       LEFT JOIN account_consents c ON c.user_id = a.id
      WHERE s.token_hash = ? AND s.expires_at > UTC_TIMESTAMP(3)
      LIMIT 1`,
    [tokenHash]
  );
  if (!rows.length) return null;
  const row = rows[0];
  const usedCookie = !bearer;
  if (requireCsrf && usedCookie) {
    const supplied = req.headers['x-csrf-token'];
    if (typeof supplied !== 'string' || !equalHex(digestToken(supplied), row.csrf_hash)) return null;
  }
  return {
    tokenHash: row.token_hash,
    csrfHash: row.csrf_hash,
    clientType: row.client_type,
    usedCookie,
    user: {
      id: row.id,
      email: row.email,
      displayName: row.display_name,
      createdAt: row.created_at,
      lastLoginAt: row.last_login_at
    },
    consents: {
      analyticsOptIn: Boolean(row.analytics_opt_in),
      diagnosticsOptIn: Boolean(row.diagnostics_opt_in)
    }
  };
}
