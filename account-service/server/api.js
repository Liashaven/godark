import { randomBytes, randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import {
  authenticate,
  clearSessionCookie,
  createSession,
  digestToken,
  equalHex,
  hashPassword,
  readCookies,
  sessionCookie,
  verifyPassword
} from './security.js';
import { runScheduledRetention } from './retention.js';

const TERMS_VERSION = '2026-11-16-draft1';
const PRIVACY_VERSION = '2026-11-16-draft1';
const USAGE_FEATURES = new Set([
  'app_launch',
  'settings_open',
  'account_settings_open',
  'help_open',
  'connectivity_status_open',
  'invite_flow_open'
]);
const CRASH_KINDS = new Set(['app_crash', 'startup_failure', 'freeze', 'other']);
const APP_VERSION_PATTERN = /^\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.-]{1,16})?$/;
const DEVICE_MODEL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9.,_-]{0,79}$/;
const loginAttempts = new Map();
const DUMMY_PASSWORD_HASH = 'scrypt$32768$8$1$00000000000000000000000000000000$00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
const PREAUTH_CSRF_COOKIE = 'godark_pre_csrf';

class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function reply(res, status, payload, headers = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, private',
    'X-Content-Type-Options': 'nosniff',
    ...headers
  });
  res.end(JSON.stringify(payload));
}

async function readJson(req, limitBytes = 16 * 1024) {
  const contentType = String(req.headers['content-type'] || '').toLowerCase();
  if (!contentType.startsWith('application/json')) throw new ApiError(415, 'JSON_REQUIRED', 'Send a JSON request.');
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limitBytes) throw new ApiError(413, 'BODY_TOO_LARGE', 'Request is too large.');
    chunks.push(chunk);
  }
  if (!size) return {};
  try {
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('object required');
    return body;
  } catch {
    throw new ApiError(400, 'INVALID_JSON', 'Request body must be a JSON object.');
  }
}

function strictKeys(body, keys) {
  const allowed = new Set(keys);
  if (Object.keys(body).some((key) => !allowed.has(key))) throw new ApiError(400, 'UNEXPECTED_FIELD', 'Request contains an unsupported field.');
}

function normalizeEmail(value) {
  if (typeof value !== 'string') return '';
  return value.trim().toLowerCase();
}

function validEmail(value) {
  return value.length >= 3 && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function textField(value, max, min = 1) {
  return typeof value === 'string' && value.trim().length >= min && value.trim().length <= max;
}

function clientType(value) {
  if (value === 'web' || value === 'native') return value;
  throw new ApiError(400, 'INVALID_CLIENT', 'Client must be web or native.');
}

function clientIp(req) {
  const trustedHops = Number.parseInt(process.env.TRUSTED_PROXY_HOPS || '0', 10);
  if (Number.isInteger(trustedHops) && trustedHops > 0) {
    const forwarded = String(req.headers['x-forwarded-for'] || '').split(',').map((part) => part.trim()).filter(Boolean);
    const candidate = forwarded[forwarded.length - trustedHops - 1];
    if (candidate && isIP(candidate)) return candidate;
  }
  const address = String(req.socket?.remoteAddress || 'unknown').replace(/^::ffff:/, '');
  return isIP(address) ? address : 'unknown';
}

function userAgent(req) {
  return String(req.headers['user-agent'] || '').slice(0, 512);
}

async function logSecurity(dbOrConnection, req, eventName, userId = null) {
  if (!(await readiness(dbOrConnection)).accountsEnabled) return;
  await dbOrConnection.execute(
    'INSERT INTO security_events (user_id, event_name, client_ip, user_agent) VALUES (?, ?, ?, ?)',
    [userId, eventName, clientIp(req), userAgent(req)]
  );
}

async function readiness(db) {
  const [rows] = await db.execute(
    'SELECT enabled, retention_task_uid, backup_retention_days, verified_at FROM service_readiness WHERE id = 1 LIMIT 1'
  );
  const row = rows[0];
  const backupDays = Number(row?.backup_retention_days);
  const accountsEnabled = Boolean(
    row && Number(row.enabled) === 1 && row.retention_task_uid && row.verified_at &&
    Number.isInteger(backupDays) && backupDays >= 1 && backupDays <= 90
  );
  return {
    accountsEnabled,
    reason: accountsEnabled ? 'ready' : 'retention_and_backup_verification_required'
  };
}

function rateLimitState(ip) {
  const now = Date.now();
  const current = loginAttempts.get(ip);
  if (!current || current.resetAt <= now) {
    const fresh = { count: 0, resetAt: now + 15 * 60 * 1000 };
    loginAttempts.set(ip, fresh);
    return fresh;
  }
  return current;
}

function assertNotRateLimited(ip) {
  if (rateLimitState(ip).count >= 8) throw new ApiError(429, 'LOGIN_RATE_LIMIT', 'Too many sign-in attempts. Try again later.');
}

function recordFailedLogin(ip) {
  const state = rateLimitState(ip);
  state.count += 1;
  if (loginAttempts.size > 5000) {
    for (const [key, value] of loginAttempts) if (value.resetAt <= Date.now()) loginAttempts.delete(key);
  }
}

function clearFailedLogins(ip) {
  loginAttempts.delete(ip);
}

function accountView(row) {
  return {
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    createdAt: row.created_at,
    lastLoginAt: row.last_login_at,
    termsVersion: row.terms_version,
    privacyVersion: row.privacy_version
  };
}

async function createWebOrNativeSession(db, res, account, type) {
  const session = await createSession(db, account.id, type);
  const headers = type === 'web' ? { 'Set-Cookie': sessionCookie(session.rawToken) } : {};
  const payload = {
    account,
    csrfToken: session.rawCsrf,
    ...(type === 'native' ? { accessToken: session.rawToken, expiresAt: session.expiresAt } : {})
  };
  reply(res, 201, payload, headers);
}

async function requireReady(db) {
  const state = await readiness(db);
  if (!state.accountsEnabled) throw new ApiError(503, 'ACCOUNT_SERVICE_NOT_READY', 'Account registration and optional telemetry are not enabled in this Preview. Retention and backup requirements are not yet verified.');
}

function preAuthCookie(token) {
  return `${PREAUTH_CSRF_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=900`;
}

function clearPreAuthCookie() {
  return `${PREAUTH_CSRF_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0`;
}

function validatePreAuthCsrf(req) {
  const cookie = readCookies(req.headers.cookie)[PREAUTH_CSRF_COOKIE] || '';
  const supplied = req.headers['x-csrf-token'];
  if (typeof supplied !== 'string' || !cookie || !equalHex(digestToken(cookie), digestToken(supplied))) {
    throw new ApiError(403, 'CSRF_REJECTED', 'Refresh the page and try again.');
  }
}

async function handleRegister(db, req, res) {
  await requireReady(db);
  const body = await readJson(req);
  strictKeys(body, ['email', 'displayName', 'password', 'termsAccepted', 'privacyAcknowledged', 'analyticsOptIn', 'diagnosticsOptIn', 'client']);
  const email = normalizeEmail(body.email);
  const displayName = typeof body.displayName === 'string' ? body.displayName.trim() : '';
  if (!validEmail(email)) throw new ApiError(400, 'INVALID_EMAIL', 'Enter a valid email address.');
  if (!textField(displayName, 80)) throw new ApiError(400, 'INVALID_DISPLAY_NAME', 'Display name must contain 1 to 80 characters.');
  if (typeof body.password !== 'string' || [...body.password].length < 12 || [...body.password].length > 128) {
    throw new ApiError(400, 'INVALID_PASSWORD', 'Password must contain 12 to 128 characters.');
  }
  if (body.termsAccepted !== true || body.privacyAcknowledged !== true) throw new ApiError(400, 'CONSENT_REQUIRED', 'Accept the Terms and acknowledge the Privacy Policy to create an account.');
  if (body.analyticsOptIn !== undefined && typeof body.analyticsOptIn !== 'boolean') throw new ApiError(400, 'INVALID_CONSENT', 'Analytics choice must be true or false.');
  if (body.diagnosticsOptIn !== undefined && typeof body.diagnosticsOptIn !== 'boolean') throw new ApiError(400, 'INVALID_CONSENT', 'Diagnostics choice must be true or false.');
  const type = clientType(body.client);
  if (type === 'web') validatePreAuthCsrf(req);
  const passwordHash = await hashPassword(body.password);
  const userId = randomUUID();
  const dbConnection = await db.getConnection();
  try {
    await dbConnection.beginTransaction();
    await dbConnection.execute(
      'INSERT INTO accounts (id, email, display_name, password_hash, terms_version, privacy_version) VALUES (?, ?, ?, ?, ?, ?)',
      [userId, email, displayName, passwordHash, TERMS_VERSION, PRIVACY_VERSION]
    );
    const analytics = body.analyticsOptIn === true;
    const diagnostics = body.diagnosticsOptIn === true;
    await dbConnection.execute(
      `INSERT INTO account_consents
        (user_id, analytics_opt_in, diagnostics_opt_in, analytics_updated_at, diagnostics_updated_at)
       VALUES (?, ?, ?, IF(?, UTC_TIMESTAMP(3), NULL), IF(?, UTC_TIMESTAMP(3), NULL))`,
      [userId, analytics, diagnostics, analytics, diagnostics]
    );
    await logSecurity(dbConnection, req, 'signup', userId);
    await dbConnection.commit();
  } catch (error) {
    await dbConnection.rollback();
    if (error?.code === 'ER_DUP_ENTRY') throw new ApiError(409, 'ACCOUNT_EXISTS', 'An account with this email address already exists.');
    throw error;
  } finally { dbConnection.release(); }

  const account = { id: userId, email, displayName, createdAt: new Date().toISOString(), lastLoginAt: null };
  await createWebOrNativeSession(db, res, account, type);
}

async function handleLogin(db, req, res) {
  await requireReady(db);
  const body = await readJson(req);
  strictKeys(body, ['email', 'password', 'client']);
  const email = normalizeEmail(body.email);
  if (!validEmail(email) || typeof body.password !== 'string' || body.password.length > 128) throw new ApiError(400, 'INVALID_CREDENTIALS', 'Email or password is incorrect.');
  const type = clientType(body.client);
  if (type === 'web') validatePreAuthCsrf(req);
  const ip = clientIp(req);
  assertNotRateLimited(ip);
  const [rows] = await db.execute('SELECT id, email, display_name, password_hash, created_at, last_login_at FROM accounts WHERE email = ? LIMIT 1', [email]);
  const record = rows[0];
  const passwordOk = await verifyPassword(body.password, record?.password_hash || DUMMY_PASSWORD_HASH);
  if (!record || !passwordOk) {
    recordFailedLogin(ip);
    await logSecurity(db, req, 'login_failed', null);
    throw new ApiError(401, 'INVALID_CREDENTIALS', 'Email or password is incorrect.');
  }
  clearFailedLogins(ip);
  await db.execute('UPDATE accounts SET last_login_at = UTC_TIMESTAMP(3) WHERE id = ?', [record.id]);
  await logSecurity(db, req, 'login_success', record.id);
  const account = accountView({ ...record, last_login_at: new Date() });
  await createWebOrNativeSession(db, res, account, type);
}

async function handleCsrf(db, req, res) {
  const session = await authenticate(db, req);
  const token = randomBytes(24).toString('base64url');
  if (!session) {
    reply(res, 200, { csrfToken: token }, { 'Set-Cookie': preAuthCookie(token) });
    return;
  }
  await db.execute('UPDATE account_sessions SET csrf_hash = ? WHERE token_hash = ?', [digestToken(token), session.tokenHash]);
  reply(res, 200, { csrfToken: token });
}

async function requireSession(db, req, { csrf = false } = {}) {
  const session = await authenticate(db, req, { requireCsrf: csrf });
  if (!session) throw new ApiError(401, csrf ? 'UNAUTHENTICATED_OR_CSRF' : 'UNAUTHENTICATED', csrf ? 'Sign in again or refresh the security token.' : 'Sign in to continue.');
  return session;
}

async function handleAccountGet(db, req, res) {
  const session = await requireSession(db, req);
  reply(res, 200, {
    account: session.user,
    consents: session.consents
  });
}

async function handleAccountUpdate(db, req, res) {
  const session = await requireSession(db, req, { csrf: true });
  const body = await readJson(req);
  strictKeys(body, ['displayName']);
  const displayName = typeof body.displayName === 'string' ? body.displayName.trim() : '';
  if (!textField(displayName, 80)) throw new ApiError(400, 'INVALID_DISPLAY_NAME', 'Display name must contain 1 to 80 characters.');
  await db.execute('UPDATE accounts SET display_name = ? WHERE id = ?', [displayName, session.user.id]);
  reply(res, 200, { account: { ...session.user, displayName } });
}

async function handleConsentUpdate(db, req, res) {
  const session = await requireSession(db, req, { csrf: true });
  const body = await readJson(req);
  strictKeys(body, ['analyticsOptIn', 'diagnosticsOptIn']);
  if (typeof body.analyticsOptIn !== 'boolean' || typeof body.diagnosticsOptIn !== 'boolean') throw new ApiError(400, 'INVALID_CONSENT', 'Choose true or false for both optional data categories.');
  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();
    const [currentRows] = await connection.execute('SELECT analytics_opt_in, diagnostics_opt_in FROM account_consents WHERE user_id = ? FOR UPDATE', [session.user.id]);
    const current = currentRows[0] || { analytics_opt_in: 0, diagnostics_opt_in: 0 };
    const serviceState = await readiness(connection);
    if (!serviceState.accountsEnabled && ((body.analyticsOptIn && !Boolean(current.analytics_opt_in)) || (body.diagnosticsOptIn && !Boolean(current.diagnostics_opt_in)))) {
      throw new ApiError(503, 'ACCOUNT_SERVICE_NOT_READY', 'Optional data collection cannot be enabled until retention and backup requirements are verified. You can still turn existing choices off.');
    }
    const analyticsChanged = Boolean(current.analytics_opt_in) !== body.analyticsOptIn;
    const diagnosticsChanged = Boolean(current.diagnostics_opt_in) !== body.diagnosticsOptIn;
    await connection.execute(
      `INSERT INTO account_consents (user_id, analytics_opt_in, diagnostics_opt_in, analytics_updated_at, diagnostics_updated_at)
       VALUES (?, ?, ?, UTC_TIMESTAMP(3), UTC_TIMESTAMP(3))
       ON DUPLICATE KEY UPDATE analytics_opt_in = VALUES(analytics_opt_in), diagnostics_opt_in = VALUES(diagnostics_opt_in),
         analytics_updated_at = IF(?, UTC_TIMESTAMP(3), analytics_updated_at),
         diagnostics_updated_at = IF(?, UTC_TIMESTAMP(3), diagnostics_updated_at), updated_at = UTC_TIMESTAMP(3)`,
      [session.user.id, body.analyticsOptIn, body.diagnosticsOptIn, analyticsChanged, diagnosticsChanged]
    );
    if (!body.analyticsOptIn) await connection.execute('DELETE FROM usage_events WHERE user_id = ?', [session.user.id]);
    if (!body.diagnosticsOptIn) await connection.execute('DELETE FROM diagnostics WHERE user_id = ?', [session.user.id]);
    await logSecurity(connection, req, 'consent_update', session.user.id);
    await connection.commit();
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally { connection.release(); }
  reply(res, 200, { ok: true, consents: { analyticsOptIn: body.analyticsOptIn, diagnosticsOptIn: body.diagnosticsOptIn }, message: 'Choices saved. Turning an option off deletes that option’s existing telemetry.' });
}

function sqlDate(isoValue) {
  const date = new Date(isoValue);
  return date.toISOString().slice(0, 23).replace('T', ' ');
}

async function handleUsage(db, req, res) {
  await requireReady(db);
  const session = await requireSession(db, req, { csrf: true });
  const body = await readJson(req, 2048);
  strictKeys(body, ['feature', 'eventTime']);
  if (!USAGE_FEATURES.has(body.feature)) throw new ApiError(400, 'INVALID_FEATURE', 'This feature event is not allowed.');
  if (typeof body.eventTime !== 'string' || Number.isNaN(Date.parse(body.eventTime))) throw new ApiError(400, 'INVALID_EVENT_TIME', 'Provide a valid event time.');
  const time = new Date(body.eventTime);
  const now = Date.now();
  if (time.getTime() > now + 60_000 || time.getTime() < now - 60 * 60 * 1000) throw new ApiError(400, 'INVALID_EVENT_TIME', 'Event time must be within the last hour and not more than one minute in the future.');
  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();
    const [consentRows] = await connection.execute('SELECT analytics_opt_in FROM account_consents WHERE user_id = ? FOR UPDATE', [session.user.id]);
    if (!Boolean(consentRows[0]?.analytics_opt_in)) throw new ApiError(403, 'ANALYTICS_NOT_CONSENTED', 'Usage analytics is off for this account.');
    await connection.execute('INSERT INTO usage_events (user_id, feature_name, event_time) VALUES (?, ?, ?)', [session.user.id, body.feature, sqlDate(time.toISOString())]);
    await connection.commit();
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally { connection.release(); }
  reply(res, 202, { ok: true });
}

export function validateDiagnostic(body) {
  strictKeys(body, ['platform', 'appVersion', 'deviceModel', 'osVersion', 'crashKind', 'signatureHash']);
  const appVersion = typeof body.appVersion === 'string' ? body.appVersion.trim() : '';
  const deviceModel = typeof body.deviceModel === 'string' ? body.deviceModel.trim() : '';
  const osVersion = typeof body.osVersion === 'string' ? body.osVersion.trim() : '';
  const osPattern = body.platform === 'android' ? /^Android-\d+(?:\.\d+){0,3}$/ : /^iOS-\d+(?:\.\d+){0,3}$/;
  if (!['android', 'ios'].includes(body.platform) || !APP_VERSION_PATTERN.test(appVersion) || !DEVICE_MODEL_PATTERN.test(deviceModel) || !osPattern.test(osVersion) || !CRASH_KINDS.has(body.crashKind)) {
    throw new ApiError(400, 'INVALID_DIAGNOSTIC', 'Diagnostic data does not match the allowed fields.');
  }
  const signatureHash = body.signatureHash === null || body.signatureHash === undefined || body.signatureHash === '' ? null : String(body.signatureHash).toLowerCase();
  if (signatureHash !== null && !/^[a-f0-9]{64}$/.test(signatureHash)) throw new ApiError(400, 'INVALID_DIAGNOSTIC', 'Crash signature must be a SHA-256 hash, not a raw stack or message.');
  return { platform: body.platform, appVersion, deviceModel, osVersion, crashKind: body.crashKind, signatureHash };
}

async function handleDiagnostic(db, req, res) {
  await requireReady(db);
  const session = await requireSession(db, req, { csrf: true });
  if (session.clientType !== 'native') throw new ApiError(403, 'NATIVE_CLIENT_REQUIRED', 'Diagnostics can only be sent by a signed-in mobile app.');
  const body = validateDiagnostic(await readJson(req, 4096));
  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();
    const [consentRows] = await connection.execute('SELECT diagnostics_opt_in FROM account_consents WHERE user_id = ? FOR UPDATE', [session.user.id]);
    if (!Boolean(consentRows[0]?.diagnostics_opt_in)) throw new ApiError(403, 'DIAGNOSTICS_NOT_CONSENTED', 'Diagnostics is off for this account.');
    await connection.execute(
      `INSERT INTO diagnostics (user_id, platform, app_version, device_model, os_version, crash_kind, crash_signature_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [session.user.id, body.platform, body.appVersion, body.deviceModel, body.osVersion, body.crashKind, body.signatureHash]
    );
    await connection.commit();
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally { connection.release(); }
  reply(res, 202, { ok: true });
}

async function handleExport(db, req, res) {
  const session = await requireSession(db, req);
  await logSecurity(db, req, 'account_export', session.user.id);
  const userId = session.user.id;
  const [[accountRows], [sessionRows], [consentRows], [usageRows], [diagnosticRows], [securityRows]] = await Promise.all([
    db.execute('SELECT id, email, display_name, terms_version, privacy_version, created_at, last_login_at FROM accounts WHERE id = ?', [userId]),
    db.execute('SELECT client_type, created_at, expires_at FROM account_sessions WHERE user_id = ? AND expires_at > UTC_TIMESTAMP(3) ORDER BY created_at', [userId]),
    db.execute('SELECT analytics_opt_in, diagnostics_opt_in, analytics_updated_at, diagnostics_updated_at, updated_at FROM account_consents WHERE user_id = ?', [userId]),
    db.execute('SELECT feature_name, event_time, created_at FROM usage_events WHERE user_id = ? AND created_at >= DATE_SUB(UTC_TIMESTAMP(3), INTERVAL 12 MONTH) ORDER BY created_at', [userId]),
    db.execute('SELECT platform, app_version, device_model, os_version, crash_kind, crash_signature_hash, created_at FROM diagnostics WHERE user_id = ? AND created_at >= DATE_SUB(UTC_TIMESTAMP(3), INTERVAL 90 DAY) ORDER BY created_at', [userId]),
    db.execute('SELECT event_name, client_ip, user_agent, created_at FROM security_events WHERE user_id = ? AND created_at >= DATE_SUB(UTC_TIMESTAMP(3), INTERVAL 30 DAY) ORDER BY created_at', [userId])
  ]);
  const row = accountRows[0];
  reply(res, 200, {
    exportedAt: new Date().toISOString(),
    account: row ? { id: row.id, email: row.email, displayName: row.display_name, termsVersion: row.terms_version, privacyVersion: row.privacy_version, createdAt: row.created_at, lastLoginAt: row.last_login_at } : null,
    sessions: sessionRows.map((item) => ({ clientType: item.client_type, createdAt: item.created_at, expiresAt: item.expires_at })),
    consents: consentRows[0] || null,
    usageEvents: usageRows,
    diagnostics: diagnosticRows,
    securityEvents: securityRows
  }, { 'Content-Disposition': 'attachment; filename="godark-account-export.json"' });
}

async function handleDeleteAccount(db, req, res) {
  const session = await requireSession(db, req, { csrf: true });
  const body = await readJson(req);
  strictKeys(body, ['password']);
  if (typeof body.password !== 'string' || body.password.length > 128) throw new ApiError(400, 'PASSWORD_REQUIRED', 'Enter your current password to delete the account.');
  const [rows] = await db.execute('SELECT password_hash FROM accounts WHERE id = ? LIMIT 1', [session.user.id]);
  if (!rows.length || !await verifyPassword(body.password, rows[0].password_hash)) throw new ApiError(401, 'PASSWORD_INCORRECT', 'Password is incorrect.');
  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();
    await logSecurity(connection, req, 'account_delete', null);
    await connection.execute('DELETE FROM accounts WHERE id = ?', [session.user.id]);
    await connection.commit();
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally { connection.release(); }
  reply(res, 200, { ok: true, message: 'Account deleted from active application records.' }, { 'Set-Cookie': [clearSessionCookie(), clearPreAuthCookie()] });
}

async function handleLogout(db, req, res) {
  const session = await requireSession(db, req, { csrf: true });
  await logSecurity(db, req, 'logout', session.user.id);
  await db.execute('DELETE FROM account_sessions WHERE token_hash = ?', [session.tokenHash]);
  reply(res, 200, { ok: true }, { 'Set-Cookie': [clearSessionCookie(), clearPreAuthCookie()] });
}

export async function handleApiRequest(db, req, res, url) {
  const route = `${req.method} ${url.pathname}`;
  try {
    if (route === 'GET /api/status') {
      const state = await readiness(db);
      reply(res, 200, { ...state, collectionCategories: ['account', 'opt-in diagnostics', 'opt-in usage analytics', 'security logs'] });
      return;
    }
    if (url.pathname === '/api/scheduled/retention' && req.method === 'POST') {
      await runScheduledRetention(db, req, res);
      return;
    }
    if (route === 'POST /api/auth/register') return await handleRegister(db, req, res);
    if (route === 'POST /api/auth/login') return await handleLogin(db, req, res);
    if (route === 'GET /api/auth/csrf') return await handleCsrf(db, req, res);
    if (route === 'GET /api/account') return await handleAccountGet(db, req, res);
    if (route === 'PATCH /api/account') return await handleAccountUpdate(db, req, res);
    if (route === 'PATCH /api/account/consent') return await handleConsentUpdate(db, req, res);
    if (route === 'GET /api/account/export') return await handleExport(db, req, res);
    if (route === 'DELETE /api/account') return await handleDeleteAccount(db, req, res);
    if (route === 'POST /api/auth/logout') return await handleLogout(db, req, res);
    if (route === 'POST /api/telemetry/usage') return await handleUsage(db, req, res);
    if (route === 'POST /api/telemetry/diagnostics') return await handleDiagnostic(db, req, res);
    throw new ApiError(404, 'NOT_FOUND', 'API route not found.');
  } catch (error) {
    if (error instanceof ApiError) {
      reply(res, error.status, { error: error.code, message: error.message });
      return;
    }
    if (error?.code === 'ER_DUP_ENTRY') {
      reply(res, 409, { error: 'CONFLICT', message: 'The requested account change conflicts with existing data.' });
      return;
    }
    console.error('GoDark API request failed:', error?.name || 'Error');
    reply(res, 500, { error: 'INTERNAL_ERROR', message: 'The request could not be completed.' });
  }
}
