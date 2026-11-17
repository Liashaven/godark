import { createHmac, timingSafeEqual } from 'node:crypto';
import { readCookies } from './security.js';

function unauthorized(res, message = 'Scheduled task authorization failed') {
  res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify({ error: 'UNAUTHORIZED', message }));
}

function decodeJwt(ticket) {
  const parts = ticket.split('.');
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    const actual = Buffer.from(parts[2], 'base64url');
    const expected = createHmac('sha256', process.env.MANUS_JWT_SECRET || '')
      .update(`${parts[0]}.${parts[1]}`).digest();
    if (header.alg !== 'HS256' || actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;
    if (payload.appId !== process.env.MANUS_PROJECT_ID || !String(payload.openId || '').startsWith('cron_')) return null;
    if (!Number.isFinite(payload.exp) || payload.exp <= Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

export async function pruneExpired(db) {
  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();
    const [sessions] = await connection.execute('DELETE FROM account_sessions WHERE expires_at <= UTC_TIMESTAMP(3)');
    const [diagnostics] = await connection.execute('DELETE FROM diagnostics WHERE created_at < DATE_SUB(UTC_TIMESTAMP(3), INTERVAL 90 DAY)');
    const [usage] = await connection.execute('DELETE FROM usage_events WHERE created_at < DATE_SUB(UTC_TIMESTAMP(3), INTERVAL 12 MONTH)');
    const [security] = await connection.execute('DELETE FROM security_events WHERE created_at < DATE_SUB(UTC_TIMESTAMP(3), INTERVAL 30 DAY)');
    await connection.commit();
    return {
      sessions: sessions.affectedRows,
      diagnostics: diagnostics.affectedRows,
      usage: usage.affectedRows,
      security: security.affectedRows
    };
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally { connection.release(); }
}

export async function runScheduledRetention(db, req, res) {
  const ticket = readCookies(req.headers.cookie)['app_session_id'] || '';
  if (!ticket || !process.env.MANUS_JWT_SECRET || !process.env.MANUS_PROJECT_ID || !process.env.MANUS_OAUTH_API_URL) {
    unauthorized(res);
    return;
  }
  const claims = decodeJwt(ticket);
  if (!claims) { unauthorized(res); return; }

  let identityResponse;
  try {
    identityResponse = await fetch(`${process.env.MANUS_OAUTH_API_URL.replace(/\/$/, '')}/webdev.v1.WebDevAuthPublicService/GetUserInfoWithJwt`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jwt_token: ticket, project_id: process.env.MANUS_PROJECT_ID }),
      signal: AbortSignal.timeout(8000)
    });
  } catch {
    res.writeHead(503, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify({ error: 'IDENTITY_LOOKUP_UNAVAILABLE', message: 'Could not verify the scheduled task identity' }));
    return;
  }
  if (!identityResponse.ok) { unauthorized(res); return; }
  const identity = await identityResponse.json().catch(() => ({}));
  if (identity.error || identity.projectId !== process.env.MANUS_PROJECT_ID || !String(identity.openId || '').startsWith('cron_') || !identity.taskUid) {
    unauthorized(res);
    return;
  }
  const [rows] = await db.execute(
    'SELECT retention_task_uid, enabled, backup_retention_days, verified_at FROM service_readiness WHERE id = 1 LIMIT 1'
  );
  const readiness = rows[0];
  if (!readiness || !readiness.enabled || readiness.retention_task_uid !== identity.taskUid || !readiness.verified_at || Number(readiness.backup_retention_days) > 90) {
    unauthorized(res);
    return;
  }

  const removed = await pruneExpired(db);
  res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify({ ok: true, deleted: removed }));
}
