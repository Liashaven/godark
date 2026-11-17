import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { handleApiRequest } from '../server/api.js';

function fakeResponse() {
  return {
    statusCode: 0,
    headers: {},
    body: '',
    writeHead(status, headers = {}) { this.statusCode = status; this.headers = headers; },
    end(body = '') { this.body = String(body); }
  };
}

function request(body, authorization = '') {
  const req = Readable.from([Buffer.from(JSON.stringify(body))]);
  req.method = 'POST';
  req.headers = { 'content-type': 'application/json', authorization };
  req.socket = { remoteAddress: '127.0.0.1' };
  return req;
}

test('sign-in is refused while account-service readiness is disabled', async () => {
  let calls = 0;
  const db = {
    async execute() {
      calls += 1;
      return [[{ enabled: 0, retention_task_uid: null, backup_retention_days: null, verified_at: null }]];
    }
  };
  const res = fakeResponse();
  await handleApiRequest(db, request({ email: 'user@example.test', password: 'not-a-real-password', client: 'native' }), res, new URL('https://godark.invalid/api/auth/login'));
  assert.equal(res.statusCode, 503);
  assert.equal(JSON.parse(res.body).error, 'ACCOUNT_SERVICE_NOT_READY');
  assert.equal(calls, 1);
});

test('diagnostics insert only the validated, normalized fields', async () => {
  const inserted = [];
  const db = {
    async execute(sql) {
      assert.match(sql, /SELECT enabled, retention_task_uid/);
      return [[{ enabled: 1, retention_task_uid: 'daily-retention-task', backup_retention_days: 90, verified_at: new Date() }]];
    },
    async getConnection() {
      return {
        async beginTransaction() {},
        async commit() {},
        async rollback() {},
        release() {},
        async execute(sql, values = []) {
          if (sql.includes('SELECT diagnostics_opt_in')) return [[{ diagnostics_opt_in: 1 }]];
          if (sql.includes('INSERT INTO diagnostics')) { inserted.push(values); return [{ affectedRows: 1 }]; }
          throw new Error(`Unexpected SQL: ${sql}`);
        }
      };
    }
  };
  const sessionRow = {
    token_hash: 'f'.repeat(64), csrf_hash: 'e'.repeat(64), client_type: 'native', expires_at: new Date(Date.now() + 60_000),
    id: 'account-1', email: 'user@example.test', display_name: 'Tester', created_at: new Date(), last_login_at: null,
    analytics_opt_in: 0, diagnostics_opt_in: 1
  };
  const originalExecute = db.execute;
  db.execute = async (sql, values) => {
    if (sql.includes('SELECT enabled, retention_task_uid')) return [[{ enabled: 1, retention_task_uid: 'daily-retention-task', backup_retention_days: 90, verified_at: new Date() }]];
    if (sql.includes('FROM account_sessions s')) return [[sessionRow]];
    return originalExecute(sql, values);
  };
  const payload = {
    platform: 'android', appVersion: '1.2.3', deviceModel: 'Pixel-8', osVersion: 'Android-15',
    crashKind: 'freeze', signatureHash: 'A'.repeat(64)
  };
  const res = fakeResponse();
  await handleApiRequest(db, request(payload, `Bearer ${'a'.repeat(40)}`), res, new URL('https://godark.invalid/api/telemetry/diagnostics'));
  assert.equal(res.statusCode, 202);
  assert.deepEqual(inserted, [['account-1', 'android', '1.2.3', 'Pixel-8', 'Android-15', 'freeze', 'a'.repeat(64)]]);
});
