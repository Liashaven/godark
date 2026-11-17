import test from 'node:test';
import assert from 'node:assert/strict';
import { validateDiagnostic } from '../server/api.js';
import { digestToken, hashPassword, readCookies, verifyPassword } from '../server/security.js';

test('password hashes are salted and verify only the original password', async () => {
  const first = await hashPassword('unique-test-only-passphrase');
  const second = await hashPassword('unique-test-only-passphrase');
  assert.notEqual(first, second);
  assert.equal(await verifyPassword('unique-test-only-passphrase', first), true);
  assert.equal(await verifyPassword('different-test-only-passphrase', first), false);
});

test('session tokens are stored as one-way digests', () => {
  assert.match(digestToken('sample-session-token'), /^[a-f0-9]{64}$/);
  assert.notEqual(digestToken('sample-session-token'), 'sample-session-token');
  assert.notEqual(digestToken('sample-session-token'), digestToken('other-token'));
});

test('cookie parser handles multiple cookies without decoding attacker-controlled values', () => {
  const cookies = readCookies('godark_web_session=abc123; theme=dark; malformed; empty=');
  assert.equal(cookies.godark_web_session, 'abc123');
  assert.equal(cookies.theme, 'dark');
  assert.equal(cookies.malformed, undefined);
  assert.equal(cookies.empty, undefined);
});

test('diagnostics accept only normalized, bounded fields and never free-form text', () => {
  const valid = {
    platform: 'android', appVersion: '0.4.1', deviceModel: 'Pixel-8-Pro', osVersion: 'Android-15',
    crashKind: 'freeze', signatureHash: 'a'.repeat(64)
  };
  assert.deepEqual(validateDiagnostic(valid), { ...valid });
  for (const [field, value] of [
    ['appVersion', 'message: meet at 123 main st'],
    ['deviceModel', 'Alice is trapped at 123 Main Street'],
    ['osVersion', 'Android-15; GPS 51.5,-0.1'],
    ['signatureHash', 'raw crash text'],
    ['extra', 'private message']
  ]) {
    assert.throws(() => validateDiagnostic({ ...valid, [field]: value }), { code: field === 'signatureHash' ? 'INVALID_DIAGNOSTIC' : field === 'extra' ? 'UNEXPECTED_FIELD' : 'INVALID_DIAGNOSTIC' });
  }
  assert.equal(validateDiagnostic({ ...valid, platform: 'ios', osVersion: 'iOS-18.2', signatureHash: null }).platform, 'ios');
});
