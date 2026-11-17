import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const read = (file) => readFile(new URL(`../public/${file}`, import.meta.url), 'utf8');

for (const [route, file] of [['/', 'index.html'], ['/privacy', 'privacy.html'], ['/terms', 'terms.html'], ['/account', 'account.html']]) {
  test(`${route} has meaningful initial HTML and per-page metadata`, async () => {
    const html = await read(file);
    assert.match(html, /<title>[^<]{30,60}<\/title>/);
    const description = html.match(/<meta name="description" content="([^"]+)"/);
    assert.ok(description && description[1].length >= 50 && description[1].length <= 160);
    assert.match(html, /<h1>[^<]+<\/h1>/);
    assert.match(html, /<meta property="og:title"/);
    assert.match(html, /<meta name="twitter:card"/);
    if (route !== '/account') assert.doesNotMatch(html, /<meta name="robots" content="noindex/);
    if (route === '/account') assert.match(html, /<meta name="robots" content="noindex,nofollow"/);
  });
}

test('route manifest matches the four current page routes and excludes APIs/assets', async () => {
  const routes = JSON.parse(await read('manus-routes.json')).routes.map((item) => item.path);
  assert.deepEqual(routes, ['/', '/privacy', '/terms', '/account']);
  assert.equal(routes.some((item) => item.startsWith('/api/') || item.startsWith('/assets/')), false);
});

test('privacy and terms state the approved exclusions, retention and emergency/legal limits', async () => {
  const [privacy, terms] = await Promise.all([read('privacy.html'), read('terms.html')]);
  for (const item of ['90 days', '12 months', '30 days', 'message contents', 'group codes', 'contacts', 'precise location']) assert.ok(privacy.includes(item), `privacy is missing ${item}`);
  assert.match(privacy, /has not been verified/i);
  assert.match(terms, /cannot guarantee/i);
  assert.match(terms, /not an emergency-response/i);
  assert.match(terms, /cannot guarantee that a person or project will not be sued/i);
});

test('preview does not solicit new account data and uses durable current project downloads', async () => {
  const [home, account, script] = await Promise.all([read('index.html'), read('account.html'), read('account.js')]);
  assert.match(account, /New registration and optional data collection are paused in this preview/);
  assert.match(script, /New registrations and optional data collection are paused/);
  assert.ok(script.includes("document.querySelector('#register-form').hidden = true;"));
  for (const path of ['/manus-storage/README_8ab50c1f.md', '/manus-storage/privacy_bb520e05.html', '/manus-storage/terms_9cbb714a.html']) assert.ok(home.includes(path), `missing stable project asset ${path}`);
});
