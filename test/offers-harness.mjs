// Harness tests for the locallink-offers Worker (plain node, no deploy).
// D1Mock over node:sqlite; the Worker module is imported directly.
// Run: node test/offers-harness.mjs   (or: npm test)
// All secrets here are TEST-ONLY dummies — never use them in production.
import { DatabaseSync } from 'node:sqlite';
import worker from '../src/index.js';

const BASE = 'https://locallink-offers.shao42ia.workers.dev';
const TEST_PASSWORD = 'test-admin-pass-123';
const SESSION_SECRET = 'test-session-secret-xyz';
const RESEND_KEY = 're_test_dummy_key';

class D1Statement {
  constructor(db, sql) { this.db = db; this.sql = sql; this.params = []; }
  bind(...params) { this.params = params; return this; }
  async run() {
    const r = this.db.prepare(this.sql).run(...this.params);
    return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid) } };
  }
  async first() {
    const row = this.db.prepare(this.sql).get(...this.params);
    return row === undefined ? null : row;
  }
  async all() {
    return { results: this.db.prepare(this.sql).all(...this.params) };
  }
}

class D1Mock {
  constructor(db) { this.db = db; }
  prepare(sql) { return new D1Statement(this.db, sql); }
  async batch(statements) {
    const out = [];
    for (const s of statements) out.push(await s.run());
    return out;
  }
}

async function makeHash(password) {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  const b64 = (bytes) => Buffer.from(bytes).toString('base64');
  return 'pbkdf2$100000$' + b64(salt) + '$' + b64(new Uint8Array(bits));
}

const db = new DatabaseSync(':memory:');
const env = {
  DB: new D1Mock(db),
  SESSION_SECRET,
  RATE_LIMIT_SALT: 'harness-salt',
  ADMIN_PASSWORD_HASH: await makeHash(TEST_PASSWORD),
  MAIL_DAILY_CAP: '2',
  SUBSCRIBE_LIMIT_PER_MIN: '1000', // raised for the harness; lowered again in the rate-limit test
};

let passed = 0;
let failed = 0;
const failures = [];
function check(name, cond, extra) {
  if (cond) { passed++; console.log('  PASS ' + name); }
  else { failed++; failures.push(name + (extra ? ' — ' + extra : '')); console.log('  FAIL ' + name + (extra ? ' — ' + extra : '')); }
}

async function req(path, init = {}) {
  const res = await worker.fetch(new Request(BASE + path, init), env);
  const text = await res.text();
  let j = null;
  try { j = JSON.parse(text); } catch { /* html page */ }
  return { res, text, j };
}
function jsonReq(path, body, headers = {}) {
  return req(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}

console.log('== public pages ==');
{
  const { res, text } = await req('/');
  check('GET / returns signup page', res.status === 200 && text.includes('შეთავაზებები') && text.includes('consent'));
  const h = await req('/api/health');
  check('GET /api/health ok', h.res.status === 200 && h.j && h.j.ok === true);
}

console.log('== subscribe validation ==');
{
  const bad = await jsonReq('/api/subscribe', { first_name: '', last_name: 'Test', email: 'a@b.ge', consent: true });
  check('empty first name rejected', bad.res.status === 400);
  const badMail = await jsonReq('/api/subscribe', { first_name: 'Nika', last_name: 'Test', email: 'not-an-email', consent: true });
  check('bad email rejected', badMail.res.status === 400);
  const noConsent = await jsonReq('/api/subscribe', { first_name: 'Nika', last_name: 'Test', email: 'nika@test.ge', consent: false });
  check('missing consent rejected', noConsent.res.status === 400);
  const ok = await jsonReq('/api/subscribe', { first_name: 'Nika', last_name: 'Testashvili', email: 'nika@test.ge', consent: true });
  check('valid signup accepted (no Resend key: stored pending)', ok.res.status === 200 && ok.j.ok === true);
  const row = db.prepare('SELECT * FROM subscribers WHERE email = ?').get('nika@test.ge');
  check('subscriber stored as pending with tokens', row && row.status === 'pending' && row.confirm_token_hash && row.unsub_token_hash);
  const dup = await jsonReq('/api/subscribe', { first_name: 'Nika', last_name: 'Testashvili', email: 'NIKA@test.ge', consent: true });
  check('duplicate pending signup accepted (case-insensitive email)', dup.res.status === 200);
  const count = db.prepare('SELECT COUNT(*) AS n FROM subscribers').get().n;
  check('duplicate did not create a second row', count === 1);
}

console.log('== confirm / unsubscribe ==');
{
  // Wrong token first.
  const bad = await req('/confirm?token=deadbeef');
  check('bad confirm token shows error page', bad.res.status === 200 && bad.text.includes('არასწორია'));
  // Extract the real token hash from DB is impossible (hashed) — instead
  // re-subscribe a fresh user and capture the token via a stubbed Resend.
  let capturedUrl = null;
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    const body = JSON.parse(opts.body);
    const m = body.html && body.html.match(/\/confirm\?token=([0-9a-f]+)/);
    if (m) capturedUrl = '/confirm?token=' + m[1];
    return { ok: true, status: 200, json: async () => ({ id: 'mock-resend-id' }) };
  };
  env.RESEND_API_KEY = RESEND_KEY;
  const ok = await jsonReq('/api/subscribe', { first_name: 'Mari', last_name: 'Beridze', email: 'mari@test.ge', consent: true });
  check('signup with Resend stub sends confirm email', ok.res.status === 200 && capturedUrl !== null);
  globalThis.fetch = origFetch;
  delete env.RESEND_API_KEY; // no real network calls after this point
  const conf = await req(capturedUrl);
  check('confirm link activates subscriber', conf.res.status === 200 && conf.text.includes('დადასტურდა'));
  const row = db.prepare('SELECT * FROM subscribers WHERE email = ?').get('mari@test.ge');
  check('subscriber status is confirmed', row && row.status === 'confirmed' && row.confirmed_at);
  // Unsubscribe: issue a fresh token via an admin send later; here test the
  // bad-token path and the direct DB-token path.
  const badUn = await req('/unsubscribe?token=deadbeef');
  check('bad unsubscribe token shows error page', badUn.res.status === 200 && badUn.text.includes('არასწორია'));
  const token = 'unsub-test-token-123';
  const hash = await (async () => {
    const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
    return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, '0')).join('');
  })();
  db.prepare('UPDATE subscribers SET unsub_token_hash = ? WHERE email = ?').run(hash, 'mari@test.ge');
  const un = await req('/unsubscribe?token=' + token);
  check('unsubscribe link works', un.res.status === 200 && un.text.includes('გაუქმდა'));
  const row2 = db.prepare('SELECT status FROM subscribers WHERE email = ?').get('mari@test.ge');
  check('subscriber status is unsubscribed', row2 && row2.status === 'unsubscribed');
  // Re-subscribe after unsubscribe -> pending again.
  const re = await jsonReq('/api/subscribe', { first_name: 'Mari', last_name: 'Beridze', email: 'mari@test.ge', consent: true });
  check('re-subscribe after unsubscribe accepted', re.res.status === 200);
  const row3 = db.prepare('SELECT status FROM subscribers WHERE email = ?').get('mari@test.ge');
  check('re-subscribed status is pending', row3 && row3.status === 'pending');
}

console.log('== admin login ==');
let cookie = '';
{
  const bad = await jsonReq('/api/admin/login', { password: 'wrong-pass' });
  check('wrong password rejected', bad.res.status === 401);
  const me0 = await req('/api/admin/me');
  check('me: not authenticated before login', me0.j && me0.j.authenticated === false);
  const ok = await jsonReq('/api/admin/login', { password: TEST_PASSWORD });
  check('correct password logs in', ok.res.status === 200 && ok.j.ok === true);
  cookie = ok.res.headers.get('Set-Cookie') || '';
  check('login sets session cookie', cookie.includes('lo_session='));
  const me1 = await req('/api/admin/me', { headers: { Cookie: cookie.split(';')[0] } });
  check('me: authenticated after login', me1.j && me1.j.authenticated === true);
}

console.log('== admin send ==');
{
  const auth = { Cookie: cookie.split(';')[0] };
  // Seed two confirmed subscribers.
  for (const [fn, ln, em] of [['Ana', 'Kapanadze', 'ana@test.ge'], ['Giorgi', 'Maisuradze', 'gio@test.ge']]) {
    db.prepare(`INSERT INTO subscribers (email, first_name, last_name, status, consent_at, confirmed_at, created_at)
      VALUES (?, ?, ?, 'confirmed', 1, 1, 1)`).run(em, fn, ln);
  }
  const ids = db.prepare('SELECT id FROM subscribers WHERE status = ? ORDER BY id').all('confirmed').map((r) => r.id);
  check('two confirmed subscribers seeded', ids.length === 2);

  // Without Resend key -> 503.
  delete env.RESEND_API_KEY;
  const noKey = await jsonReq('/api/admin/send', { ids, subject: 'Test', body: 'Hello' }, auth);
  check('send without RESEND_API_KEY returns 503', noKey.res.status === 503);

  // With stubbed Resend -> sends, records campaign + sends rows.
  env.RESEND_API_KEY = RESEND_KEY;
  let calls = 0;
  const origFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    calls++;
    return { ok: true, status: 200, json: async () => ({ id: 'mock-' + calls }) };
  };
  const sent = await jsonReq('/api/admin/send', { ids, subject: 'ფასდაკლება!', body: 'მოგესალმებით,\nახალი შეთავაზება!' }, auth);
  check('send with mock Resend succeeds', sent.res.status === 200 && sent.j.sent === 2 && sent.j.failed === 0, JSON.stringify(sent.j));
  check('Resend called once per recipient', calls === 2);
  globalThis.fetch = origFetch;
  const camp = db.prepare('SELECT * FROM campaigns ORDER BY id DESC LIMIT 1').get();
  check('campaign recorded with totals', camp && camp.total === 2 && camp.sent === 2);
  const sends = db.prepare('SELECT COUNT(*) AS n FROM sends WHERE campaign_id = ?').get(camp.id).n;
  check('send rows recorded', sends === 2);

  // Daily cap is 2 in the harness env: a second send must be refused.
  const over = await jsonReq('/api/admin/send', { ids, subject: 'Again', body: 'Hi' }, auth);
  check('daily cap enforced (429)', over.res.status === 429, JSON.stringify(over.j));
}

console.log('== admin list / export / delete ==');
{
  const auth = { Cookie: cookie.split(';')[0] };
  const list = await req('/api/admin/subscribers?limit=100', { headers: auth });
  check('subscriber list returns rows', list.res.status === 200 && list.j.subscribers.length >= 3 && list.j.total >= 3);
  const search = await req('/api/admin/subscribers?q=ana@test.ge', { headers: auth });
  check('search filters by email', search.j.subscribers.length === 1 && search.j.subscribers[0].email === 'ana@test.ge');
  const csv = await req('/api/admin/export.csv', { headers: auth });
  check('CSV export contains header + rows', csv.res.status === 200
    && csv.text.startsWith('email,first_name,last_name,status,created')
    && csv.text.includes('ana@test.ge'));
  const ana = db.prepare('SELECT id FROM subscribers WHERE email = ?').get('ana@test.ge');
  const del = await jsonReq('/api/admin/subscribers/delete', { id: ana.id }, auth);
  check('delete subscriber works', del.res.status === 200 && del.j.ok === true);
  const gone = db.prepare('SELECT * FROM subscribers WHERE email = ?').get('ana@test.ge');
  check('deleted row is gone', gone === undefined);
  const unauth = await req('/api/admin/subscribers');
  check('admin list without session is 401', unauth.res.status === 401);
}

console.log('== rate limiting ==');
{
  delete env.RESEND_API_KEY; // no real network calls in this section
  // Deterministic: a fresh IP (TEST-NET-3) with limit 2 — first two pass,
  // the third inside the same 60 s window is refused.
  env.SUBSCRIBE_LIMIT_PER_MIN = '2';
  const ip = { 'CF-Connecting-IP': '203.0.113.99' };
  const s1 = await jsonReq('/api/subscribe', { first_name: 'Rate', last_name: 'One', email: 'rate1@test.ge', consent: true }, ip);
  const s2 = await jsonReq('/api/subscribe', { first_name: 'Rate', last_name: 'Two', email: 'rate2@test.ge', consent: true }, ip);
  const s3 = await jsonReq('/api/subscribe', { first_name: 'Rate', last_name: 'Three', email: 'rate3@test.ge', consent: true }, ip);
  check('rate limit: first two subscribes pass', s1.res.status === 200 && s2.res.status === 200,
    JSON.stringify([s1.j, s2.j]));
  check('rate limit: third rapid subscribe is refused (429)', s3.res.status === 429, JSON.stringify(s3.j));
}

console.log('\n' + passed + ' passed, ' + failed + ' failed');
if (failed) { console.log('FAILURES:\n' + failures.map((f) => ' - ' + f).join('\n')); process.exit(1); }
