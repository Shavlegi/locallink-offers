/* locallink-offers — email signup + admin sending panel for Local Link.
 *
 * Cloudflare Worker + D1. Auth/session patterns follow Mini Link and
 * locallink-stock: PBKDF2-SHA256 admin password, DB-backed sessions with a
 * peppered token hash, IP-hash rate limiting. Raw IPs are never stored.
 *
 * Secrets ONLY via env: ADMIN_PASSWORD_HASH, SESSION_SECRET, RESEND_API_KEY.
 * Never hardcode, never log. Vars (not secrets): FROM_EMAIL, FROM_NAME,
 * MAIL_SENDER ('resend' — the only sender implemented in v1; 'smtp' is a
 * planned switch for a self-hosted mail server, see sendMail()).
 *
 * What it does:
 *  - Public signup page (GET /): first name, last name, email + an
 *    unchecked consent checkbox. Double opt-in: a confirmation email with
 *    a link (GET /confirm). Unsubscribe link in every campaign email
 *    (GET /unsubscribe). Only confirmed subscribers ever receive mail.
 *  - Admin panel (GET /admin): password login, subscriber list, tick
 *    checkboxes, write subject + text, send, campaign history, CSV export.
 *  - Sending goes through Resend (free tier: 3,000/month, 100/day). The
 *    Worker enforces the 100/day cap itself so the free tier is never
 *    exceeded by accident. If RESEND_API_KEY is not set, signups still
 *    work (stored as pending) and the panel says sending is not set up.
 *
 * The UI is Georgian only (v1, test). All HTML is embedded below — no
 * static files, no external assets.
 */

const CONFIG = {
  sessionDays: 7,
  pbkdf2Iterations: 100000,
  subscribeLimitPerMin: 5,
  loginLimitPerMin: 5,
  sendDailyCap: 100, // Resend free tier daily cap
  sendPerRequestCap: 100,
  confirmTokenBytes: 32,
};

const te = new TextEncoder();
function enc(s) { return te.encode(s); }

function bytesToBase64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function randomToken(bytes = CONFIG.confirmTokenBytes) {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return bytesToHex(b);
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', enc(text));
  return bytesToHex(new Uint8Array(digest));
}

/* ---------- schema (lazy, idempotent — same as locallink-stock) ---------- */

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS subscribers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    confirm_token_hash TEXT,
    unsub_token_hash TEXT,
    consent_at INTEGER,
    confirmed_at INTEGER,
    created_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_subscribers_status ON subscribers(status)`,
  `CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    window_start INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    total INTEGER NOT NULL,
    sent INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS sends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    subscriber_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    error TEXT,
    created_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_sends_campaign ON sends(campaign_id)`,
];

let schemaDone = false;
async function ensureSchema(env) {
  if (schemaDone) return;
  for (const sql of SCHEMA) await env.DB.prepare(sql).run();
  schemaDone = true;
}

/* ---------- auth (PBKDF2 + DB sessions, Mini Link pattern) ---------- */

async function verifyPassword(password, stored) {
  try {
    const parts = String(stored || '').split('$');
    if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
    const iterations = parseInt(parts[1], 10);
    const salt = Uint8Array.from(atob(parts[2]), (c) => c.charCodeAt(0));
    const want = Uint8Array.from(atob(parts[3]), (c) => c.charCodeAt(0));
    const key = await crypto.subtle.importKey('raw', enc(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, key, want.length * 8);
    const got = new Uint8Array(bits);
    if (got.length !== want.length) return false;
    let diff = 0;
    for (let i = 0; i < got.length; i++) diff |= got[i] ^ want[i];
    return diff === 0;
  } catch { return false; }
}

function getCookie(request, name) {
  const h = request.headers.get('Cookie') || '';
  for (const part of h.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return null;
}

async function createSession(env) {
  const token = randomToken(32);
  const tokenHash = await sha256Hex((env.SESSION_SECRET || '') + ':' + token);
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(
    'INSERT INTO sessions (token_hash, created_at, expires_at) VALUES (?, ?, ?)')
    .bind(tokenHash, now, now + CONFIG.sessionDays * 86400).run();
  return token;
}

async function getSession(env, request) {
  const token = getCookie(request, 'lo_session');
  if (!token) return false;
  const tokenHash = await sha256Hex((env.SESSION_SECRET || '') + ':' + token);
  const row = await env.DB.prepare(
    'SELECT expires_at FROM sessions WHERE token_hash = ?').bind(tokenHash).first();
  if (!row) return false;
  if (row.expires_at < Math.floor(Date.now() / 1000)) {
    await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(tokenHash).run();
    return false;
  }
  return true;
}

async function destroySession(env, request) {
  const token = getCookie(request, 'lo_session');
  if (!token) return;
  const tokenHash = await sha256Hex((env.SESSION_SECRET || '') + ':' + token);
  await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(tokenHash).run();
}

function sessionCookie(token) {
  return `lo_session=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${CONFIG.sessionDays * 86400}`;
}
function clearSessionCookie() {
  return 'lo_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0';
}

/* ---------- rate limiting (IP hash only, never the raw IP) ---------- */

async function rateLimit(env, scope, request, limit, windowSec) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const day = Math.floor(Date.now() / 1000 / windowSec);
  const key = scope + ':' + await sha256Hex(
    ip + '|' + day + '|' + (env.RATE_LIMIT_SALT || 'locallink-offers-default-salt'));
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - (now % windowSec);
  try {
    const row = await env.DB.prepare(
      'SELECT count, window_start FROM rate_limits WHERE key = ?').bind(key).first();
    if (!row || row.window_start !== windowStart) {
      await env.DB.prepare(
        'INSERT OR REPLACE INTO rate_limits (key, count, window_start) VALUES (?, 1, ?)')
        .bind(key, windowStart).run();
      return true;
    }
    if (row.count >= limit) return false;
    await env.DB.prepare(
      'UPDATE rate_limits SET count = count + 1 WHERE key = ?').bind(key).run();
    return true;
  } catch (e) {
    console.error('rateLimit error:', e && e.message ? e.message : e);
    return true; // fail open on DB errors, like locallink-stock
  }
}

/* ---------- validation ---------- */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
function validEmail(email) {
  return typeof email === 'string' && email.length <= 254 && EMAIL_RE.test(email.trim());
}
function cleanName(s) {
  return typeof s === 'string' ? s.trim().replace(/\s+/g, ' ') : '';
}
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function textToHtml(s) {
  return escapeHtml(s).replace(/\n/g, '<br>');
}

/* ---------- mail sending (swappable sender) ---------- */

// v1 implements only 'resend'. To switch to a self-hosted SMTP server
// later, add a 'smtp' branch here reading SMTP_HOST/PORT/USER/PASS from
// env and keep the same {to, subject, html, text} contract — the admin
// panel and the rest of the Worker do not need to change.
async function sendMail(env, { to, subject, html, text }) {
  const sender = String(env.MAIL_SENDER || 'resend').toLowerCase();
  if (sender === 'resend') return sendViaResend(env, { to, subject, html, text });
  throw new Error('გაგზავნის სერვისი არ არის დაყენებული (MAIL_SENDER=' + sender + ')');
}

async function sendViaResend(env, { to, subject, html, text }) {
  const key = env.RESEND_API_KEY;
  if (!key) throw new Error('RESEND_API_KEY არ არის დაყენებული');
  const fromName = env.FROM_NAME || 'Local Link';
  const fromEmail = env.FROM_EMAIL || 'noreply@locallink.store';
  const res = await globalThis.fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: fromName + ' <' + fromEmail + '>',
      to: [to],
      subject,
      html,
      text,
    }),
  });
  if (!res.ok) {
    let detail = '';
    try { const j = await res.json(); detail = j && j.message ? ': ' + j.message : ''; } catch { /* ignore */ }
    throw new Error('Resend შეცდომა (' + res.status + ')' + detail);
  }
  return true;
}

function campaignEmailHtml({ firstName, bodyHtml, unsubUrl }) {
  return '<div style="font-family:system-ui,sans-serif;max-width:560px;margin:0 auto;color:#1a1a2e">'
    + '<p>გამარჯობა' + (firstName ? ', ' + escapeHtml(firstName) : '') + '!</p>'
    + '<div>' + bodyHtml + '</div>'
    + '<hr style="border:0;border-top:1px solid #ddd;margin:24px 0 12px">'
    + '<p style="font-size:12px;color:#888">Local Link — შენი ბიზნესისთვის<br>'
    + '<a href="' + escapeHtml(unsubUrl) + '">გამოწერის გაუქმება</a></p>'
    + '</div>';
}

/* ---------- HTTP helpers ---------- */

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...securityHeaders(), ...extraHeaders },
  });
}
function securityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; font-src 'self'",
  };
}
function htmlPage(title, body) {
  return new Response(
    '<!DOCTYPE html><html lang="ka"><head><meta charset="utf-8">'
    + '<meta name="viewport" content="width=device-width, initial-scale=1">'
    + '<title>' + escapeHtml(title) + '</title>'
    + '<style>body{font-family:system-ui,sans-serif;max-width:560px;margin:32px auto;padding:0 16px;line-height:1.6;color:#1a1a2e}'
    + 'h1{font-size:1.4rem;color:#12275c}label{display:block;font-weight:600;margin:14px 0 4px}'
    + 'input[type=text],input[type=email],input[type=password],textarea{width:100%;padding:11px;font-size:1rem;border:1px solid #c9d2e8;border-radius:8px;box-sizing:border-box}'
    + 'textarea{min-height:140px}button{margin-top:16px;padding:12px 20px;font-size:1rem;font-weight:700;background:#12275c;color:#fff;border:0;border-radius:8px;cursor:pointer}'
    + 'button:disabled{opacity:.5;cursor:default}.ok{background:#e8f5e9;border:1px solid #81c784;border-radius:8px;padding:12px}'
    + '.err{background:#fce8e6;border:1px solid #e57373;border-radius:8px;padding:12px}'
    + '.note{font-size:.9rem;color:#555}.consent{font-weight:400;display:flex;gap:8px;align-items:flex-start;margin-top:16px}'
    + '.consent input{margin-top:4px;width:18px;height:18px}a{color:#12275c}</style></head>'
    + '<body>' + body + '</body></html>',
    { headers: { 'Content-Type': 'text/html; charset=utf-8', ...securityHeaders() } });
}
async function readJson(request) {
  try { return await request.json(); } catch { return {}; }
}
function baseUrl(request) {
  return new URL(request.url).origin;
}
function todayStartSec() {
  const d = new Date();
  d.setUTCHours(0, 0, 0, 0);
  return Math.floor(d.getTime() / 1000);
}

/* ---------- public pages ---------- */

function signupPage() {
  return htmlPage('Local Link — შეთავაზებები', `
<h1>Local Link — შეთავაზებები</h1>
<p>დატოვე შენი მეილი და პირველი გაიგებ ჩვენს შეთავაზებებსა და ფასდაკლებებზე.</p>
<form id="f">
  <label for="first_name">სახელი</label>
  <input id="first_name" type="text" required maxlength="50" autocomplete="given-name">
  <label for="last_name">გვარი</label>
  <input id="last_name" type="text" required maxlength="50" autocomplete="family-name">
  <label for="email">ელ. ფოსტა</label>
  <input id="email" type="email" required maxlength="254" autocomplete="email">
  <label class="consent"><input id="consent" type="checkbox">
    <span>ვეთანხმები, რომ Local Link-მა ჩემი ელ. ფოსტა გამოიყენოს შეთავაზებების გასაგზავნად. ნებისმიერ დროს შემიძლია გამოწერის გაუქმება მეილში მოცემული ბმულით ან წაშლის მოთხოვნით.</span></label>
  <button id="btn" type="submit">გამოწერა</button>
</form>
<p id="msg"></p>
<p class="note">ვაგროვებთ მხოლოდ სახელს, გვარსა და ელ. ფოსტას — შეთავაზებების გასაგზავნად. მონაცემებს არავის ვაძლევთ და არ ვყიდით. რეგისტრაციის შემდეგ მეილზე დადასტურების ბმული მოგივა.</p>
<script>
const f = document.getElementById('f');
f.addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('btn');
  const msg = document.getElementById('msg');
  if (!document.getElementById('consent').checked) {
    msg.className = 'err'; msg.textContent = 'გთხოვთ, მონიშნოთ თანხმობის ველი.'; return;
  }
  btn.disabled = true; msg.className = ''; msg.textContent = 'იგზავნება…';
  try {
    const r = await fetch('/api/subscribe', { method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        first_name: document.getElementById('first_name').value,
        last_name: document.getElementById('last_name').value,
        email: document.getElementById('email').value,
        consent: true }) });
    const j = await r.json();
    if (r.ok) {
      msg.className = 'ok';
      msg.textContent = 'გმადლობთ! დადასტურების ბმული თქვენს მეილზე გაიგზავნა — დააჭირეთ მას, რომ გამოწერა დადასტურდეს.';
      f.reset();
    } else { msg.className = 'err'; msg.textContent = j.error || 'შეცდომა. სცადეთ თავიდან.'; }
  } catch { msg.className = 'err'; msg.textContent = 'ქსელის შეცდომა. სცადეთ თავიდან.'; }
  btn.disabled = false;
});
</script>`);
}

function resultPage(title, text, ok) {
  return htmlPage(title, `<div class="${ok ? 'ok' : 'err'}"><h1>${escapeHtml(title)}</h1><p>${escapeHtml(text)}</p></div><p><a href="/">მთავარ გვერდზე დაბრუნება</a></p>`);
}

/* ---------- public API ---------- */

async function handleSubscribe(env, request) {
  const limit = Number(env.SUBSCRIBE_LIMIT_PER_MIN || CONFIG.subscribeLimitPerMin);
  if (!(await rateLimit(env, 'subscribe', request, limit, 60))) {
    return json({ error: 'ძალიან ბევრი მცდელობა. სცადეთ ერთ წუთში.' }, 429);
  }
  const body = await readJson(request);
  const firstName = cleanName(body.first_name);
  const lastName = cleanName(body.last_name);
  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  if (!firstName || firstName.length > 50) return json({ error: 'სახელი შეიყვანეთ.' }, 400);
  if (!lastName || lastName.length > 50) return json({ error: 'გვარი შეიყვანეთ.' }, 400);
  if (!validEmail(email)) return json({ error: 'ელ. ფოსტის მისამართი არასწორია.' }, 400);
  if (body.consent !== true) return json({ error: 'თანხმობა სავალდებულოა.' }, 400);

  const now = Math.floor(Date.now() / 1000);
  const existing = await env.DB.prepare(
    'SELECT id, status FROM subscribers WHERE email = ?').bind(email).first();
  const confirmToken = randomToken();
  const confirmHash = await sha256Hex(confirmToken);
  const unsubToken = randomToken();
  const unsubHash = await sha256Hex(unsubToken);

  if (existing && existing.status === 'confirmed') {
    return json({ ok: true, already: true });
  }
  if (existing) {
    await env.DB.prepare(
      `UPDATE subscribers SET first_name = ?, last_name = ?, status = 'pending',
       confirm_token_hash = ?, unsub_token_hash = ?, consent_at = ?, confirmed_at = NULL
       WHERE id = ?`)
      .bind(firstName, lastName, confirmHash, unsubHash, now, existing.id).run();
  } else {
    await env.DB.prepare(
      `INSERT INTO subscribers (email, first_name, last_name, status,
       confirm_token_hash, unsub_token_hash, consent_at, created_at)
       VALUES (?, ?, ?, 'pending', ?, ?, ?, ?)`)
      .bind(email, firstName, lastName, confirmHash, unsubHash, now, now).run();
  }

  // Double opt-in email. If sending is not configured yet, the signup is
  // still stored as pending and the admin can see it in the panel.
  if (env.RESEND_API_KEY) {
    const confirmUrl = baseUrl(request) + '/confirm?token=' + confirmToken;
    try {
      await sendMail(env, {
        to: email,
        subject: 'დაადასტურეთ გამოწერა — Local Link',
        html: '<div style="font-family:system-ui,sans-serif;max-width:560px;margin:0 auto;color:#1a1a2e">'
          + '<p>გამარჯობა, ' + escapeHtml(firstName) + '!</p>'
          + '<p>Local Link-ის შეთავაზებებზე გამოსაწერად დააჭირეთ ბმულს:</p>'
          + '<p><a href="' + escapeHtml(confirmUrl) + '">გამოწერის დადასტურება</a></p>'
          + '<p style="font-size:12px;color:#888">თუ თქვენ არ მოგვითხოვიათ გამოწერა, უბრალოდ უგულებელყავით ეს მეილი.</p></div>',
        text: 'გამარჯობა, ' + firstName + '!\n\nგამოწერის დასადასტურებლად გახსენით ბმული:\n' + confirmUrl
          + '\n\nთუ თქვენ არ მოგვითხოვიათ გამოწერა, უგულებელყავით ეს მეილი.',
      });
    } catch (e) {
      console.error('confirm email failed:', e && e.message ? e.message : e);
      // Stored as pending; the admin panel shows the Resend error.
    }
  }
  return json({ ok: true });
}

async function handleConfirm(env, request) {
  const token = new URL(request.url).searchParams.get('token') || '';
  if (!token) return resultPage('ბმული არასწორია', 'დადასტურების ბმულში ტოკენი აკლია.', false);
  const hash = await sha256Hex(token);
  const row = await env.DB.prepare(
    'SELECT id, status FROM subscribers WHERE confirm_token_hash = ?').bind(hash).first();
  if (!row) return resultPage('ბმული არასწორია', 'ეს დადასტურების ბმული ვერ მოიძებნა ან უკვე გამოყენებულია.', false);
  if (row.status === 'confirmed') {
    return resultPage('გამოწერა დადასტურებულია', 'თქვენი გამოწერა უკვე დადასტურებულია. მადლობა!', true);
  }
  await env.DB.prepare(
    "UPDATE subscribers SET status = 'confirmed', confirmed_at = ? WHERE id = ?")
    .bind(Math.floor(Date.now() / 1000), row.id).run();
  return resultPage('გამოწერა დადასტურდა', 'მადლობა! ახლა Local Link-ის შეთავაზებებს მეილზე მიიღებთ.', true);
}

async function handleUnsubscribe(env, request) {
  const token = new URL(request.url).searchParams.get('token') || '';
  if (!token) return resultPage('ბმული არასწორია', 'გაუქმების ბმულში ტოკენი აკლია.', false);
  const hash = await sha256Hex(token);
  const row = await env.DB.prepare(
    'SELECT id, status FROM subscribers WHERE unsub_token_hash = ?').bind(hash).first();
  if (!row) return resultPage('ბმული არასწორია', 'ეს გაუქმების ბმული ვერ მოიძებნა.', false);
  if (row.status === 'unsubscribed') {
    return resultPage('გამოწერა გაუქმებულია', 'თქვენი გამოწერა უკვე გაუქმებულია.', true);
  }
  await env.DB.prepare(
    "UPDATE subscribers SET status = 'unsubscribed' WHERE id = ?").bind(row.id).run();
  return resultPage('გამოწერა გაუქმდა', 'თქვენი მეილი სიიდან ამოღებულია. აღარაფერს გამოგიგზავნით.', true);
}

/* ---------- admin panel ---------- */

function adminPage() {
  return htmlPage('Local Link Offers — ადმინ პანელი', `
<h1>Local Link Offers — ადმინ პანელი</h1>
<div id="login">
  <label for="pw">ადმინის პაროლი</label>
  <input id="pw" type="password" autocomplete="current-password">
  <button id="loginBtn">შესვლა</button>
  <p id="loginMsg"></p>
</div>
<div id="panel" style="display:none">
  <p id="statusLine" class="note"></p>
  <button id="logoutBtn" style="background:#888">გასვლა</button>
  <h2>გამომწერები</h2>
  <p>
    <input id="q" type="text" placeholder="ძებნა (მეილი ან სახელი)" style="width:60%">
    <button id="searchBtn">ძებნა</button>
    <button id="exportBtn" style="background:#2e7d32">CSV ექსპორტი</button>
  </p>
  <p id="countLine" class="note"></p>
  <div id="list"></div>
  <h2>შეთავაზების გაგზავნა</h2>
  <p class="note">მონიშნეთ გამომწერები სიიდან (მხოლოდ დადასტურებულებს ეგზავნებათ) და დაწერეთ ტექსტი.</p>
  <label for="subject">სათაური</label>
  <input id="subject" type="text" maxlength="200">
  <label for="body">ტექსტი</label>
  <textarea id="body"></textarea>
  <button id="sendBtn">გაგზავნა მონიშნულებზე</button>
  <p id="sendMsg"></p>
  <h2>გაგზავნის ისტორია</h2>
  <div id="history"></div>
</div>
<script>
let subs = [];
async function api(path, opts) {
  const r = await fetch(path, opts);
  const j = await r.json().catch(() => ({}));
  return { r, j };
}
async function me() {
  const { r, j } = await api('/api/admin/me');
  return r.ok && j.authenticated;
}
async function loadStatus() {
  const { r, j } = await api('/api/admin/status');
  if (!r.ok) return;
  document.getElementById('statusLine').textContent =
    'სულ: ' + j.total + ' | დადასტურებული: ' + j.confirmed + ' | დასადასტურებელი: ' + j.pending
    + ' | გაუქმებული: ' + j.unsubscribed + ' | დღეს გაგზავნილი: ' + j.today_sent + '/' + j.daily_cap
    + (j.resend_configured ? '' : ' | გაგზავნა არ არის დაყენებული (RESEND_API_KEY აკლია)');
}
async function loadSubs() {
  const q = document.getElementById('q').value;
  const { r, j } = await api('/api/admin/subscribers?q=' + encodeURIComponent(q) + '&limit=200');
  if (!r.ok) return;
  subs = j.subscribers;
  document.getElementById('countLine').textContent = 'ნაჩვენებია: ' + subs.length + ' / სულ: ' + j.total;
  const el = document.getElementById('list');
  el.innerHTML = subs.map((s) => {
    const dis = s.status !== 'confirmed' ? ' disabled' : '';
    return '<label style="display:flex;gap:8px;align-items:center;border:1px solid #ddd;border-radius:8px;padding:8px;margin:6px 0">'
      + '<input type="checkbox" class="pick" value="' + s.id + '"' + dis + '>'
      + '<span><b>' + esc(s.first_name) + ' ' + esc(s.last_name) + '</b> — ' + esc(s.email)
      + ' <i>(' + s.status + ')</i></span>'
      + '<button data-del="' + s.id + '" style="margin-left:auto;background:#c62828;padding:6px 10px">წაშლა</button>'
      + '</label>';
  }).join('') || '<p class="note">სია ცარიელია.</p>';
  el.querySelectorAll('[data-del]').forEach((b) => b.addEventListener('click', async () => {
    if (!confirm('წავშალო ეს გამომწერი?')) return;
    await api('/api/admin/subscribers/delete', { method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: Number(b.dataset.del) }) });
    loadSubs(); loadStatus();
  }));
}
function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
async function loadHistory() {
  const { r, j } = await api('/api/admin/campaigns');
  if (!r.ok) return;
  document.getElementById('history').innerHTML = j.campaigns.map((c) =>
    '<p><b>' + esc(c.subject) + '</b> — ' + new Date(c.created_at * 1000).toLocaleString('ka-GE')
    + ' | სულ: ' + c.total + ', გაგზავნილი: ' + c.sent + ', ჩავარდა: ' + c.failed + '</p>').join('')
    || '<p class="note">ჯერ არაფერი გაგზავნილა.</p>';
}
async function showPanel() {
  document.getElementById('login').style.display = 'none';
  document.getElementById('panel').style.display = 'block';
  await loadStatus(); await loadSubs(); await loadHistory();
}
document.getElementById('loginBtn').addEventListener('click', async () => {
  const pw = document.getElementById('pw').value;
  const { r, j } = await api('/api/admin/login', { method: 'POST',
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: pw }) });
  if (r.ok) { showPanel(); }
  else { document.getElementById('loginMsg').className = 'err'; document.getElementById('loginMsg').textContent = j.error || 'შეცდომა.'; }
});
document.getElementById('pw').addEventListener('keydown', (e) => { if (e.key === 'Enter') document.getElementById('loginBtn').click(); });
document.getElementById('logoutBtn').addEventListener('click', async () => {
  await api('/api/admin/logout', { method: 'POST' });
  location.reload();
});
document.getElementById('searchBtn').addEventListener('click', loadSubs);
document.getElementById('exportBtn').addEventListener('click', () => { location.href = '/api/admin/export.csv'; });
document.getElementById('sendBtn').addEventListener('click', async () => {
  const ids = Array.from(document.querySelectorAll('.pick:checked')).map((c) => Number(c.value));
  const subject = document.getElementById('subject').value.trim();
  const body = document.getElementById('body').value.trim();
  const msg = document.getElementById('sendMsg');
  if (!ids.length) { msg.className = 'err'; msg.textContent = 'მონიშნეთ მინიმუმ ერთი გამომწერი.'; return; }
  if (!subject || !body) { msg.className = 'err'; msg.textContent = 'სათაური და ტექსტი შეიყვანეთ.'; return; }
  if (!confirm('გავაგზავნო ' + ids.length + ' გამომწერს?')) return;
  msg.className = ''; msg.textContent = 'იგზავნება…';
  const { r, j } = await api('/api/admin/send', { method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ids, subject, body }) });
  if (r.ok) {
    msg.className = 'ok';
    msg.textContent = 'გაგზავნილია: ' + j.sent + ', ჩავარდა: ' + j.failed + '.';
    loadStatus(); loadHistory();
  } else { msg.className = 'err'; msg.textContent = j.error || 'შეცდომა.'; }
});
me().then((ok) => { if (ok) showPanel(); });
</script>`);
}

/* ---------- admin API ---------- */

async function requireAdmin(env, request) {
  return getSession(env, request);
}

async function handleAdminLogin(env, request) {
  const limit = Number(env.LOGIN_LIMIT_PER_MIN || CONFIG.loginLimitPerMin);
  if (!(await rateLimit(env, 'login', request, limit, 60))) {
    return json({ error: 'ძალიან ბევრი მცდელობა. სცადეთ ერთ წუთში.' }, 429);
  }
  const body = await readJson(request);
  const ok = env.ADMIN_PASSWORD_HASH
    ? await verifyPassword(String(body.password || ''), env.ADMIN_PASSWORD_HASH)
    : false;
  if (!ok) return json({ error: 'პაროლი არასწორია.' }, 401);
  const token = await createSession(env);
  return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie(token) });
}

async function handleAdminLogout(env, request) {
  await destroySession(env, request);
  return json({ ok: true }, 200, { 'Set-Cookie': clearSessionCookie() });
}

async function handleAdminStatus(env) {
  const counts = await env.DB.prepare(
    `SELECT status, COUNT(*) AS n FROM subscribers GROUP BY status`).all();
  const byStatus = { pending: 0, confirmed: 0, unsubscribed: 0 };
  let total = 0;
  for (const row of counts.results || []) { byStatus[row.status] = row.n; total += row.n; }
  const today = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM sends WHERE status = 'sent' AND created_at >= ?`)
    .bind(todayStartSec()).first();
  return json({
    total,
    pending: byStatus.pending,
    confirmed: byStatus.confirmed,
    unsubscribed: byStatus.unsubscribed,
    today_sent: today ? today.n : 0,
    daily_cap: Number(env.MAIL_DAILY_CAP || CONFIG.sendDailyCap),
    resend_configured: Boolean(env.RESEND_API_KEY),
  });
}

async function handleAdminSubscribers(env, request) {
  const url = new URL(request.url);
  const q = (url.searchParams.get('q') || '').trim();
  const status = url.searchParams.get('status') || '';
  const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit') || '200', 10) || 200, 1), 500);
  const offset = Math.max(parseInt(url.searchParams.get('offset') || '0', 10) || 0, 0);
  const where = [];
  const params = [];
  if (status && ['pending', 'confirmed', 'unsubscribed'].includes(status)) {
    where.push('status = ?'); params.push(status);
  }
  if (q) {
    where.push('(email LIKE ? OR first_name LIKE ? OR last_name LIKE ?)');
    params.push('%' + q + '%', '%' + q + '%', '%' + q + '%');
  }
  const clause = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const rows = await env.DB.prepare(
    `SELECT id, email, first_name, last_name, status, created_at, confirmed_at
     FROM subscribers ${clause} ORDER BY created_at DESC LIMIT ? OFFSET ?`)
    .bind(...params, limit, offset).all();
  const totalRow = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM subscribers ${clause}`).bind(...params).first();
  return json({ subscribers: rows.results || [], total: totalRow ? totalRow.n : 0 });
}

async function handleAdminDelete(env, request) {
  const body = await readJson(request);
  const id = Number(body.id);
  if (!id) return json({ error: 'არასწორი id.' }, 400);
  await env.DB.prepare('DELETE FROM subscribers WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

async function handleAdminSend(env, request) {
  const body = await readJson(request);
  const ids = Array.isArray(body.ids) ? body.ids.map(Number).filter(Boolean) : [];
  const subject = typeof body.subject === 'string' ? body.subject.trim() : '';
  const text = typeof body.body === 'string' ? body.body.trim() : '';
  if (!ids.length) return json({ error: 'გამომწერები არ არის მონიშნული.' }, 400);
  if (ids.length > CONFIG.sendPerRequestCap) {
    return json({ error: 'ერთ ჯერზე მაქსიმუმ ' + CONFIG.sendPerRequestCap + ' გამომწერი.' }, 400);
  }
  if (!subject || subject.length > 200) return json({ error: 'სათაური შეიყვანეთ (მაქს. 200 სიმბოლო).' }, 400);
  if (!text || text.length > 20000) return json({ error: 'ტექსტი შეიყვანეთ (მაქს. 20 000 სიმბოლო).' }, 400);
  if (!env.RESEND_API_KEY) {
    return json({ error: 'გაგზავნა არ არის დაყენებული — RESEND_API_KEY აკლია. იხ. README.' }, 503);
  }
  const dailyCap = Number(env.MAIL_DAILY_CAP || CONFIG.sendDailyCap);
  const today = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM sends WHERE status = 'sent' AND created_at >= ?`)
    .bind(todayStartSec()).first();
  const todaySent = today ? today.n : 0;
  if (todaySent + ids.length > dailyCap) {
    return json({ error: 'დღიური ლიმიტი: დღეს უკვე ' + todaySent + '/' + dailyCap
      + ' გაგზავნილია. დარჩენილია ' + Math.max(dailyCap - todaySent, 0) + '.' }, 429);
  }
  const placeholders = ids.map(() => '?').join(',');
  const rows = await env.DB.prepare(
    `SELECT id, email, first_name, unsub_token_hash FROM subscribers
     WHERE id IN (${placeholders}) AND status = 'confirmed'`).bind(...ids).all();
  const targets = rows.results || [];
  if (!targets.length) return json({ error: 'მონიშნულებში დადასტურებული გამომწერი არ არის.' }, 400);

  const now = Math.floor(Date.now() / 1000);
  const campaign = await env.DB.prepare(
    'INSERT INTO campaigns (subject, body, total, created_at) VALUES (?, ?, ?, ?)')
    .bind(subject, text, targets.length, now).run();
  const campaignId = campaign.meta.last_row_id;

  let sent = 0;
  let failed = 0;
  const errors = [];
  for (const t of targets) {
    // The unsubscribe token is stored hashed; the raw token is not kept.
    // A fresh token is issued per campaign email and its hash replaces
    // the stored one, so old links keep working only until the next send.
    const unsubToken = randomToken();
    const unsubHash = await sha256Hex(unsubToken);
    await env.DB.prepare(
      'UPDATE subscribers SET unsub_token_hash = ? WHERE id = ?').bind(unsubHash, t.id).run();
    const unsubUrl = baseUrl(request) + '/unsubscribe?token=' + unsubToken;
    const html = campaignEmailHtml({ firstName: t.first_name, bodyHtml: textToHtml(text), unsubUrl });
    const plain = 'გამარჯობა, ' + t.first_name + '!\n\n' + text
      + '\n\nგამოწერის გაუქმება: ' + unsubUrl;
    try {
      await sendMail(env, { to: t.email, subject, html, text: plain });
      await env.DB.prepare(
        "INSERT INTO sends (campaign_id, subscriber_id, status, created_at) VALUES (?, ?, 'sent', ?)")
        .bind(campaignId, t.id, Math.floor(Date.now() / 1000)).run();
      sent++;
    } catch (e) {
      const msg = e && e.message ? e.message : 'უცნობი შეცდომა';
      await env.DB.prepare(
        "INSERT INTO sends (campaign_id, subscriber_id, status, error, created_at) VALUES (?, ?, 'failed', ?, ?)")
        .bind(campaignId, t.id, String(msg).slice(0, 500), Math.floor(Date.now() / 1000)).run();
      failed++;
      if (errors.length < 5) errors.push(t.email + ': ' + msg);
    }
  }
  await env.DB.prepare(
    'UPDATE campaigns SET sent = ?, failed = ? WHERE id = ?').bind(sent, failed, campaignId).run();
  return json({ ok: true, campaign_id: campaignId, sent, failed, errors });
}

async function handleAdminCampaigns(env) {
  const rows = await env.DB.prepare(
    `SELECT id, subject, total, sent, failed, created_at FROM campaigns
     ORDER BY created_at DESC LIMIT 50`).all();
  return json({ campaigns: rows.results || [] });
}

function csvEscape(v) {
  const s = String(v == null ? '' : v);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

async function handleAdminExport(env) {
  const rows = await env.DB.prepare(
    `SELECT email, first_name, last_name, status,
     datetime(created_at, 'unixepoch') AS created
     FROM subscribers ORDER BY created_at DESC`).all();
  const lines = ['email,first_name,last_name,status,created'];
  for (const r of rows.results || []) {
    lines.push([r.email, r.first_name, r.last_name, r.status, r.created].map(csvEscape).join(','));
  }
  return new Response(lines.join('\n'), {
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="locallink-offers-subscribers.csv"',
      ...securityHeaders(),
    },
  });
}

/* ---------- router ---------- */

export default {
  async fetch(request, env) {
    try {
      await ensureSchema(env);
      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.method;

      if (path === '/' && method === 'GET') return signupPage();
      if (path === '/admin' && method === 'GET') return adminPage();
      if (path === '/confirm' && method === 'GET') return handleConfirm(env, request);
      if (path === '/unsubscribe' && method === 'GET') return handleUnsubscribe(env, request);
      if (path === '/api/health' && method === 'GET') return json({ ok: true });
      if (path === '/api/subscribe' && method === 'POST') return handleSubscribe(env, request);

      if (path === '/api/admin/login' && method === 'POST') return handleAdminLogin(env, request);
      if (path === '/api/admin/logout' && method === 'POST') return handleAdminLogout(env, request);
      if (path === '/api/admin/me' && method === 'GET') {
        return json({ authenticated: await getSession(env, request) });
      }

      // All other /api/admin/* routes need a session.
      if (path.startsWith('/api/admin/')) {
        if (!(await requireAdmin(env, request))) return json({ error: 'შესვლა საჭიროა.' }, 401);
        if (path === '/api/admin/status' && method === 'GET') return handleAdminStatus(env);
        if (path === '/api/admin/subscribers' && method === 'GET') return handleAdminSubscribers(env, request);
        if (path === '/api/admin/subscribers/delete' && method === 'POST') return handleAdminDelete(env, request);
        if (path === '/api/admin/send' && method === 'POST') return handleAdminSend(env, request);
        if (path === '/api/admin/campaigns' && method === 'GET') return handleAdminCampaigns(env);
        if (path === '/api/admin/export.csv' && method === 'GET') return handleAdminExport(env);
        return json({ error: 'ვერ მოიძებნა.' }, 404);
      }

      return json({ error: 'ვერ მოიძებნა.' }, 404);
    } catch (e) {
      console.error('fetch error:', e && e.message ? e.message : e);
      return json({ error: 'სერვერის შეცდომა.' }, 500);
    }
  },
};
