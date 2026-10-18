
'use strict';

// WRP: independently developed activation API and mobile-friendly admin dashboard.
// Node.js 20+, zero third-party dependencies.
// IMPORTANT: File-backed storage needs a persistent disk or durable database in production.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT || 10000);
const HOST = process.env.HOST || '0.0.0.0';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const KEY_PEPPER = process.env.KEY_PEPPER || '';
const DATABASE_URL = process.env.DATABASE_URL || '';
const Pool = DATABASE_URL ? require('pg').Pool : null;
const STORE_FILE = path.resolve(process.env.STORE_FILE || './wrp-data/keys.json');

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) throw new Error('Invalid PORT');
if (ADMIN_TOKEN.length < 32 || KEY_PEPPER.length < 32 || ADMIN_TOKEN === KEY_PEPPER) {
  throw new Error('Create TWO DIFFERENT long secret values in Render environment: ADMIN_TOKEN and KEY_PEPPER (32+ characters each).');
}

let pool = null;
let state = { keys: [] };

function saveLocal() {
  const temp = STORE_FILE + '.' + process.pid + '.tmp';
  fs.writeFileSync(temp, JSON.stringify(state, null, 2), { mode: 0o600 });
  fs.renameSync(temp, STORE_FILE);
}

async function initializeStorage() {
  if (DATABASE_URL) {
    pool = new Pool({
      connectionString: DATABASE_URL,
      max: 5,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000
    });
    await pool.query(
      'CREATE TABLE IF NOT EXISTS wrp_activation_keys (' +
      'id TEXT PRIMARY KEY, ' +
      'key_hash TEXT NOT NULL UNIQUE, ' +
      'created_at TIMESTAMPTZ NOT NULL, ' +
      'expires_at TIMESTAMPTZ NOT NULL, ' +
      'revoked BOOLEAN NOT NULL DEFAULT FALSE, ' +
      'device_hash TEXT)'
    );
    await pool.query('CREATE INDEX IF NOT EXISTS wrp_activation_keys_expires_idx ON wrp_activation_keys (expires_at)');
    console.log('WRP storage initialized: PostgreSQL');
    return;
  }

  fs.mkdirSync(path.dirname(STORE_FILE), { recursive: true });
  if (!fs.existsSync(STORE_FILE)) {
    fs.writeFileSync(STORE_FILE, JSON.stringify({ keys: [] }, null, 2), { flag: 'wx', mode: 0o600 });
  }
  state = JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
  if (!Array.isArray(state.keys)) throw new Error('Invalid storage file');
  console.warn('WRP storage initialized: local JSON file (not durable on Render Free)');
}

function fromDatabase(row) {
  return {
    id: row.id,
    keyHash: row.keyHash,
    createdAt: new Date(row.createdAt).toISOString(),
    expiresAt: new Date(row.expiresAt).toISOString(),
    revoked: row.revoked,
    deviceHash: row.deviceHash || null
  };
}

const KEY_SELECT = 'SELECT id, key_hash AS "keyHash", created_at AS "createdAt", expires_at AS "expiresAt", revoked, device_hash AS "deviceHash" FROM wrp_activation_keys';

async function listKeys() {
  if (!pool) return state.keys;
  const result = await pool.query(KEY_SELECT + ' ORDER BY created_at DESC');
  return result.rows.map(fromDatabase);
}

async function createKey(item) {
  if (!pool) {
    state.keys.push(item);
    saveLocal();
    return;
  }
  await pool.query(
    'INSERT INTO wrp_activation_keys (id, key_hash, created_at, expires_at, revoked, device_hash) VALUES ($1, $2, $3, $4, $5, $6)',
    [item.id, item.keyHash, item.createdAt, item.expiresAt, item.revoked, item.deviceHash]
  );
}

async function revokeKey(id) {
  if (!pool) {
    const item = state.keys.find(key => key.id === id);
    if (!item) return null;
    item.revoked = true;
    saveLocal();
    return item.id;
  }
  const result = await pool.query('UPDATE wrp_activation_keys SET revoked = TRUE WHERE id = $1 RETURNING id', [id]);
  return result.rows[0] ? result.rows[0].id : null;
}

async function findKeyByHash(keyHash) {
  if (!pool) return state.keys.find(item => constantEquals(item.keyHash, keyHash)) || null;
  const result = await pool.query(KEY_SELECT + ' WHERE key_hash = $1 LIMIT 1', [keyHash]);
  return result.rows[0] ? fromDatabase(result.rows[0]) : null;
}

async function bindDevice(id, deviceHash) {
  if (!pool) {
    const item = state.keys.find(key => key.id === id);
    if (item && !item.deviceHash && !item.revoked && Date.now() < Date.parse(item.expiresAt)) {
      item.deviceHash = deviceHash;
      saveLocal();
    }
    return;
  }
  await pool.query(
    'UPDATE wrp_activation_keys SET device_hash = $2 WHERE id = $1 AND device_hash IS NULL AND revoked = FALSE AND expires_at > NOW()',
    [id, deviceHash]
  );
}
function hmac(value) {
  return crypto.createHmac('sha256', KEY_PEPPER).update(value).digest('hex');
}
function constantEquals(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function reply(res, status, payload) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY'
  });
  res.end(JSON.stringify(payload));
}
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let buffer = '';
    let bytes = 0;
    req.setEncoding('utf8');
    req.on('data', (part) => {
      bytes += Buffer.byteLength(part);
      if (bytes > 8192) {
        reject(new Error('Request too large'));
        req.destroy();
        return;
      }
      buffer += part;
    });
    req.on('end', () => {
      try {
        const data = JSON.parse(buffer);
        if (!data || typeof data !== 'object' || Array.isArray(data)) throw Error('Invalid body');
        resolve(data);
      } catch (_) { reject(new Error('Invalid JSON object')); }
    });
    req.on('error', reject);
  });
}
const requests = new Map();
function limited(req) {
  const now = Date.now(), ip = req.socket.remoteAddress || 'unknown';
  const value = requests.get(ip);
  if (!value || now - value.started > 60_000) {
    requests.set(ip, { started: now, hits: 1 });
    if (requests.size > 1000) {
      for (const [name, row] of requests) if (now - row.started > 60_000) requests.delete(name);
    }
    return false;
  }
  value.hits++;
  return value.hits > 60;
}
function authorized(req) {
  const header = req.headers.authorization;
  return typeof header === 'string' && header.startsWith('Bearer ') &&
    constantEquals(header.slice(7), ADMIN_TOKEN);
}

const adminPage = `<!doctype html>
<html lang="my">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>WRP Control — Admin Dashboard</title>
<style>
:root{font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;color:#edf4ff;background:#080f1e;font-synthesis:none}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:radial-gradient(ellipse at 10% 0,#18345d 0,transparent 44%),linear-gradient(135deg,#080f1e,#101b30)}
button,input,select{font:inherit}
button{border:1px solid transparent;border-radius:10px;padding:11px 14px;background:#3979f6;color:#fff;font-weight:750;cursor:pointer;transition:filter .15s}
button:hover{filter:brightness(1.12)}button:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid #85b8ff;outline-offset:2px}
button:disabled{opacity:.55;cursor:wait}button.secondary{background:#24334b;border-color:#3a4a63}button.danger{background:#8f2e43}button.small{padding:7px 10px;font-size:12px}
input,select{width:100%;min-width:0;padding:12px;color:#f5f7ff;background:#0b1528;border:1px solid #34445f;border-radius:10px}
input::placeholder{color:#7387a5}
.wrap{width:min(1160px,100%);margin:0 auto;padding:24px 18px 40px}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:30px}
.brand{display:flex;align-items:center;gap:12px}.logo{display:grid;place-items:center;width:46px;height:46px;border-radius:14px;background:linear-gradient(135deg,#74b5ff,#3159e8);font-size:20px;font-weight:950;box-shadow:0 8px 28px #3478f640}
.brandname{font-weight:900;letter-spacing:.1em}.branddesc{font-size:12px;color:#91a6c5;margin-top:3px}
.pill{border:1px solid #29486c;background:#102746;color:#9bc8ff;border-radius:999px;padding:7px 11px;font-size:11px;font-weight:850;white-space:nowrap}
.eyebrow{color:#83b8ff;font-size:11px;letter-spacing:.16em;text-transform:uppercase;font-weight:850}
h1{font-size:clamp(29px,4vw,43px);letter-spacing:-.045em;line-height:1.1;margin:9px 0 12px}h2{font-size:17px;line-height:1.35;margin:0}
.lead{color:#afbed4;line-height:1.7;max-width:780px;margin:0}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:23px 0}
.stat,.panel{background:linear-gradient(145deg,#14213a,#0e192b);border:1px solid #293a55;border-radius:16px;box-shadow:0 16px 40px #0002}
.stat{padding:16px;min-width:0}.statlabel{font-size:12px;color:#a8bad3}.statnum{font-size:30px;font-weight:900;letter-spacing:-.04em;margin-top:8px}.statnote{font-size:11px;color:#8297b7;margin-top:4px}
.layout{display:grid;grid-template-columns:minmax(280px,.78fr) minmax(0,1.5fr);gap:16px;align-items:start}
.panel{padding:19px;margin-bottom:16px;min-width:0}.panelhead{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}
.desc{font-size:13px;line-height:1.65;color:#a5b6cf;margin:7px 0 14px}
label{display:block;font-size:13px;font-weight:750;color:#d2def0;margin:13px 0 7px}
.row{display:flex;align-items:center;gap:8px}.row>*{min-width:0}.tokenrow input{flex:1}.tokenrow button{flex:0 0 auto}
.hint{font-size:12px;line-height:1.6;color:#8fa3c1;margin:10px 0 0}
.warning{font-size:12px;line-height:1.65;color:#f3dba0;background:#302817;border:1px solid #665226;border-radius:10px;padding:12px;margin-top:14px}
.generated{margin-top:14px;padding:13px;background:#102c29;border:1px solid #2d6a55;border-radius:12px}.good{font-size:13px;font-weight:850;color:#8ce0bc}
.keyvalue{display:block;margin:10px 0;padding:12px;background:#071b1a;border:1px solid #245447;border-radius:9px;color:#d7fff0;overflow-wrap:anywhere;word-break:break-word;font:13px ui-monospace,SFMono-Regular,Consolas,monospace;user-select:all}
.toolbar{display:grid;grid-template-columns:minmax(130px,1fr) 155px auto;gap:8px;margin:14px 0}
.tablewrap{width:100%;overflow-x:auto;border:1px solid #293a55;border-radius:11px}
table{width:100%;border-collapse:collapse;min-width:570px;font-size:13px}
th{background:#0a1426;color:#9db0cd;font-size:11px;text-transform:uppercase;letter-spacing:.06em;text-align:left}
td,th{padding:12px 11px;border-bottom:1px solid #263750;vertical-align:middle}tbody tr:last-child td{border-bottom:0}tbody tr:hover{background:#182741}
.keyid{font:12px ui-monospace,SFMono-Regular,Consolas,monospace;color:#d3e2fa}.date{white-space:nowrap;color:#d8e3f5}
.status{display:inline-block;padding:6px 9px;border-radius:999px;font-size:11px;font-weight:850;white-space:nowrap}
.status.available{background:#12392f;color:#7fe1b5}.status.activated{background:#142e53;color:#9bc8ff}.status.expired{background:#3c2e16;color:#f7c76d}.status.revoked{background:#421d2b;color:#ff9baa}
.empty{text-align:center;color:#9aadc8;padding:26px}.message{min-height:22px;margin:14px 2px 0;font-size:13px;line-height:1.6;color:#b7d2ff}.message.error{color:#ff9baa}.message.success{color:#8ce0bc}
.footer{text-align:center;color:#778dab;font-size:11px;line-height:1.65;margin-top:17px}
@media(max-width:860px){.layout{grid-template-columns:1fr}}
@media(max-width:560px){.wrap{padding:17px 12px 30px}.topbar{align-items:flex-start}.pill{font-size:10px}.stats{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.stat{padding:13px}.statnum{font-size:26px}.panel{padding:14px}.toolbar{grid-template-columns:1fr 1fr}.toolbar input{grid-column:1/-1}.panelhead{align-items:flex-start}.row.tokenrow button{padding:10px}}
</style>
</head>
<body>
<main class="wrap">
<header class="topbar">
  <div class="brand"><div class="logo">W</div><div><div class="brandname">WRP CONTROL</div><div class="branddesc">Activation &amp; key management</div></div></div>
  <span class="pill">PRIVATE ADMIN AREA</span>
</header>

<section>
  <div class="eyebrow">Administration</div>
  <h1>Admin Key Dashboard</h1>
  <p class="lead">Activation Key များကို ဒီနေရာမှ ထုတ်ပေးခြင်း၊ သက်တမ်းနှင့် လက်ရှိအခြေအနေ စစ်ဆေးခြင်း၊ မလိုအပ်တော့သော Key ကို ပိတ်သိမ်းခြင်းတို့ ပြုလုပ်နိုင်ပါသည်။</p>
</section>

<section class="stats" aria-label="Key summary">
  <div class="stat"><div class="statlabel">Total keys / စုစုပေါင်း</div><div class="statnum" id="totalCount">—</div><div class="statnote">All issued keys</div></div>
  <div class="stat"><div class="statlabel">Available / မသုံးရသေး</div><div class="statnum" id="availableCount">—</div><div class="statnote">Ready to activate</div></div>
  <div class="stat"><div class="statlabel">Activated / အသုံးပြုပြီး</div><div class="statnum" id="activatedCount">—</div><div class="statnote">Bound to an installation</div></div>
  <div class="stat"><div class="statlabel">Expired / Revoked</div><div class="statnum" id="attentionCount">—</div><div class="statnote">No longer usable</div></div>
</section>

<div class="layout">
  <section>
    <div class="panel">
      <div class="panelhead"><h2>Admin authentication</h2><span class="pill">SECURE</span></div>
      <p class="desc">Render Environment ထဲရှိ <b>ADMIN_TOKEN</b> ကို ထည့်ပြီး Key စာရင်းကို ဖွင့်ပါ။ Token ကို ဒီစာမျက်နှာက သိမ်းဆည်းမထားပါ။</p>
      <label for="token">Admin token</label>
      <div class="row tokenrow"><input id="token" type="password" autocomplete="off" spellcheck="false" placeholder="Paste ADMIN_TOKEN"><button id="toggleToken" class="secondary" type="button">Show</button></div>
      <button id="list" type="button" style="width:100%;margin-top:12px">Connect &amp; load keys</button>
      <p class="hint">Token ကို GitHub၊ public chat သို့မဟုတ် screenshot များတွင် မမျှဝေပါနှင့်။</p>
    </div>

    <div class="panel">
      <div class="panelhead"><h2>Generate a key</h2><span class="pill">NEW KEY</span></div>
      <p class="desc">အသစ်ထုတ်မည့် Activation Key ၏ သက်တမ်းကို ရွေးချယ်ပါ။</p>
      <label for="days">Validity / သက်တမ်း</label>
      <select id="days"><option value="7">7 days</option><option value="30" selected>30 days</option><option value="90">90 days</option><option value="180">180 days</option><option value="365">365 days</option></select>
      <button id="issue" type="button" style="width:100%;margin-top:12px">＋ Generate activation key</button>
      <div id="generated" class="generated" hidden>
        <div class="good">Key အသစ်ထုတ်ပြီးပါပြီ · Key created</div>
        <code id="generatedKey" class="keyvalue"></code>
        <div class="row"><button id="copyKey" type="button">Copy key</button><button id="hideKey" class="secondary" type="button">Hide key</button></div>
      </div>
      <div class="warning">လုံခြုံရေးအတွက် Key အပြည့်အစုံကို ထုတ်ပေးသည့်အချိန်တွင်သာ ပြသပါမည်။ Server က Key ကို hash အဖြစ်သာ သိမ်းထားသောကြောင့် အဟောင်း၏ raw value ကို ပြန်ဖော်မရပါ။ Key မိတ္တူပျောက်ပါက အသစ်ထုတ်ပြီး အဟောင်းကို revoke လုပ်ပါ။</div>
    </div>
  </section>

  <section class="panel">
    <div class="panelhead"><div><h2>Issued keys</h2><p class="desc" style="margin:5px 0 0">Key ID၊ စတင်ရက်၊ သက်တမ်းကုန်ရက်နှင့် အခြေအနေကို ကြည့်ရှုနိုင်ပါသည်။</p></div><button id="refresh" class="secondary" type="button">Refresh</button></div>
    <div class="toolbar">
      <input id="search" type="search" placeholder="Search by Key ID…" aria-label="Search keys">
      <select id="filter" aria-label="Filter key status"><option value="all">All statuses</option><option value="available">Available</option><option value="activated">Activated</option><option value="expired">Expired</option><option value="revoked">Revoked</option></select>
      <button id="clearFilters" class="secondary" type="button">Clear</button>
    </div>
    <div class="tablewrap"><table><thead><tr><th>Key ID</th><th>Created</th><th>Expires</th><th>Status</th><th>Action</th></tr></thead><tbody id="keys"><tr><td class="empty" colspan="5">Admin token ထည့်ပြီး “Connect &amp; load keys” ကိုနှိပ်ပါ။</td></tr></tbody></table></div>
    <p id="message" class="message" role="status" aria-live="polite"></p>
  </section>
</div>

<p class="footer" id="storageInfo">Checking storage configuration…</p>
</main>
<script>
const $ = id => document.getElementById(id);
let allKeys = [];

async function checkStorageMode() {
  const el = $('storageInfo');
  try {
    const response = await fetch('/health', { cache: 'no-store' });
    const data = await response.json();
    if (!response.ok || !data.ok) throw new Error('Health check failed');
    if (data.storage === 'postgres') {
      el.textContent = 'Storage: PostgreSQL connected. Key records persist across service restarts and redeploys; maintain database backups and access controls.';
    } else {
      el.textContent = 'Storage: local JSON file. Data can be lost on Render restarts or redeploys. Configure DATABASE_URL for PostgreSQL before issuing production keys.';
    }
  } catch (_) {
    el.textContent = 'Storage status could not be verified. Check the server health endpoint before issuing production keys.';
  }
}
checkStorageMode();

function showMessage(text, type) {
  const el = $('message');
  el.textContent = text;
  el.className = 'message' + (type ? ' ' + type : '');
}
function dateText(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return new Intl.DateTimeFormat('en-GB', {year:'numeric',month:'short',day:'2-digit'}).format(date);
}
function keyStatus(item) {
  if (item.revoked) return 'revoked';
  if (!item.expiresAt || Number.isNaN(Date.parse(item.expiresAt)) || Date.now() >= Date.parse(item.expiresAt)) return 'expired';
  if (item.bound) return 'activated';
  return 'available';
}
function statusText(status) {
  return ({available:'Available',activated:'Activated',expired:'Expired',revoked:'Revoked'})[status] || status;
}
async function api(path, options) {
  const token = $('token').value.trim();
  if (!token) throw new Error('ADMIN_TOKEN ကို အရင်ထည့်ပါ။');
  const opts = options || {};
  const headers = Object.assign({}, opts.headers || {}, {'Authorization':'Bearer ' + token});
  if (opts.body) headers['Content-Type'] = 'application/json';
  const response = await fetch(path, Object.assign({}, opts, {headers, cache:'no-store'}));
  let data = {};
  try { data = await response.json(); } catch (_) {}
  if (!response.ok || !data.ok) throw new Error(data.error || 'Request failed (' + response.status + ')');
  return data;
}
function addCell(row, text, className) {
  const cell = document.createElement('td');
  cell.textContent = text;
  if (className) cell.className = className;
  row.appendChild(cell);
  return cell;
}
function renderKeys() {
  const query = $('search').value.trim().toLowerCase();
  const filter = $('filter').value;
  const counts = {available:0,activated:0,expired:0,revoked:0};
  allKeys.forEach(item => { counts[keyStatus(item)]++; });
  $('totalCount').textContent = String(allKeys.length);
  $('availableCount').textContent = String(counts.available);
  $('activatedCount').textContent = String(counts.activated);
  $('attentionCount').textContent = String(counts.expired + counts.revoked);

  const visible = allKeys.filter(item => {
    const status = keyStatus(item);
    return (!query || String(item.id || '').toLowerCase().includes(query)) &&
      (filter === 'all' || status === filter);
  }).sort((a,b) => Date.parse(b.createdAt || 0) - Date.parse(a.createdAt || 0));

  const tbody = $('keys');
  tbody.replaceChildren();
  if (!visible.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 5;
    cell.className = 'empty';
    cell.textContent = allKeys.length ? 'သတ်မှတ်ချက်နှင့် ကိုက်ညီသော Key မရှိပါ။' : 'Key မရှိသေးပါ။';
    row.appendChild(cell);
    tbody.appendChild(row);
    return;
  }

  visible.forEach(item => {
    const row = document.createElement('tr');
    const idCell = addCell(row, String(item.id || '').slice(0,8) + '…', 'keyid');
    idCell.title = String(item.id || '');
    const createdCell = addCell(row, dateText(item.createdAt), 'date');
    createdCell.title = item.createdAt || '';
    const expiryCell = addCell(row, dateText(item.expiresAt), 'date');
    expiryCell.title = item.expiresAt || '';
    const status = keyStatus(item);
    const statusCell = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = 'status ' + status;
    badge.textContent = statusText(status);
    statusCell.appendChild(badge);
    row.appendChild(statusCell);

    const actionCell = document.createElement('td');
    if (!item.revoked) {
      const revoke = document.createElement('button');
      revoke.type = 'button';
      revoke.className = 'danger small';
      revoke.textContent = 'Revoke';
      revoke.addEventListener('click', async () => {
        if (!confirm('ဤ Key ကို ပိတ်သိမ်းမှာ သေချာပါသလား။')) return;
        revoke.disabled = true;
        try {
          await api('/api/admin/keys/revoke', {method:'POST',body:JSON.stringify({id:item.id})});
          await loadKeys(false);
          showMessage('Key ကို ပိတ်သိမ်းပြီးပါပြီ။', 'success');
        } catch (error) {
          showMessage(error.message, 'error');
          revoke.disabled = false;
        }
      });
      actionCell.appendChild(revoke);
    } else {
      actionCell.textContent = '—';
      actionCell.style.color = '#7f94b3';
    }
    row.appendChild(actionCell);
    tbody.appendChild(row);
  });
}
async function loadKeys(showResult) {
  const buttons = [$('list'),$('refresh')];
  buttons.forEach(button => { button.disabled = true; });
  try {
    const data = await api('/api/admin/keys');
    allKeys = Array.isArray(data.keys) ? data.keys : [];
    renderKeys();
    if (showResult !== false) showMessage('Loaded ' + allKeys.length + ' key(s).', 'success');
  } catch (error) {
    showMessage(error.message, 'error');
  } finally {
    buttons.forEach(button => { button.disabled = false; });
  }
}
$('list').addEventListener('click', () => loadKeys(true));
$('refresh').addEventListener('click', () => loadKeys(true));
$('search').addEventListener('input', renderKeys);
$('filter').addEventListener('change', renderKeys);
$('clearFilters').addEventListener('click', () => {
  $('search').value = '';
  $('filter').value = 'all';
  renderKeys();
});
$('toggleToken').addEventListener('click', () => {
  const input = $('token');
  const show = input.type === 'password';
  input.type = show ? 'text' : 'password';
  $('toggleToken').textContent = show ? 'Hide' : 'Show';
});
$('issue').addEventListener('click', async () => {
  const days = Number($('days').value);
  if (!Number.isInteger(days) || days < 1 || days > 365) {
    showMessage('သက်တမ်းကို 1 မှ 365 ရက်အတွင်း ရွေးပါ။', 'error');
    return;
  }
  $('issue').disabled = true;
  try {
    const data = await api('/api/admin/keys', {method:'POST',body:JSON.stringify({days})});
    $('generatedKey').textContent = data.key;
    $('generated').hidden = false;
    await loadKeys(false);
    showMessage('Key အသစ်ထုတ်ပြီးပါပြီ။ Copy key ကိုနှိပ်ပြီး လုံခြုံသောနေရာတွင် သိမ်းပါ။', 'success');
  } catch (error) {
    showMessage(error.message, 'error');
  } finally {
    $('issue').disabled = false;
  }
});
$('copyKey').addEventListener('click', async () => {
  const key = $('generatedKey').textContent;
  try {
    await navigator.clipboard.writeText(key);
    showMessage('Key ကို clipboard သို့ ကူးယူပြီးပါပြီ။', 'success');
  } catch (_) {
    showMessage('Auto-copy မရပါ။ Key စာသားကို ဖိထားပြီး ကိုယ်တိုင် Copy လုပ်ပါ။', 'error');
  }
});
$('hideKey').addEventListener('click', () => {
  $('generatedKey').textContent = '';
  $('generated').hidden = true;
});
</script>
</body>
</html>`;

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    const route = url.pathname;
    if (route === '/health' && req.method === 'GET') return reply(res, 200, { ok: true, service: 'WRP activation backend', storage: pool ? 'postgres' : 'local-file' });
    if (route === '/admin' && req.method === 'GET') {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'Content-Security-Policy': "default-src 'none'; connect-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"
      });
      return res.end(adminPage);
    }
    if (limited(req)) return reply(res, 429, { ok: false, error: 'Too many requests. Try again in a minute.' });

    if (route.startsWith('/api/admin/')) {
      if (!authorized(req)) return reply(res, 401, { ok: false, error: 'Invalid admin token' });
      if (route === '/api/admin/keys' && req.method === 'GET') {
        const keys = await listKeys();
        return reply(res, 200, { ok: true, keys: keys.map(({ id, createdAt, expiresAt, revoked, deviceHash }) => ({
          id, createdAt, expiresAt, revoked, bound: !!deviceHash
        })) });
      }
      if (route === '/api/admin/keys' && req.method === 'POST') {
        const { days = 30 } = await parseBody(req);
        if (!Number.isInteger(days) || days < 1 || days > 365) return reply(res, 400, { ok: false, error: 'days must be 1-365' });
        const key = 'wrp_' + crypto.randomBytes(24).toString('base64url');
        const item = { id: crypto.randomUUID(), keyHash: hmac('key:' + key), createdAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + days * 86400000).toISOString(), revoked: false, deviceHash: null };
        await createKey(item);
        return reply(res, 201, { ok: true, key, id: item.id, expiresAt: item.expiresAt });
      }
      if (route === '/api/admin/keys/revoke' && req.method === 'POST') {
        const { id } = await parseBody(req);
        if (typeof id !== 'string' || !id) return reply(res, 400, { ok: false, error: 'Invalid key ID' });
        const revokedId = await revokeKey(id);
        if (!revokedId) return reply(res, 404, { ok: false, error: 'Key not found' });
        return reply(res, 200, { ok: true, id: revokedId, revoked: true });
      }
      return reply(res, 404, { ok: false, error: 'Admin route not found' });
    }

    if (route === '/api/activate' && req.method === 'POST') {
      const { key, deviceId } = await parseBody(req);
      if (typeof key !== 'string' || !/^wrp_[a-zA-Z0-9_-]{24,}$/.test(key) ||
        typeof deviceId !== 'string' || deviceId.length < 8 || deviceId.length > 128) {
        return reply(res, 400, { ok: false, error: 'Invalid activation request' });
      }
      const keyHash = hmac('key:' + key);
      let item = await findKeyByHash(keyHash);
      if (!item || item.revoked || Date.now() >= Date.parse(item.expiresAt))
        return reply(res, 403, { ok: false, error: 'Key invalid, revoked, or expired' });
      const deviceHash = hmac('device:' + deviceId);
      if (item.deviceHash && !constantEquals(item.deviceHash, deviceHash))
        return reply(res, 403, { ok: false, error: 'Key is bound to a different installation' });
      if (!item.deviceHash) {
        await bindDevice(item.id, deviceHash);
        item = await findKeyByHash(keyHash);
        if (!item || item.revoked || Date.now() >= Date.parse(item.expiresAt) ||
            !item.deviceHash || !constantEquals(item.deviceHash, deviceHash)) {
          return reply(res, 403, { ok: false, error: 'Key is invalid, revoked, expired, or already bound' });
        }
      }
      return reply(res, 200, { ok: true, expiresAt: item.expiresAt });
    }
    reply(res, 404, { ok: false, error: 'Not found' });
  } catch (e) {
    console.error('WRP request error:', e.message);
    if (!res.headersSent) reply(res, 400, { ok: false, error: 'Invalid request' });
  }
});
initializeStorage().then(() => {
  server.listen(PORT, HOST, () => console.log(`WRP Backend running on ${HOST}:${PORT}`));
}).catch(async error => {
  console.error('WRP storage initialization failed:', error.message);
  if (pool) await pool.end().catch(() => {});
  process.exit(1);
});
