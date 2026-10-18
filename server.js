
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
const STORE_FILE = path.resolve(process.env.STORE_FILE || './wrp-data/keys.json');

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) throw new Error('Invalid PORT');
if (ADMIN_TOKEN.length < 32 || KEY_PEPPER.length < 32 || ADMIN_TOKEN === KEY_PEPPER) {
  throw new Error('Create TWO DIFFERENT long secret values in Render environment: ADMIN_TOKEN and KEY_PEPPER (32+ characters each).');
}

fs.mkdirSync(path.dirname(STORE_FILE), { recursive: true });
if (!fs.existsSync(STORE_FILE)) {
  fs.writeFileSync(STORE_FILE, JSON.stringify({ keys: [] }, null, 2), { flag: 'wx', mode: 0o600 });
}
const state = JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
if (!Array.isArray(state.keys)) throw new Error('Invalid storage file');

function save() {
  const temp = STORE_FILE + '.' + process.pid + '.tmp';
  fs.writeFileSync(temp, JSON.stringify(state, null, 2), { mode: 0o600 });
  fs.renameSync(temp, STORE_FILE);
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
<html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width,initial-scale=1" />
<title>WRP Admin</title><style>
:root{font-family:Inter,system-ui,-apple-system,sans-serif;color:#edf3ff;background:#080f20;font-synthesis:none}
body{margin:0;padding:22px;background:radial-gradient(ellipse at top left,#18315c 0,transparent 48%),linear-gradient(135deg,#080f20,#101a30);min-height:100vh}.wrap{max-width:980px;margin:10px auto}h1{margin:0 0 8px;letter-spacing:-.04em;font-size:clamp(28px,4vw,40px)}
p{color:#566579;line-height:1.55}.panel{background:white;padding:20px;border-radius:14px;margin:18px 0;box-shadow:0 3px 18px #12244b10}
label{display:block;margin:12px 0 5px;font-weight:700}input{width:100%;box-sizing:border-box;padding:12px;font:inherit;border:1px solid #aab6c7;border-radius:8px}
button{background:#315ec1;color:#fff;border:0;border-radius:8px;padding:11px 15px;margin:10px 6px 0 0;font:inherit;cursor:pointer}
button.alt{background:#4b5563}button.danger{background:#9f2935}button:disabled{opacity:.6}
pre{padding:12px;background:#e9f1ff;white-space:pre-wrap;overflow-wrap:anywhere}table{width:100%;border-collapse:collapse;font-size:14px}td,th{padding:9px 4px;text-align:left;border-bottom:1px solid #e1e5ed}td{overflow-wrap:anywhere}
.notice{padding:9px;background:#fff4d0;border-radius:7px}#message{min-height:22px}
</style></head><body><main class="wrap"><h1>WRP · Admin</h1><p>Create, list and revoke activation keys. A key binds to the first app installation that activates it.</p>
<div class="panel"><label for="token">Admin token (from Render Environment)</label><input id="token" type="password" autocomplete="off" placeholder="Paste ADMIN_TOKEN" />
<p class="notice">Never paste this token in public chats or commit it to GitHub. This page does not save the token.</p><button id="list">Load keys</button></div>
<div class="panel"><h2>Issue key</h2><label for="days">Valid for (days: 1–365)</label><input id="days" type="number" min="1" max="365" value="30" /><button id="issue">Generate key</button>
<pre id="generated" hidden></pre><p>Copy the new key immediately. It is shown only when generated.</p></div>
<div class="panel"><h2>Issued keys</h2><div style="overflow-x:auto"><table><thead><tr><th>ID</th><th>Expiry</th><th>Status</th><th>Action</th></tr></thead><tbody id="keys"></tbody></table></div></div>
<p id="message" role="status"></p><p>Development starter: local-file data is lost on Render free-service restarts. Use persistent storage for real users.</p>
</main><script>
const $=id=>document.getElementById(id);const msg=s=>$('message').textContent=s;
async function api(path,opts={}){
 const token=$('token').value.trim();if(!token)throw Error('Enter your admin token first');
 const response=await fetch(path,{...opts,headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json'},cache:'no-store'});
 let obj={};try{obj=await response.json()}catch{}
 if(!response.ok||!obj.ok)throw Error(obj.error||'Request failed ('+response.status+')');return obj;
}
async function load(){
 try{const data=await api('/api/admin/keys'); const tbody=$('keys');tbody.replaceChildren();
 for(const item of data.keys){
 const tr=document.createElement('tr');
 for(const text of [item.id.slice(0,8)+'…',new Date(item.expiresAt).toLocaleDateString(),item.revoked?'Revoked':(item.bound?'Used':'Available')]){
 const td=document.createElement('td');td.textContent=text;tr.appendChild(td);}
 const td=document.createElement('td');if(!item.revoked){const btn=document.createElement('button');btn.textContent='Revoke';btn.className='danger';btn.onclick=async()=>{
 if(!confirm('Revoke this key?'))return;try{await api('/api/admin/keys/revoke',{method:'POST',body:JSON.stringify({id:item.id})});msg('Key revoked');load()}catch(e){msg(e.message)}};td.appendChild(btn)}
 tr.appendChild(td);tbody.appendChild(tr)}msg('Loaded '+data.keys.length+' keys.');
 }catch(e){msg(e.message)}
}
$('list').onclick=load;
$('issue').onclick=async()=>{
 try{const days=Number($('days').value);if(!Number.isInteger(days)||days<1||days>365)throw Error('Choose 1–365 days');
 const data=await api('/api/admin/keys',{method:'POST',body:JSON.stringify({days})});$('generated').hidden=false;$('generated').textContent=data.key;
 msg('New key issued. Copy the key now; it cannot be retrieved later.');await load();
 }catch(e){msg(e.message)}
};
</script></body></html>`;

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    const route = url.pathname;
    if (route === '/health' && req.method === 'GET') return reply(res, 200, { ok: true, service: 'WRP activation backend' });
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
        return reply(res, 200, { ok: true, keys: state.keys.map(({ id, createdAt, expiresAt, revoked, deviceHash }) => ({
          id, createdAt, expiresAt, revoked, bound: !!deviceHash
        })) });
      }
      if (route === '/api/admin/keys' && req.method === 'POST') {
        const { days = 30 } = await parseBody(req);
        if (!Number.isInteger(days) || days < 1 || days > 365) return reply(res, 400, { ok: false, error: 'days must be 1-365' });
        const key = 'wrp_' + crypto.randomBytes(24).toString('base64url');
        const item = { id: crypto.randomUUID(), keyHash: hmac('key:' + key), createdAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + days * 86400000).toISOString(), revoked: false, deviceHash: null };
        state.keys.push(item); save();
        return reply(res, 201, { ok: true, key, id: item.id, expiresAt: item.expiresAt });
      }
      if (route === '/api/admin/keys/revoke' && req.method === 'POST') {
        const { id } = await parseBody(req);
        const item = state.keys.find(k => k.id === id);
        if (!item) return reply(res, 404, { ok: false, error: 'Key not found' });
        item.revoked = true; save();
        return reply(res, 200, { ok: true, id: item.id, revoked: true });
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
      const item = state.keys.find(k => constantEquals(k.keyHash, keyHash));
      if (!item || item.revoked || Date.now() >= Date.parse(item.expiresAt))
        return reply(res, 403, { ok: false, error: 'Key invalid, revoked, or expired' });
      const deviceHash = hmac('device:' + deviceId);
      if (item.deviceHash && !constantEquals(item.deviceHash, deviceHash))
        return reply(res, 403, { ok: false, error: 'Key is bound to a different installation' });
      if (!item.deviceHash) { item.deviceHash = deviceHash; save(); }
      return reply(res, 200, { ok: true, expiresAt: item.expiresAt });
    }
    reply(res, 404, { ok: false, error: 'Not found' });
  } catch (e) {
    console.error('WRP request error:', e.message);
    if (!res.headersSent) reply(res, 400, { ok: false, error: 'Invalid request' });
  }
});
server.listen(PORT, HOST, () => console.log(`WRP Backend running on ${HOST}:${PORT}`));
