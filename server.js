const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const dgram = require('dgram');
const { spawn } = require('child_process');

const PORT = process.env.PORT || 3456;
const TUNNEL_SUBDOMAIN = process.env.TUNNEL_SUBDOMAIN || 'miyu-' + require('crypto').createHash('sha256').update(os.hostname()).digest('hex').slice(0, 8);
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'posts.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const TOKENS_FILE = path.join(DATA_DIR, 'tokens.json');
const isCloud = !!process.env.RAILWAY_ENVIRONMENT || !!process.env.RENDER || !!process.env.KOYEB;

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]', 'utf-8');
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '{}', 'utf-8');
if (!fs.existsSync(TOKENS_FILE)) fs.writeFileSync(TOKENS_FILE, '{}', 'utf-8');

const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ===== Multipart parser =====
function parseMultipart(buffer, boundary) {
  const result = { fields: {}, files: [] };
  if (!boundary || !buffer) return result;

  const boundaryStr = '--' + boundary;
  const parts = [];
  let start = buffer.indexOf(boundaryStr);
  if (start === -1) return result;

  while (start !== -1) {
    const partStart = start + boundaryStr.length + 2; // skip \r\n
    if (partStart >= buffer.length) break;
    start = buffer.indexOf(boundaryStr, partStart);
    const partEnd = start === -1 ? buffer.length - 2 : start - 2; // -2 for \r\n
    if (partEnd > partStart) {
      parts.push(buffer.slice(partStart, partEnd));
    }
  }

  for (const part of parts) {
    const headerEnd = part.indexOf('\r\n\r\n');
    if (headerEnd === -1) continue;
    const headerStr = part.slice(0, headerEnd).toString('utf-8');
    const body = part.slice(headerEnd + 4);

    const nameMatch = headerStr.match(/name="([^"]+)"/);
    const filenameMatch = headerStr.match(/filename="([^"]+)"/);
    const name = nameMatch ? nameMatch[1] : null;
    if (!name) continue;

    if (filenameMatch) {
      const filename = filenameMatch[1];
      const ext = path.extname(filename).toLowerCase();
      const safeName = Date.now().toString(36) + Math.random().toString(36).slice(2, 6) + ext;
      const filePath = path.join(UPLOADS_DIR, safeName);
      fs.writeFileSync(filePath, body);
      const mime = ext === '.mp4' || ext === '.webm' ? 'video/' + ext.slice(1)
        : ext === '.jpg' || ext === '.jpeg' ? 'image/jpeg'
        : ext === '.png' ? 'image/png'
        : ext === '.gif' ? 'image/gif'
        : ext === '.svg' ? 'image/svg+xml'
        : 'application/octet-stream';
      result.files.push({
        fieldName: name,
        originalName: filename,
        savedName: safeName,
        url: '/uploads/' + safeName,
        size: body.length,
        mimeType: mime,
      });
    } else {
      result.fields[name] = body.toString('utf-8');
    }
  }

  return result;
}

function getRawBody(req, maxSize = 50 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > maxSize) { req.destroy(); reject(new Error('too large')); return; }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ===== SSE clients =====
const sseClients = new Set();

function broadcastSSE(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) {
    try { res.write(payload); } catch { sseClients.delete(res); }
  }
}

// ===== Auth helpers =====
function readUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf-8')); } catch { return {}; }
}
function writeUsers(users) {
  fs.writeFileSync(USERS_FILE + '.tmp', JSON.stringify(users, null, 2), 'utf-8');
  fs.renameSync(USERS_FILE + '.tmp', USERS_FILE);
}
function readTokens() {
  try { return JSON.parse(fs.readFileSync(TOKENS_FILE, 'utf-8')); } catch { return {}; }
}
function writeTokens(tokens) {
  fs.writeFileSync(TOKENS_FILE + '.tmp', JSON.stringify(tokens, null, 2), 'utf-8');
  fs.renameSync(TOKENS_FILE + '.tmp', TOKENS_FILE);
}
function hashPassword(pwd) {
  return require('crypto').createHash('sha256').update('miyu_salt_' + pwd).digest('hex');
}
function getAuthUser(req) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7);
  const tokens = readTokens();
  return tokens[token] || null;
}
function genToken() {
  return require('crypto').randomBytes(24).toString('hex');
}

// ===== MIME types =====
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
};

// ===== Helpers =====
function readPosts() {
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf-8');
    return JSON.parse(raw);
  } catch { return []; }
}

function writePosts(posts) {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(posts, null, 2), 'utf-8');
  fs.renameSync(tmp, DATA_FILE);
}

function genId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

function sendJSON(res, code, data) {
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  });
  res.end(JSON.stringify(data));
}

function serveStatic(res, filePath) {
  try {
    const fullPath = path.join(__dirname, filePath);
    if (!fullPath.startsWith(__dirname)) { res.writeHead(403); res.end('Forbidden'); return; }
    if (!fs.existsSync(fullPath) || fs.statSync(fullPath).isDirectory()) return false;
    const ext = path.extname(fullPath).toLowerCase();
    const contentType = MIME[ext] || 'application/octet-stream';
    const data = fs.readFileSync(fullPath);
    res.writeHead(200, { 'Content-Type': contentType, 'Cache-Control': 'public, max-age=3600' });
    res.end(data);
    return true;
  } catch { return false; }
}

function getBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      try { resolve(JSON.parse(body)); } catch { resolve({}); }
    });
  });
}

// ===== Network / IP detection =====
function getLocalIPs() {
  const interfaces = os.networkInterfaces();
  const ips = [];
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        ips.push({ name, ip: iface.address });
      }
    }
  }
  return ips;
}

function httpGet(url, timeout = 4000) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { timeout }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}

// ===== UPnP IGD Port Mapping =====
let upnpMapped = false;
let externalIP = null;

function upnpDiscover(timeout = 3000) {
  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    const devices = [];
    const ssdpAddr = '239.255.255.250';
    const ssdpPort = 1900;
    const st = 'urn:schemas-upnp-org:device:InternetGatewayDevice:1';

    const msg = [
      'M-SEARCH * HTTP/1.1',
      `HOST: ${ssdpAddr}:${ssdpPort}`,
      'MAN: "ssdp:discover"',
      `MX: 2`,
      `ST: ${st}`,
      '', '',
    ].join('\r\n');

    socket.on('message', (data) => {
      const text = data.toString();
      if (text.includes(st) || text.includes('InternetGatewayDevice')) {
        const locMatch = text.match(/LOCATION:\s*(.+)/i);
        if (locMatch) devices.push(locMatch[1].trim());
      }
    });

    socket.on('error', () => { try { socket.close(); } catch {} });

    socket.bind(() => {
      socket.setBroadcast(true);
      socket.send(msg, ssdpPort, ssdpAddr, (err) => {
        if (err) { try { socket.close(); } catch {} }
      });
      setTimeout(() => {
        try { socket.close(); } catch {}
        resolve(devices);
      }, timeout);
    });
  });
}

async function upnpGetControlURL(locationUrl) {
  try {
    const xml = await httpGet(locationUrl, 3000);
    // Parse WANIPConnection service
    const svcMatch = xml.match(/<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1<\/serviceType>[\s\S]*?<controlURL>(.+?)<\/controlURL>/)
      || xml.match(/<serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1<\/serviceType>[\s\S]*?<controlURL>(.+?)<\/controlURL>/);
    if (!svcMatch) return null;
    const controlPath = svcMatch[1];
    const url = new URL(locationUrl);
    return `${url.protocol}//${url.host}${controlPath}`;
  } catch { return null; }
}

function upnpSoapRequest(action, body, controlURL) {
  return new Promise((resolve, reject) => {
    const url = new URL(controlURL);
    const soap = [
      '<?xml version="1.0"?>',
      '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">',
      '<s:Body>',
      body,
      '</s:Body>',
      '</s:Envelope>',
    ].join('');

    const options = {
      hostname: url.hostname,
      port: url.port || 80,
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': 'text/xml; charset="utf-8"',
        SOAPAction: `"${action}"`,
        'Content-Length': Buffer.byteLength(soap),
      },
      timeout: 4000,
    };

    const mod = url.protocol === 'https:' ? https : http;
    const req = mod.request(options, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.write(soap);
    req.end();
  });
}

async function upnpGetExternalIP(controlURL) {
  try {
    const body = '<u:GetExternalIPAddress xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"></u:GetExternalIPAddress>';
    const result = await upnpSoapRequest('urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress', body, controlURL);
    const ipMatch = result.match(/<NewExternalIPAddress>(.+?)<\/NewExternalIPAddress>/);
    return ipMatch ? ipMatch[1] : null;
  } catch { return null; }
}

async function upnpAddPortMapping(internalIP, internalPort, externalPort, desc) {
  const devices = await upnpDiscover(3000);
  for (const loc of devices) {
    const controlURL = await upnpGetControlURL(loc);
    if (!controlURL) continue;

    const body = [
      '<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">',
      `<NewRemoteHost></NewRemoteHost>`,
      `<NewExternalPort>${externalPort}</NewExternalPort>`,
      `<NewProtocol>TCP</NewProtocol>`,
      `<NewInternalPort>${internalPort}</NewInternalPort>`,
      `<NewInternalClient>${internalIP}</NewInternalClient>`,
      `<NewEnabled>1</NewEnabled>`,
      `<NewPortMappingDescription>${desc}</NewPortMappingDescription>`,
      `<NewLeaseDuration>0</NewLeaseDuration>`,
      '</u:AddPortMapping>',
    ].join('');
    try {
      await upnpSoapRequest('urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping', body, controlURL);
      const extIP = await upnpGetExternalIP(controlURL);
      return { success: true, externalIP: extIP, externalPort };
    } catch { continue; }
  }
  return { success: false };
}

async function upnpRemovePortMapping(internalPort, externalPort) {
  const devices = await upnpDiscover(2000);
  for (const loc of devices) {
    const controlURL = await upnpGetControlURL(loc);
    if (!controlURL) continue;
    const body = [
      '<u:DeletePortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">',
      `<NewRemoteHost></NewRemoteHost>`,
      `<NewExternalPort>${externalPort}</NewExternalPort>`,
      `<NewProtocol>TCP</NewProtocol>`,
      '</u:DeletePortMapping>',
    ].join('');
    try { await upnpSoapRequest('urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping', body, controlURL); } catch {}
  }
}

// ===== Router =====
const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    res.end();
    return;
  }

  const url = new URL(req.url, `http://localhost:${PORT}`);
  const segments = url.pathname.split('/').filter(Boolean);

  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
    });
    return res.end();
  }

  // POST /api/auth/register
  if (req.method === 'POST' && url.pathname === '/api/auth/register') {
    const { username, password } = await getBody(req);
    if (!username || !password) return sendJSON(res, 400, { error: '用户名和密码不能为空' });
    if (username.length < 2 || username.length > 20) return sendJSON(res, 400, { error: '用户名2-20个字符' });
    if (password.length < 4) return sendJSON(res, 400, { error: '密码至少4位' });
    const users = readUsers();
    if (users[username]) return sendJSON(res, 409, { error: '用户名已被注册' });
    const userId = 'user_' + genId();
    users[username] = { passwordHash: hashPassword(password), userId, createdAt: Date.now() };
    writeUsers(users);
    const token = genToken();
    const tokens = readTokens();
    tokens[token] = { userId, username, createdAt: Date.now() };
    writeTokens(tokens);
    return sendJSON(res, 201, { token, userId, username, isNew: true });
  }

  // POST /api/auth/login
  if (req.method === 'POST' && url.pathname === '/api/auth/login') {
    const { username, password } = await getBody(req);
    if (!username || !password) return sendJSON(res, 400, { error: '用户名和密码不能为空' });
    const users = readUsers();
    const user = users[username];
    if (!user || user.passwordHash !== hashPassword(password)) {
      return sendJSON(res, 401, { error: '用户名或密码错误' });
    }
    const tokens = readTokens();
    // Remove old tokens for this user
    for (const [k, v] of Object.entries(tokens)) {
      if (v.userId === user.userId || v.username === username) delete tokens[k];
    }
    const token = genToken();
    tokens[token] = { userId: user.userId, username, createdAt: Date.now() };
    writeTokens(tokens);
    return sendJSON(res, 200, { token, userId: user.userId, username });
  }

  // GET /api/auth/me
  if (req.method === 'GET' && url.pathname === '/api/auth/me') {
    const auth = getAuthUser(req);
    if (!auth) return sendJSON(res, 401, { error: '未登录' });
    return sendJSON(res, 200, auth);
  }

  // Health check
  if (req.method === 'GET' && url.pathname === '/health') {
    return sendJSON(res, 200, { status: 'ok', uptime: process.uptime(), upnp: upnpMapped, externalIP });
  }

  // GET /api/ip
  if (req.method === 'GET' && url.pathname === '/api/ip') {
    return sendJSON(res, 200, { ips: getLocalIPs(), port: PORT, externalIP, upnpMapped });
  }

  // GET /api/events - SSE stream
  if (req.method === 'GET' && url.pathname === '/api/events') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });
    res.write('event: connected\ndata: {}\n\n');
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
    return;
  }

  // GET /api/posts
  if (req.method === 'GET' && url.pathname === '/api/posts' && segments.length === 2) {
    let posts = readPosts();
    const search = url.searchParams.get('search');
    if (search) {
      const q = search.toLowerCase();
      posts = posts.filter((p) => p.text.toLowerCase().includes(q));
    }
    return sendJSON(res, 200, posts);
  }

  // GET /api/posts/mine
  if (req.method === 'GET' && url.pathname === '/api/posts/mine' && segments.length === 3) {
    const userId = url.searchParams.get('userId');
    if (!userId) return sendJSON(res, 400, { error: 'userId required' });
    const posts = readPosts();
    return sendJSON(res, 200, {
      created: posts.filter((p) => p.authorId === userId),
      liked: posts.filter((p) => p.likes.includes(userId)),
      bookmarked: posts.filter((p) => p.bookmarks.includes(userId)),
    });
  }

  // POST /api/posts
  if (req.method === 'POST' && url.pathname === '/api/posts' && segments.length === 2) {
    const body = await getBody(req);
    if (!body.text && !body.imageUrl && !body.videoUrl) {
      return sendJSON(res, 400, { error: 'empty content' });
    }
    const auth = getAuthUser(req);
    const post = {
      id: genId(),
      text: body.text || '',
      imageUrl: body.imageUrl || null,
      videoUrl: body.videoUrl || null,
      authorId: auth ? auth.userId : (body.authorId || 'anonymous'),
      authorName: body.authorName || '小猫咪',
      authorAvatar: body.authorAvatar || '🐱',
      timestamp: Date.now(),
      likes: [],
      bookmarks: [],
      comments: [],
    };
    const posts = readPosts();
    posts.unshift(post);
    writePosts(posts);
    broadcastSSE('post_created', { id: post.id });
    return sendJSON(res, 201, post);
  }

  // POST /api/posts/:id/like
  if (req.method === 'POST' && segments[0] === 'api' && segments[1] === 'posts' && segments[3] === 'like') {
    const postId = segments[2];
    const { userId } = await getBody(req);
    if (!userId) return sendJSON(res, 400, { error: 'userId required' });
    const posts = readPosts();
    const idx = posts.findIndex((p) => p.id === postId);
    if (idx === -1) return sendJSON(res, 404, { error: 'not found' });
    const p = posts[idx];
    const likeIdx = p.likes.indexOf(userId);
    if (likeIdx > -1) p.likes.splice(likeIdx, 1);
    else p.likes.push(userId);
    writePosts(posts);
    broadcastSSE('post_updated', { id: postId });
    return sendJSON(res, 200, p);
  }

  // POST /api/posts/:id/bookmark
  if (req.method === 'POST' && segments[0] === 'api' && segments[1] === 'posts' && segments[3] === 'bookmark') {
    const postId = segments[2];
    const { userId } = await getBody(req);
    if (!userId) return sendJSON(res, 400, { error: 'userId required' });
    const posts = readPosts();
    const idx = posts.findIndex((p) => p.id === postId);
    if (idx === -1) return sendJSON(res, 404, { error: 'not found' });
    const p = posts[idx];
    const bmIdx = p.bookmarks.indexOf(userId);
    if (bmIdx > -1) p.bookmarks.splice(bmIdx, 1);
    else p.bookmarks.push(userId);
    writePosts(posts);
    broadcastSSE('post_updated', { id: postId });
    return sendJSON(res, 200, p);
  }

  // DELETE /api/posts/:id
  if (req.method === 'DELETE' && segments[0] === 'api' && segments[1] === 'posts' && segments.length === 3) {
    const postId = segments[2];
    const auth = getAuthUser(req);
    if (!auth) return sendJSON(res, 401, { error: '请先登录' });
    const posts = readPosts();
    const idx = posts.findIndex((p) => p.id === postId);
    if (idx === -1) return sendJSON(res, 404, { error: 'not found' });
    if (posts[idx].authorId !== auth.userId) return sendJSON(res, 403, { error: '只能删除自己的留言' });
    const post = posts[idx];
    // Delete associated files
    if (post.imageUrl) {
      const imgPath = path.join(UPLOADS_DIR, path.basename(post.imageUrl));
      try { if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath); } catch {}
    }
    if (post.videoUrl) {
      const vidPath = path.join(UPLOADS_DIR, path.basename(post.videoUrl));
      try { if (fs.existsSync(vidPath)) fs.unlinkSync(vidPath); } catch {}
    }
    posts.splice(idx, 1);
    writePosts(posts);
    broadcastSSE('post_deleted', { id: postId });
    return sendJSON(res, 200, { deleted: true });
  }

  // POST /api/posts/:id/comments
  if (req.method === 'POST' && segments[0] === 'api' && segments[1] === 'posts' && segments[3] === 'comments') {
    const postId = segments[2];
    const body = await getBody(req);
    if (!body.text) return sendJSON(res, 400, { error: 'text required' });
    const posts = readPosts();
    const idx = posts.findIndex((p) => p.id === postId);
    if (idx === -1) return sendJSON(res, 404, { error: 'not found' });
    posts[idx].comments.push({
      id: genId(), text: body.text,
      authorId: body.authorId || 'anonymous',
      authorName: body.authorName || '小猫咪',
      authorAvatar: body.authorAvatar || '🐱',
      timestamp: Date.now(), replies: [],
    });
    writePosts(posts);
    broadcastSSE('post_updated', { id: postId });
    return sendJSON(res, 201, posts[idx].comments[posts[idx].comments.length - 1]);
  }

  // POST /api/posts/:id/comments/:commentId/replies
  if (req.method === 'POST' && segments[0] === 'api' && segments[1] === 'posts' &&
      segments[3] === 'comments' && segments[5] === 'replies') {
    const postId = segments[2];
    const commentId = segments[4];
    const body = await getBody(req);
    if (!body.text) return sendJSON(res, 400, { error: 'text required' });
    const posts = readPosts();
    const postIdx = posts.findIndex((p) => p.id === postId);
    if (postIdx === -1) return sendJSON(res, 404, { error: 'post not found' });
    const commentIdx = posts[postIdx].comments.findIndex((c) => c.id === commentId);
    if (commentIdx === -1) return sendJSON(res, 404, { error: 'comment not found' });
    posts[postIdx].comments[commentIdx].replies.push({
      id: genId(), text: body.text,
      authorId: body.authorId || 'anonymous',
      authorName: body.authorName || '小猫咪',
      authorAvatar: body.authorAvatar || '🐱',
      timestamp: Date.now(),
    });
    writePosts(posts);
    broadcastSSE('post_updated', { id: postId });
    return sendJSON(res, 201, posts[postIdx].comments[commentIdx].replies.slice(-1)[0]);
  }

  // POST /api/upload - upload files (multipart)
  if (req.method === 'POST' && url.pathname === '/api/upload') {
    const contentType = req.headers['content-type'] || '';
    const boundaryMatch = contentType.match(/boundary=(.+)$/);
    if (!boundaryMatch) return sendJSON(res, 400, { error: 'multipart required' });
    try {
      const buffer = await getRawBody(req);
      const parsed = parseMultipart(buffer, boundaryMatch[1].replace(/^"|"$/g, ''));
      if (parsed.files.length === 0) return sendJSON(res, 400, { error: 'no file' });
      return sendJSON(res, 200, { files: parsed.files });
    } catch (e) {
      return sendJSON(res, 400, { error: e.message === 'too large' ? 'file too large (max 50MB)' : 'upload failed' });
    }
  }

  // Static files
  if (req.method === 'GET') {
    // Serve uploaded files from data/uploads/
    if (url.pathname.startsWith('/uploads/')) {
      const uploadPath = path.join(UPLOADS_DIR, path.basename(url.pathname));
      try {
        if (fs.existsSync(uploadPath) && !fs.statSync(uploadPath).isDirectory()) {
          const ext = path.extname(uploadPath).toLowerCase();
          const contentType = MIME[ext] || 'application/octet-stream';
          const data = fs.readFileSync(uploadPath);
          res.writeHead(200, { 'Content-Type': contentType, 'Cache-Control': 'public, max-age=86400' });
          res.end(data);
          return;
        }
      } catch {}
    }
    const filePath = url.pathname === '/' ? '/index.html' : url.pathname;
    if (serveStatic(res, filePath)) return;
  }

  sendJSON(res, 404, { error: 'not found' });
});

// ===== Public Tunnel (Cloudflare Tunnel via cloudflared) =====
let tunnelPublicUrl = null;
let tunnelProcess = null;
let tunnelRestartTimer = null;

function startTunnel() {
  if (tunnelProcess) {
    try { tunnelProcess.kill(); } catch {}
    tunnelProcess = null;
  }

  console.log('  🔗 正在建立 Cloudflare 隧道...');

  const cfPath = path.join(__dirname, 'cloudflared.exe');
  const proc = spawn(cfPath, [
    'tunnel', '--url', `http://localhost:${PORT}`,
    '--no-autoupdate'
  ], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  tunnelProcess = proc;

  let urlFound = false;

  const parseUrl = (text) => {
    if (urlFound) return;
    const match = text.match(/https:\/\/[^\s]+\.trycloudflare\.com/);
    if (match) {
      urlFound = true;
      tunnelPublicUrl = match[0];
      console.log('  ✅ Cloudflare 隧道已建立');
      console.log('  🌍 公网地址：' + match[0]);
      console.log('');
      updateGitHubRedirect(match[0]);
    }
  };

  proc.stdout.on('data', (data) => { parseUrl(data.toString()); });
  proc.stderr.on('data', (data) => { parseUrl(data.toString()); });

  proc.on('close', () => {
    if (tunnelProcess === proc) tunnelProcess = null;
    if (!tunnelRestartTimer) {
      tunnelRestartTimer = setTimeout(() => {
        tunnelRestartTimer = null;
        startTunnel();
      }, 5000);
    }
  });

  proc.on('error', () => {
    if (tunnelProcess === proc) tunnelProcess = null;
    if (!tunnelRestartTimer) {
      tunnelRestartTimer = setTimeout(() => {
        tunnelRestartTimer = null;
        startTunnel();
      }, 5000);
    }
  });
}

function getTunnelUrl() {
  return tunnelPublicUrl;
}

// Update GitHub Pages redirect when tunnel URL changes
function updateGitHubRedirect(newUrl) {
  const content = Buffer.from('const TUNNEL_URL = "' + newUrl + '";\n').toString('base64');

  // Get current file SHA
  const getSha = spawn('gh', [
    'api', 'repos/Zuier1024/miyu-message-board/contents/docs/redirect.js',
    '--jq', '.sha'
  ]);
  let sha = '';
  getSha.stdout.on('data', d => sha += d.toString());
  getSha.on('close', () => {
    sha = sha.trim();
    if (!sha) return;
    const args = [
      'api', 'repos/Zuier1024/miyu-message-board/contents/docs/redirect.js',
      '-X', 'PUT',
      '-f', 'message=Update tunnel URL',
      '-f', 'content=' + content,
      '-f', 'sha=' + sha
    ];
    spawn('gh', args, { stdio: 'ignore' });
  });
  getSha.stderr.on('data', () => {});
}

// ===== Startup =====
async function start() {
  const localIPs = getLocalIPs();

  // Try UPnP port mapping
  if (!isCloud && localIPs.length > 0) {
    try {
      const result = await upnpAddPortMapping(localIPs[0].ip, PORT, PORT, 'MiyuMessageBoard');
      if (result.success) { upnpMapped = true; externalIP = result.externalIP; }
    } catch {}
  }

  if (isCloud) upnpMapped = true;

  // Start Cloudflare Tunnel for cross-WiFi
  if (!isCloud) {
    startTunnel();
    await new Promise(r => setTimeout(r, 3000));
  }

  server.listen(PORT, '0.0.0.0', () => {
    const boxWidth = 52;
    console.log('');
    console.log('  ╔' + '═'.repeat(boxWidth) + '╗');
    console.log('  ║' + ' '.repeat(Math.floor((boxWidth - 22) / 2)) + '🐱  咪语留言板 已启动  🐱' + ' '.repeat(Math.ceil((boxWidth - 22) / 2)) + '║');
    console.log('  ╚' + '═'.repeat(boxWidth) + '╝');
    console.log('');

    if (tunnelPublicUrl) {
      console.log('  🌍  公网固定地址（任何 WiFi 都能访问）：');
      console.log(`       ${tunnelPublicUrl}`);
      console.log('');
    }

    console.log('  📡 局域网地址：');
    for (const { name, ip } of localIPs) {
      console.log(`     http://${ip}:${PORT}  (${name})`);
    }
    console.log('  💻 本机访问：http://localhost:' + PORT);
    if (upnpMapped && externalIP) console.log(`  🌐 UPnP 公网：http://${externalIP}:${PORT}`);
    console.log('');
    console.log('  📁 数据目录：' + DATA_DIR);
    console.log('  🔄 实时同步：SSE  |  ☁️  Cloudflare 隧道自动重连');
    console.log('');
  });
}

// Cleanup on exit
process.on('SIGINT', async () => {
  console.log('\n🐾 咪语正在关闭...');
  if (upnpMapped && !isCloud) {
    const ips = getLocalIPs();
    if (ips.length > 0) {
      await upnpRemovePortMapping(ips[0].ip, PORT);
    }
  }
  process.exit(0);
});

start();
