const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const dgram = require('dgram');

const PORT = process.env.PORT || 3456;
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'posts.json');
const isCloud = !!process.env.RAILWAY_ENVIRONMENT || !!process.env.RENDER || !!process.env.KOYEB;

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]', 'utf-8');

// ===== SSE clients =====
const sseClients = new Set();

function broadcastSSE(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) {
    try { res.write(payload); } catch { sseClients.delete(res); }
  }
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
    const post = {
      id: genId(),
      text: body.text || '',
      imageUrl: body.imageUrl || null,
      videoUrl: body.videoUrl || null,
      authorId: body.authorId || 'anonymous',
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

  // Static files
  if (req.method === 'GET') {
    const filePath = url.pathname === '/' ? '/index.html' : url.pathname;
    if (serveStatic(res, filePath)) return;
  }

  sendJSON(res, 404, { error: 'not found' });
});

// ===== Startup =====
async function start() {
  const localIPs = getLocalIPs();

  // Try UPnP port mapping for cross-network access
  if (!isCloud && localIPs.length > 0) {
    try {
      const primaryIP = localIPs[0].ip;
      const result = await upnpAddPortMapping(primaryIP, PORT, PORT, 'MiyuMessageBoard');
      if (result.success) {
        upnpMapped = true;
        externalIP = result.externalIP;
      }
    } catch { /* UPnP not available */ }
  }

  // On cloud platforms, external access is handled by the platform
  if (isCloud) {
    upnpMapped = true;
  }

  server.listen(PORT, '0.0.0.0', () => {
    const boxWidth = isCloud ? 48 : 48;
    console.log('');
    console.log('  ╔' + '═'.repeat(boxWidth) + '╗');
    console.log('  ║' + ' '.repeat(Math.floor((boxWidth - 22) / 2)) + '🐱  咪语留言板 已启动  🐱' + ' '.repeat(Math.ceil((boxWidth - 22) / 2)) + '║');
    console.log('  ╚' + '═'.repeat(boxWidth) + '╝');
    console.log('');

    if (isCloud) {
      console.log('  ☁️  云平台模式 — 已自动配置公网访问');
      console.log('');
      console.log('  🔗 你的固定公网地址：');
      const railUrl = process.env.RAILWAY_PUBLIC_DOMAIN;
      const renderUrl = process.env.RENDER_EXTERNAL_URL;
      if (railUrl) console.log(`     https://${railUrl}`);
      else if (renderUrl) console.log(`     ${renderUrl}`);
      else console.log(`     (由云平台自动分配)`);
      console.log('');
      console.log('  ✅ 任何网络下的设备都可以通过上方地址访问！');
    } else {
      console.log('  📡 局域网内其他设备可通过以下地址访问：');
      console.log('');
      for (const { name, ip } of localIPs) {
        console.log(`     http://${ip}:${PORT}  ← ${name}`);
      }
      console.log('');

      if (upnpMapped && externalIP) {
        console.log('  🌐 UPnP 端口映射成功！外部网络可访问：');
        console.log('');
        console.log(`     http://${externalIP}:${PORT}  (公网 IP)`);
        console.log('');
        console.log('  ⚠️  这是你家庭宽带的公网 IP，重启路由器后 IP 可能会变');
      }

      console.log('  💻 本机访问：http://localhost:' + PORT);
      console.log('  📁 数据目录：' + DATA_DIR);
      console.log('  🔄 实时同步：SSE');
    }

    console.log('');
    if (!isCloud && !upnpMapped) {
      console.log('  ────────────────────────────────────────────────');
      console.log('  🌍 跨不同 WiFi 使用（固定公网地址）：');
      console.log('');
      console.log('  方式1: 部署到 Railway（免费，推荐）');
      console.log('    ① 把项目上传到 GitHub');
      console.log('    ② 在 railway.app 导入仓库，一键部署');
      console.log('    ③ 获得固定域名：xxx.up.railway.app');
      console.log('');
      console.log('  方式2: 部署到 Render（免费）');
      console.log('    ① 把项目上传到 GitHub');
      console.log('    ② 在 render.com 新建 Web Service');
      console.log('    ③ 获得固定域名：xxx.onrender.com');
      console.log('');
      console.log('  方式3: 本机公网 IP（已尝试 UPnP 自动映射）');
      console.log('    如果没有显示公网地址，说明路由器不支持 UPnP');
      console.log('    可手动在路由器设置端口转发：' + PORT);
      console.log('  ────────────────────────────────────────────────');
    }
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
      console.log('  ✓ UPnP 端口映射已清除');
    }
  }
  process.exit(0);
});

start();
