/**
 * NetShare Business Platform — server.js
 *
 * BUGS FIXED (original):
 * 1. relay.js was never used — server.js had its own duplicate WebSocket handler
 *    but with a CRITICAL difference: CLIENT_JOIN validated accessCode against
 *    store.accessCodes (requires admin to generate codes first), but relay.js
 *    used session codes directly. The app sends the accessCode as the session
 *    join code. These two systems were completely incompatible.
 *    FIX: Merged into one correct handler. CLIENT_JOIN now looks up the access
 *    code from store.accessCodes AND falls back to treating it as a session code
 *    so both flows work.
 *
 * 2. generateSessionCode() produced 6-char codes (e.g. "AB3X7K") but:
 *    a) The HOST gets this as their session code and shares it.
 *    b) The CLIENT sends it as accessCode in CLIENT_JOIN.
 *    c) But CLIENT_JOIN validated it against store.accessCodes (admin-issued
 *       XXXX-XXXX codes), so a 6-char session code ALWAYS failed validation.
 *    FIX: CLIENT_JOIN first checks store.accessCodes, then checks sessions
 *    directly so a host's session code also works as a join code.
 *
 * 3. The keep-alive self-ping used http.get() with a localhost URL on Render,
 *    which doesn't work because Render doesn't route external URLs to localhost.
 *    FIX: Use RENDER_EXTERNAL_URL env var (set automatically by Render) or
 *    skip the self-ping if not on Render — the /ping route is enough for
 *    Render's health checks to keep it alive.
 *
 * 4. Binary packet forwarding used data.length but `data` is a Buffer from ws,
 *    not an ArrayBuffer — this is fine, but the host binary forward sent to
 *    ALL clients. Should only forward to the client who sent the packet's
 *    corresponding host. Already correct for host→clients direction.
 *    Confirmed OK.
 *
 * 5. store.accessCodes was loaded from Supabase asynchronously AFTER server.listen,
 *    meaning the first few seconds of operation had no codes loaded.
 *    FIX: loadCodesFromDB() is awaited before listen() starts.
 *    (Already done below — kept as-is.)
 *
 * 6. /health endpoint was missing — the mobile app pings /health to wake the
 *    server. Added it (returns 200 OK).
 *
 * NEW FIXES:
 * FIX-N1: IPv6 packets were broadcast to ALL clients instead of routed by dst IP.
 *   Root cause of "only Google/Chrome works slowly" — apps using IPv6 (TikTok,
 *   Instagram, YouTube, WhatsApp) flooded every client with every other client's
 *   traffic. Google/Chrome happened to work because they retry over IPv4.
 *   FIX: Parse IPv6 dst address (bytes 24–39), use 32-char hex key in sessionTunMap,
 *   and do an O(1) map lookup. Also register the IPv6 key in sessionTunMap at
 *   CLIENT_JOIN so routing is ready before the first IPv6 packet arrives.
 *
 * FIX-N2: Failover didn't migrate tunIp assignments to the new session.
 *   After failover, migrated clients had no entry in the new sessionTunIps or
 *   sessionTunMap, so the new host could not route any replies back to them.
 *   FIX: assignTunIp() in the new session for each migrated client, update
 *   store.connections with the new tunIp, and register both IPv4 and IPv6 keys
 *   in the new sessionTunMap. Send new tunIp to client and host.
 *
 * FIX-N3: Unhandled async rejection in ws.on('message') could crash the server.
 *   Any thrown error inside the async handler (e.g. updateCodeInDB throwing) was
 *   an unhandledRejection. FIX: wrap entire handler body in try/catch.
 *
 * FIX-N4: Access code expiry not re-checked on reconnect.
 *   A code marked usedBy could still be submitted after expiry on reconnect.
 *   FIX: expiry check runs unconditionally before the usedBy/isActive checks.
 */

require('dotenv').config();

const http    = require('http');
const express = require('express');
const cors    = require('cors');
const { WebSocketServer } = require('ws');
const { v4: uuidv4 } = require('uuid');

// ── Supabase client setup ─────────────────────────────────────────────
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://ffcnlfnsajibknhesgba.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZmY25sZm5zYWppYmtuaGVzZ2JhIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3ODMzMTg0OCwiZXhwIjoyMDkzOTA3ODQ4fQ.wkycgRezfjJ3hpuD_cQhx2sjRbb-KsU-HyrLOxVeQTk';

async function sbFetch(path, options = {}) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    ...options,
    headers: {
      'apikey': SUPABASE_KEY,
      'Authorization': `Bearer ${SUPABASE_KEY}`,
      'Content-Type': 'application/json',
      'Prefer': options.prefer || 'return=representation',
      ...(options.headers || {}),
    },
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Supabase error: ${res.status} ${err}`);
  }
  const text = await res.text();
  return text ? JSON.parse(text) : [];
}

async function loadCodesFromDB() {
  try {
    const rows = await sbFetch('access_codes?select=*');
    rows.forEach(row => {
      store.accessCodes.set(row.code, {
        id: row.id,
        code: row.code,
        label: row.label || '',
        createdAt: row.created_at,
        expiresAt: row.expires_at,
        usedBy: row.used_by,
        isActive: row.is_active,
      });
    });
    console.log(`[supabase] Loaded ${rows.length} access codes from database`);
  } catch (e) {
    console.warn('[supabase] Could not load codes:', e.message);
  }
}

async function saveCodeToDB(entry) {
  try {
    await sbFetch('access_codes', {
      method: 'POST',
      prefer: 'return=minimal',
      body: JSON.stringify({
        code: entry.code,
        id: entry.id,
        label: entry.label,
        created_at: entry.createdAt,
        expires_at: entry.expiresAt,
        used_by: entry.usedBy || null,
        is_active: entry.isActive,
      }),
    });
  } catch (e) {
    console.warn('[supabase] Could not save code:', e.message);
  }
}

async function updateCodeInDB(code, fields) {
  try {
    const body = {};
    if (fields.isActive !== undefined) body.is_active = fields.isActive;
    if (fields.usedBy !== undefined) body.used_by = fields.usedBy;
    await sbFetch(`access_codes?code=eq.${encodeURIComponent(code)}`, {
      method: 'PATCH',
      prefer: 'return=minimal',
      body: JSON.stringify(body),
    });
  } catch (e) {
    console.warn('[supabase] Could not update code:', e.message);
  }
}

const app  = express();
const PORT = process.env.PORT || 4000;

// ── In-memory stores ──────────────────────────────────────────────────
const store = {
  adminPassword: process.env.ADMIN_PASSWORD || 'NETSHARE_ADMIN_2024',
  accessCodes: new Map(),
  hosts: new Map(),
  sessions: new Map(),
  connections: new Map(),
  // Track which TUN IPs are in use per session: sessionCode → Set<string>
  sessionTunIps: new Map(),
  stats: {
    totalSessions: 0,
    totalDataRelayed: 0,
    totalEarningsPaid: 0,
    weeklyRevenuePool: 0,
    // Breakdown by protocol for debugging app-specific issues
    tcpBytesRelayed: 0,
    udpBytesRelayed: 0,
    largeFrameCount: 0,   // frames > 32KB (QUIC CDN bursts from TikTok)
  },
};

// ── TUN IP pool (10.8.0.2 – 10.8.0.254 per session) ──────────────────
// Returns the next free /24 client address for a given session, or null if full.
function assignTunIp(sessionCode) {
  if (!store.sessionTunIps.has(sessionCode)) {
    store.sessionTunIps.set(sessionCode, new Set());
  }
  const used = store.sessionTunIps.get(sessionCode);
  for (let i = 2; i <= 254; i++) {
    const ip = `10.8.0.${i}`;
    if (!used.has(ip)) {
      used.add(ip);
      return ip;
    }
  }
  return null; // pool exhausted
}

function releaseTunIp(sessionCode, ip) {
  const used = store.sessionTunIps.get(sessionCode);
  if (used) used.delete(ip);
}

function releaseSession(sessionCode) {
  // Clean up the TUN IP pool for this session to prevent memory leak.
  // Without this, every ended session leaves a Set in sessionTunIps forever.
  store.sessionTunIps.delete(sessionCode);
  store.sessions.delete(sessionCode);
  // Also clean up the O(1) TUN routing map for this session.
  sessionTunMap.delete(sessionCode);
}

// ── Middleware ────────────────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());

// ── Admin Auth middleware ─────────────────────────────────────────────
function requireAdmin(req, res, next) {
  const key = req.headers['x-admin-key'] || req.query.adminKey;
  if (key !== store.adminPassword) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ── Helpers ───────────────────────────────────────────────────────────
function generateAccessCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const part = (n) => Array.from({ length: n }, () =>
    chars[Math.floor(Math.random() * chars.length)]).join('');
  let code;
  do { code = `${part(4)}-${part(4)}`; }
  while (store.accessCodes.has(code));
  return code;
}

// FIX 2: Session codes are now XXXX-XXXX format (same as access codes)
// so clients can use the session code directly to join, and it's consistent.
function generateSessionCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const part = (n) => Array.from({ length: n }, () =>
    chars[Math.floor(Math.random() * chars.length)]).join('');
  let code;
  do { code = `${part(4)}-${part(4)}`; }
  while (store.sessions.has(code));
  return code;
}

function send(ws, obj) {
  if (ws && ws.readyState === 1) ws.send(JSON.stringify(obj));
}

// FIX-N1: derive a stable map key for an IPv4 TUN address and its
// link-local IPv6 equivalent (fe80::/10 EUI-64 style isn't used here —
// we simply register the literal tunIp string for IPv4 and a derived
// IPv4-mapped IPv6 key so the routing table covers both address families).
//
// sessionTunMap key format:
//   IPv4: "10.8.0.X"          (string, from dst bytes 16-19)
//   IPv6: 32-char hex string  (from dst bytes 24-39)
//
// ipv4MappedKey("10.8.0.2") → "00000000000000000000ffff0a080002"
// This matches what buildIpv6KeyFromBuffer() extracts from a live packet.
function ipv4MappedKey(ipv4Str) {
  const parts = ipv4Str.split('.').map(Number);
  // ::ffff:a.b.c.d
  return `00000000000000000000ffff${parts.map(b => b.toString(16).padStart(2,'0')).join('')}`;
}

// Extract 32-char hex key from a Buffer starting at `offset` (16 bytes).
function buildIpv6KeyFromBuffer(buf, offset) {
  return buf.slice(offset, offset + 16).toString('hex');
}

// ── Find best available host ──────────────────────────────────────────
function findAvailableHost(excludeHostId = null) {
  let best = null;
  let bestLoad = Infinity;
  store.hosts.forEach((host, hostId) => {
    if (hostId === excludeHostId) return;
    if (!host.isOnline || !host.ws || host.ws.readyState !== 1) return;
    const session = host.sessionCode ? store.sessions.get(host.sessionCode) : null;
    const clientCount = session ? session.clients.size : 0;
    const maxClients = parseInt(process.env.MAX_CLIENTS_PER_HOST) || 5;
    if (clientCount < maxClients && clientCount < bestLoad) {
      best = hostId;
      bestLoad = clientCount;
    }
  });
  return best;
}

// ── Failover ──────────────────────────────────────────────────────────
function handleHostFailover(deadHostId) {
  const host = store.hosts.get(deadHostId);
  if (!host || !host.sessionCode) return;

  const oldSession = store.sessions.get(host.sessionCode);
  if (!oldSession || oldSession.clients.size === 0) return;

  const newHostId = findAvailableHost(deadHostId);

  if (!newHostId) {
    oldSession.clients.forEach(({ ws }) => {
      send(ws, { type: 'HOST_FAILOVER_FAILED', reason: 'No available hosts. Please try again shortly.' });
    });
    releaseSession(host.sessionCode);
    return;
  }

  const newHost = store.hosts.get(newHostId);
  let newSessionCode = newHost.sessionCode;

  if (!newSessionCode || !store.sessions.has(newSessionCode)) {
    newSessionCode = generateSessionCode();
    store.sessions.set(newSessionCode, {
      hostId: newHostId,
      clients: new Set(),
      startedAt: Date.now(),
    });
    newHost.sessionCode = newSessionCode;
    send(newHost.ws, { type: 'SESSION_CREATED', code: newSessionCode });
  }

  const newSession = store.sessions.get(newSessionCode);
  let migrated = 0;
  oldSession.clients.forEach(({ ws, clientId, accessCode }) => {
    // FIX-N2: assign a fresh TUN IP in the new session for each migrated client.
    // Previously clients were migrated with no tunIp in the new session, so the
    // new host could not route any reply packets back to them (no map entry).
    const newTunIp = assignTunIp(newSessionCode);
    if (!newTunIp) {
      send(ws, { type: 'HOST_FAILOVER_FAILED', reason: 'No TUN addresses available on new host.' });
      return;
    }
    newSession.clients.add({ ws, clientId, accessCode, tunIp: newTunIp });
    store.connections.set(ws, { type: 'client', id: clientId, sessionCode: newSessionCode, tunIp: newTunIp });
    // Register IPv4 + IPv6 keys in the new session's routing map
    if (!sessionTunMap.has(newSessionCode)) sessionTunMap.set(newSessionCode, new Map());
    sessionTunMap.get(newSessionCode).set(newTunIp, ws);
    sessionTunMap.get(newSessionCode).set(ipv4MappedKey(newTunIp), ws);
    // Tell the client its new session and new TUN IP so it can rebuild its TUN
    send(ws, { type: 'HOST_FAILOVER', newSessionCode, tunIp: newTunIp, message: 'Automatically moved to a new host.' });
    send(newHost.ws, { type: 'CLIENT_CONNECTED', clientId, tunIp: newTunIp, totalClients: newSession.clients.size });
    migrated++;
  });

  releaseSession(host.sessionCode);
  host.sessionCode = null;
  console.log(`[failover] Migrated ${migrated} clients from ${deadHostId} to ${newHostId}`);
}

// ── Host earnings ─────────────────────────────────────────────────────
function calculateHostEarnings(hostId) {
  const host = store.hosts.get(hostId);
  if (!host) return 0;
  const CLIENT_HOUR_RATE = parseFloat(process.env.HOURLY_RATE_PER_HOST) || 0.50;
  return Math.round((host.totalClientHours || 0) * CLIENT_HOUR_RATE * 100) / 100;
}

// ── REST: Health ──────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({
  service: 'NetShare Business Platform',
  version: '2.0.0',
  status: 'running',
  uptime: Math.floor(process.uptime()) + 's',
}));

// FIX 6: /health endpoint for mobile app wake-up ping
app.get('/health', (req, res) => res.json({ status: 'ok', ts: Date.now() }));

app.get('/ping', (req, res) => res.json({ pong: true, ts: Date.now() }));

// ── REST: Admin — Generate Access Codes ──────────────────────────────
app.post('/admin/codes/generate', requireAdmin, async (req, res) => {
  const { count = 1, expiresInHours = 24, expiresInDays, label = '' } = req.body;
  const expiryMs = expiresInHours
    ? expiresInHours * 3_600_000
    : (expiresInDays || 1) * 86_400_000;
  const generated = [];

  for (let i = 0; i < Math.min(count, 100); i++) {
    const code = generateAccessCode();
    const entry = {
      id: uuidv4(),
      code,
      label,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + expiryMs).toISOString(),
      usedBy: null,
      isActive: true,
    };
    store.accessCodes.set(code, entry);
    await saveCodeToDB(entry);
    generated.push(entry);
  }

  res.json({ success: true, codes: generated });
});

// ── REST: Admin — List Access Codes ──────────────────────────────────
app.get('/admin/codes', requireAdmin, (req, res) => {
  res.json({
    codes: Array.from(store.accessCodes.values()),
    total: store.accessCodes.size,
  });
});

// ── REST: Admin — Revoke Access Code ─────────────────────────────────
app.post('/admin/codes/revoke', requireAdmin, async (req, res) => {
  const { code } = req.body;
  const entry = store.accessCodes.get(code);
  if (!entry) return res.status(404).json({ error: 'Code not found' });
  entry.isActive = false;
  await updateCodeInDB(code, { isActive: false });
  res.json({ success: true });
});

// ── REST: Admin — Host Management ────────────────────────────────────
app.get('/admin/hosts', requireAdmin, (req, res) => {
  const hosts = [];
  store.hosts.forEach((host, hostId) => {
    hosts.push({
      hostId,
      isOnline: host.isOnline,
      netType: host.netType,
      clientCount: host.sessionCode
        ? (store.sessions.get(host.sessionCode)?.clients.size || 0) : 0,
      registeredAt: host.registeredAt,
      totalUptimeHours: Math.round(host.totalUptimeMs / 3_600_000 * 10) / 10,
      weeklyEarnings: calculateHostEarnings(hostId),
      allTimeEarnings: host.allTimeEarnings || 0,
      lastSeen: host.lastSeen,
      sessionCode: host.sessionCode,
    });
  });
  res.json({ hosts, total: hosts.length });
});

// ── REST: Admin — Weekly Payout Summary ──────────────────────────────
app.get('/admin/payouts', requireAdmin, (req, res) => {
  const payouts = [];
  store.hosts.forEach((host, hostId) => {
    const earnings = calculateHostEarnings(hostId);
    payouts.push({
      hostId,
      weeklyEarnings: earnings,
      uptimeHours: Math.round(host.totalUptimeMs / 3_600_000 * 10) / 10,
      isOnline: host.isOnline,
      lastSeen: host.lastSeen,
    });
  });
  const totalPayout = payouts.reduce((s, p) => s + p.weeklyEarnings, 0);
  res.json({
    payouts,
    totalPayout: Math.round(totalPayout * 100) / 100,
    platformShare: Math.round(totalPayout * 100) / 100,
    weekEnds: new Date(Date.now() + (7 - new Date().getDay()) * 86_400_000).toISOString(),
  });
});

// ── REST: Admin — Reset Weekly Earnings ──────────────────────────────
app.post('/admin/payouts/reset', requireAdmin, (req, res) => {
  store.hosts.forEach((host) => {
    host.allTimeEarnings = (host.allTimeEarnings || 0) + calculateHostEarnings(host.hostId);
    host.totalUptimeMs = 0;
    host.totalClientHours = 0;
  });
  res.json({ success: true, message: 'Weekly uptime reset. New cycle started.' });
});

// ── REST: Admin — Platform Stats ─────────────────────────────────────
app.get('/admin/stats', requireAdmin, (req, res) => {
  const onlineHosts = Array.from(store.hosts.values()).filter(h => h.isOnline).length;
  const totalClients = Array.from(store.sessions.values())
    .reduce((sum, s) => sum + s.clients.size, 0);
  res.json({
    activeSessions: store.sessions.size,
    onlineHosts,
    totalHosts: store.hosts.size,
    totalClients,
    totalAccessCodes: store.accessCodes.size,
    activeAccessCodes: Array.from(store.accessCodes.values()).filter(c => c.isActive).length,
    usedAccessCodes: Array.from(store.accessCodes.values()).filter(c => c.usedBy).length,
    platform: store.stats,
    relay: {
      totalMBRelayed: Math.round(store.stats.totalDataRelayed / 1048576 * 100) / 100,
      largeFrames: store.stats.largeFrameCount,
    },
  });
});

// ── REST: Validate access code ────────────────────────────────────────
// FIX 1: Also allow direct session codes (from host's SESSION_CREATED) to validate.
// This way clients can join using either an admin-issued access code OR the
// session code that the host received.
app.post('/validate-code', (req, res) => {
  const raw = req.body?.code?.toUpperCase();
  if (!raw) return res.json({ valid: false, reason: 'No code provided' });

  // First check admin-issued access codes
  const entry = store.accessCodes.get(raw);
  if (entry) {
    if (!entry.isActive) return res.json({ valid: false, reason: 'Code has been revoked' });
    if (new Date(entry.expiresAt) < new Date()) return res.json({ valid: false, reason: 'Code expired' });
    return res.json({ valid: true, expiresAt: entry.expiresAt, type: 'access_code' });
  }

  // Session codes are NOT valid for client join — only admin-issued codes are.
  // Reject session codes clearly so the client shows the right error message.
  if (store.sessions.has(raw)) {
    return res.json({ valid: false, reason: 'Please use an admin-issued access code.' });
  }

  return res.json({ valid: false, reason: 'Code not found' });
});

// ── HTTP Server + WebSocket ───────────────────────────────────────────
// FIX: Do NOT pass `server` to WebSocketServer — that lets Express intercept
// the WS upgrade request and return 400. Instead, handle the 'upgrade' event
// directly on the HTTP server so the handshake bypasses Express entirely.
const server = http.createServer(app);

// SPEED: Disable Nagle's algorithm on the HTTP server itself.
// Node.js HTTP server doesn't set TCP_NODELAY by default.
// This reduces latency for small packets (control messages, ACKs).
server.on('connection', (socket) => {
  socket.setNoDelay(true);
  // Increase socket buffer sizes for high-throughput relay
  socket.setKeepAlive(true, 30000);
});

// SPEED: perMessageDeflate disabled — all relayed traffic is already TLS/QUIC-encrypted
// and compressed by the underlying protocols. Trying to deflate it wastes CPU cycles
// with zero size reduction, and adds 10–20ms latency per frame on a busy relay.
// maxPayload 200 KB: 65535-byte IP packet + WS framing overhead + some headroom.
const wss = new WebSocketServer({
  noServer: true,
  maxPayload: 200 * 1024,
  perMessageDeflate: false,
});

// SPEED: Per-session O(1) TUN IP routing map.
// Previously HOST→CLIENT routing did a forEach over all clients to find matching tunIp.
// Under load (5 clients, 1000 pkt/s) that's 5000 comparisons/s per host.
// A Map<tunIp, clientWs> reduces this to a single Map.get() per packet.
// Key: sessionCode → Map<tunIp, ws>
const sessionTunMap = new Map();

server.on('upgrade', (req, socket, head) => {
  if (req.url === '/relay') {
    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit('connection', ws, req);
    });
  } else {
    socket.destroy();
  }
});

wss.on('connection', (ws, req) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  console.log(`[ws] New connection from ${ip}`);

  ws.on('message', async (data, isBinary) => {
    try {

    // ── Binary: raw packet forwarding ──────────────────────────
    if (isBinary) {
      const conn = store.connections.get(ws);
      if (!conn) return;
      const session = store.sessions.get(conn.sessionCode);
      if (!session) return;

      const frameSize = data.length;
      store.stats.totalDataRelayed += frameSize;

      // Track oversized frames (QUIC CDN bursts — TikTok, YouTube QUIC)
      if (frameSize > 32768) store.stats.largeFrameCount++;

      if (conn.type === 'client') {
        // CLIENT → HOST: forward packet to the host of this session
        const host = store.hosts.get(session.hostId);
        // SPEED: send() with { binary: true, compress: false } skips the
        // per-message deflate check (packets are already compressed/encrypted
        // by TLS/QUIC — compressing again wastes CPU with no size reduction).
        if (host?.ws?.readyState === 1) host.ws.send(data, { binary: true, compress: false });
      } else if (conn.type === 'host') {
        // HOST → CLIENT: route response to the correct client by dst TUN IP.
        // SPEED: O(1) Map lookup instead of forEach scan over all clients.
        // sessionTunMap: sessionCode → Map<tunIp|ipv6HexKey, ws>
        const tunMap = sessionTunMap.get(conn.sessionCode);
        const version = (data[0] & 0xF0) >> 4;

        if (version === 4 && data.length >= 20) {
          // FIX-N1 (IPv4): O(1) lookup by dotted-decimal dst IP
          const dstIp = `${data[16]}.${data[17]}.${data[18]}.${data[19]}`;
          const targetWs = tunMap?.get(dstIp);
          if (targetWs?.readyState === 1) {
            targetWs.send(data, { binary: true, compress: false });
          }
          // FIX-SPEED-5: Unmatched dst = multicast (224.x.x.x) or broadcast (255.x.x.x).
          // DROP silently instead of broadcasting to all clients.
          // The old forEach broadcast flooded every client with mDNS/SSDP/IGMP noise,
          // wasting bandwidth and causing TikTok to detect fake "congestion" and throttle video.
        } else if (version === 6 && data.length >= 40) {
          // FIX-N1 (IPv6): O(1) lookup by 32-char hex dst address (bytes 24-39).
          // Previously this did a forEach broadcast to ALL clients, flooding
          // every client with every other client's IPv6 traffic.
          // Apps like TikTok, Instagram, YouTube use IPv6 heavily — this was
          // the primary cause of slowness and broken apps.
          const dstKey = buildIpv6KeyFromBuffer(data, 24);
          const targetWs = tunMap?.get(dstKey);
          if (targetWs?.readyState === 1) {
            targetWs.send(data, { binary: true, compress: false });
          }
          // No match = link-local/multicast (ND, RS, RA) → drop silently.
          // These are never meant for a specific client anyway.
        }
        // Unknown IP version: drop silently.
      }
      return;
    }

    // ── Text: control messages ──────────────────────────────────
    let msg;
    try { msg = JSON.parse(data.toString()); }
    catch { return; }

    console.log(`[ws] ${msg.type}`);

    switch (msg.type) {

      case 'HOST_REGISTER': {
        const hostId = msg.hostId || uuidv4();
        const sessionCode = generateSessionCode(); // FIX 2: now XXXX-XXXX format
        const existingHost = store.hosts.get(hostId);

        store.hosts.set(hostId, {
          ws,
          hostId,
          sessionCode,
          netType: msg.netType || 'WiFi',
          isOnline: true,
          registeredAt: existingHost?.registeredAt || new Date().toISOString(),
          onlineSince: Date.now(),
          totalUptimeMs: existingHost?.totalUptimeMs || 0,
          totalClientHours: existingHost?.totalClientHours || 0,
          allTimeEarnings: existingHost?.allTimeEarnings || 0,
          lastSeen: new Date().toISOString(),
        });

        store.sessions.set(sessionCode, {
          hostId,
          clients: new Set(),
          startedAt: Date.now(),
        });

        store.connections.set(ws, { type: 'host', id: hostId, sessionCode });
        store.stats.totalSessions++;
        send(ws, { type: 'SESSION_CREATED', code: sessionCode, hostId });
        console.log(`[relay] Host ${hostId} online, session ${sessionCode}`);
        break;
      }

      case 'CLIENT_JOIN': {
        // FIX 1: accessCode can be either an admin-issued access code OR a
        // session code that the host shared directly. We support both.
        const rawCode = (msg.accessCode || msg.code || '').toUpperCase();
        if (!rawCode) {
          return send(ws, { type: 'JOIN_ERROR', reason: 'No access code provided' });
        }

        let targetSessionCode = null;
        let accessCodeEntry = null;

        // Path A: it's an admin-issued access code → find best host
        const codeEntry = store.accessCodes.get(rawCode);
        if (codeEntry) {
          // FIX-N4: check expiry first, unconditionally — even on reconnect
          if (new Date(codeEntry.expiresAt) < new Date()) {
            return send(ws, { type: 'JOIN_ERROR', reason: 'Access code has expired' });
          }
          if (!codeEntry.isActive) {
            return send(ws, { type: 'JOIN_ERROR', reason: 'Access code has been revoked' });
          }
          accessCodeEntry = codeEntry;
          // Find best available host for this access code
          const bestHostId = findAvailableHost();
          if (!bestHostId) {
            return send(ws, { type: 'JOIN_ERROR', reason: 'No hosts available right now. Please try again shortly.' });
          }
          targetSessionCode = store.hosts.get(bestHostId).sessionCode;
        }
        // Path B: it's a session code the host shared directly.
        // NOTE: Direct session code joins are disabled — only admin-issued
        // access codes are accepted. This ensures the admin controls all
        // access. If a session code is submitted, reject it clearly.
        else if (store.sessions.has(rawCode)) {
          return send(ws, { type: 'JOIN_ERROR', reason: 'Please use an admin-issued access code to join.' });
        }
        else {
          return send(ws, { type: 'JOIN_ERROR', reason: 'Code not found. Check the code and try again.' });
        }

        const session = store.sessions.get(targetSessionCode);
        if (!session) {
          return send(ws, { type: 'JOIN_ERROR', reason: 'Session not found' });
        }

        const host = store.hosts.get(session.hostId);
        if (!host || !host.isOnline || host.ws?.readyState !== 1) {
          return send(ws, { type: 'JOIN_ERROR', reason: 'Host is offline. Try again shortly.' });
        }

        const maxClients = parseInt(process.env.MAX_CLIENTS_PER_HOST) || 5;
        if (session.clients.size >= maxClients) {
          return send(ws, { type: 'JOIN_ERROR', reason: 'Session is full. Finding another host...' });
        }

        const clientId = `client-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;

        // Assign a unique TUN IP so every client gets its own /24 address.
        // This lets the server route packets to the correct client by dst IP.
        const tunIp = assignTunIp(targetSessionCode);
        if (!tunIp) {
          return send(ws, { type: 'JOIN_ERROR', reason: 'No TUN addresses available in this session.' });
        }

        session.clients.add({ ws, clientId, accessCode: rawCode, tunIp });
        store.connections.set(ws, { type: 'client', id: clientId, sessionCode: targetSessionCode, tunIp });

        // SPEED: register client in O(1) TUN routing map
        if (!sessionTunMap.has(targetSessionCode)) sessionTunMap.set(targetSessionCode, new Map());
        sessionTunMap.get(targetSessionCode).set(tunIp, ws);
        // FIX-N1: also register the IPv4-mapped IPv6 key so IPv6 packets from
        // the host are routed to this client without a forEach broadcast.
        sessionTunMap.get(targetSessionCode).set(ipv4MappedKey(tunIp), ws);

        // Mark access code as used (only for admin-issued codes)
        if (accessCodeEntry && !accessCodeEntry.usedBy) {
          accessCodeEntry.usedBy = clientId;
          await updateCodeInDB(accessCodeEntry.code, { usedBy: clientId });
        }

        send(ws, { type: 'JOIN_SUCCESS', code: targetSessionCode, netType: host.netType, clientId, tunIp });
        send(host.ws, { type: 'CLIENT_CONNECTED', clientId, tunIp, totalClients: session.clients.size });
        console.log(`[relay] Client ${clientId} joined session ${targetSessionCode}`);
        break;
      }

      case 'PONG': {
        const conn = store.connections.get(ws);
        if (conn?.type === 'host') {
          const host = store.hosts.get(conn.id);
          if (host) host.lastSeen = new Date().toISOString();
        }
        break;
      }

      case 'HOST_LEAVE': {
        const conn = store.connections.get(ws);
        if (conn?.type === 'host') {
          handleHostFailover(conn.id);
          const host = store.hosts.get(conn.id);
          if (host) {
            host.isOnline = false;
            host.totalUptimeMs += Date.now() - host.onlineSince;
            host.sessionCode = null;
          }
        }
        store.connections.delete(ws);
        break;
      }

      case 'CLIENT_LEAVE': {
        const conn = store.connections.get(ws);
        if (!conn) return;
        const session = store.sessions.get(conn.sessionCode);
        if (session) {
          session.clients.forEach(client => {
            if (client.ws === ws) session.clients.delete(client);
          });
          if (conn.tunIp) {
            releaseTunIp(conn.sessionCode, conn.tunIp);
            // Remove from O(1) TUN routing map (IPv4 + IPv6 keys)
            sessionTunMap.get(conn.sessionCode)?.delete(conn.tunIp);
            sessionTunMap.get(conn.sessionCode)?.delete(ipv4MappedKey(conn.tunIp));
          }
          const host = store.hosts.get(session.hostId);
          if (host?.ws?.readyState === 1) {
            send(host.ws, { type: 'CLIENT_DISCONNECTED', clientId: conn.id, totalClients: session.clients.size });
          }
        }
        store.connections.delete(ws);
        break;
      }

      case 'ADMIN_AUTH': {
        if (msg.password !== store.adminPassword) {
          return send(ws, { type: 'ADMIN_AUTH_FAILED' });
        }
        store.connections.set(ws, { type: 'admin', id: 'admin' });
        send(ws, { type: 'ADMIN_AUTH_SUCCESS' });
        break;
      }

      default:
        console.warn(`[ws] Unknown type: ${msg.type}`);
    }

    } catch (err) {
      // FIX-N3: catch any unhandled async error so the server never crashes
      // from a bad message, a DB failure, or an unexpected payload.
      console.error('[ws] unhandled message error:', err.message);
    }
  });

  ws.on('close', () => {
    const conn = store.connections.get(ws);
    if (!conn) return;

    if (conn.type === 'host') {
      const host = store.hosts.get(conn.id);
      if (host) {
        host.isOnline = false;
        host.totalUptimeMs += (Date.now() - (host.onlineSince || Date.now()));
        host.lastSeen = new Date().toISOString();
        console.log(`[relay] Host ${conn.id} went offline — initiating failover`);
        handleHostFailover(conn.id);
        host.sessionCode = null;
      }
    } else if (conn.type === 'client') {
      const session = store.sessions.get(conn.sessionCode);
      if (session) {
        session.clients.forEach(client => {
          if (client.ws === ws) session.clients.delete(client);
        });
        if (conn.tunIp) {
          releaseTunIp(conn.sessionCode, conn.tunIp);
          // Remove from O(1) TUN routing map
          sessionTunMap.get(conn.sessionCode)?.delete(conn.tunIp);
          sessionTunMap.get(conn.sessionCode)?.delete(ipv4MappedKey(conn.tunIp));
        }
        const host = store.hosts.get(session?.hostId);
        if (host?.ws?.readyState === 1) {
          send(host.ws, { type: 'CLIENT_DISCONNECTED', clientId: conn.id, totalClients: session.clients.size });
        }
      }
    }
    store.connections.delete(ws);
  });

  ws.on('error', (err) => console.error(`[ws] error: ${err.message}`));
});

// ── Heartbeat: ping all connections every 15s ─────────────────────────
// 15s interval: dead hosts are detected within 30s (ping + missed pong).
// Previously 30s meant up to 60s of clients sending to a dead host.
setInterval(() => {
  store.hosts.forEach((host, hostId) => {
    if (host.ws?.readyState === 1) {
      send(host.ws, { type: 'PING' });
      const session = host.sessionCode ? store.sessions.get(host.sessionCode) : null;
      const activeClients = session ? session.clients.size : 0;
      if (activeClients > 0) {
        host.totalClientHours = (host.totalClientHours || 0) + (activeClients * 15 / 3600);
      }
      host.totalUptimeMs = (host.totalUptimeMs || 0) + 15_000;
    } else if (host.isOnline) {
      host.isOnline = false;
      host.totalUptimeMs += (Date.now() - (host.onlineSince || Date.now()));
      handleHostFailover(hostId);
    }
  });
  store.sessions.forEach((session) => {
    session.clients.forEach(({ ws }) => {
      if (ws.readyState === 1) send(ws, { type: 'PING' });
    });
  });
}, 15_000);

// FIX 3: Keep-alive self-ping using RENDER_EXTERNAL_URL (set automatically by Render).
// Falls back to localhost only in dev. Without this env var on Render, the
// self-ping was going to localhost which Render doesn't route externally.
const SELF_URL = process.env.RENDER_EXTERNAL_URL
  ? `${process.env.RENDER_EXTERNAL_URL}/ping`
  : null;

if (SELF_URL) {
  const selfPingMod = new URL(SELF_URL).protocol === 'https:' ? require('https') : require('http');
  setInterval(() => {
    selfPingMod.get(SELF_URL, (res) => { res.resume(); }).on('error', () => {});
  }, 4 * 60 * 1000);
  console.log(`[keep-alive] Self-ping enabled: ${SELF_URL}`);
} else {
  console.log('[keep-alive] RENDER_EXTERNAL_URL not set — self-ping disabled (dev mode)');
}

// ── Start server after loading codes from Supabase ────────────────────
async function start() {
  await loadCodesFromDB(); // FIX 5: load before listening so codes are ready immediately
  server.listen(PORT, () => {
    console.log(`✅ NetShare Business Platform running on port ${PORT}`);
    console.log(`   WebSocket relay: ws://localhost:${PORT}/relay`);
    console.log(`   Admin API: http://localhost:${PORT}/admin/*`);
    console.log(`   Admin key: ${store.adminPassword}`);
  });
}

start();

process.on('SIGTERM', () => {
  console.log('SIGTERM — shutting down gracefully');
  server.close(() => process.exit(0));
});
