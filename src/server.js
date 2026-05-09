/**
 * NetShare Business Platform — server.js
 *
 * Business model:
 *  - Admin/Owner generates access passwords for clients
 *  - Clients pay the owner directly (offline/manual)
 *  - Hosts are paid weekly based on uptime/availability
 *  - Revenue split: 50% owner / 50% host per session hour
 *  - Auto-failover: if host drops, clients migrate to next available host
 */

require('dotenv').config();

const http    = require('http');
const express = require('express');
const cors    = require('cors');
const { WebSocketServer } = require('ws');
const { v4: uuidv4 } = require('uuid');
const crypto  = require('crypto');

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

// Load all active codes from Supabase into memory on startup
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
  earnings: new Map(),
  connections: new Map(),
  stats: {
    totalSessions: 0,
    totalDataRelayed: 0,
    totalEarningsPaid: 0,
    weeklyRevenuePool: 0,
  },
};

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

function generateSessionCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return Array.from({ length: 6 }, () =>
    chars[Math.floor(Math.random() * chars.length)]).join('');
}

function send(ws, obj) {
  if (ws && ws.readyState === 1) ws.send(JSON.stringify(obj));
}

function broadcastToSession(sessionCode, obj, excludeWs = null) {
  const session = store.sessions.get(sessionCode);
  if (!session) return;
  session.clients.forEach(({ ws }) => {
    if (ws !== excludeWs) send(ws, obj);
  });
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
    store.sessions.delete(host.sessionCode);
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
      hostEarningsMs: 0,
    });
    newHost.sessionCode = newSessionCode;
    send(newHost.ws, { type: 'SESSION_CREATED', code: newSessionCode });
  }

  const newSession = store.sessions.get(newSessionCode);
  let migrated = 0;
  oldSession.clients.forEach(({ ws, clientId, accessCode }) => {
    newSession.clients.add({ ws, clientId, accessCode });
    store.connections.set(ws, { type: 'client', id: clientId, sessionCode: newSessionCode });
    send(ws, { type: 'HOST_FAILOVER', newSessionCode, message: 'Your connection was automatically moved to a new host.' });
    send(newHost.ws, { type: 'CLIENT_CONNECTED', clientId, totalClients: newSession.clients.size });
    migrated++;
  });

  store.sessions.delete(host.sessionCode);
  host.sessionCode = null;
  console.log(`[failover] Migrated ${migrated} clients from host ${deadHostId} to ${newHostId}`);
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
  });
});

// ── REST: Validate access code ────────────────────────────────────────
app.post('/validate-code', (req, res) => {
  const { code } = req.body;
  const entry = store.accessCodes.get(code?.toUpperCase());
  if (!entry) return res.json({ valid: false, reason: 'Code not found' });
  if (!entry.isActive) return res.json({ valid: false, reason: 'Code has been revoked' });
  if (new Date(entry.expiresAt) < new Date()) return res.json({ valid: false, reason: 'Code expired' });
  res.json({ valid: true, expiresAt: entry.expiresAt });
});

// ── HTTP Server + WebSocket ───────────────────────────────────────────
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/relay' });

wss.on('connection', (ws, req) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  console.log(`[ws] New connection from ${ip}`);

  ws.on('message', async (data, isBinary) => {
    // ── Binary: raw packet forwarding ──────────────────────────
    if (isBinary) {
      const conn = store.connections.get(ws);
      if (!conn) return;
      const session = store.sessions.get(conn.sessionCode);
      if (!session) return;
      store.stats.totalDataRelayed += data.length;
      const host = store.hosts.get(session.hostId);
      if (conn.type === 'client') {
        if (host?.ws?.readyState === 1) host.ws.send(data, { binary: true });
      } else if (conn.type === 'host') {
        session.clients.forEach(({ ws: cws }) => {
          if (cws.readyState === 1) cws.send(data, { binary: true });
        });
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
        const sessionCode = generateSessionCode();
        const existingHost = store.hosts.get(hostId);
        const uptimeMs = existingHost?.totalUptimeMs || 0;

        store.hosts.set(hostId, {
          ws,
          hostId,
          sessionCode,
          netType: msg.netType || 'WiFi',
          isOnline: true,
          registeredAt: existingHost?.registeredAt || new Date().toISOString(),
          onlineSince: Date.now(),
          totalUptimeMs: uptimeMs,
          totalClientHours: existingHost?.totalClientHours || 0,
          allTimeEarnings: existingHost?.allTimeEarnings || 0,
          lastSeen: new Date().toISOString(),
          clientCount: 0,
        });

        store.sessions.set(sessionCode, {
          hostId,
          clients: new Set(),
          startedAt: Date.now(),
          hostEarningsMs: 0,
        });

        store.connections.set(ws, { type: 'host', id: hostId, sessionCode });
        store.stats.totalSessions++;
        send(ws, { type: 'SESSION_CREATED', code: sessionCode, hostId });
        console.log(`[relay] Host ${hostId} online, session ${sessionCode}`);
        break;
      }

      case 'CLIENT_JOIN': {
        const { accessCode, sessionCode: requestedCode } = msg;

        const codeEntry = store.accessCodes.get(accessCode?.toUpperCase());
        if (!codeEntry || !codeEntry.isActive || new Date(codeEntry.expiresAt) < new Date()) {
          return send(ws, { type: 'JOIN_ERROR', reason: 'Invalid or expired access code. Contact the platform owner.' });
        }

        let targetSessionCode = requestedCode;
        let session = targetSessionCode ? store.sessions.get(targetSessionCode) : null;

        if (!session) {
          const bestHostId = findAvailableHost();
          if (!bestHostId) {
            return send(ws, { type: 'JOIN_ERROR', reason: 'No hosts available right now. Please try again shortly.' });
          }
          targetSessionCode = store.hosts.get(bestHostId).sessionCode;
          session = store.sessions.get(targetSessionCode);
        }

        const host = store.hosts.get(session?.hostId);
        if (!host || !host.isOnline || host.ws?.readyState !== 1) {
          return send(ws, { type: 'JOIN_ERROR', reason: 'Selected host is offline. Trying to find another...' });
        }

        const maxClients = parseInt(process.env.MAX_CLIENTS_PER_HOST) || 5;
        if (session.clients.size >= maxClients) {
          return send(ws, { type: 'JOIN_ERROR', reason: 'This session is full. Finding another host...' });
        }

        const clientId = `client-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
        session.clients.add({ ws, clientId, accessCode: accessCode.toUpperCase() });
        store.connections.set(ws, { type: 'client', id: clientId, sessionCode: targetSessionCode });

        if (!codeEntry.usedBy) {
          codeEntry.usedBy = clientId;
          await updateCodeInDB(codeEntry.code, { usedBy: clientId });
        }

        send(ws, { type: 'JOIN_SUCCESS', code: targetSessionCode, netType: host.netType, clientId });
        send(host.ws, { type: 'CLIENT_CONNECTED', clientId, totalClients: session.clients.size });
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
          const host = store.hosts.get(session.hostId);
          if (host?.ws) {
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

// ── Heartbeat: ping all connections every 30s ─────────────────────────
setInterval(() => {
  store.hosts.forEach((host, hostId) => {
    if (host.ws?.readyState === 1) {
      send(host.ws, { type: 'PING' });
      const session = host.sessionCode ? store.sessions.get(host.sessionCode) : null;
      const activeClients = session ? session.clients.size : 0;
      if (activeClients > 0) {
        host.totalClientHours = (host.totalClientHours || 0) + (activeClients * 30 / 3600);
      }
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
}, 30_000);

// ── Keep-alive: prevent Render free tier from sleeping ────────────────
const SELF_URL = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
setInterval(() => {
  http.get(`${SELF_URL}/ping`, (res) => { res.resume(); }).on('error', () => {});
}, 4 * 60 * 1000);

// ── Start server after loading codes from Supabase ────────────────────
server.listen(PORT, async () => {
  console.log(`✅ NetShare Business Platform running on port ${PORT}`);
  console.log(`   WebSocket relay: ws://localhost:${PORT}/relay`);
  console.log(`   Admin API: http://localhost:${PORT}/admin/*`);
  console.log(`   Admin key: ${store.adminPassword}`);
  await loadCodesFromDB();
});

process.on('SIGTERM', () => {
  console.log('SIGTERM — shutting down gracefully');
  server.close(() => process.exit(0));
});
