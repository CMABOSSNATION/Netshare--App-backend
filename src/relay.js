/**
 * relay.js — NetShare Cloudflare Durable Object
 *
 * ALL PREVIOUS FIXES RETAINED +
 *
 * NEW: Admin-controlled access code system.
 *   - Admin generates pre-approved codes via /admin/codes/generate
 *   - Clients must present a valid admin-issued code to join a session
 *   - Hosts never see or manage codes — admin controls all access
 *   - Codes are stored in DO SQLite storage (persistent across cold starts)
 *
 * NEW: Admin routes added to relay DO:
 *   POST /admin/codes/generate  → create access codes
 *   GET  /admin/codes           → list all codes
 *   POST /admin/codes/revoke    → revoke a code
 *   GET  /admin/stats           → platform stats
 *   GET  /admin/hosts           → host list
 *   GET  /admin/payouts         → payout report
 *   POST /admin/payouts/reset   → reset weekly cycle
 */

const CODE_CHARS          = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const SESSION_TIMEOUT_MS  = 6 * 3_600_000;
const MAX_CLIENTS         = 5;
const SMALL_FRAME         = 4096;  // raised: include WhatsApp/TikTok QUIC ACK frames as "small"
const MAX_BUFFERED        = 512 * 1024;  // raised: QUIC video bursts (TikTok/YT) need more buffer
const ALARM_INTERVAL_MS   = 20_000;
const PONG_TIMEOUT_MS     = 60_000;
const HOST_RECONNECT_WAIT = 30_000;
const JOIN_WAIT_MS        = 10_000;
const HOURLY_RATE         = 0.50; // $ per host per hour online

function generateCode(sessions) {
  let code;
  do {
    const p1 = Array.from({length:4}, () => CODE_CHARS[Math.floor(Math.random()*CODE_CHARS.length)]).join('');
    const p2 = Array.from({length:4}, () => CODE_CHARS[Math.floor(Math.random()*CODE_CHARS.length)]).join('');
    code = `${p1}-${p2}`;
  } while (sessions.has(code));
  return code;
}

function generateAccessCode() {
  const p1 = Array.from({length:4}, () => CODE_CHARS[Math.floor(Math.random()*CODE_CHARS.length)]).join('');
  const p2 = Array.from({length:4}, () => CODE_CHARS[Math.floor(Math.random()*CODE_CHARS.length)]).join('');
  return `${p1}-${p2}`;
}

function send(ws, obj) {
  try { if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj)); } catch (_) {}
}

function sendBinary(ws, data) {
  try {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    if (ws.bufferedAmount > MAX_BUFFERED) return;
    const len = data instanceof ArrayBuffer ? data.byteLength : (data.length || 0);
    if (len <= SMALL_FRAME) { ws.send(data); }
    else { Promise.resolve().then(() => { if (ws && ws.readyState === WebSocket.OPEN) ws.send(data); }); }
  } catch (_) {}
}

function cors() {
  return {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-requested-with, x-admin-key',
  };
}

function json(data, status = 200) {
  return Response.json(data, { status, headers: cors() });
}

export class RelaySession {
  constructor(state, env) {
    this.state = state;
    this.env   = env;
    this.sessions    = new Map(); // relay sessions (WS-based)
    this.connections = new Map();
    this.joinWaiters = new Map();
    this.hostRegistry = new Map(); // hostId → { sessionCode, netType, clientCount, lastSeen, weeklyUptimeHours, weekStart }
    // BUG-FIX: monotonically increasing per-session IP counter so IPs are never
    // reused within a session even after clients disconnect (avoids IP collisions
    // when clients reconnect while others are still active).
    this.sessionIpCounters = new Map(); // sessionCode → next client index (starts at 1)
    this._alarmScheduled = false;
    this._restored       = false;
  }

  // ── Restore sessions from storage on cold start ───────────────────────────
  async _restoreSessions() {
    if (this._restored) return;
    this._restored = true;
    try {
      const stored = await this.state.storage.list({ prefix: 'session:' });
      const now    = Date.now();
      for (const [key, val] of stored) {
        try {
          const meta = JSON.parse(val);
          if (now - meta.createdAt > SESSION_TIMEOUT_MS) { await this.state.storage.delete(key); continue; }
          const code = key.replace('session:', '');
          this.sessions.set(code, { host: null, clients: new Set(), createdAt: meta.createdAt, netType: meta.netType || 'WiFi', hostId: meta.hostId || null, hostRay: null, _persisted: true });
        } catch (_) {}
      }
      // Restore host registry
      const hosts = await this.state.storage.list({ prefix: 'host:' });
      for (const [key, val] of hosts) {
        try {
          const meta = JSON.parse(val);
          const hostId = key.replace('host:', '');
          this.hostRegistry.set(hostId, meta);
        } catch (_) {}
      }
    } catch (e) { console.error('[relay] _restoreSessions:', e?.message); }
  }

  async _persistSession(code, session) {
    try { await this.state.storage.put(`session:${code}`, JSON.stringify({ createdAt: session.createdAt, netType: session.netType, hostId: session.hostId })); } catch (_) {}
  }

  async _deleteSession(code) {
    try { await this.state.storage.delete(`session:${code}`); } catch (_) {}
  }

  // ── Access code storage helpers ───────────────────────────────────────────
  async _getAccessCode(code) {
    try {
      const val = await this.state.storage.get(`ac:${code}`);
      return val ? JSON.parse(val) : null;
    } catch { return null; }
  }

  async _putAccessCode(code, data) {
    try { await this.state.storage.put(`ac:${code}`, JSON.stringify(data)); } catch (_) {}
  }

  async _listAccessCodes() {
    try {
      const list = await this.state.storage.list({ prefix: 'ac:' });
      const codes = [];
      for (const [key, val] of list) {
        try { codes.push({ code: key.replace('ac:', ''), ...JSON.parse(val) }); } catch (_) {}
      }
      return codes;
    } catch { return []; }
  }

  // ── Host registry helpers ─────────────────────────────────────────────────
  _upsertHost(hostId, updates) {
    const existing = this.hostRegistry.get(hostId) || {
      hostId, isOnline: false, netType: 'WiFi', clientCount: 0,
      sessionCode: null, lastSeen: Date.now(),
      totalUptimeHours: 0, weeklyUptimeHours: 0,
      weeklyEarnings: 0, weekStart: Date.now(),
      _onlineSince: null,
    };
    const merged = { ...existing, ...updates };
    this.hostRegistry.set(hostId, merged);
    // Persist async (fire and forget)
    this.state.storage.put(`host:${hostId}`, JSON.stringify(merged)).catch(() => {});
    return merged;
  }

  _markHostOnline(hostId, netType, sessionCode) {
    const h = this.hostRegistry.get(hostId) || {};
    this._upsertHost(hostId, { isOnline: true, netType, sessionCode, lastSeen: Date.now(), _onlineSince: h._onlineSince || Date.now() });
  }

  _markHostOffline(hostId) {
    const h = this.hostRegistry.get(hostId);
    if (!h) return;
    const onlineSince = h._onlineSince || Date.now();
    const hoursOnline = (Date.now() - onlineSince) / 3_600_000;
    const weeklyHrs   = (h.weeklyUptimeHours || 0) + hoursOnline;
    const totalHrs    = (h.totalUptimeHours  || 0) + hoursOnline;
    this._upsertHost(hostId, {
      isOnline: false, _onlineSince: null, lastSeen: Date.now(),
      weeklyUptimeHours: +weeklyHrs.toFixed(2),
      totalUptimeHours:  +totalHrs.toFixed(2),
      weeklyEarnings: +(weeklyHrs * HOURLY_RATE).toFixed(2),
    });
  }

  // ── Alarm ─────────────────────────────────────────────────────────────────
  async _scheduleAlarm() {
    if (this._alarmScheduled) return;
    this._alarmScheduled = true;
    try { await this.state.storage.setAlarm(Date.now() + ALARM_INTERVAL_MS); } catch (_) {}
  }

  async alarm() {
    this._alarmScheduled = false;
    const now = Date.now();
    for (const [code, session] of this.sessions) {
      if (now - session.createdAt > SESSION_TIMEOUT_MS) { await this._cleanupSession(code); continue; }
      const hostConn = session.host ? this.connections.get(session.host) : null;
      if (session.host && session.host.readyState === WebSocket.OPEN) {
        if (hostConn && now - hostConn.lastPong > PONG_TIMEOUT_MS) {
          try { session.host.close(1001, 'Ping timeout'); } catch (_) {}
        } else { send(session.host, { type: 'PING' }); }
      }
      session.clients.forEach(ws => {
        const conn = this.connections.get(ws);
        if (ws.readyState === WebSocket.OPEN) {
          if (conn && now - conn.lastPong > PONG_TIMEOUT_MS) { try { ws.close(1001, 'Ping timeout'); } catch (_) {} }
          else send(ws, { type: 'PING' });
        }
      });
    }
    if (this.sessions.size > 0) await this._scheduleAlarm();
  }

  // ── Main fetch ────────────────────────────────────────────────────────────
  async fetch(request) {
    await this._restoreSessions();
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors() });

    // ── Admin routes ────────────────────────────────────────────────────────
    if (url.pathname.startsWith('/admin/')) {
      const adminKey = request.headers.get('x-admin-key') || '';
      const expectedKey = (this.env.ADMIN_KEY) || 'netshare-admin-2026';
      if (adminKey !== expectedKey) return json({ error: 'Unauthorized' }, 401);
      return this._handleAdmin(request, url);
    }

    // ── Health ──────────────────────────────────────────────────────────────
    if (url.pathname === '/health' || url.pathname === '/ping')
      return new Response('OK', { status: 200, headers: cors() });

    // ── Stats ───────────────────────────────────────────────────────────────
    if (url.pathname === '/stats') {
      let totalClients = 0;
      this.sessions.forEach(s => { totalClients += s.clients.size; });
      return json({ activeSessions: this.sessions.size, totalClients });
    }

    // ── Validate code (used by VpnService.js before client joins) ──────────
    if (url.pathname === '/validate-code' && request.method === 'POST') {
      try {
        const body     = await request.json();
        const upper    = (body.code || '').toUpperCase();
        const deviceId = (body.deviceId || '').trim();
        const ac  = await this._getAccessCode(upper);
        const now = Date.now();
        if (!ac || !ac.isActive || new Date(ac.expiresAt).getTime() < now) {
          return json({ valid: false, reason: 'Invalid or expired access code' });
        }
        // If already claimed by a different device, reject early
        if (ac.claimedBy && deviceId && ac.claimedBy !== deviceId) {
          return json({ valid: false, reason: 'This access code is already in use by another device' });
        }
        return json({ valid: true, reason: null });
      } catch { return json({ valid: false, reason: 'Server error' }); }
    }

    // ── WebSocket upgrade ───────────────────────────────────────────────────
    if (request.headers.get('Upgrade') !== 'websocket')
      return new Response('NetShare Relay is running', { status: 200, headers: { 'Content-Type': 'text/plain', ...cors() } });

    const { 0: client, 1: server } = new WebSocketPair();
    server.accept();
    this._handleConnection(server, request);
    return new Response(null, { status: 101, webSocket: client });
  }

  // ── Admin handler ─────────────────────────────────────────────────────────
  async _handleAdmin(request, url) {
    const path = url.pathname;

    // GET /admin/stats
    if (path === '/admin/stats' && request.method === 'GET') {
      let totalClients = 0;
      this.sessions.forEach(s => { totalClients += s.clients.size; });
      const hosts = [...this.hostRegistry.values()];
      const codes = await this._listAccessCodes();
      const now   = Date.now();
      return json({
        activeSessions:   this.sessions.size,
        totalClients,
        onlineHosts:      hosts.filter(h => h.isOnline).length,
        totalHosts:       hosts.length,
        activeAccessCodes: codes.filter(c => c.isActive && new Date(c.expiresAt).getTime() > now).length,
      });
    }

    // GET /admin/codes
    if (path === '/admin/codes' && request.method === 'GET') {
      const codes = await this._listAccessCodes();
      return json({ codes });
    }

    // POST /admin/codes/generate
    if (path === '/admin/codes/generate' && request.method === 'POST') {
      try {
        const body = await request.json();
        const count = Math.min(parseInt(body.count) || 1, 100);
        const hours = parseInt(body.expiresInHours) || 24;
        const label = body.label || '';
        const codes = [];
        for (let i = 0; i < count; i++) {
          const code = generateAccessCode();
          const data = {
            isActive:  true,
            label,
            createdAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + hours * 3_600_000).toISOString(),
            claimedBy: null,
            claimedAt: null,
            usedBy:    null,
            usedAt:    null,
          };
          await this._putAccessCode(code, data);
          codes.push({ code, ...data });
        }
        return json({ codes });
      } catch (e) { return json({ error: e.message }, 400); }
    }

    // POST /admin/codes/revoke
    if (path === '/admin/codes/revoke' && request.method === 'POST') {
      try {
        const { code } = await request.json();
        const upper = (code || '').toUpperCase();
        const ac = await this._getAccessCode(upper);
        if (!ac) return json({ error: 'Code not found' }, 404);
        await this._putAccessCode(upper, { ...ac, isActive: false });
        return json({ success: true });
      } catch (e) { return json({ error: e.message }, 400); }
    }

    // GET /admin/hosts
    if (path === '/admin/hosts' && request.method === 'GET') {
      const hosts = [...this.hostRegistry.values()].map(h => ({
        hostId:          h.hostId,
        isOnline:        h.isOnline,
        netType:         h.netType,
        clientCount:     h.clientCount || 0,
        sessionCode:     h.sessionCode,
        totalUptimeHours: +(h.totalUptimeHours || 0).toFixed(1),
        weeklyEarnings:  +(h.weeklyEarnings || 0).toFixed(2),
        lastSeen:        h.lastSeen,
      }));
      return json({ hosts });
    }

    // GET /admin/payouts
    if (path === '/admin/payouts' && request.method === 'GET') {
      const payouts = [...this.hostRegistry.values()].map(h => ({
        hostId:       h.hostId,
        isOnline:     h.isOnline,
        uptimeHours:  +(h.weeklyUptimeHours || 0).toFixed(1),
        weeklyEarnings: +(h.weeklyEarnings || 0).toFixed(2),
        lastSeen:     h.lastSeen,
      }));
      const totalPayout    = payouts.reduce((s, p) => s + p.weeklyEarnings, 0);
      const platformShare  = totalPayout; // 50/50 split implied
      return json({ payouts, totalPayout: +totalPayout.toFixed(2), platformShare: +platformShare.toFixed(2) });
    }

    // POST /admin/payouts/reset
    if (path === '/admin/payouts/reset' && request.method === 'POST') {
      for (const [hostId, h] of this.hostRegistry) {
        this._upsertHost(hostId, { weeklyUptimeHours: 0, weeklyEarnings: 0, weekStart: Date.now() });
      }
      return json({ success: true });
    }

    return json({ error: 'Not found' }, 404);
  }

  // ── WebSocket connection ───────────────────────────────────────────────────
  _handleConnection(ws, request) {
    const clientIp = request.headers.get('cf-connecting-ip') || 'unknown';
    const cfRay    = request.headers.get('cf-ray') || null;
    this.connections.set(ws, { role: null, code: null, id: null, cfRay, lastPong: Date.now() });
    ws.addEventListener('message', e => this._onMessage(ws, e.data, cfRay));
    ws.addEventListener('close',   () => this._onClose(ws));
    ws.addEventListener('error',   err => console.error('[relay] WS error:', err));
    console.log(`[relay] New WS from ${clientIp}`);
  }

  async _onMessage(ws, data, cfRay) {
    // Binary relay
    if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
      const conn = this.connections.get(ws); if (!conn) return;
      const session = this.sessions.get(conn.code); if (!session) return;
      if (conn.role === 'client') { if (session.host?.readyState === WebSocket.OPEN) sendBinary(session.host, data); }
      else if (conn.role === 'host') { session.clients.forEach(cws => sendBinary(cws, data)); }
      return;
    }

    let msg;
    try { msg = JSON.parse(data); } catch { return; }

    switch (msg.type) {

      case 'HOST_REGISTER': {
        if (msg.hostId) {
          for (const [c, s] of this.sessions) {
            if (s.hostId === msg.hostId) { await this._cleanupSession(c); break; }
          }
        }
        const code = generateCode(this.sessions);
        const session = { host: ws, clients: new Set(), createdAt: Date.now(), netType: msg.netType || 'WiFi', hostRay: cfRay, hostId: msg.hostId || null };
        this.sessions.set(code, session);
        const conn = this.connections.get(ws) || {};
        this.connections.set(ws, { ...conn, role: 'host', code, id: `host-${code}`, lastPong: Date.now() });
        send(ws, { type: 'SESSION_CREATED', code, netType: msg.netType });
        await this._persistSession(code, session);
        if (msg.hostId) this._markHostOnline(msg.hostId, msg.netType || 'WiFi', code);
        this._resolveJoinWaiters(code);
        console.log(`[relay] Session ${code} created`);
        await this._scheduleAlarm();
        break;
      }

      case 'CLIENT_JOIN': {
        const code     = (msg.accessCode || msg.code || '').toUpperCase();
        const deviceId = (msg.deviceId || '').trim();
        if (!code) return send(ws, { type: 'JOIN_ERROR', reason: 'No code provided' });
        if (!deviceId) return send(ws, { type: 'JOIN_ERROR', reason: 'Device ID missing — update your app' });

        const ac  = await this._getAccessCode(code);
        const now = Date.now();

        // Basic validity: must exist, be active, not expired
        if (!ac || !ac.isActive || new Date(ac.expiresAt).getTime() < now) {
          return send(ws, { type: 'JOIN_ERROR', reason: 'Invalid or expired access code' });
        }

        // ONE-DEVICE LOCK:
        // - If code has never been used → claim it for this device
        // - If code already claimed → only the same device can reconnect
        // - Different device → permanently rejected until code expires/revoked
        if (!ac.claimedBy) {
          // First use — lock to this device
          await this._putAccessCode(code, {
            ...ac,
            claimedBy: deviceId,
            claimedAt: new Date().toISOString(),
          });
          console.log(`[relay] Code ${code} claimed by device ${deviceId.slice(0,8)}…`);
        } else if (ac.claimedBy !== deviceId) {
          // Different device — reject
          console.log(`[relay] Code ${code} rejected — claimed by different device`);
          return send(ws, { type: 'JOIN_ERROR', reason: 'This access code is already in use by another device' });
        }
        // Same device reconnecting — allowed, fall through

        // Find an available session (any online host, not full).
        // BUG-FIX: if no host is up yet, wait up to JOIN_WAIT_MS for one to appear
        // (previously _waitForHost was defined but never called, so clients that
        // connected 1–2 s before the host got a permanent JOIN_ERROR).
        let targetSession = null;
        let targetCode = null;
        const findSession = () => {
          for (const [c, s] of this.sessions) {
            if (s.host && s.host.readyState === WebSocket.OPEN && s.clients.size < MAX_CLIENTS) {
              return { s, c };
            }
          }
          return null;
        };
        let found = findSession();
        if (!found) {
          // Wait for any host session to become available
          const firstSessionCode = this.sessions.size > 0 ? [...this.sessions.keys()][0] : '__any__';
          const waited = await this._waitForHost(firstSessionCode, JOIN_WAIT_MS);
          if (waited) found = findSession();
        }
        if (!found) {
          return send(ws, { type: 'JOIN_ERROR', reason: 'No hosts available right now. Try again shortly.' });
        }
        targetSession = found.s; targetCode = found.c;

        // BUG-FIX: use a monotonic per-session counter for tunnel IPs instead of
        // clients.size, which causes IP collisions when clients disconnect/reconnect
        // (size decreases, so a new client gets the same .x as an existing one).
        if (!this.sessionIpCounters.has(targetCode)) this.sessionIpCounters.set(targetCode, 1);
        const ipIndex = this.sessionIpCounters.get(targetCode);
        this.sessionIpCounters.set(targetCode, ipIndex + 1);

        const clientId = `client-${Date.now()}-${Math.random().toString(36).slice(2,6)}`;
        const tunIp    = `10.8.0.${ipIndex + 1}`; // .2 for first client, .3 for second, etc.
        targetSession.clients.add(ws);
        const conn = this.connections.get(ws) || {};
        this.connections.set(ws, { ...conn, role: 'client', code: targetCode, id: clientId, tunIp, lastPong: Date.now() });
        send(ws, { type: 'JOIN_SUCCESS', code: targetCode, netType: targetSession.netType, clientId, tunIp });
        send(targetSession.host, { type: 'CLIENT_CONNECTED', clientId, tunIp, totalClients: targetSession.clients.size });
        // Update host client count
        const hostConn = this.connections.get(targetSession.host);
        if (hostConn?.id) {
          const hId = [...this.hostRegistry.keys()].find(id => {
            const h = this.hostRegistry.get(id);
            return h.sessionCode === targetCode;
          });
          if (hId) this._upsertHost(hId, { clientCount: targetSession.clients.size });
        }
        console.log(`[relay] Client ${clientId} joined ${targetCode} via admin code → ${tunIp}`);
        await this._scheduleAlarm();
        break;
      }

      case 'HOST_RECONNECT': {
        let existingCode = null;
        for (const [c, s] of this.sessions) {
          if (s.hostId && s.hostId === msg.hostId) { existingCode = c; break; }
        }
        if (!existingCode) {
          const stored = await this.state.storage.list({ prefix: 'session:' });
          for (const [key, val] of stored) {
            try {
              const meta = JSON.parse(val);
              if (meta.hostId === msg.hostId && Date.now() - meta.createdAt < SESSION_TIMEOUT_MS) {
                existingCode = key.replace('session:', '');
                if (!this.sessions.has(existingCode)) {
                  this.sessions.set(existingCode, { host: null, clients: new Set(), createdAt: meta.createdAt, netType: meta.netType || 'WiFi', hostId: meta.hostId, hostRay: null, _persisted: true });
                }
                break;
              }
            } catch (_) {}
          }
        }
        if (!existingCode) {
          const code = generateCode(this.sessions);
          const session = { host: ws, clients: new Set(), createdAt: Date.now(), netType: msg.netType || 'WiFi', hostRay: cfRay, hostId: msg.hostId };
          this.sessions.set(code, session);
          const conn = this.connections.get(ws) || {};
          this.connections.set(ws, { ...conn, role: 'host', code, id: `host-${code}`, lastPong: Date.now() });
          send(ws, { type: 'SESSION_CREATED', code, netType: msg.netType });
          await this._persistSession(code, session);
          if (msg.hostId) this._markHostOnline(msg.hostId, msg.netType || 'WiFi', code);
        } else {
          const session = this.sessions.get(existingCode);
          if (session.host) this.connections.delete(session.host);
          session.host = ws; session.hostRay = cfRay;
          const conn = this.connections.get(ws) || {};
          this.connections.set(ws, { ...conn, role: 'host', code: existingCode, id: `host-${existingCode}`, lastPong: Date.now() });
          send(ws, { type: 'SESSION_RESUMED', code: existingCode, netType: session.netType });
          session.clients.forEach(cws => send(cws, { type: 'HOST_FAILOVER', newSessionCode: existingCode }));
          if (msg.hostId) this._markHostOnline(msg.hostId, msg.netType || 'WiFi', existingCode);
          this._resolveJoinWaiters(existingCode);
        }
        await this._scheduleAlarm();
        break;
      }

      case 'PONG': {
        const conn = this.connections.get(ws);
        if (conn) conn.lastPong = Date.now();
        break;
      }

      case 'HOST_LEAVE': {
        const conn = this.connections.get(ws);
        if (conn?.role === 'host') await this._cleanupSession(conn.code);
        break;
      }

      case 'CLIENT_LEAVE': {
        const conn = this.connections.get(ws); if (!conn) return;
        const session = this.sessions.get(conn.code);
        if (session) {
          session.clients.delete(ws);
          if (session.host?.readyState === WebSocket.OPEN)
            send(session.host, { type: 'CLIENT_DISCONNECTED', clientId: conn.id, totalClients: session.clients.size });
        }
        this.connections.delete(ws);
        break;
      }

      default:
        console.warn(`[relay] Unknown type: ${msg.type}`);
    }
  }

  _waitForHost(code, timeoutMs) {
    return new Promise(resolve => {
      const session = this.sessions.get(code);
      if (session?.host?.readyState === WebSocket.OPEN) { resolve(true); return; }
      if (!this.joinWaiters.has(code)) this.joinWaiters.set(code, []);
      const timer = setTimeout(() => {
        const w = this.joinWaiters.get(code) || [];
        const i = w.findIndex(x => x.resolve === resolve);
        if (i !== -1) w.splice(i, 1);
        resolve(false);
      }, timeoutMs);
      this.joinWaiters.get(code).push({ resolve, timer });
    });
  }

  _resolveJoinWaiters(code) {
    const waiters = this.joinWaiters.get(code);
    if (!waiters || !waiters.length) return;
    waiters.forEach(({ resolve, timer }) => { clearTimeout(timer); resolve(true); });
    this.joinWaiters.delete(code);
  }

  _onClose(ws) {
    const conn = this.connections.get(ws);
    if (!conn || !conn.role) { this.connections.delete(ws); return; }
    if (conn.role === 'host') {
      // Find hostId for this session
      const session = this.sessions.get(conn.code);
      const hostId = session?.hostId;
      setTimeout(async () => {
        const s = this.sessions.get(conn.code);
        if (s && s.host === ws) {
          if (hostId) this._markHostOffline(hostId);
          await this._cleanupSession(conn.code);
        }
      }, HOST_RECONNECT_WAIT);
    } else if (conn.role === 'client') {
      const session = this.sessions.get(conn.code);
      if (session) {
        session.clients.delete(ws);
        if (session.host?.readyState === WebSocket.OPEN)
          send(session.host, { type: 'CLIENT_DISCONNECTED', clientId: conn.id, totalClients: session.clients.size });
      }
    }
    this.connections.delete(ws);
  }

  async _cleanupSession(code) {
    const session = this.sessions.get(code); if (!session) return;
    session.clients.forEach(cws => { send(cws, { type: 'HOST_LEFT', reason: 'Host disconnected' }); this.connections.delete(cws); });
    if (session.host) this.connections.delete(session.host);
    this.sessions.delete(code);
    this.sessionIpCounters.delete(code); // BUG-FIX: free IP counter for this session
    await this._deleteSession(code);
    const waiters = this.joinWaiters.get(code);
    if (waiters) { waiters.forEach(({ resolve, timer }) => { clearTimeout(timer); resolve(false); }); this.joinWaiters.delete(code); }
    console.log(`[relay] Session ${code} cleaned up`);
  }
}
