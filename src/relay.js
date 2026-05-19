/**
 * relay.js — NetShare Proxy Session Durable Object
 *
 * Host connects  → /ws/host/:code
 * Client connects → /ws/client/:code
 * DO bridges them: pipes raw binary frames both ways through Cloudflare.
 *
 * Session lifecycle:
 *   1. Host POSTs { ip, port, tunnelMode:true } → /register → { code, sessionId }
 *   2. Host POSTs /ping every 30s to keep session alive
 *   3. Client GETs /join/:code → { sessionId }
 *   4. Host + client open WebSockets → DO bridges them
 *   5. Host POSTs /deregister when done
 *
 * FIX LOG
 * FIX 1: PING_GRACE_MS raised 90s → 300s (mobile networks need more grace)
 * FIX 2: WS heartbeat every 25s prevents Cloudflare from killing idle sockets
 * FIX 3: 30s reconnect window — peer not killed immediately on disconnect
 * FIX 4: Text frames (heartbeats/control) are NEVER forwarded as binary data.
 *         Both message handlers check typeof evt.data === 'string' and drop them.
 *         Previously only binary ArrayBuffer frames should be forwarded, but the
 *         check was wrong — JSON.parse inside catch still let text frames through.
 * FIX 5: onMessage guard also handles ArrayBuffer explicitly (Cloudflare Workers
 *         can deliver binary frames as ArrayBuffer, not just string).
 * FIX 6: _closeTunnelPair now nulls out pair.host/pair.client before closing to
 *         prevent double-close races in the reconnect timer callbacks.
 */

const SESSION_TTL_MS      = 2 * 60 * 60 * 1000;
const PING_GRACE_MS       = 300 * 1000;           // FIX 1
const CODE_LENGTH         = 4;
const CODE_CHARS          = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const ALARM_INTERVAL      = 60_000;
const WS_HEARTBEAT_MS     = 25_000;               // FIX 2
const RECONNECT_WINDOW_MS = 30_000;               // FIX 3

function randomCode(existing) {
  let code;
  do {
    code = Array.from({ length: CODE_LENGTH }, () =>
      CODE_CHARS[Math.floor(Math.random() * CODE_CHARS.length)]
    ).join('');
  } while (existing.has(code));
  return code;
}

function randomChars(n) {
  return Array.from({ length: n }, () =>
    CODE_CHARS[Math.floor(Math.random() * CODE_CHARS.length)]
  ).join('');
}

function cors() {
  return {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-admin-key, x-requested-with',
  };
}

function jsonResp(data, status = 200) {
  return Response.json(data, { status, headers: cors() });
}

// FIX 4: Checks if a WebSocket message event carries a heartbeat/control frame.
// Returns true if the message should be DROPPED (not forwarded as data).
function isControlFrame(data) {
  if (typeof data === 'string') {
    try {
      const msg = JSON.parse(data);
      if (msg?.type === 'ping' || msg?.type === 'pong' ||
          msg?.type === 'paired' || msg?.type === 'waiting_for_client' ||
          msg?.type === 'waiting_for_host') {
        return true;
      }
    } catch (_) {}
    // Any text frame that isn't valid JSON binary data should be dropped
    return true;
  }
  // Binary (ArrayBuffer or ArrayBufferView) — this is real proxy data, forward it
  return false;
}

export class ProxySession {
  constructor(state, env) {
    this.state = state;
    this.env   = env;

    this.proxySessions = new Map();
    this.sessionIdMap  = new Map();
    this.tunnelPairs   = new Map();
    this.hostRegistry  = new Map();
    this._alarmScheduled = false;
    this._restored     = false;
  }

  async _restore() {
    if (this._restored) return;
    this._restored = true;
    try {
      const stored = await this.state.storage.list({ prefix: 'ps:' });
      const now    = Date.now();
      for (const [k, v] of stored) {
        try {
          const s = JSON.parse(v);
          if (now - s.lastPing > PING_GRACE_MS) {
            await this.state.storage.delete(k);
            continue;
          }
          this.proxySessions.set(s.code, s);
          this.sessionIdMap.set(s.sessionId, s.code);
        } catch (_) {}
      }
      const hosts = await this.state.storage.list({ prefix: 'host:' });
      for (const [k, v] of hosts) {
        try { this.hostRegistry.set(k.replace('host:', ''), JSON.parse(v)); } catch (_) {}
      }
    } catch (e) { console.error('[relay] restore:', e?.message); }
  }

  async _saveSession(s) {
    try { await this.state.storage.put(`ps:${s.code}`, JSON.stringify(s)); } catch (_) {}
  }

  async _removeSession(code) {
    try { await this.state.storage.delete(`ps:${code}`); } catch (_) {}
  }

  async _scheduleAlarm() {
    if (this._alarmScheduled) return;
    this._alarmScheduled = true;
    try { await this.state.storage.setAlarm(Date.now() + ALARM_INTERVAL); } catch (_) {}
  }

  async alarm() {
    this._alarmScheduled = false;
    const now = Date.now();
    for (const [code, s] of this.proxySessions) {
      if (now - s.lastPing > PING_GRACE_MS) {
        this.proxySessions.delete(code);
        this.sessionIdMap.delete(s.sessionId);
        await this._removeSession(code);
        this._closeTunnelPair(code);
        console.log(`[relay] Session ${code} expired`);
      }
    }
    if (this.proxySessions.size > 0) await this._scheduleAlarm();
  }

  // FIX 6: null out references before closing to prevent double-close races
  _closeTunnelPair(code) {
    const pair = this.tunnelPairs.get(code);
    if (!pair) return;
    if (pair.hostHeartbeat)        clearInterval(pair.hostHeartbeat);
    if (pair.clientHeartbeat)      clearInterval(pair.clientHeartbeat);
    if (pair.hostReconnectTimer)   clearTimeout(pair.hostReconnectTimer);
    if (pair.clientReconnectTimer) clearTimeout(pair.clientReconnectTimer);

    const h = pair.host;   pair.host   = null;  // FIX 6: null before close
    const c = pair.client; pair.client = null;
    try { h?.close(1000, 'Session ended'); }   catch (_) {}
    try { c?.close(1000, 'Session ended'); }   catch (_) {}

    this.tunnelPairs.delete(code);
  }

  _startHeartbeat(ws, code, side) {
    return setInterval(() => {
      try {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'ping' }));
        }
      } catch (_) {}
    }, WS_HEARTBEAT_MS);
  }

  async fetch(request) {
    const url  = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors() });

    await this._restore();

    if (path === '/register' && request.method === 'POST') {
      try {
        const { ip, port, type, tunnelMode } = await request.json();
        const code      = randomCode(this.proxySessions);
        const sessionId = crypto.randomUUID();
        const session   = {
          code, sessionId,
          ip:        ip   || null,
          port:      port ? parseInt(port) : null,
          type:      type || 'http-proxy',
          tunnelMode: !!tunnelMode,
          lastPing:  Date.now(),
          createdAt: Date.now(),
        };
        this.proxySessions.set(code, session);
        this.sessionIdMap.set(sessionId, code);
        await this._saveSession(session);
        await this._scheduleAlarm();

        if (tunnelMode) {
          this.tunnelPairs.set(code, {
            host: null, client: null,
            hostHeartbeat: null, clientHeartbeat: null,
            hostReconnectTimer: null, clientReconnectTimer: null,
          });
        }
        console.log(`[relay] Registered ${code} tunnelMode=${tunnelMode}`);
        return jsonResp({ code, sessionId, tunnelMode: !!tunnelMode });
      } catch (e) {
        return jsonResp({ error: e.message }, 500);
      }
    }

    if (path.startsWith('/join/') && request.method === 'GET') {
      const code = path.replace('/join/', '').toUpperCase().trim();
      const s    = this.proxySessions.get(code);
      if (!s) return jsonResp({ error: 'Session code not found or expired' }, 404);
      if (Date.now() - s.lastPing > PING_GRACE_MS) {
        this.proxySessions.delete(code);
        this.sessionIdMap.delete(s.sessionId);
        await this._removeSession(code);
        return jsonResp({ error: 'Session expired' }, 404);
      }
      return jsonResp({ ip: s.ip, port: s.port, sessionId: s.sessionId, code: s.code, tunnelMode: s.tunnelMode });
    }

    if (path === '/ping' && request.method === 'POST') {
      try {
        const { sessionId } = await request.json();
        const code = this.sessionIdMap.get(sessionId);
        if (!code) return jsonResp({ ok: false, reason: 'Session not found' }, 404);
        const s = this.proxySessions.get(code);
        if (!s) return jsonResp({ ok: false, reason: 'Session not found' }, 404);
        s.lastPing = Date.now();
        await this._saveSession(s);
        return jsonResp({ ok: true });
      } catch (e) {
        return jsonResp({ ok: false, reason: e.message }, 500);
      }
    }

    if (path === '/deregister' && request.method === 'POST') {
      try {
        const { sessionId } = await request.json();
        const code = this.sessionIdMap.get(sessionId);
        if (code) {
          this.proxySessions.delete(code);
          this.sessionIdMap.delete(sessionId);
          await this._removeSession(code);
          this._closeTunnelPair(code);
          console.log(`[relay] Deregistered ${code}`);
        }
        return jsonResp({ ok: true });
      } catch (e) {
        return jsonResp({ ok: false, reason: e.message }, 500);
      }
    }

    if (path.startsWith('/ws/host/') && request.headers.get('Upgrade') === 'websocket') {
      const code = path.replace('/ws/host/', '').toUpperCase().trim();
      return this._handleTunnelHost(request, code);
    }

    if (path.startsWith('/ws/client/') && request.headers.get('Upgrade') === 'websocket') {
      const code = path.replace('/ws/client/', '').toUpperCase().trim();
      return this._handleTunnelClient(request, code);
    }

    if (path === '/stats') {
      return jsonResp({
        activeSessions: this.proxySessions.size,
        sessions: [...this.proxySessions.values()].map(s => ({
          code: s.code, ip: s.ip, port: s.port,
          tunnelMode: s.tunnelMode, lastPing: s.lastPing, createdAt: s.createdAt,
        })),
      });
    }

    if (path === '/validate-code' && request.method === 'POST') {
      try {
        const b        = await request.json();
        const upper    = (b.code || '').toUpperCase();
        const deviceId = (b.deviceId || '').trim();
        const ac       = await this._getAC(upper);
        const now      = Date.now();
        if (!ac || !ac.isActive || new Date(ac.expiresAt).getTime() < now)
          return jsonResp({ valid: false, reason: 'Invalid or expired access code' });
        if (ac.claimedBy && deviceId && ac.claimedBy !== deviceId)
          return jsonResp({ valid: false, reason: 'Code already in use' });
        return jsonResp({ valid: true, reason: null });
      } catch { return jsonResp({ valid: false, reason: 'Server error' }); }
    }

    if (path.startsWith('/admin/')) {
      const key = request.headers.get('x-admin-key') || '';
      if (key !== (this.env.ADMIN_KEY || 'netshare-admin-2026'))
        return jsonResp({ error: 'Unauthorized' }, 401);
      return this._handleAdmin(request, url);
    }

    if (request.headers.get('Upgrade') === 'websocket') {
      const { 0: clientWs, 1: serverWs } = new WebSocketPair();
      serverWs.accept();
      return new Response(null, { status: 101, webSocket: clientWs });
    }

    return jsonResp({ message: 'NetShare Relay' });
  }

  // ── Host WebSocket handler ────────────────────────────────────────────────

  _handleTunnelHost(request, code) {
    const session = this.proxySessions.get(code);
    if (!session) return new Response('Session not found', { status: 404 });

    const { 0: clientWs, 1: serverWs } = new WebSocketPair();
    serverWs.accept();

    let pair = this.tunnelPairs.get(code);
    if (!pair) {
      pair = { host: null, client: null, hostHeartbeat: null, clientHeartbeat: null,
               hostReconnectTimer: null, clientReconnectTimer: null };
      this.tunnelPairs.set(code, pair);
    }

    if (pair.hostReconnectTimer) { clearTimeout(pair.hostReconnectTimer); pair.hostReconnectTimer = null; }
    if (pair.host) {
      try { pair.host.close(1000, 'Replaced'); } catch (_) {}
      if (pair.hostHeartbeat) { clearInterval(pair.hostHeartbeat); pair.hostHeartbeat = null; }
    }

    pair.host = serverWs;
    pair.hostHeartbeat = this._startHeartbeat(serverWs, code, 'host');

    serverWs.addEventListener('message', (evt) => {
      // FIX 4: drop ALL text frames — only binary proxy data gets forwarded
      if (isControlFrame(evt.data)) return;
      const p = this.tunnelPairs.get(code);
      if (p?.client && p.client.readyState === WebSocket.OPEN) {
        try { p.client.send(evt.data); } catch (_) {}
      }
    });

    serverWs.addEventListener('close', (evt) => {
      const p = this.tunnelPairs.get(code);
      if (!p) return;
      if (pair.hostHeartbeat) { clearInterval(pair.hostHeartbeat); pair.hostHeartbeat = null; }
      p.host = null;
      console.log(`[relay] Host WS closed for ${code} (${evt.code}). Reconnect window ${RECONNECT_WINDOW_MS}ms`);
      p.hostReconnectTimer = setTimeout(() => {
        const p2 = this.tunnelPairs.get(code);
        if (p2 && !p2.host) {
          console.log(`[relay] Host did not reconnect for ${code}, closing client`);
          const c = p2.client; p2.client = null;
          try { c?.close(1000, 'Host disconnected'); } catch (_) {}
          if (!p2.host && !p2.client) this.tunnelPairs.delete(code);
        }
      }, RECONNECT_WINDOW_MS);
    });

    serverWs.addEventListener('error', () => {
      const p = this.tunnelPairs.get(code);
      if (p) p.host = null;
    });

    if (pair.client && pair.client.readyState === WebSocket.OPEN) {
      try { serverWs.send(JSON.stringify({ type: 'paired' })); }    catch (_) {}
      try { pair.client.send(JSON.stringify({ type: 'paired' })); } catch (_) {}
    } else {
      try { serverWs.send(JSON.stringify({ type: 'waiting_for_client' })); } catch (_) {}
    }

    return new Response(null, { status: 101, webSocket: clientWs });
  }

  // ── Client WebSocket handler ──────────────────────────────────────────────

  _handleTunnelClient(request, code) {
    const session = this.proxySessions.get(code);
    if (!session) return new Response('Session not found', { status: 404 });

    const { 0: clientWs, 1: serverWs } = new WebSocketPair();
    serverWs.accept();

    let pair = this.tunnelPairs.get(code);
    if (!pair) {
      pair = { host: null, client: null, hostHeartbeat: null, clientHeartbeat: null,
               hostReconnectTimer: null, clientReconnectTimer: null };
      this.tunnelPairs.set(code, pair);
    }

    if (pair.clientReconnectTimer) { clearTimeout(pair.clientReconnectTimer); pair.clientReconnectTimer = null; }
    if (pair.client) {
      try { pair.client.close(1000, 'Replaced'); } catch (_) {}
      if (pair.clientHeartbeat) { clearInterval(pair.clientHeartbeat); pair.clientHeartbeat = null; }
    }

    pair.client = serverWs;
    pair.clientHeartbeat = this._startHeartbeat(serverWs, code, 'client');

    serverWs.addEventListener('message', (evt) => {
      // FIX 4: drop ALL text frames — only binary proxy data gets forwarded
      if (isControlFrame(evt.data)) return;
      const p = this.tunnelPairs.get(code);
      if (p?.host && p.host.readyState === WebSocket.OPEN) {
        try { p.host.send(evt.data); } catch (_) {}
      }
    });

    serverWs.addEventListener('close', (evt) => {
      const p = this.tunnelPairs.get(code);
      if (!p) return;
      if (pair.clientHeartbeat) { clearInterval(pair.clientHeartbeat); pair.clientHeartbeat = null; }
      p.client = null;
      console.log(`[relay] Client WS closed for ${code} (${evt.code}). Reconnect window ${RECONNECT_WINDOW_MS}ms`);
      p.clientReconnectTimer = setTimeout(() => {
        const p2 = this.tunnelPairs.get(code);
        if (p2 && !p2.client) {
          console.log(`[relay] Client did not reconnect for ${code}, closing host`);
          const h = p2.host; p2.host = null;
          try { h?.close(1000, 'Client disconnected'); } catch (_) {}
          if (!p2.host && !p2.client) this.tunnelPairs.delete(code);
        }
      }, RECONNECT_WINDOW_MS);
    });

    serverWs.addEventListener('error', () => {
      const p = this.tunnelPairs.get(code);
      if (p) p.client = null;
    });

    if (pair.host && pair.host.readyState === WebSocket.OPEN) {
      try { serverWs.send(JSON.stringify({ type: 'paired' })); }  catch (_) {}
      try { pair.host.send(JSON.stringify({ type: 'paired' })); } catch (_) {}
    } else {
      try { serverWs.send(JSON.stringify({ type: 'waiting_for_host' })); } catch (_) {}
    }

    return new Response(null, { status: 101, webSocket: clientWs });
  }

  // ── Access code helpers ───────────────────────────────────────────────────

  async _getAC(code) {
    try { const v = await this.state.storage.get(`ac:${code}`); return v ? JSON.parse(v) : null; }
    catch { return null; }
  }
  async _putAC(code, data) {
    try { await this.state.storage.put(`ac:${code}`, JSON.stringify(data)); } catch (_) {}
  }
  async _listAC() {
    try {
      const l = await this.state.storage.list({ prefix: 'ac:' });
      const out = [];
      for (const [k, v] of l) { try { out.push({ code: k.replace('ac:', ''), ...JSON.parse(v) }); } catch (_) {} }
      return out;
    } catch { return []; }
  }

  _upsertHost(hostId, updates) {
    const e = this.hostRegistry.get(hostId) || {
      hostId, isOnline: false, weeklyEarnings: 0,
      weeklyUptimeHours: 0, totalUptimeHours: 0,
      lastSeen: Date.now(), _onlineSince: null,
    };
    const m = { ...e, ...updates };
    this.hostRegistry.set(hostId, m);
    this.state.storage.put(`host:${hostId}`, JSON.stringify(m)).catch(() => {});
    return m;
  }

  async _handleAdmin(request, url) {
    const p = url.pathname;

    if (p === '/admin/stats') {
      return jsonResp({
        activeSessions: this.proxySessions.size,
        totalHosts:     this.hostRegistry.size,
        onlineHosts:    [...this.hostRegistry.values()].filter(h => h.isOnline).length,
        activeTunnels:  this.tunnelPairs.size,
      });
    }

    if (p === '/admin/codes' && request.method === 'GET') {
      return jsonResp({ codes: await this._listAC() });
    }

    if (p === '/admin/codes/generate' && request.method === 'POST') {
      try {
        const b     = await request.json();
        const count = Math.min(parseInt(b.count) || 1, 100);
        const hours = parseInt(b.expiresInHours) || 24;
        const codes = [];
        for (let i = 0; i < count; i++) {
          const code = `${randomChars(4)}-${randomChars(4)}`;
          const data = {
            isActive: true, label: b.label || '',
            createdAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + hours * 3_600_000).toISOString(),
            claimedBy: null, claimedAt: null,
          };
          await this._putAC(code, data);
          codes.push({ code, ...data });
        }
        return jsonResp({ codes });
      } catch (e) { return jsonResp({ error: e.message }, 400); }
    }

    if (p === '/admin/codes/revoke' && request.method === 'POST') {
      try {
        const { code } = await request.json();
        const upper    = (code || '').toUpperCase();
        const ac       = await this._getAC(upper);
        if (!ac) return jsonResp({ error: 'Not found' }, 404);
        await this._putAC(upper, { ...ac, isActive: false });
        return jsonResp({ success: true });
      } catch (e) { return jsonResp({ error: e.message }, 400); }
    }

    if (p === '/admin/sessions') {
      return jsonResp({
        sessions: [...this.proxySessions.values()].map(s => ({
          code: s.code, ip: s.ip, port: s.port,
          tunnelMode: s.tunnelMode, lastPing: s.lastPing, createdAt: s.createdAt,
        })),
      });
    }

    return jsonResp({ error: 'Not found' }, 404);
  }
}
