/**
 * relay.js — NetShare Proxy Session Durable Object
 *
 * ── Global Tunnel Mode only (LAN mode removed) ───────────────────────────────
 *
 * Host connects via WebSocket to /ws/host/:code
 * Client connects via WebSocket to /ws/client/:code
 * This DO pairs them and pipes raw binary frames both ways through Cloudflare.
 * Client uses Android VpnService — ALL device traffic (WiFi + mobile data)
 * is captured and routed through the tunnel automatically. No manual setup.
 *
 * Session lifecycle:
 *   1. Host POSTs { ip, port, tunnelMode:true } to /register → { code, sessionId }
 *   2. Host POSTs to /ping every 30s to keep session alive
 *   3. Client GETs /join/:code → gets { sessionId }
 *   4. Host + client both open WSs → DO bridges them with binary frame piping
 *   5. Host POSTs /deregister when done
 *
 * ── FIX LOG ───────────────────────────────────────────────────────────────────
 * FIX 1: PING_GRACE_MS raised 90s → 300s. 90s was too tight for mobile networks.
 * FIX 2: WS heartbeat added. Server sends JSON ping frame every 25s so Cloudflare
 *         never silently drops idle WebSockets (CF kills WS idle > ~100s).
 * FIX 3: Reconnect window added. When one side disconnects, the other side is NOT
 *         immediately closed. A 30s window allows the dropped peer to reconnect.
 *         Only if no reconnect happens within the window do we close the other side.
 */

const SESSION_TTL_MS       = 2 * 60 * 60 * 1000; // 2 hours
const PING_GRACE_MS        = 300 * 1000;          // FIX 1: 300s grace (was 90s)
const CODE_LENGTH          = 4;
const CODE_CHARS           = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const ALARM_INTERVAL       = 60_000;              // cleanup check every 60s
const WS_HEARTBEAT_MS      = 25_000;              // FIX 2: WS ping every 25s
const RECONNECT_WINDOW_MS  = 30_000;              // FIX 3: 30s reconnect grace

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

// ═══════════════════════════════════════════════════════════════════════════════
export class ProxySession {
  constructor(state, env) {
    this.state = state;
    this.env   = env;

    // Proxy sessions: code → { ip, port, sessionId, lastPing, tunnelMode }
    this.proxySessions = new Map();
    // sessionId → code (reverse lookup)
    this.sessionIdMap  = new Map();

    // ── WebSocket tunnel state ──────────────────────────────────────────────
    // For long-distance mode: pairs host WS ↔ client WS per session code
    // code → { host: WebSocket|null, client: WebSocket|null,
    //           hostReconnectTimer: id|null, clientReconnectTimer: id|null,
    //           hostHeartbeat: id|null, clientHeartbeat: id|null }
    this.tunnelPairs   = new Map();

    // Admin / access codes
    this.hostRegistry  = new Map();
    this._alarmScheduled = false;
    this._restored     = false;
  }

  // ── Restore state from storage ───────────────────────────────────────────
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
        // Clean up any tunnel pair
        this._closeTunnelPair(code);
        console.log(`[relay] Session ${code} expired`);
      }
    }
    if (this.proxySessions.size > 0) await this._scheduleAlarm();
  }

  // ── Close both sides of a tunnel pair ───────────────────────────────────
  _closeTunnelPair(code) {
    const pair = this.tunnelPairs.get(code);
    if (!pair) return;
    // Clear all timers
    if (pair.hostHeartbeat)        clearInterval(pair.hostHeartbeat);
    if (pair.clientHeartbeat)      clearInterval(pair.clientHeartbeat);
    if (pair.hostReconnectTimer)   clearTimeout(pair.hostReconnectTimer);
    if (pair.clientReconnectTimer) clearTimeout(pair.clientReconnectTimer);
    try { pair.host?.close(1000, 'Session ended'); }   catch (_) {}
    try { pair.client?.close(1000, 'Session ended'); } catch (_) {}
    this.tunnelPairs.delete(code);
  }

  // FIX 2: Start a heartbeat interval that sends JSON ping frames
  // so Cloudflare never kills the WS for idleness.
  _startHeartbeat(ws, code, side) {
    return setInterval(() => {
      try {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'ping' }));
        }
      } catch (_) {}
    }, WS_HEARTBEAT_MS);
  }

  // ════════════════════════════════════════════════════════════════════════════
  // Main fetch dispatcher
  // ════════════════════════════════════════════════════════════════════════════
  async fetch(request) {
    const url  = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors() });

    await this._restore();

    // ── POST /register ───────────────────────────────────────────────────────
    if (path === '/register' && request.method === 'POST') {
      try {
        const { ip, port, type, tunnelMode } = await request.json();
        // tunnelMode is always true — ip/port are optional (tunnel doesn't need them)

        const code      = randomCode(this.proxySessions);
        const sessionId = crypto.randomUUID();
        const session   = {
          code,
          sessionId,
          ip:          ip || null,
          port:        port ? parseInt(port) : null,
          type:        type || 'http-proxy',
          tunnelMode:  !!tunnelMode,
          lastPing:    Date.now(),
          createdAt:   Date.now(),
        };

        this.proxySessions.set(code, session);
        this.sessionIdMap.set(sessionId, code);
        await this._saveSession(session);
        await this._scheduleAlarm();

        // Pre-create tunnel pair slot if tunnelMode
        if (tunnelMode) {
          this.tunnelPairs.set(code, {
            host: null, client: null,
            hostHeartbeat: null, clientHeartbeat: null,
            hostReconnectTimer: null, clientReconnectTimer: null,
          });
        }

        console.log(`[relay] Registered session ${code} tunnelMode=${tunnelMode}`);
        return jsonResp({ code, sessionId, tunnelMode: !!tunnelMode });
      } catch (e) {
        return jsonResp({ error: e.message }, 500);
      }
    }

    // ── GET /join/:code ──────────────────────────────────────────────────────
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

      return jsonResp({
        ip:         s.ip,
        port:       s.port,
        sessionId:  s.sessionId,
        code:       s.code,
        tunnelMode: s.tunnelMode,
      });
    }

    // ── POST /ping — keeps session alive ─────────────────────────────────────
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

    // ── POST /deregister ──────────────────────────────────────────────────────
    if (path === '/deregister' && request.method === 'POST') {
      try {
        const { sessionId } = await request.json();
        const code = this.sessionIdMap.get(sessionId);
        if (code) {
          this.proxySessions.delete(code);
          this.sessionIdMap.delete(sessionId);
          await this._removeSession(code);
          this._closeTunnelPair(code);
          console.log(`[relay] Deregistered session ${code}`);
        }
        return jsonResp({ ok: true });
      } catch (e) {
        return jsonResp({ ok: false, reason: e.message }, 500);
      }
    }

    // ── WebSocket Tunnel: Host connects ───────────────────────────────────────
    if (path.startsWith('/ws/host/') && request.headers.get('Upgrade') === 'websocket') {
      const code = path.replace('/ws/host/', '').toUpperCase().trim();
      return this._handleTunnelHost(request, code);
    }

    // ── WebSocket Tunnel: Client connects ─────────────────────────────────────
    if (path.startsWith('/ws/client/') && request.headers.get('Upgrade') === 'websocket') {
      const code = path.replace('/ws/client/', '').toUpperCase().trim();
      return this._handleTunnelClient(request, code);
    }

    // ── GET /stats ────────────────────────────────────────────────────────────
    if (path === '/stats') {
      return jsonResp({
        activeSessions: this.proxySessions.size,
        sessions: [...this.proxySessions.values()].map(s => ({
          code:       s.code,
          ip:         s.ip,
          port:       s.port,
          tunnelMode: s.tunnelMode,
          lastPing:   s.lastPing,
          createdAt:  s.createdAt,
        })),
      });
    }

    // ── POST /validate-code ───────────────────────────────────────────────────
    if (path === '/validate-code' && request.method === 'POST') {
      try {
        const b = await request.json();
        const upper    = (b.code || '').toUpperCase();
        const deviceId = (b.deviceId || '').trim();
        const ac  = await this._getAC(upper);
        const now = Date.now();
        if (!ac || !ac.isActive || new Date(ac.expiresAt).getTime() < now)
          return jsonResp({ valid: false, reason: 'Invalid or expired access code' });
        if (ac.claimedBy && deviceId && ac.claimedBy !== deviceId)
          return jsonResp({ valid: false, reason: 'Code already in use' });
        return jsonResp({ valid: true, reason: null });
      } catch { return jsonResp({ valid: false, reason: 'Server error' }); }
    }

    // ── Admin routes ──────────────────────────────────────────────────────────
    if (path.startsWith('/admin/')) {
      const key = request.headers.get('x-admin-key') || '';
      if (key !== (this.env.ADMIN_KEY || 'netshare-admin-2026'))
        return jsonResp({ error: 'Unauthorized' }, 401);
      return this._handleAdmin(request, url);
    }

    // ── Legacy broker WebSocket (backward compat) ─────────────────────────────
    if (request.headers.get('Upgrade') === 'websocket') {
      const { 0: clientWs, 1: serverWs } = new WebSocketPair();
      serverWs.accept();
      return new Response(null, { status: 101, webSocket: clientWs });
    }

    return jsonResp({ message: 'NetShare Relay' });
  }

  // ════════════════════════════════════════════════════════════════════════════
  // WebSocket Tunnel Logic (long-distance / 300km+ mode)
  // ════════════════════════════════════════════════════════════════════════════

  _handleTunnelHost(request, code) {
    const session = this.proxySessions.get(code);
    if (!session) {
      return new Response('Session not found', { status: 404 });
    }

    const { 0: clientWs, 1: serverWs } = new WebSocketPair();
    serverWs.accept();

    let pair = this.tunnelPairs.get(code);
    if (!pair) {
      pair = {
        host: null, client: null,
        hostHeartbeat: null, clientHeartbeat: null,
        hostReconnectTimer: null, clientReconnectTimer: null,
      };
      this.tunnelPairs.set(code, pair);
    }

    // FIX 3: Cancel any pending reconnect timer for host side
    if (pair.hostReconnectTimer) {
      clearTimeout(pair.hostReconnectTimer);
      pair.hostReconnectTimer = null;
    }
    // Close old host WS if still lingering
    if (pair.host) {
      try { pair.host.close(1000, 'Replaced by new connection'); } catch (_) {}
      if (pair.hostHeartbeat) { clearInterval(pair.hostHeartbeat); pair.hostHeartbeat = null; }
    }

    pair.host = serverWs;

    // FIX 2: Start heartbeat for host WS
    pair.hostHeartbeat = this._startHeartbeat(serverWs, code, 'host');

    serverWs.addEventListener('message', (evt) => {
      // Ignore heartbeat pings in both text and binary forms
      if (typeof evt.data === 'string') {
        try {
          const msg = JSON.parse(evt.data);
          if (msg?.type === 'ping' || msg?.type === 'pong') return;
        } catch (_) {}
        // Don't forward control text frames as data
        return;
      }
      // Forward binary host → client only
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
      console.log(`[relay] Host WS closed for ${code}, code=${evt.code}. Waiting ${RECONNECT_WINDOW_MS}ms for reconnect.`);

      // FIX 3: Give host time to reconnect before killing client
      p.hostReconnectTimer = setTimeout(() => {
        const p2 = this.tunnelPairs.get(code);
        if (p2 && !p2.host) {
          console.log(`[relay] Host did not reconnect for ${code}, closing client.`);
          try { p2.client?.close(1000, 'Host disconnected'); } catch (_) {}
          if (!p2.host && !p2.client) this.tunnelPairs.delete(code);
        }
      }, RECONNECT_WINDOW_MS);
    });

    serverWs.addEventListener('error', () => {
      const p = this.tunnelPairs.get(code);
      if (p) { p.host = null; }
    });

    // Signal pairing status
    if (pair.client && pair.client.readyState === WebSocket.OPEN) {
      try { serverWs.send(JSON.stringify({ type: 'paired' })); }   catch (_) {}
      try { pair.client.send(JSON.stringify({ type: 'paired' })); } catch (_) {}
    } else {
      try { serverWs.send(JSON.stringify({ type: 'waiting_for_client' })); } catch (_) {}
    }

    return new Response(null, { status: 101, webSocket: clientWs });
  }

  _handleTunnelClient(request, code) {
    const session = this.proxySessions.get(code);
    if (!session) {
      return new Response('Session not found', { status: 404 });
    }

    const { 0: clientWs, 1: serverWs } = new WebSocketPair();
    serverWs.accept();

    let pair = this.tunnelPairs.get(code);
    if (!pair) {
      pair = {
        host: null, client: null,
        hostHeartbeat: null, clientHeartbeat: null,
        hostReconnectTimer: null, clientReconnectTimer: null,
      };
      this.tunnelPairs.set(code, pair);
    }

    // FIX 3: Cancel any pending reconnect timer for client side
    if (pair.clientReconnectTimer) {
      clearTimeout(pair.clientReconnectTimer);
      pair.clientReconnectTimer = null;
    }
    // Close old client WS if still lingering
    if (pair.client) {
      try { pair.client.close(1000, 'Replaced by new connection'); } catch (_) {}
      if (pair.clientHeartbeat) { clearInterval(pair.clientHeartbeat); pair.clientHeartbeat = null; }
    }

    pair.client = serverWs;

    // FIX 2: Start heartbeat for client WS
    pair.clientHeartbeat = this._startHeartbeat(serverWs, code, 'client');

    serverWs.addEventListener('message', (evt) => {
      // Ignore heartbeat pings in both text and binary forms
      if (typeof evt.data === 'string') {
        try {
          const msg = JSON.parse(evt.data);
          if (msg?.type === 'ping' || msg?.type === 'pong') return;
        } catch (_) {}
        // Don't forward control text frames as data
        return;
      }
      // Forward binary client → host only
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
      console.log(`[relay] Client WS closed for ${code}, code=${evt.code}. Waiting ${RECONNECT_WINDOW_MS}ms for reconnect.`);

      // FIX 3: Give client time to reconnect before killing host
      p.clientReconnectTimer = setTimeout(() => {
        const p2 = this.tunnelPairs.get(code);
        if (p2 && !p2.client) {
          console.log(`[relay] Client did not reconnect for ${code}, closing host.`);
          try { p2.host?.close(1000, 'Client disconnected'); } catch (_) {}
          if (!p2.host && !p2.client) this.tunnelPairs.delete(code);
        }
      }, RECONNECT_WINDOW_MS);
    });

    serverWs.addEventListener('error', () => {
      const p = this.tunnelPairs.get(code);
      if (p) { p.client = null; }
    });

    // Signal pairing status
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

  // ── Admin routes ──────────────────────────────────────────────────────────
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
            isActive:  true,
            label:     b.label || '',
            createdAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + hours * 3_600_000).toISOString(),
            claimedBy: null,
            claimedAt: null,
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
        const upper = (code || '').toUpperCase();
        const ac = await this._getAC(upper);
        if (!ac) return jsonResp({ error: 'Not found' }, 404);
        await this._putAC(upper, { ...ac, isActive: false });
        return jsonResp({ success: true });
      } catch (e) { return jsonResp({ error: e.message }, 400); }
    }

    if (p === '/admin/sessions') {
      return jsonResp({
        sessions: [...this.proxySessions.values()].map(s => ({
          code:       s.code,
          ip:         s.ip,
          port:       s.port,
          tunnelMode: s.tunnelMode,
          lastPing:   s.lastPing,
          createdAt:  s.createdAt,
        })),
      });
    }

    return jsonResp({ error: 'Not found' }, 404);
  }
}
