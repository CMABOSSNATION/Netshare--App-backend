/**
 * relay.js — NetShare Proxy Session Durable Object
 *
 * Handles session signalling for the HTTP proxy architecture.
 * Traffic never flows through here — only IP:port exchange.
 *
 * Session lifecycle:
 *   1. Host POSTs { ip, port } to /register → gets { code, sessionId }
 *   2. Host POSTs to /ping every 30s to keep session alive
 *   3. Client GETs /join/:code → gets { ip, port, sessionId }
 *   4. Client configures Android WiFi proxy to ip:port
 *   5. All traffic flows directly host ↔ client (NOT through Cloudflare)
 *   6. Host POSTs /deregister when done
 */

const SESSION_TTL_MS   = 2 * 60 * 60 * 1000; // 2 hours
const CODE_TTL_MS      = 5 * 60 * 1000;       // code expires if host doesn't ping
const PING_GRACE_MS    = 90 * 1000;           // 90s grace before session dies
const CODE_LENGTH      = 4;
const CODE_CHARS       = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const ALARM_INTERVAL   = 60_000;              // cleanup check every 60s
const HOURLY_RATE      = 0.50;

function randomCode(existing) {
  let code;
  do {
    code = Array.from({ length: CODE_LENGTH }, () =>
      CODE_CHARS[Math.floor(Math.random() * CODE_CHARS.length)]
    ).join('');
  } while (existing.has(code));
  return code;
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

function randomChars(n) {
  return Array.from({ length: n }, () =>
    CODE_CHARS[Math.floor(Math.random() * CODE_CHARS.length)]
  ).join('');
}

// ═══════════════════════════════════════════════════════════════════════════════
export class ProxySession {
  constructor(state, env) {
    this.state = state;
    this.env   = env;

    // Proxy sessions: code → { ip, port, sessionId, lastPing, hostId }
    this.proxySessions  = new Map();
    // sessionId → code (reverse lookup)
    this.sessionIdMap   = new Map();

    // Legacy broker state (kept for backward compat)
    this.sessions          = new Map();
    this.connections       = new Map();
    this.joinWaiters       = new Map();
    this.hostRegistry      = new Map();
    this.sessionIpCounters = new Map();
    this._alarmScheduled   = false;
    this._restored         = false;
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
        console.log(`[relay] Session ${code} expired`);
      }
    }
    if (this.proxySessions.size > 0) await this._scheduleAlarm();
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
        const { ip, port, type } = await request.json();
        if (!ip || !port) return jsonResp({ error: 'Missing ip or port' }, 400);

        const code      = randomCode(this.proxySessions);
        const sessionId = crypto.randomUUID();
        const session   = {
          code, sessionId, ip, port: parseInt(port),
          type:      type || 'http-proxy',
          lastPing:  Date.now(),
          createdAt: Date.now(),
        };

        this.proxySessions.set(code, session);
        this.sessionIdMap.set(sessionId, code);
        await this._saveSession(session);
        await this._scheduleAlarm();

        console.log(`[relay] Registered session ${code} for ${ip}:${port}`);
        return jsonResp({ code, sessionId });
      } catch (e) {
        return jsonResp({ error: e.message }, 500);
      }
    }

    // ── GET /join/:code ──────────────────────────────────────────────────────
    if (path.startsWith('/join/') && request.method === 'GET') {
      const code = path.replace('/join/', '').toUpperCase().trim();
      const s    = this.proxySessions.get(code);

      if (!s) {
        return jsonResp({ error: 'Session code not found or expired' }, 404);
      }

      // Check session freshness
      if (Date.now() - s.lastPing > PING_GRACE_MS) {
        this.proxySessions.delete(code);
        this.sessionIdMap.delete(s.sessionId);
        await this._removeSession(code);
        return jsonResp({ error: 'Session expired' }, 404);
      }

      return jsonResp({
        ip:        s.ip,
        port:      s.port,
        sessionId: s.sessionId,
        code:      s.code,
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
          console.log(`[relay] Deregistered session ${code}`);
        }
        return jsonResp({ ok: true });
      } catch (e) {
        return jsonResp({ ok: false, reason: e.message }, 500);
      }
    }

    // ── GET /stats ────────────────────────────────────────────────────────────
    if (path === '/stats') {
      return jsonResp({
        activeSessions: this.proxySessions.size,
        sessions: [...this.proxySessions.values()].map(s => ({
          code:      s.code,
          ip:        s.ip,
          port:      s.port,
          lastPing:  s.lastPing,
          createdAt: s.createdAt,
        })),
      });
    }

    // ── POST /validate-code ───────────────────────────────────────────────────
    if (path === '/validate-code' && request.method === 'POST') {
      try {
        const b = await request.json();
        const upper = (b.code || '').toUpperCase();
        const deviceId = (b.deviceId || '').trim();
        const ac = await this._getAC(upper);
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

    // ── Legacy broker WebSocket ───────────────────────────────────────────────
    if (request.headers.get('Upgrade') === 'websocket') {
      const { 0: clientWs, 1: serverWs } = new WebSocketPair();
      serverWs.accept();
      return new Response(null, { status: 101, webSocket: clientWs });
    }

    return jsonResp({ message: 'NetShare Relay' });
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
    const e = this.hostRegistry.get(hostId) || { hostId, isOnline: false, weeklyEarnings: 0, weeklyUptimeHours: 0, totalUptimeHours: 0, lastSeen: Date.now(), _onlineSince: null };
    const m = { ...e, ...updates }; this.hostRegistry.set(hostId, m);
    this.state.storage.put(`host:${hostId}`, JSON.stringify(m)).catch(() => {}); return m;
  }

  // ── Admin routes ──────────────────────────────────────────────────────────
  async _handleAdmin(request, url) {
    const p = url.pathname;

    if (p === '/admin/stats') {
      return jsonResp({
        activeSessions: this.proxySessions.size,
        totalHosts:     this.hostRegistry.size,
        onlineHosts:    [...this.hostRegistry.values()].filter(h => h.isOnline).length,
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
          const data = { isActive: true, label: b.label || '', createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + hours * 3_600_000).toISOString(), claimedBy: null, claimedAt: null };
          await this._putAC(code, data); codes.push({ code, ...data });
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
          code: s.code, ip: s.ip, port: s.port,
          lastPing: s.lastPing, createdAt: s.createdAt,
        })),
      });
    }

    return jsonResp({ error: 'Not found' }, 404);
  }
}
