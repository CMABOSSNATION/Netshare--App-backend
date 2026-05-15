/**
 * relay.js — Cloudflare Durable Object (Free Plan)
 *
 * ALL PREVIOUS FIXES RETAINED +
 *
 * FIX-9: Session persistence via DO SQLite storage.
 *   Sessions are saved to storage on create and deleted on cleanup.
 *   On DO cold start, sessions are restored from storage so clients
 *   never get "session not found" after a Cloudflare restart.
 *
 * FIX-10: validate-code checks BOTH in-memory sessions AND storage,
 *   so a client validating a code right after a cold start still gets
 *   a valid response even before the host has reconnected.
 *
 * FIX-11: CLIENT_JOIN waits for host to reconnect up to 10s before
 *   returning "Host is offline" — handles the brief gap during cold start.
 *
 * FIX-12: Host reconnect grace period extended to 30s to give host
 *   time to reconnect after a DO cold start.
 */

const CODE_CHARS          = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const SESSION_TIMEOUT_MS  = 6 * 3_600_000;  // 6 hours
const MAX_CLIENTS         = 5;
const SMALL_FRAME         = 512;
const MAX_BUFFERED        = 256 * 1024;
const ALARM_INTERVAL_MS   = 20_000;
const PONG_TIMEOUT_MS     = 60_000;
const HOST_RECONNECT_WAIT = 30_000;  // FIX-12: 30s grace for host to reconnect
const JOIN_WAIT_MS        = 10_000;  // FIX-11: wait up to 10s for host

// ── Helpers ────────────────────────────────────────────────────────────────

function generateCode(sessions) {
  let code;
  do {
    const p1 = Array.from({ length: 4 }, () =>
      CODE_CHARS[Math.floor(Math.random() * CODE_CHARS.length)]
    ).join('');
    const p2 = Array.from({ length: 4 }, () =>
      CODE_CHARS[Math.floor(Math.random() * CODE_CHARS.length)]
    ).join('');
    code = `${p1}-${p2}`;
  } while (sessions.has(code));
  return code;
}

function send(ws, obj) {
  try {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
  } catch (_) {}
}

function sendBinary(ws, data) {
  try {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    if (ws.bufferedAmount > MAX_BUFFERED) return;
    const len = data instanceof ArrayBuffer ? data.byteLength : (data.length || 0);
    if (len <= SMALL_FRAME) {
      ws.send(data);
    } else {
      Promise.resolve().then(() => {
        if (ws && ws.readyState === WebSocket.OPEN) ws.send(data);
      });
    }
  } catch (_) {}
}

function parseCfHeaders(request) {
  const clientIp = request.headers.get('cf-connecting-ip')
    || request.headers.get('x-forwarded-for')
    || 'unknown';
  const cfRay = request.headers.get('cf-ray') || null;
  let isQuic = false;
  try {
    const cfVisitor = request.headers.get('cf-visitor');
    if (cfVisitor) {
      const v = JSON.parse(cfVisitor);
      isQuic = v.scheme === 'https' && cfRay !== null;
    }
  } catch (_) {}
  return { clientIp, cfRay, isQuic };
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-requested-with',
  };
}

// ── Durable Object ─────────────────────────────────────────────────────────

export class RelaySession {
  constructor(state, env) {
    this.state = state;
    this.env   = env;

    // In-memory: live WebSocket connections
    this.sessions    = new Map(); // code → { host, clients: Set<ws>, createdAt, netType, hostId, hostRay }
    this.connections = new Map(); // ws → { role, code, id, cfRay, isQuic, tunIp?, lastPong }

    // FIX-11: pending join waiters: code → [{ ws, resolve }]
    this.joinWaiters = new Map();

    this._alarmScheduled = false;
    this._restored       = false;
  }

  // ── FIX-9: Restore sessions from SQLite on cold start ─────────────────────
  async _restoreSessions() {
    if (this._restored) return;
    this._restored = true;
    try {
      const stored = await this.state.storage.list({ prefix: 'session:' });
      const now    = Date.now();
      for (const [key, val] of stored) {
        try {
          const meta = JSON.parse(val);
          // Skip expired sessions
          if (now - meta.createdAt > SESSION_TIMEOUT_MS) {
            await this.state.storage.delete(key);
            continue;
          }
          const code = key.replace('session:', '');
          // Restore without live host/clients — they reconnect via WebSocket
          this.sessions.set(code, {
            host:      null,   // will be set when host reconnects
            clients:   new Set(),
            createdAt: meta.createdAt,
            netType:   meta.netType || 'WiFi',
            hostId:    meta.hostId  || null,
            hostRay:   null,
            _persisted: true,  // flag: restored from storage
          });
          console.log(`[relay] Restored session ${code} from storage`);
        } catch (_) {}
      }
    } catch (e) {
      console.error('[relay] _restoreSessions error:', e?.message);
    }
  }

  // ── FIX-9: Persist session metadata to SQLite ──────────────────────────────
  async _persistSession(code, session) {
    try {
      await this.state.storage.put(`session:${code}`, JSON.stringify({
        createdAt: session.createdAt,
        netType:   session.netType,
        hostId:    session.hostId,
      }));
    } catch (e) {
      console.error('[relay] _persistSession error:', e?.message);
    }
  }

  // ── FIX-9: Delete session from SQLite ──────────────────────────────────────
  async _deletePersistedSession(code) {
    try {
      await this.state.storage.delete(`session:${code}`);
    } catch (_) {}
  }

  // ── Schedule alarm ─────────────────────────────────────────────────────────
  async _scheduleAlarm() {
    if (this._alarmScheduled) return;
    this._alarmScheduled = true;
    try {
      await this.state.storage.setAlarm(Date.now() + ALARM_INTERVAL_MS);
    } catch (_) {}
  }

  // ── Alarm handler ──────────────────────────────────────────────────────────
  async alarm() {
    this._alarmScheduled = false;
    const now = Date.now();

    for (const [code, session] of this.sessions) {
      if (now - session.createdAt > SESSION_TIMEOUT_MS) {
        await this._cleanupSession(code);
        continue;
      }

      const hostConn = session.host ? this.connections.get(session.host) : null;
      if (session.host && session.host.readyState === WebSocket.OPEN) {
        if (hostConn && now - hostConn.lastPong > PONG_TIMEOUT_MS) {
          console.log(`[relay] Host dead (no pong) in session ${code}`);
          try { session.host.close(1001, 'Ping timeout'); } catch (_) {}
        } else {
          send(session.host, { type: 'PING' });
        }
      }

      session.clients.forEach(ws => {
        const conn = this.connections.get(ws);
        if (ws.readyState === WebSocket.OPEN) {
          if (conn && now - conn.lastPong > PONG_TIMEOUT_MS) {
            console.log(`[relay] Client dead (no pong) ${conn?.id}`);
            try { ws.close(1001, 'Ping timeout'); } catch (_) {}
          } else {
            send(ws, { type: 'PING' });
          }
        }
      });
    }

    if (this.sessions.size > 0) {
      await this._scheduleAlarm();
    }
  }

  // ── Fetch entry point ──────────────────────────────────────────────────────
  async fetch(request) {
    // FIX-9: Always restore sessions first on any request
    await this._restoreSessions();

    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    if (url.pathname === '/stats') {
      let totalClients = 0;
      this.sessions.forEach(s => { totalClients += s.clients.size; });
      return Response.json(
        { activeSessions: this.sessions.size, totalClients },
        { headers: corsHeaders() }
      );
    }

    // FIX-10: validate-code checks both memory AND storage
    if (url.pathname === '/validate-code' && request.method === 'POST') {
      try {
        const { code } = await request.json();
        const upper = (code || '').toUpperCase();
        let valid = this.sessions.has(upper);
        // FIX-10: also check storage in case of cold start
        if (!valid) {
          const stored = await this.state.storage.get(`session:${upper}`);
          if (stored) {
            try {
              const meta = JSON.parse(stored);
              valid = (Date.now() - meta.createdAt) < SESSION_TIMEOUT_MS;
            } catch (_) {}
          }
        }
        return Response.json(
          { valid, reason: valid ? null : 'Session not found' },
          { headers: corsHeaders() }
        );
      } catch {
        return Response.json(
          { valid: false, reason: 'Server error' },
          { headers: corsHeaders() }
        );
      }
    }

    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('NetShare Relay is running', {
        status: 200,
        headers: { 'Content-Type': 'text/plain', ...corsHeaders() },
      });
    }

    const { 0: client, 1: server } = new WebSocketPair();
    server.accept();
    this._handleConnection(server, request);
    return new Response(null, { status: 101, webSocket: client });
  }

  // ── WebSocket connection ───────────────────────────────────────────────────
  _handleConnection(ws, request) {
    const { clientIp, cfRay, isQuic } = parseCfHeaders(request);
    console.log(`[relay] New WS from ${clientIp}`);
    this.connections.set(ws, {
      role: null, code: null, id: null, cfRay, isQuic, lastPong: Date.now()
    });
    ws.addEventListener('message', e => this._onMessage(ws, e.data, cfRay, isQuic));
    ws.addEventListener('close',   () => this._onClose(ws));
    ws.addEventListener('error',   err => console.error('[relay] WS error:', err));
  }

  // ── Message handler ────────────────────────────────────────────────────────
  async _onMessage(ws, data, cfRay, isQuic) {
    // Binary relay
    if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
      const conn = this.connections.get(ws); if (!conn) return;
      const session = this.sessions.get(conn.code); if (!session) return;
      if (conn.role === 'client') {
        if (session.host?.readyState === WebSocket.OPEN) sendBinary(session.host, data);
      } else if (conn.role === 'host') {
        session.clients.forEach(cws => sendBinary(cws, data));
      }
      return;
    }

    let msg;
    try { msg = JSON.parse(data); } catch { return; }

    switch (msg.type) {

      case 'HOST_REGISTER': {
        // Replace stale session with same hostId
        if (msg.hostId) {
          for (const [c, s] of this.sessions) {
            if (s.hostId === msg.hostId) {
              await this._cleanupSession(c);
              break;
            }
          }
        }
        const code = generateCode(this.sessions);
        const session = {
          host:      ws,
          clients:   new Set(),
          createdAt: Date.now(),
          netType:   msg.netType || 'WiFi',
          hostRay:   cfRay,
          hostId:    msg.hostId || null,
        };
        this.sessions.set(code, session);
        const conn = this.connections.get(ws) || {};
        this.connections.set(ws, { ...conn, role: 'host', code, id: `host-${code}`, lastPong: Date.now() });
        send(ws, { type: 'SESSION_CREATED', code, netType: msg.netType });
        // FIX-9: persist to SQLite immediately
        await this._persistSession(code, session);
        // FIX-11: notify any waiting clients that host is now online
        this._resolveJoinWaiters(code);
        console.log(`[relay] Session ${code} created and persisted`);
        await this._scheduleAlarm();
        break;
      }

      case 'CLIENT_JOIN': {
        const code = (msg.accessCode || msg.code || '').toUpperCase();
        if (!code) return send(ws, { type: 'JOIN_ERROR', reason: 'No code provided' });

        let session = this.sessions.get(code);

        // FIX-10: if session not in memory, check storage (cold start recovery)
        if (!session) {
          const stored = await this.state.storage.get(`session:${code}`);
          if (stored) {
            try {
              const meta = JSON.parse(stored);
              if (Date.now() - meta.createdAt < SESSION_TIMEOUT_MS) {
                // Recreate skeleton session — host will reconnect shortly
                session = {
                  host:      null,
                  clients:   new Set(),
                  createdAt: meta.createdAt,
                  netType:   meta.netType || 'WiFi',
                  hostId:    meta.hostId  || null,
                  hostRay:   null,
                  _persisted: true,
                };
                this.sessions.set(code, session);
                console.log(`[relay] Restored session ${code} from storage for joining client`);
              }
            } catch (_) {}
          }
        }

        if (!session) return send(ws, { type: 'JOIN_ERROR', reason: 'Session not found' });
        if (session.clients.size >= MAX_CLIENTS)
          return send(ws, { type: 'JOIN_ERROR', reason: 'Session is full' });

        // FIX-11: if host not online, wait up to 10s for host to reconnect
        if (!session.host || session.host.readyState !== WebSocket.OPEN) {
          console.log(`[relay] Client waiting for host on session ${code}`);
          const hostOnline = await this._waitForHost(code, JOIN_WAIT_MS);
          if (!hostOnline) {
            return send(ws, { type: 'JOIN_ERROR', reason: 'Host is offline — please try again in a moment' });
          }
          // Re-fetch session after wait
          session = this.sessions.get(code);
          if (!session) return send(ws, { type: 'JOIN_ERROR', reason: 'Session expired' });
        }

        const clientId = `client-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
        const tunIp    = `10.8.0.${session.clients.size + 2}`;
        session.clients.add(ws);
        const conn = this.connections.get(ws) || {};
        this.connections.set(ws, { ...conn, role: 'client', code, id: clientId, tunIp, lastPong: Date.now() });
        send(ws, { type: 'JOIN_SUCCESS', code, netType: session.netType, clientId, tunIp });
        send(session.host, { type: 'CLIENT_CONNECTED', clientId, tunIp, totalClients: session.clients.size });
        console.log(`[relay] Client ${clientId} joined ${code} → ${tunIp}`);
        await this._scheduleAlarm();
        break;
      }

      case 'HOST_RECONNECT': {
        let existingCode = null;
        // Check memory first
        for (const [c, s] of this.sessions) {
          if (s.hostId && s.hostId === msg.hostId) { existingCode = c; break; }
        }
        // FIX-9: Check storage if not in memory
        if (!existingCode) {
          const stored = await this.state.storage.list({ prefix: 'session:' });
          for (const [key, val] of stored) {
            try {
              const meta = JSON.parse(val);
              if (meta.hostId === msg.hostId && Date.now() - meta.createdAt < SESSION_TIMEOUT_MS) {
                existingCode = key.replace('session:', '');
                // Restore session skeleton if not in memory
                if (!this.sessions.has(existingCode)) {
                  this.sessions.set(existingCode, {
                    host: null, clients: new Set(),
                    createdAt: meta.createdAt, netType: meta.netType || 'WiFi',
                    hostId: meta.hostId, hostRay: null, _persisted: true,
                  });
                }
                break;
              }
            } catch (_) {}
          }
        }

        if (!existingCode) {
          const code = generateCode(this.sessions);
          const session = {
            host: ws, clients: new Set(), createdAt: Date.now(),
            netType: msg.netType || 'WiFi', hostRay: cfRay, hostId: msg.hostId,
          };
          this.sessions.set(code, session);
          const conn = this.connections.get(ws) || {};
          this.connections.set(ws, { ...conn, role: 'host', code, id: `host-${code}`, lastPong: Date.now() });
          send(ws, { type: 'SESSION_CREATED', code, netType: msg.netType });
          await this._persistSession(code, session);
        } else {
          const session = this.sessions.get(existingCode);
          if (session.host) this.connections.delete(session.host);
          session.host    = ws;
          session.hostRay = cfRay;
          const conn = this.connections.get(ws) || {};
          this.connections.set(ws, { ...conn, role: 'host', code: existingCode, id: `host-${existingCode}`, lastPong: Date.now() });
          send(ws, { type: 'SESSION_RESUMED', code: existingCode, netType: session.netType });
          session.clients.forEach(cws =>
            send(cws, { type: 'HOST_FAILOVER', newSessionCode: existingCode })
          );
          // FIX-11: resolve any clients waiting for host
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

  // ── FIX-11: Wait for host to come online ──────────────────────────────────
  _waitForHost(code, timeoutMs) {
    return new Promise(resolve => {
      const session = this.sessions.get(code);
      if (session?.host?.readyState === WebSocket.OPEN) {
        resolve(true);
        return;
      }
      if (!this.joinWaiters.has(code)) this.joinWaiters.set(code, []);
      const timer = setTimeout(() => {
        const waiters = this.joinWaiters.get(code) || [];
        const idx = waiters.findIndex(w => w.resolve === resolve);
        if (idx !== -1) waiters.splice(idx, 1);
        resolve(false);
      }, timeoutMs);
      this.joinWaiters.get(code).push({ resolve, timer });
    });
  }

  // ── FIX-11: Resolve waiting clients when host reconnects ─────────────────
  _resolveJoinWaiters(code) {
    const waiters = this.joinWaiters.get(code);
    if (!waiters || waiters.length === 0) return;
    waiters.forEach(({ resolve, timer }) => {
      clearTimeout(timer);
      resolve(true);
    });
    this.joinWaiters.delete(code);
  }

  // ── Close handler ──────────────────────────────────────────────────────────
  _onClose(ws) {
    const conn = this.connections.get(ws);
    if (!conn || !conn.role) {
      this.connections.delete(ws);
      return;
    }
    if (conn.role === 'host') {
      // FIX-12: 30s grace period for host to reconnect
      setTimeout(async () => {
        const session = this.sessions.get(conn.code);
        if (session && session.host === ws) {
          console.log(`[relay] Host did not reconnect in 30s, cleaning up ${conn.code}`);
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

  // ── Session cleanup ────────────────────────────────────────────────────────
  async _cleanupSession(code) {
    const session = this.sessions.get(code); if (!session) return;
    session.clients.forEach(cws => {
      send(cws, { type: 'HOST_LEFT', reason: 'Host disconnected' });
      this.connections.delete(cws);
    });
    if (session.host) this.connections.delete(session.host);
    this.sessions.delete(code);
    // FIX-9: remove from SQLite too
    await this._deletePersistedSession(code);
    // FIX-11: resolve any waiters with failure
    const waiters = this.joinWaiters.get(code);
    if (waiters) {
      waiters.forEach(({ resolve, timer }) => { clearTimeout(timer); resolve(false); });
      this.joinWaiters.delete(code);
    }
    console.log(`[relay] Session ${code} cleaned up`);
  }
}
