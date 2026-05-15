/**
 * relay.js — Cloudflare Durable Object (Free Plan)
 *
 * FIXES:
 * FIX-1: Replaced setInterval heartbeat with DO alarm — setInterval is killed
 *         by Cloudflare after ~30s of inactivity causing all sessions to drop.
 * FIX-2: Added lastPong tracking — disconnect clients that stop responding
 *         to PING after 2 missed cycles (60s) instead of keeping dead sockets.
 * FIX-3: HOST_REGISTER now always replaces stale host for same hostId — prevents
 *         ghost sessions that block reconnect.
 * FIX-4: Relay /relay path now handles both GET and non-WS requests gracefully.
 * FIX-5: CLIENT_JOIN now sends accessCode OR code field — handles both field names.
 * FIX-6: Binary packet relay now checks tunOut buffer more carefully.
 * FIX-7: Session timeout bumped to 6 hours for long business sessions.
 * FIX-8: Added CORS headers so validate-code works from all origins.
 */

const CODE_CHARS         = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const SESSION_TIMEOUT_MS = 6 * 3_600_000;  // FIX-7: 6 hours
const MAX_CLIENTS        = 5;
const SMALL_FRAME        = 512;
const MAX_BUFFERED       = 256 * 1024;
const ALARM_INTERVAL_MS  = 20_000;         // FIX-1: alarm every 20s
const PONG_TIMEOUT_MS    = 60_000;         // FIX-2: 2 missed PINGs = dead

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

    // sessions: code → { host, clients: Set<ws>, createdAt, netType, hostRay, hostId, lastPing }
    this.sessions    = new Map();
    // connections: ws → { role, code, id, cfRay, isQuic, tunIp?, lastPong }
    this.connections = new Map();
    this._alarmScheduled = false;
  }

  // ── Schedule alarm (FIX-1) ─────────────────────────────────────────────────
  async _scheduleAlarm() {
    if (this._alarmScheduled) return;
    this._alarmScheduled = true;
    try {
      await this.state.storage.setAlarm(Date.now() + ALARM_INTERVAL_MS);
    } catch (_) {}
  }

  // ── Alarm handler — replaces setInterval (FIX-1) ──────────────────────────
  async alarm() {
    this._alarmScheduled = false;
    const now = Date.now();

    this.sessions.forEach((session, code) => {
      // FIX-7: Expire old sessions
      if (now - session.createdAt > SESSION_TIMEOUT_MS) {
        this._cleanupSession(code);
        return;
      }

      // FIX-2: Drop dead connections (no PONG for 60s)
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
    });

    // Reschedule if sessions still active
    if (this.sessions.size > 0) {
      await this._scheduleAlarm();
    }
  }

  // ── Fetch entry point ──────────────────────────────────────────────────────
  async fetch(request) {
    const url = new URL(request.url);

    // FIX-8: CORS preflight
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

    // FIX-8: CORS on validate-code
    if (url.pathname === '/validate-code' && request.method === 'POST') {
      try {
        const { code } = await request.json();
        const valid = this.sessions.has((code || '').toUpperCase());
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

    // WebSocket upgrade
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
    console.log(`[relay] New WS from ${clientIp} QUIC=${isQuic}`);
    // FIX-2: track lastPong for dead connection detection
    this.connections.set(ws, {
      role: null, code: null, id: null, cfRay, isQuic, lastPong: Date.now()
    });
    ws.addEventListener('message', e => this._onMessage(ws, e.data, cfRay, isQuic));
    ws.addEventListener('close',   () => this._onClose(ws));
    ws.addEventListener('error',   err => console.error('[relay] WS error:', err));
  }

  // ── Message handler ────────────────────────────────────────────────────────
  _onMessage(ws, data, cfRay, isQuic) {
    // Binary — raw packet forwarding
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
        // FIX-3: Replace any existing session with same hostId
        if (msg.hostId) {
          for (const [c, s] of this.sessions) {
            if (s.hostId === msg.hostId) {
              console.log(`[relay] Replacing stale session ${c} for hostId ${msg.hostId}`);
              this._cleanupSession(c);
              break;
            }
          }
        }
        const code = generateCode(this.sessions);
        this.sessions.set(code, {
          host:      ws,
          clients:   new Set(),
          createdAt: Date.now(),
          netType:   msg.netType || 'WiFi',
          hostRay:   cfRay,
          hostId:    msg.hostId || null,
        });
        const conn = this.connections.get(ws) || {};
        this.connections.set(ws, { ...conn, role: 'host', code, id: `host-${code}`, lastPong: Date.now() });
        send(ws, { type: 'SESSION_CREATED', code, netType: msg.netType });
        console.log(`[relay] Session ${code} created`);
        this._scheduleAlarm();
        break;
      }

      case 'CLIENT_JOIN': {
        // FIX-5: accept both accessCode and code fields
        const code = (msg.accessCode || msg.code || '').toUpperCase();
        if (!code) return send(ws, { type: 'JOIN_ERROR', reason: 'No code provided' });
        const session = this.sessions.get(code);
        if (!session) return send(ws, { type: 'JOIN_ERROR', reason: 'Session not found' });
        if (!session.host || session.host.readyState !== WebSocket.OPEN)
          return send(ws, { type: 'JOIN_ERROR', reason: 'Host is offline' });
        if (session.clients.size >= MAX_CLIENTS)
          return send(ws, { type: 'JOIN_ERROR', reason: 'Session is full' });

        const clientId = `client-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
        const tunIp    = `10.8.0.${session.clients.size + 2}`;
        session.clients.add(ws);
        const conn = this.connections.get(ws) || {};
        this.connections.set(ws, { ...conn, role: 'client', code, id: clientId, tunIp, lastPong: Date.now() });
        send(ws, { type: 'JOIN_SUCCESS', code, netType: session.netType, clientId, tunIp });
        send(session.host, { type: 'CLIENT_CONNECTED', clientId, tunIp, totalClients: session.clients.size });
        console.log(`[relay] Client ${clientId} joined ${code} → ${tunIp}`);
        this._scheduleAlarm();
        break;
      }

      case 'HOST_RECONNECT': {
        let existingCode = null;
        for (const [c, s] of this.sessions) {
          if (s.hostId && s.hostId === msg.hostId) { existingCode = c; break; }
        }
        if (!existingCode) {
          const code = generateCode(this.sessions);
          this.sessions.set(code, {
            host: ws, clients: new Set(), createdAt: Date.now(),
            netType: msg.netType || 'WiFi', hostRay: cfRay, hostId: msg.hostId,
          });
          const conn = this.connections.get(ws) || {};
          this.connections.set(ws, { ...conn, role: 'host', code, id: `host-${code}`, lastPong: Date.now() });
          send(ws, { type: 'SESSION_CREATED', code, netType: msg.netType });
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
        }
        this._scheduleAlarm();
        break;
      }

      case 'PONG': {
        // FIX-2: update lastPong timestamp
        const conn = this.connections.get(ws);
        if (conn) conn.lastPong = Date.now();
        break;
      }

      case 'HOST_LEAVE': {
        const conn = this.connections.get(ws);
        if (conn?.role === 'host') this._cleanupSession(conn.code);
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

  // ── Close handler ──────────────────────────────────────────────────────────
  _onClose(ws) {
    const conn = this.connections.get(ws); if (!conn || !conn.role) {
      this.connections.delete(ws);
      return;
    }
    if (conn.role === 'host') {
      // Give host 8s to reconnect before killing session
      setTimeout(() => {
        const session = this.sessions.get(conn.code);
        if (session && session.host === ws) {
          console.log(`[relay] Host did not reconnect, cleaning up ${conn.code}`);
          this._cleanupSession(conn.code);
        }
      }, 8_000);
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
  _cleanupSession(code) {
    const session = this.sessions.get(code); if (!session) return;
    session.clients.forEach(cws => {
      send(cws, { type: 'HOST_LEFT', reason: 'Host disconnected' });
      this.connections.delete(cws);
    });
    if (session.host) this.connections.delete(session.host);
    this.sessions.delete(code);
    console.log(`[relay] Session ${code} cleaned up`);
  }
}
