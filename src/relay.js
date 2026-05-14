/**
 * relay.js — Cloudflare Durable Object (Free Plan)
 *
 * Uses new_sqlite_classes so it works on the FREE Workers plan.
 *
 * Features:
 *  - WebSocket host/client relay
 *  - Session codes (XXXX-XXXX format)
 *  - Up to 5 clients per session
 *  - Binary IP packet forwarding
 *  - 15s heartbeat (PING/PONG)
 *  - Host reconnect / failover
 *  - Back-pressure guard
 *  - CF header parsing (IP, Ray, QUIC)
 */

const CODE_CHARS         = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const SESSION_TIMEOUT_MS = 3_600_000;  // 1 hour
const MAX_CLIENTS        = 5;
const SMALL_FRAME        = 512;
const MAX_BUFFERED       = 256 * 1024;

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
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
  } catch (_) {}
}

function sendBinary(ws, data) {
  try {
    if (ws.readyState !== WebSocket.OPEN) return;
    if (ws.bufferedAmount > MAX_BUFFERED) return;
    const len = data instanceof ArrayBuffer ? data.byteLength : (data.length || 0);
    if (len <= SMALL_FRAME) {
      ws.send(data);
    } else {
      Promise.resolve().then(() => {
        if (ws.readyState === WebSocket.OPEN) ws.send(data);
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

// ── Durable Object ─────────────────────────────────────────────────────────

export class RelaySession {
  constructor(state, env) {
    this.state = state;
    this.env   = env;

    // sessions: code → { host, clients: Set<ws>, createdAt, netType, hostRay, hostId }
    this.sessions    = new Map();
    // connections: ws → { role, code, id, cfRay, isQuic, tunIp? }
    this.connections = new Map();

    this._startHeartbeat();
  }

  // ── Fetch entry point ──────────────────────────────────────────────────────
  async fetch(request) {
    const url = new URL(request.url);

    // Stats endpoint
    if (url.pathname === '/stats') {
      let totalClients = 0;
      this.sessions.forEach(s => { totalClients += s.clients.size; });
      return Response.json({ activeSessions: this.sessions.size, totalClients });
    }

    // Validate code endpoint
    if (url.pathname === '/validate-code' && request.method === 'POST') {
      try {
        const { code } = await request.json();
        const valid = this.sessions.has((code || '').toUpperCase());
        return Response.json({ valid, reason: valid ? null : 'Session not found' });
      } catch {
        return Response.json({ valid: false, reason: 'Server error' });
      }
    }

    // WebSocket upgrade
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('Expected WebSocket', { status: 426 });
    }

    const { 0: client, 1: server } = new WebSocketPair();
    server.accept();
    this._handleConnection(server, request);
    return new Response(null, { status: 101, webSocket: client });
  }

  // ── WebSocket connection ───────────────────────────────────────────────────
  _handleConnection(ws, request) {
    const { clientIp, cfRay, isQuic } = parseCfHeaders(request);
    console.log(`[relay] New WS from ${clientIp} QUIC=${isQuic} ray=${cfRay}`);

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

    // Text — control messages
    let msg;
    try { msg = JSON.parse(data); } catch { return; }
    console.log(`[relay] msg=${msg.type}`);

    switch (msg.type) {

      case 'HOST_REGISTER': {
        const code = generateCode(this.sessions);
        this.sessions.set(code, {
          host:      ws,
          clients:   new Set(),
          createdAt: Date.now(),
          netType:   msg.netType || 'WiFi',
          hostRay:   cfRay,
          hostId:    msg.hostId || null,
        });
        this.connections.set(ws, { role: 'host', code, id: `host-${code}`, cfRay, isQuic });
        send(ws, { type: 'SESSION_CREATED', code, netType: msg.netType });
        console.log(`[relay] Session ${code} created`);
        break;
      }

      case 'CLIENT_JOIN': {
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
        this.connections.set(ws, { role: 'client', code, id: clientId, cfRay, isQuic, tunIp });
        send(ws, { type: 'JOIN_SUCCESS', code, netType: session.netType, clientId, tunIp });
        send(session.host, { type: 'CLIENT_CONNECTED', clientId, tunIp, totalClients: session.clients.size });
        console.log(`[relay] Client ${clientId} joined ${code} → ${tunIp}`);
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
          this.connections.set(ws, { role: 'host', code, id: `host-${code}`, cfRay, isQuic });
          send(ws, { type: 'SESSION_CREATED', code, netType: msg.netType });
        } else {
          const session = this.sessions.get(existingCode);
          this.connections.delete(session.host);
          session.host    = ws;
          session.hostRay = cfRay;
          this.connections.set(ws, { role: 'host', code: existingCode, id: `host-${existingCode}`, cfRay, isQuic });
          send(ws, { type: 'SESSION_RESUMED', code: existingCode, netType: session.netType });
          session.clients.forEach(cws =>
            send(cws, { type: 'HOST_FAILOVER', newSessionCode: existingCode })
          );
        }
        break;
      }

      case 'PONG': break;

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
    const conn = this.connections.get(ws); if (!conn) return;
    if (conn.role === 'host') {
      setTimeout(() => {
        const session = this.sessions.get(conn.code);
        if (session && session.host === ws) this._cleanupSession(conn.code);
      }, 5_000);
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
    this.sessions.delete(code);
    console.log(`[relay] Session ${code} cleaned up`);
  }

  // ── Heartbeat — 15s interval ───────────────────────────────────────────────
  _startHeartbeat() {
    setInterval(() => {
      const now = Date.now();
      this.sessions.forEach((session, code) => {
        if (now - session.createdAt > SESSION_TIMEOUT_MS) {
          this._cleanupSession(code);
          return;
        }
        if (session.host?.readyState === WebSocket.OPEN) send(session.host, { type: 'PING' });
        session.clients.forEach(ws => send(ws, { type: 'PING' }));
      });
    }, 15_000);
  }
}
