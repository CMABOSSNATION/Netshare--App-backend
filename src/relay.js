/**
 * relay.js — Cloudflare Durable Object
 *
 * Replaces the Node.js ws + Express relay.
 * All session state lives inside this single Durable Object
 * so every Worker instance shares the same in-memory store.
 *
 * Preserved from original:
 *  - QUIC-1  CF header parsing (CF-Connecting-IP, CF-Ray, CF-Visitor)
 *  - QUIC-3  15s heartbeat
 *  - QUIC-4  HOST_RECONNECT / connection-migration
 *  - QUIC-5  512-byte small-frame threshold
 *  - RELAY-PERF-4  back-pressure guard (bufferedAmount)
 *  - All message types: HOST_REGISTER, CLIENT_JOIN, HOST_RECONNECT,
 *    PONG, HOST_LEAVE, CLIENT_LEAVE
 *
 * Workers differences from Node ws:
 *  - WebSocket API is the browser-standard API (no ws library)
 *  - setInterval / setTimeout work normally inside Durable Objects
 *  - No process / require — use ES modules
 *  - Binary data arrives as ArrayBuffer (not Buffer)
 */

const CODE_CHARS         = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const SESSION_TIMEOUT_MS = 3_600_000;   // 1 hour
const MAX_CLIENTS        = 5;
const SMALL_FRAME        = 512;         // QUIC-5
const MAX_BUFFERED       = 256 * 1024;  // RELAY-PERF-4 back-pressure limit

// ── Helpers ────────────────────────────────────────────────────────────

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
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(obj));
    }
  } catch (_) {}
}

// RELAY-PERF-4: back-pressure guard + QUIC-5: small-frame threshold
function sendBinary(ws, data) {
  try {
    if (ws.readyState !== WebSocket.OPEN) return;
    if (ws.bufferedAmount > MAX_BUFFERED) return; // drop — client too slow
    const len = data instanceof ArrayBuffer ? data.byteLength : (data.length || 0);
    if (len <= SMALL_FRAME) {
      ws.send(data);
    } else {
      // Defer large frames one microtask for fair interleaving
      Promise.resolve().then(() => {
        if (ws.readyState === WebSocket.OPEN) ws.send(data);
      });
    }
  } catch (_) {}
}

// QUIC-1: parse Cloudflare headers
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

// ── Durable Object ─────────────────────────────────────────────────────

export class RelaySession {
  constructor(state, env) {
    this.state = state;
    this.env   = env;

    // sessions: code → { host, clients: Set<ws>, createdAt, netType, hostRay, hostId }
    this.sessions    = new Map();
    // connections: ws → { role, code, id, cfRay, isQuic }
    this.connections = new Map();

    this._startHeartbeat();
  }

  // ── Durable Object fetch entry point ──────────────────────────────
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === '/stats') {
      let totalClients = 0;
      this.sessions.forEach(s => { totalClients += s.clients.size; });
      return Response.json({
        activeSessions: this.sessions.size,
        totalClients,
      });
    }

    // WebSocket upgrade
    const { 0: client, 1: server } = new WebSocketPair();
    this.state.acceptWebSocket(server);
    this._handleConnection(server, request);
    return new Response(null, { status: 101, webSocket: client });
  }

  // ── WebSocket lifecycle ────────────────────────────────────────────
  _handleConnection(ws, request) {
    const { clientIp, cfRay, isQuic } = parseCfHeaders(request);
    console.log(`[relay] New WS from ${clientIp} QUIC=${isQuic} ray=${cfRay}`);

    ws.addEventListener('message', (event) => {
      this._onMessage(ws, event.data, cfRay, isQuic);
    });

    ws.addEventListener('close', () => {
      this._onClose(ws, cfRay);
    });

    ws.addEventListener('error', (err) => {
      console.error('[relay] WS error:', err);
    });
  }

  // ── Message handler ────────────────────────────────────────────────
  _onMessage(ws, data, cfRay, isQuic) {
    // Binary → raw IP packet forwarding
    if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
      const conn = this.connections.get(ws);
      if (!conn) return;
      const session = this.sessions.get(conn.code);
      if (!session) return;

      if (conn.role === 'client') {
        if (session.host?.readyState === WebSocket.OPEN) {
          sendBinary(session.host, data);
        }
      } else if (conn.role === 'host') {
        session.clients.forEach(clientWs => sendBinary(clientWs, data));
      }
      return;
    }

    // Text → control message
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
        console.log(`[relay] Session ${code} created (QUIC=${isQuic})`);
        break;
      }

      case 'CLIENT_JOIN': {
        const code = msg.accessCode || msg.code;
        if (!code) return send(ws, { type: 'JOIN_ERROR', reason: 'No code provided' });

        const session = this.sessions.get(code);
        if (!session) return send(ws, { type: 'JOIN_ERROR', reason: 'Session not found' });
        if (!session.host || session.host.readyState !== WebSocket.OPEN) {
          return send(ws, { type: 'JOIN_ERROR', reason: 'Host is offline' });
        }
        if (session.clients.size >= MAX_CLIENTS) {
          return send(ws, { type: 'JOIN_ERROR', reason: 'Session is full' });
        }

        const clientId = `client-${Date.now()}-${Math.random().toString(36).slice(2,6)}`;
        const tunIp    = `10.8.0.${session.clients.size + 2}`;

        session.clients.add(ws);
        this.connections.set(ws, { role: 'client', code, id: clientId, cfRay, isQuic, tunIp });

        send(ws, { type: 'JOIN_SUCCESS', code, netType: session.netType, clientId, tunIp });
        send(session.host, { type: 'CLIENT_CONNECTED', clientId, tunIp, totalClients: session.clients.size });
        console.log(`[relay] Client ${clientId} joined ${code} → ${tunIp}`);
        break;
      }

      // QUIC-4: host reconnects after QUIC connection migration
      case 'HOST_RECONNECT': {
        let existingCode = null;
        for (const [c, s] of this.sessions) {
          if (s.hostId && s.hostId === msg.hostId) { existingCode = c; break; }
        }

        if (!existingCode) {
          // No existing session — fresh register
          const code = generateCode(this.sessions);
          this.sessions.set(code, {
            host: ws, clients: new Set(), createdAt: Date.now(),
            netType: msg.netType || 'WiFi', hostRay: cfRay, hostId: msg.hostId,
          });
          this.connections.set(ws, { role: 'host', code, id: `host-${code}`, cfRay, isQuic });
          send(ws, { type: 'SESSION_CREATED', code, netType: msg.netType });
          console.log(`[relay] HOST_RECONNECT: new session ${code} for hostId=${msg.hostId}`);
        } else {
          const session = this.sessions.get(existingCode);
          this.connections.delete(session.host);
          session.host    = ws;
          session.hostRay = cfRay;
          this.connections.set(ws, { role: 'host', code: existingCode, id: `host-${existingCode}`, cfRay, isQuic });
          send(ws, { type: 'SESSION_RESUMED', code: existingCode, netType: session.netType });
          session.clients.forEach(clientWs =>
            send(clientWs, { type: 'HOST_FAILOVER', newSessionCode: existingCode })
          );
          console.log(`[relay] HOST_RECONNECT: resumed ${existingCode} for hostId=${msg.hostId}`);
        }
        break;
      }

      case 'PONG': break; // alive, nothing to do

      case 'HOST_LEAVE': {
        const conn = this.connections.get(ws);
        if (conn?.role === 'host') this._cleanupSession(conn.code);
        break;
      }

      case 'CLIENT_LEAVE': {
        const conn = this.connections.get(ws);
        if (!conn) return;
        const session = this.sessions.get(conn.code);
        if (session) {
          session.clients.delete(ws);
          if (session.host?.readyState === WebSocket.OPEN) {
            send(session.host, { type: 'CLIENT_DISCONNECTED', clientId: conn.id, totalClients: session.clients.size });
          }
        }
        this.connections.delete(ws);
        break;
      }

      default:
        console.warn(`[relay] Unknown type: ${msg.type}`);
    }
  }

  // ── Close handler ──────────────────────────────────────────────────
  _onClose(ws, cfRay) {
    const conn = this.connections.get(ws);
    if (!conn) return;

    if (conn.role === 'host') {
      // QUIC-4: delay 5s to allow reconnect before telling clients host is gone
      setTimeout(() => {
        const session = this.sessions.get(conn.code);
        if (session && session.host === ws) {
          this._cleanupSession(conn.code);
        }
      }, 5_000);
    } else if (conn.role === 'client') {
      const session = this.sessions.get(conn.code);
      if (session) {
        session.clients.delete(ws);
        if (session.host?.readyState === WebSocket.OPEN) {
          send(session.host, {
            type: 'CLIENT_DISCONNECTED',
            clientId: conn.id,
            totalClients: session.clients.size,
          });
        }
      }
    }
    this.connections.delete(ws);
  }

  // ── Session cleanup ────────────────────────────────────────────────
  _cleanupSession(code) {
    const session = this.sessions.get(code);
    if (!session) return;
    session.clients.forEach(clientWs => {
      send(clientWs, { type: 'HOST_LEFT', reason: 'Host disconnected' });
      this.connections.delete(clientWs);
    });
    this.sessions.delete(code);
    console.log(`[relay] Session ${code} cleaned up`);
  }

  // ── Heartbeat — QUIC-3: 15s interval ──────────────────────────────
  _startHeartbeat() {
    setInterval(() => {
      const now = Date.now();
      this.sessions.forEach((session, code) => {
        if (now - session.createdAt > SESSION_TIMEOUT_MS) {
          console.log(`[relay] Session ${code} expired`);
          this._cleanupSession(code);
          return;
        }
        if (session.host?.readyState === WebSocket.OPEN) {
          send(session.host, { type: 'PING' });
        }
        session.clients.forEach(ws => send(ws, { type: 'PING' }));
      });
    }, 15_000);
  }
}
