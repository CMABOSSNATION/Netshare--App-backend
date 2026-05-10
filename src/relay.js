/**
 * relay.js — NetShare Relay Server (Updated for Native VPN)
 *
 * Session flow:
 *  1. HOST connects → server assigns code → HOST gets SESSION_CREATED
 *  2. CLIENT connects with code → server pairs them → both get JOIN_SUCCESS
 *  3. Binary packets flow: CLIENT TUN → relay → HOST network stack
 *  4. Either side disconnects → other side is notified
 *
 * BUGS FIXED:
 * 1. generateCode() produced 6-char codes but app expects XXXX-XXXX (8 chars + dash).
 *    Fixed: generate XXXX-XXXX format.
 * 2. CLIENT_JOIN handler read msg.code but app sends msg.accessCode.
 *    Fixed: read msg.accessCode (with msg.code fallback for compatibility).
 */

const WebSocket = require('ws');

// ── Session store ─────────────────────────────────────────────────
// Map of code → { host: ws, clients: Set<ws>, createdAt, netType }
const sessions = new Map();

// Map of ws → { role, code, id }
const connections = new Map();

const CODE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const SESSION_TIMEOUT_MS = parseInt(process.env.SESSION_TIMEOUT_MS) || 3_600_000;
const MAX_CLIENTS = parseInt(process.env.MAX_CLIENTS_PER_HOST) || 5;

// FIX 1: Generate XXXX-XXXX format to match the app's access code input.
// The app validates length >= 8 and formats input as XXXX-XXXX.
function generateCode() {
  let code;
  do {
    const part1 = Array.from({ length: 4 }, () =>
      CODE_CHARS[Math.floor(Math.random() * CODE_CHARS.length)]
    ).join('');
    const part2 = Array.from({ length: 4 }, () =>
      CODE_CHARS[Math.floor(Math.random() * CODE_CHARS.length)]
    ).join('');
    code = `${part1}-${part2}`;
  } while (sessions.has(code));
  return code;
}

function send(ws, obj) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(obj));
  }
}

function cleanupSession(code) {
  const session = sessions.get(code);
  if (!session) return;

  // Notify all clients host left
  session.clients.forEach(clientWs => {
    send(clientWs, { type: 'HOST_LEFT', reason: 'Host disconnected' });
    connections.delete(clientWs);
  });

  sessions.delete(code);
  console.log(`[relay] Session ${code} cleaned up`);
}

function setupRelay(wss) {
  // Heartbeat to keep Render connections alive
  const heartbeat = setInterval(() => {
    sessions.forEach((session, code) => {
      // Remove expired sessions
      if (Date.now() - session.createdAt > SESSION_TIMEOUT_MS) {
        console.log(`[relay] Session ${code} expired`);
        cleanupSession(code);
        return;
      }
      // Ping all connections in session
      if (session.host?.readyState === WebSocket.OPEN) {
        send(session.host, { type: 'PING' });
      }
      session.clients.forEach(ws => send(ws, { type: 'PING' }));
    });
  }, 30_000);

  wss.on('close', () => clearInterval(heartbeat));

  wss.on('connection', (ws, req) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    console.log(`[relay] New connection from ${ip}`);

    ws.on('message', (data, isBinary) => {
      // ── Binary packet: raw IP packet forwarding ──────────────
      if (isBinary) {
        const conn = connections.get(ws);
        if (!conn) return;

        const session = sessions.get(conn.code);
        if (!session) return;

        if (conn.role === 'client') {
          // CLIENT → HOST: forward packet to host
          if (session.host?.readyState === WebSocket.OPEN) {
            session.host.send(data, { binary: true });
          }
        } else if (conn.role === 'host') {
          // HOST → CLIENT: forward response back to all clients
          session.clients.forEach(clientWs => {
            if (clientWs.readyState === WebSocket.OPEN) {
              clientWs.send(data, { binary: true });
            }
          });
        }
        return;
      }

      // ── Text message: control messages ───────────────────────
      let msg;
      try {
        msg = JSON.parse(data.toString());
      } catch {
        return;
      }

      console.log(`[relay] Message: ${msg.type}`);

      switch (msg.type) {

        case 'HOST_REGISTER': {
          const code = generateCode();
          sessions.set(code, {
            host: ws,
            clients: new Set(),
            createdAt: Date.now(),
            netType: msg.netType || 'WiFi',
          });
          connections.set(ws, { role: 'host', code, id: `host-${code}` });

          send(ws, { type: 'SESSION_CREATED', code, netType: msg.netType });
          console.log(`[relay] Session ${code} created by host`);
          break;
        }

        case 'CLIENT_JOIN': {
          // FIX 2: App sends accessCode, not code. Support both for compatibility.
          const code = msg.accessCode || msg.code;
          if (!code) return send(ws, { type: 'JOIN_ERROR', reason: 'No code provided' });

          const session = sessions.get(code);
          if (!session) return send(ws, { type: 'JOIN_ERROR', reason: 'Session not found' });
          if (!session.host || session.host.readyState !== WebSocket.OPEN) {
            return send(ws, { type: 'JOIN_ERROR', reason: 'Host is offline' });
          }
          if (session.clients.size >= MAX_CLIENTS) {
            return send(ws, { type: 'JOIN_ERROR', reason: 'Session is full' });
          }

          const clientId = `client-${Date.now()}`;
          session.clients.add(ws);
          connections.set(ws, { role: 'client', code, id: clientId });

          send(ws, { type: 'JOIN_SUCCESS', code, netType: session.netType });
          send(session.host, { type: 'CLIENT_CONNECTED', clientId, totalClients: session.clients.size });
          console.log(`[relay] Client ${clientId} joined session ${code}`);
          break;
        }

        case 'PONG': {
          break;
        }

        case 'HOST_LEAVE': {
          const conn = connections.get(ws);
          if (conn?.role === 'host') cleanupSession(conn.code);
          break;
        }

        case 'CLIENT_LEAVE': {
          const conn = connections.get(ws);
          if (!conn) return;
          const session = sessions.get(conn.code);
          if (session) {
            session.clients.delete(ws);
            send(session.host, {
              type: 'CLIENT_DISCONNECTED',
              clientId: conn.id,
              totalClients: session.clients.size,
            });
          }
          connections.delete(ws);
          break;
        }

        default:
          console.warn(`[relay] Unknown message type: ${msg.type}`);
      }
    });

    ws.on('close', () => {
      const conn = connections.get(ws);
      if (!conn) return;

      if (conn.role === 'host') {
        cleanupSession(conn.code);
      } else if (conn.role === 'client') {
        const session = sessions.get(conn.code);
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
      connections.delete(ws);
    });

    ws.on('error', (err) => {
      console.error(`[relay] WS error: ${err.message}`);
    });
  });

  console.log('[relay] Relay handler attached to WebSocket server');
}

function getStats() {
  const stats = { activeSessions: sessions.size, totalClients: 0 };
  sessions.forEach(s => { stats.totalClients += s.clients.size; });
  return stats;
}

module.exports = { setupRelay, getStats };
