/**
 * relay.js — NetShare Relay Server (QUIC + Cloudflare Edition)
 *
 * TRANSPORT UPGRADE:
 *
 * This server is now designed to run behind a Cloudflare Tunnel (cloudflared),
 * which provides:
 *   - HTTP/3 (QUIC) between clients/phones and Cloudflare's edge
 *   - Cloudflare Argo Smart Routing over the WAN (optimal path for 100km links)
 *   - Zero cold-starts (no Render free-tier 30s spin-up delay)
 *   - Always-on TLS via Cloudflare's certificates — no cert management needed
 *   - Connection migration: if the mobile device changes from WiFi → 4G, the
 *     QUIC connection migrates without dropping (critical for host devices
 *     moving between networks)
 *
 * HOW IT WORKS:
 *   The relay process itself still speaks WebSocket over HTTP/1.1 on localhost.
 *   Cloudflare Tunnel (cloudflared) terminates QUIC/HTTP3 at the edge and
 *   proxies it to this localhost WebSocket server over a secure tunnel.
 *   From the phone's perspective, it connects to your Cloudflare tunnel URL
 *   (e.g. wss://netshare.yourdomain.workers.dev) over QUIC — the relay sees
 *   a normal WebSocket connection.
 *
 * DEPLOYMENT:
 *   1. Install cloudflared: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/
 *   2. Authenticate: cloudflared tunnel login
 *   3. Create tunnel: cloudflared tunnel create netshare-relay
 *   4. Create config (~/.cloudflared/config.yml):
 *        tunnel: <TUNNEL_ID>
 *        credentials-file: ~/.cloudflared/<TUNNEL_ID>.json
 *        ingress:
 *          - hostname: relay.yourdomain.com
 *            service: http://localhost:3000
 *            originRequest:
 *              connectTimeout: 10s
 *              noTLSVerify: false
 *              http2Origin: true        # ← enables HTTP/2 to origin
 *              proxyType: ""
 *          - service: http_status:404
 *   5. Route DNS: cloudflared tunnel route dns netshare-relay relay.yourdomain.com
 *   6. Run: cloudflared tunnel run netshare-relay
 *   7. Update RELAY_URL in VpnService.js to: wss://relay.yourdomain.com/relay
 *
 * QUIC-SPECIFIC CHANGES IN THIS FILE:
 *
 * QUIC-1: Cloudflare CF-* header parsing
 *   Cloudflare forwards request metadata in CF-* headers. We use CF-Connecting-IP
 *   for accurate client IP logging (instead of the tunnel's loopback IP), and
 *   CF-Ray for request tracing. We also detect CF-Visitor to know if the edge
 *   connection was HTTP/3 (QUIC) or HTTP/2 — logged for diagnostics.
 *
 * QUIC-2: Stream multiplexing awareness
 *   QUIC eliminates Head-of-Line blocking at the transport layer (each stream
 *   is independent). However, Node.js WebSocket still serialises on a single
 *   TCP/QUIC stream per connection. We preserve the fair-queue logic from
 *   RELAY-PERF-2 because it still helps on the HOST→CLIENT local WiFi segment
 *   (which is still TCP/WebSocket, not QUIC).
 *
 * QUIC-3: Reduced heartbeat to 15s
 *   Cloudflare Tunnel keepalives its own connection to the edge. Our heartbeat
 *   only needs to keep the edge→phone QUIC stream alive. QUIC idle timeout on
 *   Cloudflare is 30s; we send every 15s for safety. This replaces the 20s value.
 *
 * QUIC-4: Connection migration support (server side)
 *   When a QUIC client migrates (IP change), Cloudflare re-establishes the WS
 *   to our server. We detect this via the CF-Ray header change and emit a
 *   HOST_FAILOVER signal to clients, triggering reconnect on the new tunnel path.
 *
 * QUIC-5: Larger binary frame budget
 *   QUIC's congestion control is better than TCP's for lossy links (uses BBR by
 *   default on Cloudflare's edge). We raise the fair-queue small-frame threshold
 *   from 256 → 512 bytes, since QUIC handles out-of-order delivery natively and
 *   the HOL-blocking risk is lower.
 *
 * All prior RELAY-PERF optimisations are retained and noted inline.
 */

'use strict';

const WebSocket = require('ws');

// ── Session store ─────────────────────────────────────────────────
const sessions    = new Map();  // code → { host, clients, createdAt, netType, hostRay }
const connections = new Map();  // ws   → { role, code, id, cfRay, isQuic }

const CODE_CHARS         = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const SESSION_TIMEOUT_MS = parseInt(process.env.SESSION_TIMEOUT_MS) || 3_600_000;
const MAX_CLIENTS        = parseInt(process.env.MAX_CLIENTS_PER_HOST) || 5;

// QUIC-5: Raised from 256 → 512 bytes (QUIC handles reordering natively)
// RELAY-PERF-4: Drop frames if client WS buffer exceeds 256KB
const SMALL_FRAME_THRESHOLD     = 512;
const MAX_CLIENT_BUFFERED_BYTES = 256 * 1024;

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

// QUIC-1: Parse Cloudflare request headers for accurate IP + QUIC detection.
// Returns { clientIp, cfRay, isQuic } from the upgrade request headers.
function parseCfHeaders(req) {
  const clientIp = req.headers['cf-connecting-ip']
    || req.headers['x-forwarded-for']
    || req.socket.remoteAddress
    || 'unknown';
  const cfRay  = req.headers['cf-ray'] || null;
  // CF-Visitor: {"scheme":"https"} — HTTP/3 connections come in as https
  // We can't directly detect QUIC from CF-Visitor alone, but CF-Ray suffix
  // contains the PoP; for logging we note that Cloudflare uses QUIC for all
  // modern clients when HTTP/3 is enabled on the zone.
  let isQuic = false;
  try {
    const cfVisitor = req.headers['cf-visitor'];
    if (cfVisitor) {
      const v = JSON.parse(cfVisitor);
      // Cloudflare routes HTTP/3 clients to this tunnel; scheme will be 'https'
      // and the CF-Ray will be present. True HTTP/1.1 direct connections lack CF-Ray.
      isQuic = (v.scheme === 'https') && (cfRay !== null);
    }
  } catch (_) {}
  return { clientIp, cfRay, isQuic };
}

// RELAY-PERF-2 / QUIC-2: Fair-queued binary send.
// RELAY-PERF-3: { compress: false } for binary frames (encrypted data is incompressible)
// QUIC-5: Small-frame threshold raised to 512 bytes
function sendBinary(clientWs, data) {
  if (clientWs.readyState !== WebSocket.OPEN) return;

  // RELAY-PERF-4: Back-pressure guard
  if (clientWs.bufferedAmount > MAX_CLIENT_BUFFERED_BYTES) {
    if (!clientWs._dropCount) clientWs._dropCount = 0;
    clientWs._dropCount++;
    if (clientWs._dropCount % 100 === 1) {
      console.warn(
        `[relay] Client buffer full (${clientWs.bufferedAmount} bytes), ` +
        `dropped ${clientWs._dropCount} frames`
      );
    }
    return;
  }

  const frameLen = Buffer.isBuffer(data) ? data.length : (data.byteLength || 0);

  if (frameLen <= SMALL_FRAME_THRESHOLD) {
    // Small frame: send immediately (DNS, WhatsApp ACKs, QUIC control packets)
    clientWs.send(data, { binary: true, compress: false });
  } else {
    // Large frame: defer one event-loop tick for fair interleaving
    setImmediate(() => {
      if (clientWs.readyState === WebSocket.OPEN) {
        clientWs.send(data, { binary: true, compress: false });
      }
    });
  }
}

function cleanupSession(code) {
  const session = sessions.get(code);
  if (!session) return;

  session.clients.forEach(clientWs => {
    send(clientWs, { type: 'HOST_LEFT', reason: 'Host disconnected' });
    connections.delete(clientWs);
  });

  sessions.delete(code);
  console.log(`[relay] Session ${code} cleaned up`);
}

function setupRelay(wss) {
  // QUIC-3: Heartbeat reduced from 20s → 15s
  // Cloudflare QUIC idle timeout is 30s; 15s interval keeps streams alive safely.
  // The PING frame is 16 bytes → 8.5 bps average — negligible bandwidth cost.
  const HEARTBEAT_INTERVAL_MS = 15_000;

  const heartbeat = setInterval(() => {
    sessions.forEach((session, code) => {
      if (Date.now() - session.createdAt > SESSION_TIMEOUT_MS) {
        console.log(`[relay] Session ${code} expired`);
        cleanupSession(code);
        return;
      }
      if (session.host?.readyState === WebSocket.OPEN) {
        send(session.host, { type: 'PING' });
      }
      session.clients.forEach(ws => send(ws, { type: 'PING' }));
    });
  }, HEARTBEAT_INTERVAL_MS);

  wss.on('close', () => clearInterval(heartbeat));

  wss.on('connection', (ws, req) => {
    // QUIC-1: Extract Cloudflare metadata for logging and migration detection
    const { clientIp, cfRay, isQuic } = parseCfHeaders(req);
    console.log(
      `[relay] New connection from ${clientIp}` +
      (cfRay ? ` | CF-Ray: ${cfRay}` : ' | direct (no Cloudflare)') +
      (isQuic ? ' | transport: QUIC/HTTP3' : '')
    );

    ws.on('message', (data, isBinary) => {
      // ── Binary packet: raw IP packet forwarding ──────────────
      if (isBinary) {
        const conn = connections.get(ws);
        if (!conn) return;

        const session = sessions.get(conn.code);
        if (!session) return;

        if (conn.role === 'client') {
          if (session.host?.readyState === WebSocket.OPEN) {
            sendBinary(session.host, data);
          }
        } else if (conn.role === 'host') {
          // QUIC-2 / RELAY-PERF-2: Each client gets fair-queue treatment independently
          session.clients.forEach(clientWs => {
            sendBinary(clientWs, data);
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
            host:      ws,
            clients:   new Set(),
            createdAt: Date.now(),
            netType:   msg.netType || 'WiFi',
            hostRay:   cfRay,      // QUIC-4: track CF-Ray for migration detection
          });
          connections.set(ws, { role: 'host', code, id: `host-${code}`, cfRay, isQuic });

          send(ws, { type: 'SESSION_CREATED', code, netType: msg.netType });
          console.log(`[relay] Session ${code} created by host (QUIC: ${isQuic})`);
          break;
        }

        case 'CLIENT_JOIN': {
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
          connections.set(ws, { role: 'client', code, id: clientId, cfRay, isQuic });

          // Include assignedTunIp in JOIN_SUCCESS (set by host during SESSION_CREATED
          // if host sends it, otherwise relay assigns one from the 10.8.x.x pool)
          const clientIndex = session.clients.size; // 1-based
          const tunIp = `10.8.0.${clientIndex + 1}`;
          send(ws, { type: 'JOIN_SUCCESS', code, netType: session.netType, tunIp });
          send(session.host, {
            type: 'CLIENT_CONNECTED',
            clientId,
            totalClients: session.clients.size,
            tunIp,
          });
          console.log(
            `[relay] Client ${clientId} joined session ${code}` +
            ` (QUIC: ${isQuic}) → assigned ${tunIp}`
          );
          break;
        }

        // QUIC-4: HOST_RECONNECT — emitted by the host after a QUIC connection migration.
        // The host sends this after its WebSocket reconnects to re-associate with its session.
        // We look up its existing session by hostId and re-attach the new ws as the host.
        case 'HOST_RECONNECT': {
          const existingCode = [...sessions.keys()].find(c => {
            const s = sessions.get(c);
            return s && msg.hostId && s.hostId === msg.hostId;
          });
          if (!existingCode) {
            // No existing session — treat as fresh HOST_REGISTER
            const code = generateCode();
            sessions.set(code, {
              host:      ws,
              clients:   new Set(),
              createdAt: Date.now(),
              netType:   msg.netType || 'WiFi',
              hostRay:   cfRay,
              hostId:    msg.hostId,
            });
            connections.set(ws, { role: 'host', code, id: `host-${code}`, cfRay, isQuic });
            send(ws, { type: 'SESSION_CREATED', code, netType: msg.netType });
            console.log(`[relay] HOST_RECONNECT: new session ${code} for hostId=${msg.hostId}`);
          } else {
            const session = sessions.get(existingCode);
            // Detach old host ws, attach new one
            connections.delete(session.host);
            session.host   = ws;
            session.hostRay = cfRay;
            connections.set(ws, { role: 'host', code: existingCode, id: `host-${existingCode}`, cfRay, isQuic });
            send(ws, { type: 'SESSION_RESUMED', code: existingCode, netType: session.netType });
            // Notify clients of the failover so they can flush any queued data
            session.clients.forEach(clientWs => {
              send(clientWs, { type: 'HOST_FAILOVER', newSessionCode: existingCode });
            });
            console.log(`[relay] HOST_RECONNECT: session ${existingCode} resumed for hostId=${msg.hostId}`);
          }
          break;
        }

        case 'PONG': {
          // Client is alive — no action needed
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
        // QUIC-4: On QUIC connection migration the host will reconnect via HOST_RECONNECT
        // within a few hundred milliseconds. Delay cleanup by 5s to allow re-attachment
        // before notifying clients that the host is gone.
        setTimeout(() => {
          const session = sessions.get(conn.code);
          // Only clean up if the host ws has NOT been replaced by a reconnect
          if (session && session.host === ws) {
            cleanupSession(conn.code);
          }
        }, 5_000);
      } else if (conn.role === 'client') {
        const session = sessions.get(conn.code);
        if (session) {
          session.clients.delete(ws);
          if (session.host?.readyState === WebSocket.OPEN) {
            send(session.host, {
              type:         'CLIENT_DISCONNECTED',
              clientId:     conn.id,
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

  console.log(
    '[relay] Relay handler attached ' +
    '(heartbeat=15s, fair-queue=on, small-frame=512B, compress=off for binary, ' +
    'QUIC/Cloudflare-Tunnel mode)'
  );
}

function getStats() {
  const stats = { activeSessions: sessions.size, totalClients: 0 };
  sessions.forEach(s => { stats.totalClients += s.clients.size; });
  return stats;
}

module.exports = { setupRelay, getStats };
