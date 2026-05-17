/**
 * relay.js — NetShare Durable Object: TCP Tunnel + Admin State
 *
 * This file exports ONE Durable Object class: TcpTunnelSession.
 *
 * When instantiated as a tunnel shard (name prefix "tunnel:"):
 *   1. Accepts the WebSocket upgrade from the Worker.
 *   2. Waits for a single JSON INIT message from the client:
 *        { type: "INIT", host: "google.com", port: 443 }
 *   3. Opens a raw outbound TCP socket via Cloudflare's Socket API.
 *   4. Pipes binary data bidirectionally with zero parsing:
 *        WS → TCP writer   (client → internet)
 *        TCP reader → WS   (internet → client)
 *   5. Tears everything down cleanly on any error or close.
 *
 * When instantiated as the admin singleton (name "global-admin"):
 *   - Handles all non-tunnel HTTP routes (access codes, host registry, stats).
 *   - This code path is entirely independent of the TCP tunnel logic.
 *
 * Cloudflare Socket API docs:
 *   https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/
 *
 * IMPORTANT PLATFORM CONSTRAINTS:
 *   - TCP is supported via `cloudflare:sockets` (workers with "nodejs_compat" flag).
 *   - UDP is NOT supported on Cloudflare Workers. Voice/video (WebRTC) must use
 *     an external TURN server. See COTURN_SETUP.md for instructions.
 *   - TLS wrapping is supported via socket.startTls() for HTTPS targets.
 *   - Max outbound TCP connections per DO instance: effectively 1 tunnel per shard
 *     (which is exactly our architecture — one DO per session).
 */

import { connect } from 'cloudflare:sockets';

// ── Shared constants ───────────────────────────────────────────────────────────
const CODE_CHARS          = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const SESSION_TIMEOUT_MS  = 6 * 3_600_000;   // 6 hours
const MAX_CLIENTS         = 5;
const MAX_BUFFERED_BYTES  = 512 * 1024;       // 512 KB back-pressure threshold
const ALARM_INTERVAL_MS   = 20_000;
const PONG_TIMEOUT_MS     = 60_000;
const HOST_RECONNECT_WAIT = 30_000;
const JOIN_WAIT_MS        = 10_000;
const HOURLY_RATE         = 0.50;             // $ per host per hour online
const INIT_TIMEOUT_MS     = 10_000;           // max wait for INIT message
const MAX_CHUNK_BYTES     = 64 * 1024;        // 64 KB — chunk large reads
const TLS_PORTS           = new Set([443, 8443, 993, 995, 465, 587]);

// ── Utility functions ─────────────────────────────────────────────────────────

function generateCode(map) {
  let code;
  do {
    const p1 = randomChars(4);
    const p2 = randomChars(4);
    code = `${p1}-${p2}`;
  } while (map.has(code));
  return code;
}

function randomChars(n) {
  return Array.from({ length: n }, () =>
    CODE_CHARS[Math.floor(Math.random() * CODE_CHARS.length)]
  ).join('');
}

function sendJson(ws, obj) {
  try {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(obj));
    }
  } catch (_) {}
}

/**
 * Sends binary data to a WebSocket with back-pressure awareness.
 * Large frames are deferred one microtask to yield to the event loop.
 */
function sendBinary(ws, data) {
  try {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    if (ws.bufferedAmount > MAX_BUFFERED_BYTES)   return; // drop under pressure
    const byteLen = data instanceof ArrayBuffer ? data.byteLength : (data.byteLength ?? data.length ?? 0);
    if (byteLen <= 4096) {
      ws.send(data);
    } else {
      // Yield to event loop before sending large frames (avoids blocking I/O)
      Promise.resolve().then(() => {
        if (ws && ws.readyState === WebSocket.OPEN) ws.send(data);
      });
    }
  } catch (_) {}
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-requested-with, x-admin-key',
  };
}

function jsonResponse(data, status = 200) {
  return Response.json(data, { status, headers: corsHeaders() });
}

/**
 * Validates a target host:port pair.
 * Blocks RFC-1918 / loopback addresses to prevent SSRF.
 */
function validateTarget(host, port) {
  if (!host || typeof host !== 'string') return 'Missing host';
  if (!port  || typeof port !== 'number') return 'Missing or invalid port';
  if (port < 1 || port > 65535)          return 'Port out of range';

  // Block internal/loopback addresses
  const h = host.toLowerCase().trim();
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1') return 'Loopback target not allowed';
  if (/^10\./.test(h))           return 'RFC-1918 target not allowed';
  if (/^192\.168\./.test(h))     return 'RFC-1918 target not allowed';
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return 'RFC-1918 target not allowed';
  if (/^169\.254\./.test(h))     return 'Link-local target not allowed';

  return null; // valid
}

// ═════════════════════════════════════════════════════════════════════════════
// TcpTunnelSession — the single exported Durable Object class
//
// The same class handles both roles:
//   A. TCP tunnel shard   (when DO name starts with "tunnel:")
//   B. Admin singleton    (when DO name is "global-admin")
//
// Role is determined in fetch() by inspecting the internal _sid query param
// injected by index.js.
// ═════════════════════════════════════════════════════════════════════════════
export class TcpTunnelSession {
  constructor(state, env) {
    this.state = state;
    this.env   = env;

    // ── Admin-only state (used only in the global-admin instance) ────────────
    this.sessions        = new Map(); // relay sessions (legacy WebSocket broker)
    this.connections     = new Map(); // ws → conn metadata
    this.joinWaiters     = new Map(); // code → [{ resolve, timer }]
    this.hostRegistry    = new Map(); // hostId → host metadata
    this.sessionIpCounters = new Map();
    this._alarmScheduled = false;
    this._restored       = false;

    // ── Tunnel-shard state (used only in tunnel: instances) ──────────────────
    this._tcpSocket  = null; // cloudflare:sockets Socket
    this._tcpWriter  = null; // WritableStreamDefaultWriter
    this._clientWs   = null; // the single WebSocket for this shard
    this._sessionId  = null;
    this._tunnelOpen = false;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SECTION A: TUNNEL SHARD — raw TCP bridge
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Opens the WebSocket, waits for an INIT message, then establishes the
   * outbound TCP connection and starts the bidirectional pipe.
   */
  async _handleTunnelUpgrade(request, sessionId) {
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('WebSocket upgrade required', { status: 426 });
    }

    const { 0: clientWs, 1: serverWs } = new WebSocketPair();
    serverWs.accept();

    this._clientWs  = serverWs;
    this._sessionId = sessionId;

    // Run the tunnel lifecycle asynchronously so we can return the 101 immediately.
    this.state.waitUntil(this._runTunnel(serverWs));

    return new Response(null, {
      status:    101,
      webSocket: clientWs,
      headers: {
        'X-Session-Id': sessionId,
        ...corsHeaders(),
      },
    });
  }

  /**
   * Full tunnel lifecycle:
   *   1. Wait for INIT message (with timeout).
   *   2. Validate target.
   *   3. Open TCP socket (with optional TLS upgrade).
   *   4. Pipe data in both directions until either side closes.
   */
  async _runTunnel(ws) {
    let host, port, useTls;
    try {
      // ── Step 1: wait for INIT ──────────────────────────────────────────────
      const initMsg = await this._waitForInit(ws);
      if (!initMsg) {
        this._closeTunnel(ws, 4000, 'INIT timeout — send { type:"INIT", host, port } first');
        return;
      }

      host   = (initMsg.host || '').trim();
      port   = parseInt(initMsg.port, 10);
      useTls = initMsg.tls ?? TLS_PORTS.has(port); // auto-detect TLS by port if not specified

      // ── Step 2: validate target ────────────────────────────────────────────
      const validationError = validateTarget(host, port);
      if (validationError) {
        this._closeTunnel(ws, 4001, `Invalid target: ${validationError}`);
        return;
      }

      console.log(`[tunnel:${this._sessionId}] Opening TCP → ${host}:${port} tls=${useTls}`);

      // ── Step 3: open TCP socket ────────────────────────────────────────────
      let socket;
      try {
        socket = connect({ hostname: host, port }, { allowHalfOpen: false });
      } catch (err) {
        this._closeTunnel(ws, 4002, `TCP connect failed: ${err.message}`);
        return;
      }

      // Upgrade to TLS if required (e.g. HTTPS, IMAPS, SMTPS)
      if (useTls) {
        try {
          socket = socket.startTls({ expectedServerHostname: host });
        } catch (err) {
          this._closeTunnel(ws, 4003, `TLS upgrade failed: ${err.message}`);
          return;
        }
      }

      this._tcpSocket = socket;
      this._tcpWriter = socket.writable.getWriter();
      this._tunnelOpen = true;

      // Notify client that the tunnel is ready
      sendJson(ws, { type: 'TUNNEL_READY', host, port, tls: useTls });

      // ── Step 4: bidirectional pipe ─────────────────────────────────────────
      // Run both directions concurrently and race them — first to finish tears down both.
      await Promise.race([
        this._pipeWsToTcp(ws),
        this._pipeTcpToWs(ws, socket),
      ]);

    } catch (err) {
      console.error(`[tunnel:${this._sessionId}] Unexpected error:`, err?.message);
    } finally {
      this._teardown(ws);
    }
  }

  /**
   * Waits for the first WebSocket message, which MUST be a JSON INIT frame.
   * Returns the parsed object or null on timeout.
   */
  _waitForInit(ws) {
    return new Promise((resolve) => {
      let timer;
      const onMessage = (event) => {
        clearTimeout(timer);
        ws.removeEventListener('message', onMessage);
        ws.removeEventListener('close',   onClose);
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'INIT' && msg.host) {
            resolve(msg);
          } else {
            resolve(null);
          }
        } catch {
          resolve(null);
        }
      };
      const onClose = () => {
        clearTimeout(timer);
        ws.removeEventListener('message', onMessage);
        resolve(null);
      };
      timer = setTimeout(() => {
        ws.removeEventListener('message', onMessage);
        ws.removeEventListener('close',   onClose);
        resolve(null);
      }, INIT_TIMEOUT_MS);

      ws.addEventListener('message', onMessage);
      ws.addEventListener('close',   onClose);
    });
  }

  /**
   * WS → TCP pipe.
   * Reads binary frames from the WebSocket and writes them to the TCP socket.
   * Resolves when the WebSocket closes or an error occurs.
   */
  _pipeWsToTcp(ws) {
    return new Promise((resolve) => {
      const onMessage = async (event) => {
        if (!this._tunnelOpen) return;
        try {
          let data = event.data;
          // Normalize to Uint8Array regardless of whether the WS sent
          // ArrayBuffer, Uint8Array, or (rarely) a string frame.
          if (typeof data === 'string') {
            // Ignore JSON control frames that arrive after INIT (e.g. PING/PONG)
            try {
              const ctrl = JSON.parse(data);
              if (ctrl.type === 'PING') { sendJson(ws, { type: 'PONG' }); return; }
              if (ctrl.type === 'PONG') { return; }
            } catch (_) {}
            // Plain string data — encode to bytes
            data = new TextEncoder().encode(data);
          } else if (data instanceof ArrayBuffer) {
            data = new Uint8Array(data);
          }
          // Write to TCP — back-pressure: await the write before accepting more data.
          await this._tcpWriter.write(data);
        } catch (err) {
          console.error(`[tunnel:${this._sessionId}] WS→TCP write error:`, err?.message);
          resolve();
        }
      };

      const onClose = () => {
        ws.removeEventListener('message', onMessage);
        resolve();
      };

      const onError = (err) => {
        console.error(`[tunnel:${this._sessionId}] WS error:`, err);
        ws.removeEventListener('message', onMessage);
        resolve();
      };

      ws.addEventListener('message', onMessage);
      ws.addEventListener('close',   onClose);
      ws.addEventListener('error',   onError);
    });
  }

  /**
   * TCP → WS pipe.
   * Reads chunks from the TCP readable stream and forwards them to the WebSocket.
   * Resolves when the TCP socket closes (FIN) or an error occurs.
   */
  async _pipeTcpToWs(ws, socket) {
    const reader = socket.readable.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break; // TCP socket closed (FIN from remote)
        if (!value || value.byteLength === 0) continue;

        // Send in chunks to avoid blocking the event loop with huge reads
        if (value.byteLength > MAX_CHUNK_BYTES) {
          for (let offset = 0; offset < value.byteLength; offset += MAX_CHUNK_BYTES) {
            const chunk = value.subarray(offset, offset + MAX_CHUNK_BYTES);
            sendBinary(ws, chunk.buffer);
          }
        } else {
          sendBinary(ws, value.buffer);
        }
      }
    } catch (err) {
      // ECONNRESET, ETIMEDOUT, etc. — not a bug, just remote closing
      console.log(`[tunnel:${this._sessionId}] TCP read ended:`, err?.message);
    } finally {
      try { reader.releaseLock(); } catch (_) {}
    }
  }

  /** Cleanly close the WebSocket with a code and reason. */
  _closeTunnel(ws, code, reason) {
    try { ws.close(code, reason); } catch (_) {}
    console.log(`[tunnel:${this._sessionId}] Closed: ${reason}`);
  }

  /** Full teardown: close both the TCP socket and the WebSocket. */
  _teardown(ws) {
    this._tunnelOpen = false;

    // Close TCP writer
    try { this._tcpWriter?.close(); } catch (_) {}
    // Close TCP socket
    try { this._tcpSocket?.close(); } catch (_) {}
    // Close WebSocket if still open
    try {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.close(1000, 'Tunnel closed');
      }
    } catch (_) {}

    this._tcpSocket = null;
    this._tcpWriter = null;
    console.log(`[tunnel:${this._sessionId}] Teardown complete`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SECTION B: ADMIN / BROKER — shared state management
  // (all methods below are used only by the "global-admin" DO instance)
  // ═══════════════════════════════════════════════════════════════════════════

  async _restoreSessions() {
    if (this._restored) return;
    this._restored = true;
    try {
      const stored = await this.state.storage.list({ prefix: 'session:' });
      const now    = Date.now();
      for (const [key, val] of stored) {
        try {
          const meta = JSON.parse(val);
          if (now - meta.createdAt > SESSION_TIMEOUT_MS) {
            await this.state.storage.delete(key);
            continue;
          }
          const code = key.replace('session:', '');
          this.sessions.set(code, {
            host: null, clients: new Set(),
            createdAt: meta.createdAt, netType: meta.netType || 'WiFi',
            hostId: meta.hostId || null, hostRay: null, _persisted: true,
          });
        } catch (_) {}
      }
      const hosts = await this.state.storage.list({ prefix: 'host:' });
      for (const [key, val] of hosts) {
        try {
          const meta = JSON.parse(val);
          const hostId = key.replace('host:', '');
          this.hostRegistry.set(hostId, meta);
        } catch (_) {}
      }
    } catch (e) { console.error('[admin] _restoreSessions:', e?.message); }
  }

  async _persistSession(code, session) {
    try {
      await this.state.storage.put(`session:${code}`, JSON.stringify({
        createdAt: session.createdAt,
        netType:   session.netType,
        hostId:    session.hostId,
      }));
    } catch (_) {}
  }

  async _deleteSession(code) {
    try { await this.state.storage.delete(`session:${code}`); } catch (_) {}
  }

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
    this.state.storage.put(`host:${hostId}`, JSON.stringify(merged)).catch(() => {});
    return merged;
  }

  _markHostOnline(hostId, netType, sessionCode) {
    const h = this.hostRegistry.get(hostId) || {};
    this._upsertHost(hostId, {
      isOnline: true, netType, sessionCode,
      lastSeen: Date.now(), _onlineSince: h._onlineSince || Date.now(),
    });
  }

  _markHostOffline(hostId) {
    const h = this.hostRegistry.get(hostId);
    if (!h) return;
    const onlineSince  = h._onlineSince || Date.now();
    const hoursOnline  = (Date.now() - onlineSince) / 3_600_000;
    const weeklyHrs    = (h.weeklyUptimeHours || 0) + hoursOnline;
    const totalHrs     = (h.totalUptimeHours  || 0) + hoursOnline;
    this._upsertHost(hostId, {
      isOnline: false, _onlineSince: null, lastSeen: Date.now(),
      weeklyUptimeHours: +weeklyHrs.toFixed(2),
      totalUptimeHours:  +totalHrs.toFixed(2),
      weeklyEarnings:    +(weeklyHrs * HOURLY_RATE).toFixed(2),
    });
  }

  async _scheduleAlarm() {
    if (this._alarmScheduled) return;
    this._alarmScheduled = true;
    try { await this.state.storage.setAlarm(Date.now() + ALARM_INTERVAL_MS); } catch (_) {}
  }

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
          try { session.host.close(1001, 'Ping timeout'); } catch (_) {}
        } else {
          sendJson(session.host, { type: 'PING' });
        }
      }
      session.clients.forEach(ws => {
        const conn = this.connections.get(ws);
        if (ws.readyState === WebSocket.OPEN) {
          if (conn && now - conn.lastPong > PONG_TIMEOUT_MS) {
            try { ws.close(1001, 'Ping timeout'); } catch (_) {}
          } else {
            sendJson(ws, { type: 'PING' });
          }
        }
      });
    }
    if (this.sessions.size > 0) await this._scheduleAlarm();
  }

  // ── Main fetch dispatcher ──────────────────────────────────────────────────
  async fetch(request) {
    const url  = new URL(request.url);
    const path = url.pathname;
    const sid  = url.searchParams.get('_sid'); // injected by index.js for tunnel shards

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    // ── Tunnel shard path ────────────────────────────────────────────────────
    if (sid && request.headers.get('Upgrade') === 'websocket') {
      return this._handleTunnelUpgrade(request, sid);
    }

    // ── Admin-only paths (global-admin instance only) ─────────────────────────
    await this._restoreSessions();

    if (path === '/health' || path === '/ping') {
      return new Response('OK', { status: 200, headers: corsHeaders() });
    }

    if (path === '/stats') {
      let totalClients = 0;
      this.sessions.forEach(s => { totalClients += s.clients.size; });
      return jsonResponse({ activeSessions: this.sessions.size, totalClients });
    }

    if (path === '/validate-code' && request.method === 'POST') {
      return this._handleValidateCode(request);
    }

    if (path.startsWith('/admin/')) {
      const adminKey     = request.headers.get('x-admin-key') || '';
      const expectedKey  = this.env.ADMIN_KEY || 'netshare-admin-2026';
      if (adminKey !== expectedKey) return jsonResponse({ error: 'Unauthorized' }, 401);
      return this._handleAdmin(request, url);
    }

    // ── Legacy WebSocket broker (for host-register / client-join via admin DO) ─
    if (request.headers.get('Upgrade') === 'websocket') {
      const { 0: clientWs, 1: serverWs } = new WebSocketPair();
      serverWs.accept();
      this._handleBrokerConnection(serverWs, request);
      return new Response(null, { status: 101, webSocket: clientWs });
    }

    return new Response('NetShare Relay is running', {
      status:  200,
      headers: { 'Content-Type': 'text/plain', ...corsHeaders() },
    });
  }

  // ── Validate access code ───────────────────────────────────────────────────
  async _handleValidateCode(request) {
    try {
      const body     = await request.json();
      const upper    = (body.code || '').toUpperCase();
      const deviceId = (body.deviceId || '').trim();
      const ac       = await this._getAccessCode(upper);
      const now      = Date.now();
      if (!ac || !ac.isActive || new Date(ac.expiresAt).getTime() < now) {
        return jsonResponse({ valid: false, reason: 'Invalid or expired access code' });
      }
      if (ac.claimedBy && deviceId && ac.claimedBy !== deviceId) {
        return jsonResponse({ valid: false, reason: 'Access code already in use by another device' });
      }
      return jsonResponse({ valid: true, reason: null });
    } catch { return jsonResponse({ valid: false, reason: 'Server error' }); }
  }

  // ── Admin routes ───────────────────────────────────────────────────────────
  async _handleAdmin(request, url) {
    const path = url.pathname;

    if (path === '/admin/stats' && request.method === 'GET') {
      let totalClients = 0;
      this.sessions.forEach(s => { totalClients += s.clients.size; });
      const hosts = [...this.hostRegistry.values()];
      const codes = await this._listAccessCodes();
      const now   = Date.now();
      return jsonResponse({
        activeSessions:    this.sessions.size,
        totalClients,
        onlineHosts:       hosts.filter(h => h.isOnline).length,
        totalHosts:        hosts.length,
        activeAccessCodes: codes.filter(c => c.isActive && new Date(c.expiresAt).getTime() > now).length,
      });
    }

    if (path === '/admin/codes' && request.method === 'GET') {
      return jsonResponse({ codes: await this._listAccessCodes() });
    }

    if (path === '/admin/codes/generate' && request.method === 'POST') {
      try {
        const body  = await request.json();
        const count = Math.min(parseInt(body.count) || 1, 100);
        const hours = parseInt(body.expiresInHours) || 24;
        const label = body.label || '';
        const codes = [];
        for (let i = 0; i < count; i++) {
          const code = `${randomChars(4)}-${randomChars(4)}`;
          const data = {
            isActive: true, label,
            createdAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + hours * 3_600_000).toISOString(),
            claimedBy: null, claimedAt: null,
          };
          await this._putAccessCode(code, data);
          codes.push({ code, ...data });
        }
        return jsonResponse({ codes });
      } catch (e) { return jsonResponse({ error: e.message }, 400); }
    }

    if (path === '/admin/codes/revoke' && request.method === 'POST') {
      try {
        const { code } = await request.json();
        const upper = (code || '').toUpperCase();
        const ac    = await this._getAccessCode(upper);
        if (!ac) return jsonResponse({ error: 'Code not found' }, 404);
        await this._putAccessCode(upper, { ...ac, isActive: false });
        return jsonResponse({ success: true });
      } catch (e) { return jsonResponse({ error: e.message }, 400); }
    }

    if (path === '/admin/hosts' && request.method === 'GET') {
      const hosts = [...this.hostRegistry.values()].map(h => ({
        hostId:           h.hostId,
        isOnline:         h.isOnline,
        netType:          h.netType,
        clientCount:      h.clientCount || 0,
        sessionCode:      h.sessionCode,
        totalUptimeHours: +(h.totalUptimeHours || 0).toFixed(1),
        weeklyEarnings:   +(h.weeklyEarnings || 0).toFixed(2),
        lastSeen:         h.lastSeen,
      }));
      return jsonResponse({ hosts });
    }

    if (path === '/admin/payouts' && request.method === 'GET') {
      const payouts = [...this.hostRegistry.values()].map(h => ({
        hostId:         h.hostId,
        isOnline:       h.isOnline,
        uptimeHours:    +(h.weeklyUptimeHours || 0).toFixed(1),
        weeklyEarnings: +(h.weeklyEarnings || 0).toFixed(2),
        lastSeen:       h.lastSeen,
      }));
      const totalPayout = payouts.reduce((s, p) => s + p.weeklyEarnings, 0);
      return jsonResponse({
        payouts,
        totalPayout:   +totalPayout.toFixed(2),
        platformShare: +totalPayout.toFixed(2),
      });
    }

    if (path === '/admin/payouts/reset' && request.method === 'POST') {
      for (const [hostId] of this.hostRegistry) {
        this._upsertHost(hostId, { weeklyUptimeHours: 0, weeklyEarnings: 0, weekStart: Date.now() });
      }
      return jsonResponse({ success: true });
    }

    return jsonResponse({ error: 'Not found' }, 404);
  }

  // ── Legacy WebSocket broker (global-admin handles HOST_REGISTER / CLIENT_JOIN) ─
  _handleBrokerConnection(ws, request) {
    const clientIp = request.headers.get('cf-connecting-ip') || 'unknown';
    const cfRay    = request.headers.get('cf-ray') || null;
    this.connections.set(ws, { role: null, code: null, id: null, cfRay, lastPong: Date.now() });
    ws.addEventListener('message', e => this._onBrokerMessage(ws, e.data, cfRay));
    ws.addEventListener('close',   () => this._onBrokerClose(ws));
    ws.addEventListener('error',   err => console.error('[broker] WS error:', err));
    console.log(`[broker] New WS from ${clientIp}`);
  }

  async _onBrokerMessage(ws, data, cfRay) {
    // Binary relay between host ↔ clients
    if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
      const conn    = this.connections.get(ws); if (!conn) return;
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
        if (msg.hostId) {
          for (const [c, s] of this.sessions) {
            if (s.hostId === msg.hostId) { await this._cleanupSession(c); break; }
          }
        }
        const code    = generateCode(this.sessions);
        const session = {
          host: ws, clients: new Set(),
          createdAt: Date.now(), netType: msg.netType || 'WiFi',
          hostRay: cfRay, hostId: msg.hostId || null,
        };
        this.sessions.set(code, session);
        const conn = this.connections.get(ws) || {};
        this.connections.set(ws, { ...conn, role: 'host', code, id: `host-${code}`, lastPong: Date.now() });
        sendJson(ws, { type: 'SESSION_CREATED', code, netType: msg.netType });
        await this._persistSession(code, session);
        if (msg.hostId) this._markHostOnline(msg.hostId, msg.netType || 'WiFi', code);
        this._resolveJoinWaiters(code);
        await this._scheduleAlarm();
        break;
      }

      case 'CLIENT_JOIN': {
        const code     = (msg.accessCode || msg.code || '').toUpperCase();
        const deviceId = (msg.deviceId || '').trim();
        if (!code)     return sendJson(ws, { type: 'JOIN_ERROR', reason: 'No code provided' });
        if (!deviceId) return sendJson(ws, { type: 'JOIN_ERROR', reason: 'Device ID missing' });

        const ac  = await this._getAccessCode(code);
        const now = Date.now();
        if (!ac || !ac.isActive || new Date(ac.expiresAt).getTime() < now) {
          return sendJson(ws, { type: 'JOIN_ERROR', reason: 'Invalid or expired access code' });
        }
        if (!ac.claimedBy) {
          await this._putAccessCode(code, { ...ac, claimedBy: deviceId, claimedAt: new Date().toISOString() });
        } else if (ac.claimedBy !== deviceId) {
          return sendJson(ws, { type: 'JOIN_ERROR', reason: 'Access code already in use by another device' });
        }

        // Find available session
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
          const firstCode = this.sessions.size > 0 ? [...this.sessions.keys()][0] : '__any__';
          const waited = await this._waitForHost(firstCode, JOIN_WAIT_MS);
          if (waited) found = findSession();
        }
        if (!found) {
          return sendJson(ws, { type: 'JOIN_ERROR', reason: 'No hosts available. Try again shortly.' });
        }

        const { s: targetSession, c: targetCode } = found;
        if (!this.sessionIpCounters.has(targetCode)) this.sessionIpCounters.set(targetCode, 1);
        const ipIndex = this.sessionIpCounters.get(targetCode);
        this.sessionIpCounters.set(targetCode, ipIndex + 1);

        const clientId = `client-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
        const tunIp    = `10.8.0.${ipIndex + 1}`;
        targetSession.clients.add(ws);
        const conn = this.connections.get(ws) || {};
        this.connections.set(ws, { ...conn, role: 'client', code: targetCode, id: clientId, tunIp, lastPong: Date.now() });
        sendJson(ws, { type: 'JOIN_SUCCESS', code: targetCode, netType: targetSession.netType, clientId, tunIp });
        sendJson(targetSession.host, { type: 'CLIENT_CONNECTED', clientId, tunIp, totalClients: targetSession.clients.size });
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
          const code    = generateCode(this.sessions);
          const session = { host: ws, clients: new Set(), createdAt: Date.now(), netType: msg.netType || 'WiFi', hostRay: cfRay, hostId: msg.hostId };
          this.sessions.set(code, session);
          const conn = this.connections.get(ws) || {};
          this.connections.set(ws, { ...conn, role: 'host', code, id: `host-${code}`, lastPong: Date.now() });
          sendJson(ws, { type: 'SESSION_CREATED', code, netType: msg.netType });
          await this._persistSession(code, session);
          if (msg.hostId) this._markHostOnline(msg.hostId, msg.netType || 'WiFi', code);
        } else {
          const session = this.sessions.get(existingCode);
          if (session.host) this.connections.delete(session.host);
          session.host   = ws;
          session.hostRay = cfRay;
          const conn = this.connections.get(ws) || {};
          this.connections.set(ws, { ...conn, role: 'host', code: existingCode, id: `host-${existingCode}`, lastPong: Date.now() });
          sendJson(ws, { type: 'SESSION_RESUMED', code: existingCode, netType: session.netType });
          session.clients.forEach(cws => sendJson(cws, { type: 'HOST_FAILOVER', newSessionCode: existingCode }));
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
          if (session.host?.readyState === WebSocket.OPEN) {
            sendJson(session.host, { type: 'CLIENT_DISCONNECTED', clientId: conn.id, totalClients: session.clients.size });
          }
        }
        this.connections.delete(ws);
        break;
      }

      default:
        console.warn(`[broker] Unknown type: ${msg.type}`);
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
    if (!waiters?.length) return;
    waiters.forEach(({ resolve, timer }) => { clearTimeout(timer); resolve(true); });
    this.joinWaiters.delete(code);
  }

  _onBrokerClose(ws) {
    const conn = this.connections.get(ws);
    if (!conn?.role) { this.connections.delete(ws); return; }
    if (conn.role === 'host') {
      const session = this.sessions.get(conn.code);
      const hostId  = session?.hostId;
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
        if (session.host?.readyState === WebSocket.OPEN) {
          sendJson(session.host, { type: 'CLIENT_DISCONNECTED', clientId: conn.id, totalClients: session.clients.size });
        }
      }
    }
    this.connections.delete(ws);
  }

  async _cleanupSession(code) {
    const session = this.sessions.get(code); if (!session) return;
    session.clients.forEach(cws => {
      sendJson(cws, { type: 'HOST_LEFT', reason: 'Host disconnected' });
      this.connections.delete(cws);
    });
    if (session.host) this.connections.delete(session.host);
    this.sessions.delete(code);
    this.sessionIpCounters.delete(code);
    await this._deleteSession(code);
    const waiters = this.joinWaiters.get(code);
    if (waiters) {
      waiters.forEach(({ resolve, timer }) => { clearTimeout(timer); resolve(false); });
      this.joinWaiters.delete(code);
    }
    console.log(`[broker] Session ${code} cleaned up`);
  }
}
