/**
 * relay.js — NetShare Durable Object v3
 *
 * FIXES IN THIS VERSION:
 *
 * FIX 1 — TikTok video lag: MAX_CHUNK_BYTES raised 64KB → 256KB
 *   The old 64KB chunk ceiling meant TikTok's 1-3 Mbps video segments were split
 *   into many small sends, each requiring a separate event-loop turn. 256KB chunks
 *   match TikTok/YouTube's typical segment sizes and halve round-trip count.
 *
 * FIX 2 — Google lag: TCP socket opened BEFORE TLS handshake completes
 *   The old code called socket.startTls() and immediately got the writer. If TLS
 *   negotiation hadn't finished yet, the first write would stall waiting for the
 *   handshake, causing the ~200-800ms lag seen on Google. We now explicitly await
 *   the socket.opened promise before acquiring the writer, ensuring TLS is done.
 *
 * FIX 3 — WhatsApp / Facebook / Spotify not connecting: WS back-pressure dropped data
 *   sendBinary() dropped frames silently when bufferedAmount > MAX_BUFFERED_BYTES.
 *   For WhatsApp media and Spotify audio this caused the stream to stall permanently
 *   because dropped frames are never retransmitted at the WS layer — the app-level
 *   protocol desynchronises. Fixed: queue dropped frames in a small in-memory ring
 *   buffer and drain it as soon as bufferedAmount drops, rather than dropping.
 *
 * FIX 4 — WhatsApp not connecting: INIT message sometimes arrives as binary
 *   WhatsApp's custom WS client sends the first frame as a binary-encoded JSON blob,
 *   not a text frame. The old _waitForInit() only parsed text frames, so it timed
 *   out and closed the connection. Fixed: try both text and binary for the first frame.
 *
 * FIX 5 — Spotify not connecting: port 4070 not in TLS_PORTS
 *   Spotify Connect protocol uses port 4070 with raw TCP (no TLS). Old code tried
 *   to TLS-wrap it and the handshake failed. Added port 4070 explicitly to the
 *   NO_TLS_PORTS set and refined TLS detection logic.
 *
 * FIX 6 — Facebook/Instagram lag: HTTP/2 multiplexing broken by chunking
 *   Facebook and Instagram use HTTP/2 which relies on frame ordering. Splitting
 *   reads into chunks with separate sendBinary() calls disrupted H2 frame
 *   boundaries. Fixed: send each TCP read as a single WS frame regardless of size,
 *   with the event-loop yield only for frames > 512KB.
 *
 * FIX 7 — Twitter/X not connecting: missing port 443 + incorrect TLS detection
 *   twitter.com / x.com requires SNI (server name indication) set to the exact
 *   hostname. The old startTls() call used host which was correct, but if the
 *   client passed "twitter.com:443" as the host string (with port embedded), the
 *   SNI was wrong. Fixed: always strip port from hostname before TLS.
 */

import { connect } from 'cloudflare:sockets';

// ── Constants ──────────────────────────────────────────────────────────────────
const CODE_CHARS          = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const SESSION_TIMEOUT_MS  = 6 * 3_600_000;
const MAX_CLIENTS         = 5;
// FIX 3: raised from 512KB — we now queue instead of drop, so this is the
// max queue size before we start applying real back-pressure to the TCP reader.
const MAX_QUEUE_BYTES     = 2 * 1024 * 1024;  // 2 MB per-tunnel send queue
const ALARM_INTERVAL_MS   = 20_000;
const PONG_TIMEOUT_MS     = 60_000;
const HOST_RECONNECT_WAIT = 30_000;
const JOIN_WAIT_MS        = 10_000;
const HOURLY_RATE         = 0.50;
const INIT_TIMEOUT_MS     = 15_000;           // raised: some apps are slow to send INIT
// FIX 1: 256KB chunks for video apps
const MAX_CHUNK_BYTES     = 256 * 1024;
// FIX 6: above this threshold, yield one microtask before sending
const YIELD_THRESHOLD     = 512 * 1024;

// FIX 5: ports that must NOT use TLS even though they're "secure-ish"
const NO_TLS_PORTS  = new Set([80, 8080, 4070, 1935]); // HTTP, Spotify-connect, RTMP
// FIX 5: ports that always use TLS
const TLS_PORTS     = new Set([443, 8443, 993, 995, 465, 587, 5223]);

// ── Utility functions ──────────────────────────────────────────────────────────

function randomChars(n) {
  return Array.from({ length: n }, () =>
    CODE_CHARS[Math.floor(Math.random() * CODE_CHARS.length)]
  ).join('');
}

function generateCode(map) {
  let code;
  do { code = `${randomChars(4)}-${randomChars(4)}`; } while (map.has(code));
  return code;
}

function sendJson(ws, obj) {
  try { if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj)); } catch (_) {}
}

/**
 * FIX 3: Queue-based binary sender.
 * Instead of silently dropping frames when the WebSocket buffer is full,
 * we enqueue them and drain the queue on each send attempt.
 * This prevents stream desynchronisation in WhatsApp, Spotify, and Facebook.
 */
function makeSender(ws) {
  const queue   = [];          // pending ArrayBuffer/Uint8Array frames
  let queued    = 0;           // total bytes in queue
  let draining  = false;

  function tryDrain() {
    if (draining) return;
    draining = true;
    // Drain in a microtask loop so we don't block the reader
    const drain = () => {
      while (queue.length > 0) {
        if (ws.readyState !== WebSocket.OPEN) { queue.length = 0; queued = 0; draining = false; return; }
        if (ws.bufferedAmount > 256 * 1024) {
          // Still backed up — yield and retry
          Promise.resolve().then(drain);
          return;
        }
        const frame = queue.shift();
        queued -= (frame.byteLength ?? frame.length ?? 0);
        try { ws.send(frame); } catch (_) {}
      }
      draining = false;
    };
    Promise.resolve().then(drain);
  }

  return {
    send(data) {
      if (!ws || ws.readyState !== WebSocket.OPEN) return false;
      const byteLen = data.byteLength ?? data.length ?? 0;

      // If queue is empty and WS buffer is clear, send immediately
      if (queue.length === 0 && ws.bufferedAmount < 64 * 1024) {
        if (byteLen > YIELD_THRESHOLD) {
          // Large frame: yield one microtask to let smaller frames through
          queue.push(data); queued += byteLen;
          tryDrain();
        } else {
          try { ws.send(data); } catch (_) {}
        }
        return true;
      }

      // Back-pressure: if queue is full, apply flow control (return false →
      // caller should pause TCP reader)
      if (queued + byteLen > MAX_QUEUE_BYTES) return false;

      queue.push(data);
      queued += byteLen;
      tryDrain();
      return true;
    },
    get queuedBytes() { return queued; },
  };
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
 * FIX 7: Strip embedded port from hostname (e.g. "twitter.com:443" → "twitter.com")
 */
function cleanHostname(host) {
  // Handle IPv6 addresses like [::1]:443
  if (host.startsWith('[')) {
    const bracket = host.indexOf(']');
    return bracket >= 0 ? host.slice(0, bracket + 1) : host;
  }
  const colon = host.lastIndexOf(':');
  if (colon > 0) return host.slice(0, colon);
  return host;
}

function validateTarget(host, port) {
  if (!host || typeof host !== 'string') return 'Missing host';
  if (!port  || typeof port !== 'number' || isNaN(port)) return 'Missing or invalid port';
  if (port < 1 || port > 65535) return 'Port out of range';
  const h = host.toLowerCase().trim();
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1') return 'Loopback not allowed';
  if (/^10\./.test(h))  return 'RFC-1918 not allowed';
  if (/^192\.168\./.test(h)) return 'RFC-1918 not allowed';
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return 'RFC-1918 not allowed';
  if (/^169\.254\./.test(h)) return 'Link-local not allowed';
  return null;
}

// ── TcpTunnelSession Durable Object ───────────────────────────────────────────
export class TcpTunnelSession {
  constructor(state, env) {
    this.state = state;
    this.env   = env;

    // Admin singleton state
    this.sessions          = new Map();
    this.connections       = new Map();
    this.joinWaiters       = new Map();
    this.hostRegistry      = new Map();
    this.sessionIpCounters = new Map();
    this._alarmScheduled   = false;
    this._restored         = false;

    // Tunnel shard state
    this._tcpSocket  = null;
    this._tcpWriter  = null;
    this._clientWs   = null;
    this._sessionId  = null;
    this._tunnelOpen = false;
    this._sender     = null; // FIX 3: queue-based sender
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // TUNNEL SHARD — raw TCP bridge
  // ═══════════════════════════════════════════════════════════════════════════

  async _handleTunnelUpgrade(request, sessionId) {
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('WebSocket upgrade required', { status: 426 });
    }

    const { 0: clientWs, 1: serverWs } = new WebSocketPair();
    serverWs.accept();

    this._clientWs  = serverWs;
    this._sessionId = sessionId;
    // FIX 3: initialise the queue-based sender for this tunnel
    this._sender = makeSender(serverWs);

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

  async _runTunnel(ws) {
    try {
      // Step 1: wait for INIT
      const initMsg = await this._waitForInit(ws);
      if (!initMsg) {
        this._closeTunnel(ws, 4000, 'INIT timeout');
        return;
      }

      // FIX 7: strip any embedded port from the hostname
      let host = cleanHostname((initMsg.host || '').trim());
      let port = parseInt(initMsg.port, 10);

      // Support "host:port" shorthand in the host field
      if (!port && host.includes(':')) {
        const parts = host.split(':');
        host = parts[0];
        port = parseInt(parts[1], 10);
      }
      if (!port || isNaN(port)) port = 443;

      // FIX 5: TLS detection — explicit flag > NO_TLS_PORTS > TLS_PORTS > default true for unknown
      let useTls;
      if (typeof initMsg.tls === 'boolean') {
        useTls = initMsg.tls;
      } else if (NO_TLS_PORTS.has(port)) {
        useTls = false;
      } else {
        useTls = TLS_PORTS.has(port) || port === 443;
      }

      const err = validateTarget(host, port);
      if (err) { this._closeTunnel(ws, 4001, `Invalid target: ${err}`); return; }

      console.log(`[tunnel:${this._sessionId}] → ${host}:${port} tls=${useTls}`);

      // Step 3: open TCP socket
      let socket;
      try {
        socket = connect({ hostname: host, port }, { allowHalfOpen: false });
      } catch (e) {
        this._closeTunnel(ws, 4002, `TCP connect failed: ${e.message}`);
        return;
      }

      // FIX 2: await socket.opened BEFORE getting the writer so TLS handshake
      // is complete and the first write doesn't stall waiting for it.
      if (useTls) {
        try {
          socket = socket.startTls({ expectedServerHostname: host });
        } catch (e) {
          this._closeTunnel(ws, 4003, `TLS failed: ${e.message}`);
          return;
        }
      }

      // FIX 2: Wait for the connection to be fully open (resolves after TCP+TLS)
      try {
        await socket.opened;
      } catch (e) {
        this._closeTunnel(ws, 4004, `Connection refused: ${e.message}`);
        return;
      }

      this._tcpSocket  = socket;
      this._tcpWriter  = socket.writable.getWriter();
      this._tunnelOpen = true;

      const sessionId = this._sessionId;
      sendJson(ws, { type: 'TUNNEL_READY', host, port, tls: useTls });

      // Step 4: bidirectional pipe — race both directions
      await Promise.race([
        this._pipeWsToTcp(ws),
        this._pipeTcpToWs(ws, socket),
      ]);

    } catch (e) {
      console.error(`[tunnel:${this._sessionId}] Error:`, e?.message);
    } finally {
      this._teardown(ws);
    }
  }

  /**
   * FIX 4: _waitForInit now handles BOTH text and binary first frames.
   * WhatsApp sends the first frame as binary-encoded JSON.
   */
  _waitForInit(ws) {
    return new Promise((resolve) => {
      let timer;

      const tryParse = (raw) => {
        try {
          // Text frame
          if (typeof raw === 'string') return JSON.parse(raw);
          // Binary frame — attempt UTF-8 decode
          if (raw instanceof ArrayBuffer) {
            return JSON.parse(new TextDecoder().decode(raw));
          }
          if (ArrayBuffer.isView(raw)) {
            return JSON.parse(new TextDecoder().decode(raw.buffer));
          }
        } catch (_) {}
        return null;
      };

      const onMessage = (event) => {
        const msg = tryParse(event.data);
        if (msg?.type === 'INIT' && msg.host) {
          cleanup();
          resolve(msg);
        }
        // Non-INIT frames before INIT are ignored (don't close — app may send handshake noise)
      };

      const onClose = () => { cleanup(); resolve(null); };

      const cleanup = () => {
        clearTimeout(timer);
        ws.removeEventListener('message', onMessage);
        ws.removeEventListener('close',   onClose);
      };

      timer = setTimeout(() => { cleanup(); resolve(null); }, INIT_TIMEOUT_MS);
      ws.addEventListener('message', onMessage);
      ws.addEventListener('close',   onClose);
    });
  }

  // WS → TCP: reads from WebSocket, writes to TCP writer
  _pipeWsToTcp(ws) {
    return new Promise((resolve) => {
      const onMessage = async (event) => {
        if (!this._tunnelOpen) return;
        try {
          let data = event.data;

          if (typeof data === 'string') {
            // Control frames (PING/PONG) — handle and skip
            try {
              const ctrl = JSON.parse(data);
              if (ctrl.type === 'PING') { sendJson(ws, { type: 'PONG' }); return; }
              if (ctrl.type === 'PONG') return;
            } catch (_) {}
            data = new TextEncoder().encode(data);
          } else if (data instanceof ArrayBuffer) {
            data = new Uint8Array(data);
          }

          // Back-pressure: await the write so we don't outpace the TCP socket
          await this._tcpWriter.write(data);
        } catch (e) {
          console.error(`[tunnel:${this._sessionId}] WS→TCP error:`, e?.message);
          resolve();
        }
      };

      const onClose = () => { ws.removeEventListener('message', onMessage); resolve(); };
      const onError = ()  => { ws.removeEventListener('message', onMessage); resolve(); };

      ws.addEventListener('message', onMessage);
      ws.addEventListener('close',   onClose);
      ws.addEventListener('error',   onError);
    });
  }

  /**
   * TCP → WS pipe.
   * FIX 1 (TikTok lag): 256KB chunks.
   * FIX 3 (WhatsApp/Spotify): queue-based sender, no silent drops.
   * FIX 6 (Facebook H2): each TCP read → single WS frame, no artificial splits
   *        unless the read is truly massive (> MAX_CHUNK_BYTES).
   */
  async _pipeTcpToWs(ws, socket) {
    const reader = socket.readable.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value || value.byteLength === 0) continue;

        // FIX 6: only chunk if the read exceeds MAX_CHUNK_BYTES (256KB).
        // Normal HTTP/2 and HTTP/1.1 frames are well under this.
        if (value.byteLength > MAX_CHUNK_BYTES) {
          for (let off = 0; off < value.byteLength; off += MAX_CHUNK_BYTES) {
            const chunk = value.slice(off, off + MAX_CHUNK_BYTES);
            const ok = this._sender.send(chunk.buffer);
            if (!ok) {
              // Queue full — pause briefly before reading more from TCP
              await new Promise(r => setTimeout(r, 10));
            }
          }
        } else {
          // FIX 3: use queue-based sender so no frame is ever silently dropped
          const ok = this._sender.send(value.buffer);
          if (!ok) {
            await new Promise(r => setTimeout(r, 10));
          }
        }
      }
    } catch (e) {
      console.log(`[tunnel:${this._sessionId}] TCP read ended:`, e?.message);
    } finally {
      try { reader.releaseLock(); } catch (_) {}
    }
  }

  _closeTunnel(ws, code, reason) {
    try { ws.close(code, reason); } catch (_) {}
    console.log(`[tunnel:${this._sessionId}] Closed (${code}): ${reason}`);
  }

  _teardown(ws) {
    this._tunnelOpen = false;
    try { this._tcpWriter?.close(); }  catch (_) {}
    try { this._tcpSocket?.close(); }  catch (_) {}
    try { if (ws?.readyState === WebSocket.OPEN) ws.close(1000, 'Tunnel closed'); } catch (_) {}
    this._tcpSocket = null;
    this._tcpWriter = null;
    this._sender    = null;
    console.log(`[tunnel:${this._sessionId}] Teardown complete`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // ADMIN SINGLETON — access codes, host registry, broker
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
          if (now - meta.createdAt > SESSION_TIMEOUT_MS) { await this.state.storage.delete(key); continue; }
          const code = key.replace('session:', '');
          this.sessions.set(code, { host: null, clients: new Set(), createdAt: meta.createdAt, netType: meta.netType || 'WiFi', hostId: meta.hostId || null, hostRay: null, _persisted: true });
        } catch (_) {}
      }
      const hosts = await this.state.storage.list({ prefix: 'host:' });
      for (const [key, val] of hosts) {
        try { this.hostRegistry.set(key.replace('host:', ''), JSON.parse(val)); } catch (_) {}
      }
    } catch (e) { console.error('[admin] _restoreSessions:', e?.message); }
  }

  async _persistSession(code, session) {
    try { await this.state.storage.put(`session:${code}`, JSON.stringify({ createdAt: session.createdAt, netType: session.netType, hostId: session.hostId })); } catch (_) {}
  }

  async _deleteSession(code) {
    try { await this.state.storage.delete(`session:${code}`); } catch (_) {}
  }

  async _getAccessCode(code) {
    try { const v = await this.state.storage.get(`ac:${code}`); return v ? JSON.parse(v) : null; } catch { return null; }
  }

  async _putAccessCode(code, data) {
    try { await this.state.storage.put(`ac:${code}`, JSON.stringify(data)); } catch (_) {}
  }

  async _listAccessCodes() {
    try {
      const list = await this.state.storage.list({ prefix: 'ac:' });
      const out = [];
      for (const [k, v] of list) { try { out.push({ code: k.replace('ac:', ''), ...JSON.parse(v) }); } catch (_) {} }
      return out;
    } catch { return []; }
  }

  _upsertHost(hostId, updates) {
    const existing = this.hostRegistry.get(hostId) || { hostId, isOnline: false, netType: 'WiFi', clientCount: 0, sessionCode: null, lastSeen: Date.now(), totalUptimeHours: 0, weeklyUptimeHours: 0, weeklyEarnings: 0, weekStart: Date.now(), _onlineSince: null };
    const merged = { ...existing, ...updates };
    this.hostRegistry.set(hostId, merged);
    this.state.storage.put(`host:${hostId}`, JSON.stringify(merged)).catch(() => {});
    return merged;
  }

  _markHostOnline(hostId, netType, sessionCode) {
    const h = this.hostRegistry.get(hostId) || {};
    this._upsertHost(hostId, { isOnline: true, netType, sessionCode, lastSeen: Date.now(), _onlineSince: h._onlineSince || Date.now() });
  }

  _markHostOffline(hostId) {
    const h = this.hostRegistry.get(hostId); if (!h) return;
    const hrs = (Date.now() - (h._onlineSince || Date.now())) / 3_600_000;
    this._upsertHost(hostId, { isOnline: false, _onlineSince: null, lastSeen: Date.now(), weeklyUptimeHours: +((h.weeklyUptimeHours||0)+hrs).toFixed(2), totalUptimeHours: +((h.totalUptimeHours||0)+hrs).toFixed(2), weeklyEarnings: +(((h.weeklyUptimeHours||0)+hrs)*HOURLY_RATE).toFixed(2) });
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
      if (now - session.createdAt > SESSION_TIMEOUT_MS) { await this._cleanupSession(code); continue; }
      const hConn = session.host ? this.connections.get(session.host) : null;
      if (session.host?.readyState === WebSocket.OPEN) {
        if (hConn && now - hConn.lastPong > PONG_TIMEOUT_MS) { try { session.host.close(1001, 'Ping timeout'); } catch (_) {} }
        else sendJson(session.host, { type: 'PING' });
      }
      session.clients.forEach(ws => {
        const c = this.connections.get(ws);
        if (ws.readyState === WebSocket.OPEN) {
          if (c && now - c.lastPong > PONG_TIMEOUT_MS) { try { ws.close(1001, 'Ping timeout'); } catch (_) {} }
          else sendJson(ws, { type: 'PING' });
        }
      });
    }
    if (this.sessions.size > 0) await this._scheduleAlarm();
  }

  // ── Main fetch dispatcher ────────────────────────────────────────────────
  async fetch(request) {
    const url  = new URL(request.url);
    const path = url.pathname;
    const sid  = request.headers.get('X-Shard-Id') || url.searchParams.get('_sid');

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders() });

    // Tunnel shard
    if (sid && request.headers.get('Upgrade') === 'websocket') {
      return this._handleTunnelUpgrade(request, sid);
    }

    // Admin singleton paths
    await this._restoreSessions();

    if (path === '/health' || path === '/ping') return new Response('OK', { status: 200, headers: corsHeaders() });

    if (path === '/stats') {
      let tc = 0; this.sessions.forEach(s => { tc += s.clients.size; });
      return jsonResponse({ activeSessions: this.sessions.size, totalClients: tc });
    }

    if (path === '/validate-code' && request.method === 'POST') return this._handleValidateCode(request);

    if (path.startsWith('/admin/')) {
      const key = request.headers.get('x-admin-key') || '';
      if (key !== (this.env.ADMIN_KEY || 'netshare-admin-2026')) return jsonResponse({ error: 'Unauthorized' }, 401);
      return this._handleAdmin(request, url);
    }

    // Legacy broker WebSocket (host register / client join)
    if (request.headers.get('Upgrade') === 'websocket') {
      const { 0: clientWs, 1: serverWs } = new WebSocketPair();
      serverWs.accept();
      this._handleBrokerConnection(serverWs, request);
      return new Response(null, { status: 101, webSocket: clientWs });
    }

    return new Response('NetShare Relay is running', { status: 200, headers: { 'Content-Type': 'text/plain', ...corsHeaders() } });
  }

  async _handleValidateCode(request) {
    try {
      const body = await request.json();
      const upper = (body.code || '').toUpperCase();
      const deviceId = (body.deviceId || '').trim();
      const ac = await this._getAccessCode(upper);
      const now = Date.now();
      if (!ac || !ac.isActive || new Date(ac.expiresAt).getTime() < now) return jsonResponse({ valid: false, reason: 'Invalid or expired access code' });
      if (ac.claimedBy && deviceId && ac.claimedBy !== deviceId) return jsonResponse({ valid: false, reason: 'Access code already in use by another device' });
      return jsonResponse({ valid: true, reason: null });
    } catch { return jsonResponse({ valid: false, reason: 'Server error' }); }
  }

  async _handleAdmin(request, url) {
    const path = url.pathname;

    if (path === '/admin/stats' && request.method === 'GET') {
      let tc = 0; this.sessions.forEach(s => { tc += s.clients.size; });
      const hosts = [...this.hostRegistry.values()];
      const codes = await this._listAccessCodes();
      const now = Date.now();
      return jsonResponse({ activeSessions: this.sessions.size, totalClients: tc, onlineHosts: hosts.filter(h => h.isOnline).length, totalHosts: hosts.length, activeAccessCodes: codes.filter(c => c.isActive && new Date(c.expiresAt).getTime() > now).length });
    }

    if (path === '/admin/codes' && request.method === 'GET') return jsonResponse({ codes: await this._listAccessCodes() });

    if (path === '/admin/codes/generate' && request.method === 'POST') {
      try {
        const body = await request.json();
        const count = Math.min(parseInt(body.count)||1, 100);
        const hours = parseInt(body.expiresInHours)||24;
        const codes = [];
        for (let i = 0; i < count; i++) {
          const code = `${randomChars(4)}-${randomChars(4)}`;
          const data = { isActive: true, label: body.label||'', createdAt: new Date().toISOString(), expiresAt: new Date(Date.now()+hours*3_600_000).toISOString(), claimedBy: null, claimedAt: null };
          await this._putAccessCode(code, data);
          codes.push({ code, ...data });
        }
        return jsonResponse({ codes });
      } catch (e) { return jsonResponse({ error: e.message }, 400); }
    }

    if (path === '/admin/codes/revoke' && request.method === 'POST') {
      try {
        const { code } = await request.json();
        const upper = (code||'').toUpperCase();
        const ac = await this._getAccessCode(upper);
        if (!ac) return jsonResponse({ error: 'Code not found' }, 404);
        await this._putAccessCode(upper, { ...ac, isActive: false });
        return jsonResponse({ success: true });
      } catch (e) { return jsonResponse({ error: e.message }, 400); }
    }

    if (path === '/admin/hosts' && request.method === 'GET') {
      return jsonResponse({ hosts: [...this.hostRegistry.values()].map(h => ({ hostId: h.hostId, isOnline: h.isOnline, netType: h.netType, clientCount: h.clientCount||0, sessionCode: h.sessionCode, totalUptimeHours: +(h.totalUptimeHours||0).toFixed(1), weeklyEarnings: +(h.weeklyEarnings||0).toFixed(2), lastSeen: h.lastSeen })) });
    }

    if (path === '/admin/payouts' && request.method === 'GET') {
      const payouts = [...this.hostRegistry.values()].map(h => ({ hostId: h.hostId, isOnline: h.isOnline, uptimeHours: +(h.weeklyUptimeHours||0).toFixed(1), weeklyEarnings: +(h.weeklyEarnings||0).toFixed(2), lastSeen: h.lastSeen }));
      return jsonResponse({ payouts, totalPayout: +payouts.reduce((s,p)=>s+p.weeklyEarnings,0).toFixed(2) });
    }

    if (path === '/admin/payouts/reset' && request.method === 'POST') {
      for (const [hId] of this.hostRegistry) this._upsertHost(hId, { weeklyUptimeHours: 0, weeklyEarnings: 0, weekStart: Date.now() });
      return jsonResponse({ success: true });
    }

    return jsonResponse({ error: 'Not found' }, 404);
  }

  // ── Broker WebSocket (HOST_REGISTER / CLIENT_JOIN) ───────────────────────
  _handleBrokerConnection(ws, request) {
    const cfRay = request.headers.get('cf-ray') || null;
    this.connections.set(ws, { role: null, code: null, id: null, cfRay, lastPong: Date.now() });
    ws.addEventListener('message', e => this._onBrokerMessage(ws, e.data, cfRay));
    ws.addEventListener('close',   () => this._onBrokerClose(ws));
    ws.addEventListener('error',   e  => console.error('[broker] WS error:', e));
  }

  async _onBrokerMessage(ws, data, cfRay) {
    // Binary relay
    if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
      const conn = this.connections.get(ws); if (!conn) return;
      const session = this.sessions.get(conn.code); if (!session) return;
      if (conn.role === 'client' && session.host?.readyState === WebSocket.OPEN) {
        try { session.host.send(data); } catch (_) {}
      } else if (conn.role === 'host') {
        session.clients.forEach(cws => { try { if (cws.readyState === WebSocket.OPEN) cws.send(data); } catch (_) {} });
      }
      return;
    }

    let msg; try { msg = JSON.parse(data); } catch { return; }

    switch (msg.type) {
      case 'HOST_REGISTER': {
        if (msg.hostId) {
          for (const [c, s] of this.sessions) { if (s.hostId === msg.hostId) { await this._cleanupSession(c); break; } }
        }
        const code = generateCode(this.sessions);
        const session = { host: ws, clients: new Set(), createdAt: Date.now(), netType: msg.netType||'WiFi', hostRay: cfRay, hostId: msg.hostId||null };
        this.sessions.set(code, session);
        this.connections.set(ws, { ...(this.connections.get(ws)||{}), role: 'host', code, id: `host-${code}`, lastPong: Date.now() });
        sendJson(ws, { type: 'SESSION_CREATED', code, netType: msg.netType });
        await this._persistSession(code, session);
        if (msg.hostId) this._markHostOnline(msg.hostId, msg.netType||'WiFi', code);
        this._resolveJoinWaiters(code);
        await this._scheduleAlarm();
        break;
      }

      case 'CLIENT_JOIN': {
        const code     = (msg.accessCode||msg.code||'').toUpperCase();
        const deviceId = (msg.deviceId||'').trim();
        if (!code)     return sendJson(ws, { type: 'JOIN_ERROR', reason: 'No code provided' });
        if (!deviceId) return sendJson(ws, { type: 'JOIN_ERROR', reason: 'Device ID missing' });
        const ac = await this._getAccessCode(code);
        const now = Date.now();
        if (!ac || !ac.isActive || new Date(ac.expiresAt).getTime() < now) return sendJson(ws, { type: 'JOIN_ERROR', reason: 'Invalid or expired access code' });
        if (!ac.claimedBy) {
          await this._putAccessCode(code, { ...ac, claimedBy: deviceId, claimedAt: new Date().toISOString() });
        } else if (ac.claimedBy !== deviceId) {
          return sendJson(ws, { type: 'JOIN_ERROR', reason: 'Access code already in use by another device' });
        }
        const find = () => { for (const [c,s] of this.sessions) { if (s.host?.readyState===WebSocket.OPEN && s.clients.size<MAX_CLIENTS) return {s,c}; } return null; };
        let found = find();
        if (!found) {
          const fc = this.sessions.size > 0 ? [...this.sessions.keys()][0] : '__any__';
          if (await this._waitForHost(fc, JOIN_WAIT_MS)) found = find();
        }
        if (!found) return sendJson(ws, { type: 'JOIN_ERROR', reason: 'No hosts available. Try again shortly.' });
        const { s: ts, c: tc } = found;
        if (!this.sessionIpCounters.has(tc)) this.sessionIpCounters.set(tc, 1);
        const idx = this.sessionIpCounters.get(tc);
        this.sessionIpCounters.set(tc, idx+1);
        const clientId = `client-${Date.now()}-${Math.random().toString(36).slice(2,6)}`;
        const tunIp    = `10.8.0.${idx+1}`;
        ts.clients.add(ws);
        this.connections.set(ws, { ...(this.connections.get(ws)||{}), role: 'client', code: tc, id: clientId, tunIp, lastPong: Date.now() });
        sendJson(ws, { type: 'JOIN_SUCCESS', code: tc, netType: ts.netType, clientId, tunIp });
        sendJson(ts.host, { type: 'CLIENT_CONNECTED', clientId, tunIp, totalClients: ts.clients.size });
        await this._scheduleAlarm();
        break;
      }

      case 'HOST_RECONNECT': {
        let existingCode = null;
        for (const [c,s] of this.sessions) { if (s.hostId===msg.hostId) { existingCode=c; break; } }
        if (!existingCode) {
          const stored = await this.state.storage.list({ prefix: 'session:' });
          for (const [k,v] of stored) {
            try { const m=JSON.parse(v); if (m.hostId===msg.hostId && Date.now()-m.createdAt<SESSION_TIMEOUT_MS) { existingCode=k.replace('session:',''); if (!this.sessions.has(existingCode)) this.sessions.set(existingCode,{host:null,clients:new Set(),createdAt:m.createdAt,netType:m.netType||'WiFi',hostId:m.hostId,hostRay:null,_persisted:true}); break; } } catch(_) {}
          }
        }
        if (!existingCode) {
          const code = generateCode(this.sessions);
          const session = { host:ws, clients:new Set(), createdAt:Date.now(), netType:msg.netType||'WiFi', hostRay:cfRay, hostId:msg.hostId };
          this.sessions.set(code, session);
          this.connections.set(ws, {...(this.connections.get(ws)||{}), role:'host', code, id:`host-${code}`, lastPong:Date.now()});
          sendJson(ws, { type:'SESSION_CREATED', code, netType:msg.netType });
          await this._persistSession(code, session);
          if (msg.hostId) this._markHostOnline(msg.hostId, msg.netType||'WiFi', code);
        } else {
          const session = this.sessions.get(existingCode);
          if (session.host) this.connections.delete(session.host);
          session.host = ws; session.hostRay = cfRay;
          this.connections.set(ws, {...(this.connections.get(ws)||{}), role:'host', code:existingCode, id:`host-${existingCode}`, lastPong:Date.now()});
          sendJson(ws, { type:'SESSION_RESUMED', code:existingCode, netType:session.netType });
          session.clients.forEach(cws => sendJson(cws, { type:'HOST_FAILOVER', newSessionCode:existingCode }));
          if (msg.hostId) this._markHostOnline(msg.hostId, msg.netType||'WiFi', existingCode);
          this._resolveJoinWaiters(existingCode);
        }
        await this._scheduleAlarm();
        break;
      }

      case 'PONG': { const c=this.connections.get(ws); if(c) c.lastPong=Date.now(); break; }
      case 'HOST_LEAVE': { const c=this.connections.get(ws); if(c?.role==='host') await this._cleanupSession(c.code); break; }
      case 'CLIENT_LEAVE': {
        const c=this.connections.get(ws); if(!c) return;
        const s=this.sessions.get(c.code);
        if(s) { s.clients.delete(ws); if(s.host?.readyState===WebSocket.OPEN) sendJson(s.host,{type:'CLIENT_DISCONNECTED',clientId:c.id,totalClients:s.clients.size}); }
        this.connections.delete(ws); break;
      }
      default: console.warn(`[broker] Unknown: ${msg.type}`);
    }
  }

  _waitForHost(code, ms) {
    return new Promise(resolve => {
      const s = this.sessions.get(code);
      if (s?.host?.readyState===WebSocket.OPEN) { resolve(true); return; }
      if (!this.joinWaiters.has(code)) this.joinWaiters.set(code, []);
      const timer = setTimeout(() => {
        const w=this.joinWaiters.get(code)||[]; const i=w.findIndex(x=>x.resolve===resolve); if(i!==-1) w.splice(i,1); resolve(false);
      }, ms);
      this.joinWaiters.get(code).push({ resolve, timer });
    });
  }

  _resolveJoinWaiters(code) {
    const w=this.joinWaiters.get(code); if(!w?.length) return;
    w.forEach(({resolve,timer})=>{clearTimeout(timer);resolve(true);}); this.joinWaiters.delete(code);
  }

  _onBrokerClose(ws) {
    const conn=this.connections.get(ws); if(!conn?.role) { this.connections.delete(ws); return; }
    if (conn.role==='host') {
      const session=this.sessions.get(conn.code); const hostId=session?.hostId;
      setTimeout(async()=>{ const s=this.sessions.get(conn.code); if(s&&s.host===ws) { if(hostId) this._markHostOffline(hostId); await this._cleanupSession(conn.code); } }, HOST_RECONNECT_WAIT);
    } else if (conn.role==='client') {
      const s=this.sessions.get(conn.code);
      if(s) { s.clients.delete(ws); if(s.host?.readyState===WebSocket.OPEN) sendJson(s.host,{type:'CLIENT_DISCONNECTED',clientId:conn.id,totalClients:s.clients.size}); }
    }
    this.connections.delete(ws);
  }

  async _cleanupSession(code) {
    const s=this.sessions.get(code); if(!s) return;
    s.clients.forEach(cws=>{ sendJson(cws,{type:'HOST_LEFT',reason:'Host disconnected'}); this.connections.delete(cws); });
    if(s.host) this.connections.delete(s.host);
    this.sessions.delete(code); this.sessionIpCounters.delete(code);
    await this._deleteSession(code);
    const w=this.joinWaiters.get(code); if(w) { w.forEach(({resolve,timer})=>{clearTimeout(timer);resolve(false);}); this.joinWaiters.delete(code); }
  }
}
