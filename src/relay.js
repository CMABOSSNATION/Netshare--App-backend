/**
 * relay.js — NetShare Cloudflare Worker (HTTP Proxy Edition)
 *
 * ─── What changed from the WebSocket version ─────────────────────────────────
 *
 * OLD: This worker was a complex TCP tunnel relay. All client traffic flowed
 * through it over WebSocket. It needed Durable Objects, INIT messages, TCP
 * socket bridging, back-pressure queues, TLS detection, and 870 lines of code.
 *
 * NEW: This worker is a thin signalling layer only. No traffic flows through it.
 * Total code: ~200 lines.
 *
 * ─── Endpoints ────────────────────────────────────────────────────────────────
 *
 *  POST /register
 *    Body: { ip, port, type: 'http-proxy' }
 *    Response: { code, sessionId }
 *    Action: Host registers its proxy IP:port. Relay stores it and returns
 *            a short session code that clients use to find the host.
 *
 *  GET  /join/:code
 *    Response: { ip, port, sessionId }
 *    Action: Client looks up host IP:port by session code.
 *
 *  POST /ping
 *    Body: { sessionId }
 *    Action: Host keeps session alive (sessions expire after 6 hours of no pings).
 *
 *  POST /deregister
 *    Body: { sessionId }
 *    Action: Host explicitly removes its session when stopping.
 *
 *  POST /probe
 *    Body: { ip, port }
 *    Response: { ok: true } or 502
 *    Action: Tests whether a given IP:port is reachable from the Cloudflare edge.
 *            Used by the client app to verify proxy connectivity before showing
 *            a "connected" state.
 *
 *  GET  /health
 *    Response: "OK"
 *
 * ─── Storage ──────────────────────────────────────────────────────────────────
 *
 *  Uses Cloudflare KV (SESSIONS namespace) to store session records.
 *  Each record: { ip, port, sessionId, createdAt, lastPing }
 *  TTL: 6 hours (set on KV write).
 *  Key: `session:<sessionId>`
 *  Index: `code:<CODE>` → sessionId (for code lookup)
 *
 * ─── No Durable Objects needed ───────────────────────────────────────────────
 *
 *  The old relay used Durable Objects to maintain WebSocket state.
 *  The new relay is stateless — all state lives in KV.
 *  This also means zero cold-start latency and no DO billing.
 */

const CODE_CHARS        = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const SESSION_TTL_SEC   = 6 * 3600;   // 6 hours
const MAX_CLIENTS       = 5;
const PROBE_TIMEOUT_MS  = 5000;

// ── Helpers ───────────────────────────────────────────────────────────────────

function cors() {
  return {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-admin-key',
  };
}

function json(data, status = 200) {
  return Response.json(data, { status, headers: cors() });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

function randomCode(n = 4) {
  return Array.from({ length: n },
    () => CODE_CHARS[Math.floor(Math.random() * CODE_CHARS.length)]
  ).join('');
}

function validateIp(ip) {
  // Reject private / loopback ranges — clients must be on same LAN as host,
  // but we still validate to prevent abuse.
  if (!ip || typeof ip !== 'string') return false;
  if (ip === 'localhost' || ip === '::1') return false;
  // Allow RFC-1918 (that's where hosts will be — 192.168.x.x, 10.x.x.x)
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);
}

// ── Main fetch handler ────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url  = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors() });
    }

    // ── Health check ─────────────────────────────────────────────────────────

    if (path === '/health' || path === '/ping-health') {
      return new Response('OK', { status: 200, headers: { 'Content-Type': 'text/plain', ...cors() } });
    }

    // ── Register (HOST) ───────────────────────────────────────────────────────

    if (path === '/register' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return err('Invalid JSON'); }

      const { ip, port } = body;

      if (!validateIp(ip))              return err('Invalid IP address');
      if (!port || port < 1 || port > 65535) return err('Invalid port');

      // Generate a unique session code
      const sessionId = crypto.randomUUID();
      let   code;
      let   attempts = 0;

      do {
        code = randomCode(4);
        const existing = await env.SESSIONS.get(`code:${code}`);
        if (!existing) break;
        attempts++;
      } while (attempts < 20);

      const record = JSON.stringify({
        ip, port, sessionId,
        createdAt: Date.now(),
        lastPing:  Date.now(),
        clients:   0,
      });

      // Store with TTL
      await Promise.all([
        env.SESSIONS.put(`session:${sessionId}`, record, { expirationTtl: SESSION_TTL_SEC }),
        env.SESSIONS.put(`code:${code}`, sessionId,      { expirationTtl: SESSION_TTL_SEC }),
      ]);

      console.log(`[register] ${ip}:${port} → code=${code} session=${sessionId}`);
      return json({ code, sessionId });
    }

    // ── Join (CLIENT) ─────────────────────────────────────────────────────────

    const joinMatch = path.match(/^\/join\/([A-Z0-9]{4,8})$/i);
    if (joinMatch && request.method === 'GET') {
      const code      = joinMatch[1].toUpperCase();
      const sessionId = await env.SESSIONS.get(`code:${code}`);

      if (!sessionId) return err('Session not found or expired', 404);

      const raw = await env.SESSIONS.get(`session:${sessionId}`);
      if (!raw)  return err('Session expired', 404);

      const session = JSON.parse(raw);

      if (session.clients >= MAX_CLIENTS) {
        return err('Session is full (max ' + MAX_CLIENTS + ' clients)', 403);
      }

      // Increment client count
      session.clients++;
      await env.SESSIONS.put(`session:${sessionId}`, JSON.stringify(session),
        { expirationTtl: SESSION_TTL_SEC });

      console.log(`[join] code=${code} → ${session.ip}:${session.port}`);
      return json({ ip: session.ip, port: session.port, sessionId });
    }

    // ── Ping / keep-alive (HOST) ──────────────────────────────────────────────

    if (path === '/ping' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return err('Invalid JSON'); }

      const raw = await env.SESSIONS.get(`session:${body.sessionId}`);
      if (!raw) return err('Session not found', 404);

      const session    = JSON.parse(raw);
      session.lastPing = Date.now();

      await env.SESSIONS.put(`session:${body.sessionId}`, JSON.stringify(session),
        { expirationTtl: SESSION_TTL_SEC });

      return json({ ok: true });
    }

    // ── Deregister (HOST stopping) ────────────────────────────────────────────

    if (path === '/deregister' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return err('Invalid JSON'); }

      const raw = await env.SESSIONS.get(`session:${body.sessionId}`);
      if (raw) {
        const session = JSON.parse(raw);
        // Delete both keys
        await Promise.all([
          env.SESSIONS.delete(`session:${body.sessionId}`),
          // We don't store reverse code→session mapping after deregister,
          // but the code key TTL will expire naturally.
        ]);
        console.log(`[deregister] session=${body.sessionId}`);
      }

      return json({ ok: true });
    }

    // ── Probe (CLIENT connectivity test) ──────────────────────────────────────

    if (path === '/probe' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return err('Invalid JSON'); }

      const { ip, port } = body;
      if (!validateIp(ip) || !port) return err('Invalid ip/port');

      // Attempt a real TCP connection to ip:port using Cloudflare sockets
      try {
        const { connect } = await import('cloudflare:sockets');
        const socket = connect({ hostname: ip, port: parseInt(port) });

        // Race the open promise against a timeout
        const opened = await Promise.race([
          socket.opened,
          new Promise((_, rej) =>
            setTimeout(() => rej(new Error('timeout')), PROBE_TIMEOUT_MS)
          ),
        ]);

        // Close immediately — we just needed to know it's reachable
        try { await socket.close(); } catch (_) {}
        return json({ ok: true, reachable: true });
      } catch (e) {
        return json({ ok: false, reachable: false, reason: e.message }, 502);
      }
    }

    // ── Admin: list sessions ──────────────────────────────────────────────────

    if (path === '/admin/sessions' && request.method === 'GET') {
      const adminKey = request.headers.get('x-admin-key');
      if (adminKey !== env.ADMIN_KEY) return err('Unauthorized', 401);

      const { keys } = await env.SESSIONS.list({ prefix: 'session:' });
      const sessions = await Promise.all(
        keys.map(async k => {
          const raw = await env.SESSIONS.get(k.name);
          return raw ? JSON.parse(raw) : null;
        })
      );

      return json({ sessions: sessions.filter(Boolean), count: sessions.length });
    }

    return err('Not found', 404);
  },
};
