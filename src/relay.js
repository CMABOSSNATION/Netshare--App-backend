/**
 * relay.js — NetShare Cloudflare Worker (HTTP Proxy Edition)
 *
 * ─── Role ─────────────────────────────────────────────────────────────────────
 *
 * Thin signalling layer ONLY. No app traffic flows through here.
 * Stores host IP:port in KV so clients can find the host by session code.
 *
 * ─── Endpoints ────────────────────────────────────────────────────────────────
 *
 *  POST /register        Host registers proxy IP:port → gets session code
 *  GET  /join/:code      Client looks up host IP:port by code
 *  POST /ping            Host keeps session alive (call every 30s)
 *  POST /deregister      Host removes session on stop
 *  GET  /health          Health check → "OK"
 *  GET  /admin/sessions  List active sessions (requires x-admin-key header)
 *
 * ─── Why /probe was removed ───────────────────────────────────────────────────
 *
 *  The old /probe used cloudflare:sockets to TCP-connect to the host's
 *  private IP (192.168.x.x). Cloudflare Workers CANNOT reach RFC-1918
 *  private addresses — they only have internet egress. The probe would
 *  always time out and return "unreachable" even when the proxy works fine.
 *
 *  Fix: the client app tests the proxy directly over local Wi-Fi by
 *  making a plain HTTP request to http://ip:port/netshare-probe and
 *  checking the response. Faster, accurate, no relay needed.
 *
 * ─── Storage ──────────────────────────────────────────────────────────────────
 *
 *  Cloudflare KV namespace: SESSIONS
 *  Keys:
 *    session:<sessionId>  →  { ip, port, sessionId, createdAt, lastPing, clients }
 *    code:<CODE>          →  sessionId
 *  TTL: 6 hours on every write (auto-expires stale sessions).
 *
 * ─── No Durable Objects needed ───────────────────────────────────────────────
 *
 *  Old relay used Durable Objects for WebSocket state.
 *  New relay is fully stateless — everything lives in KV.
 *  Zero cold-start latency, no DO billing.
 *
 * ─── wrangler.toml setup ─────────────────────────────────────────────────────
 *
 *  1. Create KV namespace:
 *       wrangler kv:namespace create SESSIONS
 *     Copy the printed id into wrangler.toml under [[kv_namespaces]]
 *
 *  2. Set admin secret:
 *       wrangler secret put ADMIN_KEY
 *
 *  3. Deploy:
 *       wrangler deploy
 */

const CODE_CHARS      = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const SESSION_TTL_SEC = 6 * 3600;  // 6 hours
const MAX_CLIENTS     = 5;

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
  if (!ip || typeof ip !== 'string') return false;
  if (ip === 'localhost' || ip === '::1') return false;
  // Accept RFC-1918 LAN IPs (192.168.x.x, 10.x.x.x) — that's where hosts live
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);
}

// ── Main fetch handler ────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url  = new URL(request.url);
    const path = url.pathname;

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors() });
    }

    // ── Health ────────────────────────────────────────────────────────────────

    if (path === '/health' || path === '/ping-health') {
      return new Response('OK', {
        status: 200,
        headers: { 'Content-Type': 'text/plain', ...cors() },
      });
    }

    // ── POST /register — Host registers proxy ─────────────────────────────────

    if (path === '/register' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return err('Invalid JSON'); }

      const { ip, port } = body;

      if (!validateIp(ip))                   return err('Invalid IP address');
      if (!port || port < 1 || port > 65535) return err('Invalid port');

      const sessionId = crypto.randomUUID();
      let code;
      let attempts = 0;

      // Generate a collision-free 4-char code
      do {
        code = randomCode(4);
        const existing = await env.SESSIONS.get(`code:${code}`);
        if (!existing) break;
        attempts++;
      } while (attempts < 20);

      const record = JSON.stringify({
        ip,
        port,
        sessionId,
        createdAt: Date.now(),
        lastPing:  Date.now(),
        clients:   0,
      });

      await Promise.all([
        env.SESSIONS.put(`session:${sessionId}`, record,    { expirationTtl: SESSION_TTL_SEC }),
        env.SESSIONS.put(`code:${code}`,         sessionId, { expirationTtl: SESSION_TTL_SEC }),
      ]);

      console.log(`[register] ${ip}:${port} code=${code} session=${sessionId}`);
      return json({ code, sessionId });
    }

    // ── GET /join/:code — Client looks up host ────────────────────────────────

    const joinMatch = path.match(/^\/join\/([A-Z0-9]{4,8})$/i);
    if (joinMatch && request.method === 'GET') {
      const code      = joinMatch[1].toUpperCase();
      const sessionId = await env.SESSIONS.get(`code:${code}`);

      if (!sessionId) return err('Session not found or expired', 404);

      const raw = await env.SESSIONS.get(`session:${sessionId}`);
      if (!raw)       return err('Session expired', 404);

      const session = JSON.parse(raw);

      if (session.clients >= MAX_CLIENTS) {
        return err(`Session full (max ${MAX_CLIENTS} clients)`, 403);
      }

      // Track client count
      session.clients++;
      await env.SESSIONS.put(
        `session:${sessionId}`,
        JSON.stringify(session),
        { expirationTtl: SESSION_TTL_SEC }
      );

      console.log(`[join] code=${code} → ${session.ip}:${session.port}`);
      return json({ ip: session.ip, port: session.port, sessionId });
    }

    // ── POST /ping — Host keep-alive ──────────────────────────────────────────

    if (path === '/ping' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return err('Invalid JSON'); }

      const raw = await env.SESSIONS.get(`session:${body.sessionId}`);
      if (!raw) return err('Session not found', 404);

      const session    = JSON.parse(raw);
      session.lastPing = Date.now();

      await env.SESSIONS.put(
        `session:${body.sessionId}`,
        JSON.stringify(session),
        { expirationTtl: SESSION_TTL_SEC }
      );

      return json({ ok: true });
    }

    // ── POST /deregister — Host stops ─────────────────────────────────────────

    if (path === '/deregister' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return err('Invalid JSON'); }

      const raw = await env.SESSIONS.get(`session:${body.sessionId}`);
      if (raw) {
        await env.SESSIONS.delete(`session:${body.sessionId}`);
        // code:XXXX key expires naturally via TTL
        console.log(`[deregister] session=${body.sessionId}`);
      }

      return json({ ok: true });
    }

    // ── GET /admin/sessions — Admin panel ─────────────────────────────────────

    if (path === '/admin/sessions' && request.method === 'GET') {
      const adminKey = request.headers.get('x-admin-key');
      if (!adminKey || adminKey !== env.ADMIN_KEY) {
        return err('Unauthorized', 401);
      }

      const { keys } = await env.SESSIONS.list({ prefix: 'session:' });
      const sessions = await Promise.all(
        keys.map(async k => {
          const raw = await env.SESSIONS.get(k.name);
          return raw ? JSON.parse(raw) : null;
        })
      );

      const active = sessions.filter(Boolean);
      return json({ sessions: active, count: active.length });
    }

    return err('Not found', 404);
  },
};
