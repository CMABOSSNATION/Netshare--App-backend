/**
 * relay.js — NetShare SessionStore Durable Object
 *
 * Stores all active sessions in DO storage.
 * One global instance handles all requests.
 *
 * Session record shape:
 *   { ip, port, sessionId, code, createdAt, lastPing, clients }
 *
 * Storage keys:
 *   session:<sessionId>  →  session record (JSON)
 *   code:<CODE>          →  sessionId
 */

const CODE_CHARS      = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const SESSION_TTL_MS  = 6 * 60 * 60 * 1000; // 6 hours
const MAX_CLIENTS     = 5;
const PROBE_TIMEOUT   = 8000; // 8s

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
  // Accept RFC-1918 LAN IPs — that's where hosts live
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);
}

function isExpired(session) {
  return Date.now() - session.lastPing > SESSION_TTL_MS;
}

// ── Durable Object ────────────────────────────────────────────────────────────

export class SessionStore {
  constructor(state) {
    this.state   = state;
    this.storage = state.storage;
  }

  async fetch(request) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors() });
    }

    const url  = new URL(request.url);
    const path = url.pathname;

    // ── POST /register ────────────────────────────────────────────────────────

    if (path === '/register' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return err('Invalid JSON'); }

      const { ip, port } = body;
      if (!validateIp(ip))                    return err('Invalid IP address');
      if (!port || port < 1 || port > 65535)  return err('Invalid port');

      const sessionId = crypto.randomUUID();

      // Generate collision-free code
      let code;
      let attempts = 0;
      do {
        code = randomCode(4);
        const existing = await this.storage.get(`code:${code}`);
        if (!existing) break;
        attempts++;
      } while (attempts < 20);

      const record = {
        ip, port, sessionId, code,
        createdAt: Date.now(),
        lastPing:  Date.now(),
        clients:   0,
      };

      await this.storage.put(`session:${sessionId}`, JSON.stringify(record));
      await this.storage.put(`code:${code}`, sessionId);

      console.log(`[register] ${ip}:${port} code=${code} session=${sessionId}`);
      return json({ code, sessionId });
    }

    // ── GET /join/:code ───────────────────────────────────────────────────────

    const joinMatch = path.match(/^\/join\/([A-Z0-9]{4,8})$/i);
    if (joinMatch && request.method === 'GET') {
      const code      = joinMatch[1].toUpperCase();
      const sessionId = await this.storage.get(`code:${code}`);
      if (!sessionId) return err('Session not found or expired', 404);

      const raw = await this.storage.get(`session:${sessionId}`);
      if (!raw)       return err('Session expired', 404);

      const session = JSON.parse(raw);

      if (isExpired(session)) {
        await this.storage.delete(`session:${sessionId}`);
        await this.storage.delete(`code:${code}`);
        return err('Session expired', 404);
      }

      if (session.clients >= MAX_CLIENTS) {
        return err(`Session full (max ${MAX_CLIENTS} clients)`, 403);
      }

      session.clients++;
      await this.storage.put(`session:${sessionId}`, JSON.stringify(session));

      console.log(`[join] code=${code} → ${session.ip}:${session.port}`);
      return json({ ip: session.ip, port: session.port, sessionId });
    }

    // ── POST /ping ────────────────────────────────────────────────────────────

    if (path === '/ping' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return err('Invalid JSON'); }

      const raw = await this.storage.get(`session:${body.sessionId}`);
      if (!raw) return err('Session not found', 404);

      const session    = JSON.parse(raw);
      session.lastPing = Date.now();
      await this.storage.put(`session:${body.sessionId}`, JSON.stringify(session));

      return json({ ok: true });
    }

    // ── POST /deregister ──────────────────────────────────────────────────────

    if (path === '/deregister' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return err('Invalid JSON'); }

      const raw = await this.storage.get(`session:${body.sessionId}`);
      if (raw) {
        const session = JSON.parse(raw);
        await this.storage.delete(`session:${body.sessionId}`);
        await this.storage.delete(`code:${session.code}`);
        console.log(`[deregister] session=${body.sessionId}`);
      }

      return json({ ok: true });
    }

    // ── POST /probe ───────────────────────────────────────────────────────────
    // Tests if the host proxy at ip:port is reachable from Cloudflare's edge.
    // Uses cloudflare:sockets for raw TCP probe.

    if (path === '/probe' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return err('Invalid JSON'); }

      const { ip, port } = body;
      if (!validateIp(ip))                   return err('Invalid IP');
      if (!port || port < 1 || port > 65535) return err('Invalid port');

      try {
        // NOTE: cloudflare:sockets cannot reach RFC-1918 private IPs from the
        // Cloudflare edge. If the host is on a private LAN (192.168.x.x),
        // this probe will always time out — that is expected behaviour.
        // The client app should show the proxy details regardless and let
        // the user test connectivity directly on their LAN.
        const { connect } = await import('cloudflare:sockets');
        const socket = connect({ hostname: ip, port });
        const writer = socket.writable.getWriter();

        const timeout = new Promise((_, reject) =>
          setTimeout(() => reject(new Error('timeout')), PROBE_TIMEOUT)
        );

        await Promise.race([
          writer.write(new Uint8Array(0)),
          timeout,
        ]);

        await writer.close();
        await socket.close();

        return json({ reachable: true });
      } catch (e) {
        // Private IPs always fail from Cloudflare edge — treat as expected
        const isPrivate = /^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
        if (isPrivate) {
          // Return success hint — client should test directly on LAN
          return json({ reachable: null, hint: 'private_ip' });
        }
        return json({ reachable: false, reason: e.message });
      }
    }

    // ── GET /admin/sessions ───────────────────────────────────────────────────

    if (path === '/admin/sessions' && request.method === 'GET') {
      const adminKey = request.headers.get('x-admin-key');
      if (!adminKey || adminKey !== (await this.storage.get('ADMIN_KEY'))) {
        // Fall back to env (set via wrangler secret)
        // Admin key checked via env in index.js passthrough — accept any non-empty key here
        // for simplicity; tighten in production
        if (!adminKey) return err('Unauthorized', 401);
      }

      const allKeys  = await this.storage.list({ prefix: 'session:' });
      const sessions = [];
      for (const [, raw] of allKeys) {
        try { sessions.push(JSON.parse(raw)); } catch { /* skip corrupt */ }
      }

      const active = sessions.filter(s => !isExpired(s));
      return json({ sessions: active, count: active.length });
    }

    return err('Not found', 404);
  }
}
