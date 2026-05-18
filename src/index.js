/**
 * index.js — NetShare Relay Worker
 *
 * This relay handles SESSION SIGNALLING ONLY.
 * It does NOT carry any user traffic.
 *
 * The host phone runs a real HTTP CONNECT proxy on its WiFi IP:8899.
 * The relay just stores { ip, port } and hands it out via a session code.
 *
 * Routes used by ProxyService.js:
 *   POST /register      → host registers { ip, port } → returns { code, sessionId }
 *   GET  /join/:code    → client looks up code → returns { ip, port, sessionId }
 *   POST /deregister    → host removes session
 *   POST /ping          → host keeps session alive
 *   POST /probe         → server-side reachability check of { ip, port }
 *   GET  /health        → edge health check
 *   /admin/*            → admin routes (access codes, stats)
 */

import { ProxySession } from './relay.js';
export { ProxySession };

const ADMIN_DO_NAME = 'global-admin';

function getAdminStub(env) {
  return env.RELAY.get(env.RELAY.idFromName(ADMIN_DO_NAME));
}

function cors() {
  return {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-admin-key, x-requested-with',
  };
}

function jsonResp(data, status = 200) {
  return Response.json(data, { status, headers: cors() });
}

export default {
  async fetch(request, env) {
    let url;
    try { url = new URL(request.url); }
    catch { return new Response('Bad Request', { status: 400 }); }

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors() });
    }

    const path = url.pathname;

    // ── Edge health check — no DO needed ─────────────────────────────────
    if (path === '/health' || path === '/ping') {
      return jsonResp({ status: 'ok', ts: Date.now() });
    }

    // ── POST /register — host registers its proxy IP:port ─────────────────
    // Returns a short session code the host shows to the client.
    if (path === '/register' && request.method === 'POST') {
      return getAdminStub(env).fetch(request);
    }

    // ── GET /join/:code — client looks up a session code ──────────────────
    if (path.startsWith('/join/') && request.method === 'GET') {
      return getAdminStub(env).fetch(request);
    }

    // ── POST /deregister — host removes its session ────────────────────────
    if (path === '/deregister' && request.method === 'POST') {
      return getAdminStub(env).fetch(request);
    }

    // ── POST /ping — host keeps session alive ──────────────────────────────
    if (path === '/ping' && request.method === 'POST') {
      return getAdminStub(env).fetch(request);
    }

    // ── POST /probe — server checks if ip:port is reachable ───────────────
    // Used by the client to verify the host proxy is live before
    // asking the user to configure Android WiFi proxy settings.
    if (path === '/probe' && request.method === 'POST') {
      try {
        const { ip, port } = await request.json();
        if (!ip || !port) return jsonResp({ ok: false, reason: 'Missing ip or port' }, 400);

        // Attempt TCP connect to host ip:port via cloudflare:sockets
        // If it connects, the host proxy is reachable
        const { connect } = await import('cloudflare:sockets');
        let reachable = false;
        try {
          const sock = connect({ hostname: ip, port: parseInt(port) }, { allowHalfOpen: false });
          await Promise.race([
            sock.opened,
            new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 5000)),
          ]);
          reachable = true;
          try { await sock.close(); } catch (_) {}
        } catch (_) {
          reachable = false;
        }
        return jsonResp({ ok: reachable });
      } catch (e) {
        return jsonResp({ ok: false, reason: e.message }, 500);
      }
    }

    // ── Admin routes ───────────────────────────────────────────────────────
    if (path.startsWith('/admin/') || path === '/validate-code' || path === '/stats') {
      return getAdminStub(env).fetch(request);
    }

    // ── Legacy WebSocket broker ────────────────────────────────────────────
    if (request.headers.get('Upgrade') === 'websocket') {
      return getAdminStub(env).fetch(request);
    }

    return jsonResp({ message: 'NetShare Relay — HTTP Proxy Edition' });
  },
};
