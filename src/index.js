/**
 * index.js — NetShare Relay Worker (Global Tunnel Only)
 *
 * Routes:
 *   POST /register        → host registers → { code, sessionId }
 *   GET  /join/:code      → client looks up session → { sessionId }
 *   POST /deregister      → host removes session
 *   POST /ping            → host keeps session alive
 *   GET  /health          → edge health check
 *   WS   /ws/host/:code   → host WebSocket tunnel (Cloudflare pipes to client)
 *   WS   /ws/client/:code → client WebSocket tunnel (VPN routes all traffic here)
 *   /admin/*              → admin routes
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

    // ── Edge health check — no DO needed ─────────────────────────────────────
    if (path === '/health') {
      return jsonResp({ status: 'ok', ts: Date.now() });
    }

    // ── POST /register ────────────────────────────────────────────────────────
    if (path === '/register' && request.method === 'POST') {
      return getAdminStub(env).fetch(request);
    }

    // ── GET /join/:code ───────────────────────────────────────────────────────
    if (path.startsWith('/join/') && request.method === 'GET') {
      return getAdminStub(env).fetch(request);
    }

    // ── POST /deregister ──────────────────────────────────────────────────────
    if (path === '/deregister' && request.method === 'POST') {
      return getAdminStub(env).fetch(request);
    }

    // ── POST /ping ────────────────────────────────────────────────────────────
    if (path === '/ping' && request.method === 'POST') {
      return getAdminStub(env).fetch(request);
    }

    // ── WebSocket Tunnel routes (long-distance mode) ──────────────────────────
    // These are forwarded to the DO that owns the session code.
    // The DO pairs host WS ↔ client WS and pipes bytes between them.
    if (path.startsWith('/ws/host/') || path.startsWith('/ws/client/')) {
      // Extract code from path to route to the right DO instance
      // We use a single global DO (same as admin) so all sessions share state.
      // If you want per-session DOs, derive idFromName(code) here instead.
      return getAdminStub(env).fetch(request);
    }

    // /probe removed — LAN mode no longer supported (tunnel-only now)

    // ── Admin + validate-code + stats ─────────────────────────────────────────
    if (path.startsWith('/admin/') || path === '/validate-code' || path === '/stats') {
      return getAdminStub(env).fetch(request);
    }

    // ── Legacy WebSocket broker ───────────────────────────────────────────────
    if (request.headers.get('Upgrade') === 'websocket') {
      return getAdminStub(env).fetch(request);
    }

    return jsonResp({ message: 'NetShare Relay — HTTP Proxy Edition' });
  },
};
