/**
 * index.js — NetShare Relay Worker Entry Point
 *
 * Architecture: Dynamic Session Sharding
 * ─────────────────────────────────────────────────────────────────────────────
 * Instead of routing every connection to a single shared 'global' Durable Object
 * (which becomes a CPU/memory bottleneck), we now spin up ONE isolated Durable
 * Object per user session. Each DO handles exactly one TCP tunnel: one WebSocket
 * client ↔ one outbound TCP socket to the target internet host.
 *
 * Session routing logic:
 *   1. A client connects with ?sessionId=<uuid> in the URL.
 *   2. The Worker derives a DO name from that sessionId (or generates one).
 *   3. The WebSocket upgrade is forwarded into that isolated DO instance.
 *   4. The DO opens a raw TCP socket to the target host and pipes data bidirectionally.
 *
 * Non-WebSocket routes (health, admin, stats, validate-code) are still routed to
 * a single named 'global-admin' DO instance so that access-code state and host
 * registry remain consistent across all DOs.
 *
 * Cloudflare Durable Objects guarantee that all requests sharing the same DO name
 * are routed to the same isolated V8 isolate in the same data center, giving us:
 *   - Single-tenant CPU isolation (no head-of-line blocking)
 *   - Automatic geographic co-location with the client
 *   - In-memory state that lives exactly as long as the TCP tunnel needs it
 */

import { TcpTunnelSession } from './relay.js';
export { TcpTunnelSession };

// ── Constants ──────────────────────────────────────────────────────────────────
const ADMIN_DO_NAME = 'global-admin';

// Administrative + non-tunnel HTTP routes that don't need their own DO shard.
const ADMIN_HTTP_ROUTES = new Set([
  '/health', '/ping', '/stats', '/validate-code',
  '/admin/stats', '/admin/codes', '/admin/codes/generate',
  '/admin/codes/revoke', '/admin/hosts', '/admin/payouts',
  '/admin/payouts/reset',
]);

// ── Helpers ────────────────────────────────────────────────────────────────────

/**
 * Extracts or generates a stable sessionId for this connection.
 *
 * Priority order:
 *   1. ?sessionId= query param  (client explicitly requests sticky session)
 *   2. ?hostId=    query param  (host reconnect path — use hostId as shard key)
 *   3. X-Session-Id request header
 *   4. crypto.randomUUID()      (first-time connection; client should store and reuse)
 *
 * The sessionId is echoed back in the 101 response headers so the client can
 * persist it across reconnections (see Session Stickiness section in the guide).
 */
function resolveSessionId(url, request) {
  const fromParam  = url.searchParams.get('sessionId');
  const fromHostId = url.searchParams.get('hostId');
  const fromHeader = request.headers.get('X-Session-Id');
  return (fromParam || fromHostId || fromHeader || crypto.randomUUID()).trim().slice(0, 64);
}

/**
 * Returns a Durable Object stub for an isolated session shard.
 * DO names are prefixed with 'tunnel:' to namespace them away from admin state.
 */
function getTunnelStub(env, sessionId) {
  const doId = env.RELAY.idFromName(`tunnel:${sessionId}`);
  return env.RELAY.get(doId);
}

/**
 * Returns the single shared admin DO stub.
 */
function getAdminStub(env) {
  const doId = env.RELAY.idFromName(ADMIN_DO_NAME);
  return env.RELAY.get(doId);
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-requested-with, x-admin-key, x-session-id',
  };
}

// ── Worker entry point ─────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url = request.url ? new URL(request.url) : null;
    if (!url) return new Response('Bad Request', { status: 400 });

    // ── CORS pre-flight ──────────────────────────────────────────────────────
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    const path = url.pathname;

    // ── Fast health check (answered at the Worker edge, no DO needed) ────────
    if (path === '/health' || path === '/ping') {
      return new Response('OK', {
        status: 200,
        headers: { 'Content-Type': 'text/plain', ...corsHeaders() },
      });
    }

    // ── WebSocket upgrade → isolated tunnel shard ────────────────────────────
    if (request.headers.get('Upgrade') === 'websocket') {
      const sessionId = resolveSessionId(url, request);
      const stub      = getTunnelStub(env, sessionId);

      // Forward the full request (including upgrade headers) into the shard DO.
      // The DO will call server.accept() and return a 101 response.
      const tunnelReq = new Request(request.url, {
        method:  request.method,
        headers: request.headers,
        // Attach sessionId so the DO can echo it back
        // (we do this via URL param to avoid header clobbering)
      });

      const tunnelUrl = new URL(tunnelReq.url);
      tunnelUrl.searchParams.set('_sid', sessionId); // internal shard param

      const response = await stub.fetch(new Request(tunnelUrl.toString(), {
        method:  request.method,
        headers: request.headers,
      }));

      // Echo the sessionId back to the client in the 101 upgrade response
      // so mobile apps can persist it for sticky reconnections.
      if (response.status === 101) {
        const headers = new Headers(response.headers);
        headers.set('X-Session-Id', sessionId);
        return new Response(response.body, {
          status:  101,
          webSocket: response.webSocket,
          headers,
        });
      }
      return response;
    }

    // ── All remaining HTTP routes → shared admin DO ──────────────────────────
    if (ADMIN_HTTP_ROUTES.has(path) || path.startsWith('/admin/')) {
      const stub = getAdminStub(env);
      return stub.fetch(request);
    }

    // ── Default: route unknown paths to admin DO (it will return 404) ────────
    const stub = getAdminStub(env);
    return stub.fetch(request);
  },
};
