/**
 * index.js — NetShare Relay Worker Entry Point v3
 *
 * FIXES IN THIS VERSION:
 *
 * FIX 1 — Broken 101 response reconstruction (root cause of WhatsApp/Facebook/Spotify failures)
 *   The old code cloned the DO's 101 response and tried to add headers. Cloudflare
 *   does not allow cloning WebSocket 101 responses across DO fetch boundaries —
 *   the internal webSocket handle is not transferable that way. We now forward
 *   the request directly and let the DO return its own 101 cleanly.
 *
 * FIX 2 — sessionId injected via header, not URL mutation
 *   Mutating the URL searchParams and rebuilding a Request added unnecessary latency
 *   and occasionally mangled URLs with special characters. Header injection is cleaner.
 *
 * FIX 3 — Admin routes explicitly caught before fallthrough
 *   Previously unknown paths fell through two stub.fetch() calls. Now one clean branch.
 */

import { TcpTunnelSession } from './relay.js';
export { TcpTunnelSession };

const ADMIN_DO_NAME = 'global-admin';

function resolveSessionId(url, request) {
  const p = url.searchParams.get('sessionId')
         || url.searchParams.get('hostId')
         || request.headers.get('X-Session-Id');
  return (p || crypto.randomUUID()).trim().slice(0, 64);
}

function getTunnelStub(env, sessionId) {
  return env.RELAY.get(env.RELAY.idFromName(`tunnel:${sessionId}`));
}

function getAdminStub(env) {
  return env.RELAY.get(env.RELAY.idFromName(ADMIN_DO_NAME));
}

function cors() {
  return {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-requested-with, x-admin-key, x-session-id',
  };
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

    // Health — answered at edge, zero DO overhead
    if (path === '/health' || path === '/ping') {
      return new Response('OK', { status: 200, headers: { 'Content-Type': 'text/plain', ...cors() } });
    }

    // WebSocket upgrade → isolated tunnel shard
    if (request.headers.get('Upgrade') === 'websocket') {
      const sessionId = resolveSessionId(url, request);
      const stub      = getTunnelStub(env, sessionId);

      // Inject sessionId via header — DO reads X-Shard-Id and echoes it back
      const fwdHeaders = new Headers(request.headers);
      fwdHeaders.set('X-Shard-Id', sessionId);

      // Forward directly — DO owns the WebSocketPair and returns the clean 101
      return stub.fetch(new Request(request.url, {
        method:  request.method,
        headers: fwdHeaders,
      }));
    }

    // Everything else → global admin DO (stats, codes, broker, admin routes)
    return getAdminStub(env).fetch(request);
  },
};
