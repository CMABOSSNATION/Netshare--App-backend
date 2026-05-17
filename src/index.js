/**
 * index.js — NetShare Relay Worker Entry Point v4
 *
 * ROOT CAUSE FIX — Wrong WebSocket routing (caused all INIT timeout errors)
 *   The previous version sent EVERY WebSocket connection to a tunnel shard DO,
 *   including the broker connections (HOST_REGISTER, CLIENT_JOIN, HOST_RECONNECT).
 *   Those broker connections never send an INIT message, so the tunnel shard
 *   always hit INIT timeout and closed — making the host appear to connect then
 *   immediately disconnect in a loop.
 *
 *   Fix: Only route to a tunnel shard when the request is explicitly for a tunnel
 *   (path === '/tunnel' OR sessionId/hostId param is in the URL).
 *   All other WebSocket connections go to the admin/broker DO as intended.
 */

import { TcpTunnelSession } from './relay.js';
export { TcpTunnelSession };

const ADMIN_DO_NAME = 'global-admin';

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

    if (request.headers.get('Upgrade') === 'websocket') {
      // Route to tunnel shard ONLY when explicitly requested:
      //   - path is /tunnel, OR
      //   - sessionId or hostId query param is present
      //
      // All other WS connections (HOST_REGISTER, CLIENT_JOIN, HOST_RECONNECT)
      // are broker connections and MUST go to the admin DO.
      const explicitId = url.searchParams.get('sessionId') || url.searchParams.get('hostId');
      const isTunnel   = path === '/tunnel' || Boolean(explicitId);

      if (isTunnel) {
        const sessionId = explicitId
          ? explicitId.trim().slice(0, 64)
          : crypto.randomUUID();

        const fwdHeaders = new Headers(request.headers);
        fwdHeaders.set('X-Shard-Id', sessionId);

        return getTunnelStub(env, sessionId).fetch(new Request(request.url, {
          method:  request.method,
          headers: fwdHeaders,
        }));
      }

      // Broker WebSocket (HOST_REGISTER / CLIENT_JOIN / HOST_RECONNECT) → admin DO
      return getAdminStub(env).fetch(request);
    }

    // All HTTP routes → admin DO (stats, codes, admin panel)
    return getAdminStub(env).fetch(request);
  },
};
