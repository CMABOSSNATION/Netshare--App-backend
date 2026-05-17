/**
 * index.js — NetShare Relay Worker Entry Point
 *
 * Routes all HTTP requests to the SessionStore Durable Object.
 * The DO handles all session state: register, join, ping, deregister, probe.
 *
 * Endpoints (all handled by SessionStore DO):
 *   POST /register        — Host registers { ip, port } → returns { code, sessionId }
 *   GET  /join/:code      — Client looks up host by code → returns { ip, port, sessionId }
 *   POST /ping            — Host keep-alive { sessionId }
 *   POST /deregister      — Host removes session { sessionId }
 *   POST /probe           — Client tests if host proxy is reachable { ip, port }
 *   GET  /health          — Health check
 *   GET  /admin/sessions  — List sessions (requires x-admin-key header)
 */

export { SessionStore } from './relay.js';

function cors() {
  return {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-admin-key',
  };
}

export default {
  async fetch(request, env) {
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors() });
    }

    const url  = new URL(request.url);
    const path = url.pathname;

    // Health check — answered at edge, no DO needed
    if (path === '/health') {
      return new Response('OK', {
        status: 200,
        headers: { 'Content-Type': 'text/plain', ...cors() },
      });
    }

    // Route everything else to the single global SessionStore DO
    const id   = env.SESSION_STORE.idFromName('global');
    const stub = env.SESSION_STORE.get(id);
    return stub.fetch(request);
  },
};
