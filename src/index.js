/**
 * index.js — NetShare Relay Worker entry point
 *
 * Routes:
 *   GET  /relay         → WebSocket upgrade (hosts + clients)
 *   GET  /health        → 200 OK
 *   GET  /ping          → 200 OK
 *   GET  /stats         → JSON relay stats
 *   POST /validate-code → { valid: bool }
 */

import { RelaySession } from './relay.js';
export { RelaySession };

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Health check — no DO needed
    if (url.pathname === '/health' || url.pathname === '/ping') {
      return new Response('OK', { status: 200 });
    }

    // All other routes → single shared Durable Object
    const id   = env.RELAY.idFromName('global');
    const stub = env.RELAY.get(id);
    return stub.fetch(request);
  },
};
