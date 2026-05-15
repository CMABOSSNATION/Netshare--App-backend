/**
 * index.js — NetShare Relay Worker entry point
 *
 * Routes:
 *   WS   /relay               → WebSocket (hosts + clients)
 *   GET  /health, /ping       → 200 OK
 *   GET  /stats               → relay stats
 *   POST /validate-code       → { valid: bool } — validates admin-issued code
 *   GET  /admin/stats         → platform overview (requires x-admin-key)
 *   GET  /admin/codes         → list access codes
 *   POST /admin/codes/generate → generate codes
 *   POST /admin/codes/revoke  → revoke a code
 *   GET  /admin/hosts         → host list + uptime
 *   GET  /admin/payouts       → payout report
 *   POST /admin/payouts/reset → reset weekly cycle
 */

import { RelaySession } from './relay.js';
export { RelaySession };

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/health' || url.pathname === '/ping') {
      return new Response('OK', { status: 200 });
    }

    // All routes → single shared Durable Object instance
    const id   = env.RELAY.idFromName('global');
    const stub = env.RELAY.get(id);
    return stub.fetch(request);
  },
};
