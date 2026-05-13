/**
 * NetShare Relay — Cloudflare Worker
 *
 * Replaces Express + ws with the Workers WebSocket API.
 * State is held in a Durable Object (RelaySession) so it
 * survives across the Worker's stateless fetch() calls.
 *
 * Routes:
 *   GET /relay   → WebSocket upgrade (hosts + clients)
 *   GET /health  → 200 OK
 *   GET /ping    → 200 OK
 *   GET /stats   → JSON relay stats
 */

import { RelaySession } from './relay.js';
export { RelaySession };

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ── Health / ping ──────────────────────────────────────────
    if (url.pathname === '/health' || url.pathname === '/ping') {
      return new Response('OK', { status: 200 });
    }

    // ── Stats ──────────────────────────────────────────────────
    if (url.pathname === '/stats') {
      const id = env.RELAY.idFromName('global');
      const obj = env.RELAY.get(id);
      return obj.fetch(new Request('https://internal/stats'));
    }

    // ── WebSocket relay ────────────────────────────────────────
    if (url.pathname === '/relay') {
      const upgradeHeader = request.headers.get('Upgrade');
      if (upgradeHeader !== 'websocket') {
        return new Response('Expected WebSocket', { status: 426 });
      }
      // Route to the single global Durable Object instance
      const id = env.RELAY.idFromName('global');
      const obj = env.RELAY.get(id);
      return obj.fetch(request);
    }

    return new Response('NetShare Relay Worker', { status: 200 });
  },
};
