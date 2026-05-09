require('dotenv').config();

const http       = require('http');
const express    = require('express');
const cors       = require('cors');
const { WebSocketServer } = require('ws');
const { setupRelay, getStats } = require('./relay');
const logger     = require('./logger');

const app  = express();
const PORT = process.env.PORT || 4000;

// ── Middleware ────────────────────────────────────────────────
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  methods: ['GET', 'POST'],
}));
app.use(express.json());

// ── REST Endpoints ────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    service: 'NetShare Relay Server',
    version: '1.0.0',
    status:  'running',
    uptime:  Math.floor(process.uptime()) + 's',
  });
});

app.get('/stats', (req, res) => {
  res.json(getStats());
});

app.get('/ping', (req, res) => {
  res.json({ pong: true, ts: Date.now() });
});

// ── HTTP Server ───────────────────────────────────────────────
const server = http.createServer(app);

// ── WebSocket Server ──────────────────────────────────────────
const wss = new WebSocketServer({ server, path: '/relay' });

// Wire relay logic — this is what was missing
setupRelay(wss);

wss.on('error', (err) => {
  logger.error(`WSS error: ${err.message}`);
});

// ── Start ─────────────────────────────────────────────────────
server.listen(PORT, () => {
  logger.ok  (`NetShare relay running on port ${PORT}`);
  logger.ok  (`WebSocket endpoint: ws://localhost:${PORT}/relay`);
  logger.info(`Stats: http://localhost:${PORT}/stats`);
});

process.on('SIGTERM', () => {
  logger.warn('SIGTERM received — shutting down gracefully');
  server.close(() => process.exit(0));
});
