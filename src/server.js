require('dotenv').config();

const http    = require('http');
const express = require('express');
const cors    = require('cors');
const { WebSocketServer } = require('ws');
const { handleMessage, handleDisconnect, getStats } = require('./relay');
const logger  = require('./logger');

const app  = express();
const PORT = process.env.PORT || 4000;

// ── Middleware ────────────────────────────────────────────────
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  methods: ['GET', 'POST'],
}));
app.use(express.json());

// ── REST Endpoints ────────────────────────────────────────────

// Health check — Render uses this to detect service is alive
app.get('/', (req, res) => {
  res.json({
    service: 'NetShare Relay Server',
    version: '1.0.0',
    status:  'running',
    uptime:  Math.floor(process.uptime()) + 's',
  });
});

// Live session stats
app.get('/stats', (req, res) => {
  res.json(getStats());
});

// Wake ping — frontend calls this to keep Render from sleeping
app.get('/ping', (req, res) => {
  res.json({ pong: true, ts: Date.now() });
});

// ── HTTP Server ───────────────────────────────────────────────
const server = http.createServer(app);

// ── WebSocket Server ──────────────────────────────────────────
const wss = new WebSocketServer({ server, path: '/relay' });

wss.on('connection', (socket, req) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  logger.info(`New connection from ${ip}`);

  // Send welcome handshake
  socket.send(JSON.stringify({
    type: 'CONNECTED',
    message: 'NetShare relay ready',
    ts: Date.now(),
  }));

  socket.on('message', (raw) => {
    handleMessage(socket, raw.toString());
  });

  socket.on('close', () => {
    handleDisconnect(socket);
    logger.info(`Connection closed: ${ip}`);
  });

  socket.on('error', (err) => {
    logger.error(`Socket error from ${ip}: ${err.message}`);
    handleDisconnect(socket);
  });

  // Heartbeat — keep connection alive on Render free tier
  socket._heartbeat = setInterval(() => {
    if (socket.readyState === 1) {
      socket.send(JSON.stringify({ type: 'PING' }));
    } else {
      clearInterval(socket._heartbeat);
    }
  }, 25000);
});

wss.on('error', (err) => {
  logger.error(`WSS error: ${err.message}`);
});

// ── Start ─────────────────────────────────────────────────────
server.listen(PORT, () => {
  logger.ok(`NetShare relay running on port ${PORT}`);
  logger.ok(`WebSocket endpoint: ws://localhost:${PORT}/relay`);
  logger.info(`Stats: http://localhost:${PORT}/stats`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.warn('SIGTERM received — shutting down gracefully');
  server.close(() => process.exit(0));
});
