const { v4: uuidv4 } = require('uuid');
const logger = require('./logger');

// In-memory session store
// sessions = { CODE: { hostSocket, clients: Map<id, socket>, createdAt, netType } }
const sessions = new Map();

// Generate unique 6-char alphanumeric code
function generateCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  // Ensure uniqueness
  return sessions.has(code) ? generateCode() : code;
}

// Send JSON safely to a socket
function send(socket, data) {
  try {
    if (socket && socket.readyState === 1) {
      socket.send(JSON.stringify(data));
    }
  } catch (err) {
    logger.error(`Send failed: ${err.message}`);
  }
}

// Broadcast to all clients in a session
function broadcastToClients(session, data) {
  session.clients.forEach((clientSocket) => {
    send(clientSocket, data);
  });
}

// Handle HOST_REGISTER message
function handleHostRegister(socket, payload) {
  const { netType = 'WiFi' } = payload;

  // Remove any previous session this socket owned
  sessions.forEach((session, code) => {
    if (session.hostSocket === socket) {
      broadcastToClients(session, { type: 'HOST_LEFT', reason: 'Host re-registered' });
      sessions.delete(code);
      logger.warn(`Cleaned up old session ${code}`);
    }
  });

  const code = generateCode();
  sessions.set(code, {
    hostSocket: socket,
    clients: new Map(),
    createdAt: Date.now(),
    netType,
  });

  socket._sessionCode = code;
  socket._role = 'host';

  send(socket, { type: 'SESSION_CREATED', code, netType });
  logger.ok(`Host registered session: ${code} (${netType})`);
}

// Handle CLIENT_JOIN message
function handleClientJoin(socket, payload) {
  const { code } = payload;

  if (!code || !sessions.has(code)) {
    send(socket, { type: 'JOIN_ERROR', reason: 'Session not found. Check the code.' });
    logger.warn(`Client tried invalid code: ${code}`);
    return;
  }

  const session = sessions.get(code);

  // Check client limit
  const maxClients = parseInt(process.env.MAX_CLIENTS_PER_HOST || '5');
  if (session.clients.size >= maxClients) {
    send(socket, { type: 'JOIN_ERROR', reason: 'Session is full.' });
    return;
  }

  const clientId = uuidv4();
  socket._clientId = clientId;
  socket._sessionCode = code;
  socket._role = 'client';

  session.clients.set(clientId, socket);

  // Notify client
  send(socket, {
    type: 'JOIN_SUCCESS',
    clientId,
    code,
    netType: session.netType,
    message: 'Tunnel active. Traffic is being relayed.',
  });

  // Notify host
  send(session.hostSocket, {
    type: 'CLIENT_CONNECTED',
    clientId,
    totalClients: session.clients.size,
  });

  logger.ok(`Client ${clientId.slice(0,8)} joined session ${code}`);
}

// Handle HOST_LEAVE
function handleHostLeave(socket) {
  const code = socket._sessionCode;
  if (!code || !sessions.has(code)) return;

  const session = sessions.get(code);
  broadcastToClients(session, {
    type: 'HOST_LEFT',
    reason: 'Host ended the session.',
  });

  sessions.delete(code);
  logger.info(`Host ended session ${code}`);
}

// Handle CLIENT_LEAVE
function handleClientLeave(socket) {
  const code = socket._sessionCode;
  const clientId = socket._clientId;
  if (!code || !sessions.has(code)) return;

  const session = sessions.get(code);
  session.clients.delete(clientId);

  send(session.hostSocket, {
    type: 'CLIENT_DISCONNECTED',
    clientId,
    totalClients: session.clients.size,
  });

  logger.info(`Client ${clientId?.slice(0,8)} left session ${code}`);
}

// Relay data packets between host ↔ client
function handleDataRelay(socket, payload) {
  const code = socket._sessionCode;
  if (!code || !sessions.has(code)) return;

  const session = sessions.get(code);

  if (socket._role === 'host') {
    // Host → specific client or broadcast
    const { targetClientId, data } = payload;
    if (targetClientId && session.clients.has(targetClientId)) {
      send(session.clients.get(targetClientId), { type: 'DATA', data });
    } else {
      broadcastToClients(session, { type: 'DATA', data });
    }
  } else if (socket._role === 'client') {
    // Client → host
    send(session.hostSocket, {
      type: 'DATA',
      fromClientId: socket._clientId,
      data: payload.data,
    });
  }
}

// Main message router
function handleMessage(socket, raw) {
  let msg;
  try {
    msg = JSON.parse(raw);
  } catch {
    logger.warn('Received non-JSON message');
    return;
  }

  const { type, ...payload } = msg;

  switch (type) {
    case 'HOST_REGISTER':  handleHostRegister(socket, payload); break;
    case 'CLIENT_JOIN':    handleClientJoin(socket, payload);   break;
    case 'HOST_LEAVE':     handleHostLeave(socket);             break;
    case 'CLIENT_LEAVE':   handleClientLeave(socket);           break;
    case 'DATA':           handleDataRelay(socket, payload);    break;
    default:
      logger.warn(`Unknown message type: ${type}`);
  }
}

// Handle socket disconnect (cleanup)
function handleDisconnect(socket) {
  if (socket._role === 'host')   handleHostLeave(socket);
  if (socket._role === 'client') handleClientLeave(socket);
}

// Stats endpoint data
function getStats() {
  const stats = { activeSessions: sessions.size, sessions: [] };
  sessions.forEach((session, code) => {
    stats.sessions.push({
      code,
      netType: session.netType,
      clients: session.clients.size,
      ageSeconds: Math.floor((Date.now() - session.createdAt) / 1000),
    });
  });
  return stats;
}

// Auto-expire sessions older than SESSION_TIMEOUT_MS
setInterval(() => {
  const timeout = parseInt(process.env.SESSION_TIMEOUT_MS || '3600000');
  sessions.forEach((session, code) => {
    if (Date.now() - session.createdAt > timeout) {
      broadcastToClients(session, { type: 'HOST_LEFT', reason: 'Session expired.' });
      send(session.hostSocket, { type: 'SESSION_EXPIRED' });
      sessions.delete(code);
      logger.warn(`Session ${code} expired and removed`);
    }
  });
}, 60_000);

module.exports = { handleMessage, handleDisconnect, getStats };
