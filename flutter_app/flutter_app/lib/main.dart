/**
 * CipherLink Zero-Knowledge WebSocket Relay Server
 * 
 * Design:
 * - 100% In-Memory (Zero Database, Zero Disk Persistence)
 * - Immediate packet forwarding with instant memory disposal
 * - Zero offline queuing for maximum metadata privacy
 * - Keep-alive heartbeats to cleanly remove stale connections
 */

const http = require('http');
const { WebSocketServer, WebSocket } = require('ws');

const PORT = process.env.PORT || 8080;

// HTTP server for platform health checks (Render, Railway, Fly.io, etc.)
const server = http.createServer((req, res) => {
  if (req.url === '/health' || req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'online',
      service: 'CipherLink Zero-Knowledge Relay',
      activePeers: activeConnections.size,
      timestamp: Date.now()
    }));
  } else {
    res.writeHead(404);
    res.end();
  }
});

// Initialize WebSocket Server
const wss = new WebSocketServer({ 
  server,
  maxPayload: 128 * 1024 // 128 KB per frame limit to prevent buffer exhaustion
});

// In-Memory routing table: Map<PublicKey, WebSocketClient>
const activeConnections = new Map();

wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.registeredPublicKey = null;

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  ws.on('message', (data) => {
    let message;
    try {
      message = JSON.parse(data.toString());
    } catch (e) {
      // Discard malformed non-JSON data immediately
      return;
    }

    // 1. Initial Handshake: Client registers their Public Key ID
    if (message.type === 'register' && message.publicKey) {
      const pubKey = message.publicKey.trim();
      
      // Clean up previous registration for this socket if key changed
      if (ws.registeredPublicKey && ws.registeredPublicKey !== pubKey) {
        activeConnections.delete(ws.registeredPublicKey);
      }

      ws.registeredPublicKey = pubKey;
      activeConnections.set(pubKey, ws);

      ws.send(JSON.stringify({
        type: 'registered',
        publicKey: pubKey,
        timestamp: Date.now()
      }));
      return;
    }

    // 2. Encrypted Message Routing: { to, from, cipherText, iv, timestamp }
    if (message.to && message.cipherText && message.iv) {
      // Auto-register sender's key if provided and not yet registered
      if (message.from && !ws.registeredPublicKey) {
        ws.registeredPublicKey = message.from.trim();
        activeConnections.set(ws.registeredPublicKey, ws);
      }

      const targetSocket = activeConnections.get(message.to.trim());

      // Forward to target socket if online
      if (targetSocket && targetSocket.readyState === WebSocket.OPEN) {
        targetSocket.send(JSON.stringify(message));
      } else {
        // Zero-Knowledge Policy: Target is offline.
        // Dropped immediately. No offline queueing for metadata privacy.
      }
      
      // Dereference immediately for garbage collection
      message = null;
    }
  });

  // Client disconnect cleanup
  ws.on('close', () => {
    if (ws.registeredPublicKey) {
      if (activeConnections.get(ws.registeredPublicKey) === ws) {
        activeConnections.delete(ws.registeredPublicKey);
      }
    }
  });

  ws.on('error', () => {
    if (ws.registeredPublicKey && activeConnections.get(ws.registeredPublicKey) === ws) {
      activeConnections.delete(ws.registeredPublicKey);
    }
  });
});

// Periodic Heartbeat: Detect and terminate broken connections every 30 seconds
const heartbeatInterval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) {
      if (ws.registeredPublicKey && activeConnections.get(ws.registeredPublicKey) === ws) {
        activeConnections.delete(ws.registeredPublicKey);
      }
      return ws.terminate();
    }
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

wss.on('close', () => {
  clearInterval(heartbeatInterval);
});

server.listen(PORT, () => {
  console.log(`[CipherLink] Zero-Knowledge Relay running on port ${PORT}`);
});
