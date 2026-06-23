/**
 * Shared WebSocket client for real-time ThreatDock updates.
 * Singleton pattern — only one connection across all components.
 */
import { io } from 'socket.io-client';

let socket = null;
const listeners = new Map();

function getSocket() {
  if (!socket) {
    socket = io({ transports: ['polling', 'websocket'], autoConnect: false });
  }
  return socket;
}

/**
 * Connect and register a listener for an event.
 * Automatically connects on first listener.
 */
export function on(event, callback) {
  const s = getSocket();
  if (!listeners.has(event)) {
    listeners.set(event, new Set());
  }
  listeners.get(event).add(callback);
  s.on(event, callback);
  if (!s.connected) {
    s.connect();
  }
  return () => {
    s.off(event, callback);
    listeners.get(event)?.delete(callback);
  };
}

/**
 * Disconnect the WebSocket (on logout).
 */
export function disconnect() {
  if (socket) {
    socket.removeAllListeners();
    socket.disconnect();
    socket = null;
  }
  listeners.clear();
}

export default { on, disconnect };
