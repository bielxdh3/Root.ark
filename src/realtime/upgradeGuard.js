"use strict";

function createRealtimeUpgradeGuard({ getPeerKey, authorize, maxAttempts, windowMs, maxConnections, now = Date.now }) {
  const attempts = new Map();
  const connections = new Map();

  function getAttemptState(peer, timestamp) {
    let state = attempts.get(peer);
    if (!state || timestamp - state.startedAt >= windowMs) {
      state = { startedAt: timestamp, count: 0 };
      attempts.set(peer, state);
    }
    return state;
  }

  function pruneAttempts(timestamp) {
    for (const [peer, state] of attempts) {
      if (timestamp - state.startedAt >= windowMs) attempts.delete(peer);
    }
  }

  function releaseConnection(peer) {
    const current = connections.get(peer) || 0;
    if (current <= 1) connections.delete(peer);
    else connections.set(peer, current - 1);
  }

  function verifyClient(info, done) {
    const peer = getPeerKey(info.req) || "unknown";
    const timestamp = now();
    pruneAttempts(timestamp);
    let state = attempts.get(peer);
    if (!state && attempts.size >= 10_000) return done(false, 503, "WebSocket upgrade capacity unavailable");
    state = getAttemptState(peer, timestamp);
    state.count += 1;
    if (state.count > maxAttempts) return done(false, 429, "WebSocket upgrade rate limit exceeded");

    let authorization;
    try { authorization = authorize(info.req); } catch { authorization = null; }
    if (!authorization?.user) return done(false, authorization?.statusCode || 401, authorization?.message || "WebSocket authentication required");
    if ((connections.get(peer) || 0) >= maxConnections) return done(false, 429, "WebSocket connection limit exceeded");

    connections.set(peer, (connections.get(peer) || 0) + 1);
    info.req.rootarkRealtimeClientIp = peer;
    info.req.rootarkRealtimeUser = authorization.user;
    let released = false;
    info.req.rootarkReleaseRealtimeReservation = () => {
      if (released) return;
      released = true;
      releaseConnection(peer);
    };
    info.req.socket?.once("close", info.req.rootarkReleaseRealtimeReservation);
    return done(true);
  }

  function trackConnection(socket, req) {
    if (req.rootarkRealtimeReleaseReservation) socket.once("close", req.rootarkReleaseRealtimeReservation);
  }

  return { trackConnection, verifyClient };
}

module.exports = { createRealtimeUpgradeGuard };
