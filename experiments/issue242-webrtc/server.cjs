'use strict';

// Disposable loopback-only experiment. No Root.ark modules, storage, auth or keys.
const { createServer: createHttpServer } = require('node:http');
const { randomBytes } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const WebSocket = require('ws');

const MAX_MEMBERS = 4;
const ROOM_TTL_MS = 5 * 60_000;
const INVITE_TTL_MS = 60_000;
const MAX_SIGNAL_BYTES = 16_384;
const token = () => randomBytes(32).toString('hex');
const shortId = () => randomBytes(8).toString('hex');
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);

function makeBroker({ now = Date.now, inviteTtlMs = INVITE_TTL_MS, roomTtlMs = ROOM_TTL_MS } = {}) {
  const rooms = new Map();
  const participants = new Map();
  const wss = new WebSocket.WebSocketServer({ noServer: true, maxPayload: MAX_SIGNAL_BYTES, perMessageDeflate: false });
  let origin = '';
  let listener;

  function send(ws, data) {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data));
  }
  function error(ws, code) { send(ws, { type: 'error', code }); }
  function roomOf(ws) {
    const p = participants.get(ws);
    return p && rooms.get(p.roomId);
  }
  function expireRoom(room) {
    rooms.delete(room.id);
    for (const peer of room.members.values()) {
      error(peer.ws, 'ROOM_CLOSED');
      peer.ws.close(1000, 'room closed');
      participants.delete(peer.ws);
    }
    room.members.clear();
    room.invites.clear();
    room.pending.clear();
    room.allowed.clear();
  }
  function validRoom(room) {
    if (!room || now() >= room.expires) {
      if (room) expireRoom(room);
      return false;
    }
    return true;
  }
  function removePeer(ws) {
    const peer = participants.get(ws);
    if (!peer) return;
    participants.delete(ws);
    const room = rooms.get(peer.roomId);
    if (!room) return;
    room.members.delete(peer.id);
    room.pending.forEach((p, id) => { if (p.from === peer.id || p.to === peer.id) room.pending.delete(id); });
    for (const key of room.allowed) if (key.split(':').includes(peer.id)) room.allowed.delete(key);
    for (const other of room.members.values()) send(other.ws, { type: 'peer-left', peerId: peer.id });
    if (peer.role === 'host') expireRoom(room);
  }
  const pair = (a, b) => [a, b].sort().join(':');
  function onMessage(ws, raw) {
    if (raw.length > MAX_SIGNAL_BYTES) return ws.close(1009, 'too large');
    let message;
    try { message = JSON.parse(raw.toString()); } catch { return error(ws, 'BAD_MESSAGE'); }
    if (!object(message) || typeof message.type !== 'string') return error(ws, 'BAD_MESSAGE');
    const current = participants.get(ws);
    if (!current) {
      if (message.type !== 'join' || typeof message.roomId !== 'string') return error(ws, 'NOT_JOINED');
      const room = rooms.get(message.roomId);
      if (!validRoom(room)) return error(ws, 'INVALID_INVITE');
      if (room.members.size >= MAX_MEMBERS) return error(ws, 'FULL');
      let role;
      if (message.hostKey === room.hostKey && ![...room.members.values()].some(p => p.role === 'host')) {
        role = 'host';
      } else {
        const invite = typeof message.invitation === 'string' && room.invites.get(message.invitation);
        if (!invite || invite.used || invite.expires <= now()) return error(ws, 'INVALID_INVITE');
        room.invites.delete(message.invitation); // One-time join, never eligible for replay.
        role = 'guest';
      }
      const id = shortId();
      const peer = { id, role, roomId: room.id, ws };
      participants.set(ws, peer);
      room.members.set(id, peer);
      send(ws, { type: 'joined', peerId: id, role, members: [...room.members.values()].filter(p => p.id !== id).map(p => ({ peerId: p.id, role: p.role })) });
      for (const other of room.members.values()) if (other.id !== id) send(other.ws, { type: 'peer-joined', peerId: id, role });
      return;
    }
    const room = roomOf(ws);
    if (!validRoom(room)) return error(ws, 'ROOM_CLOSED');
    const target = typeof message.to === 'string' && room.members.get(message.to);
    if (message.type === 'invite' && current.role === 'host') {
      for (const [key, invite] of room.invites) if (invite.expires <= now()) room.invites.delete(key);
      const outstanding = [...room.invites.values()].filter(i => !i.used && i.expires > now()).length;
      if (outstanding + room.members.size >= MAX_MEMBERS) return error(ws, 'FULL');
      const invitation = token();
      const id = shortId();
      const expires = now() + inviteTtlMs;
      room.invites.set(invitation, { id, expires, used: false });
      send(ws, { type: 'invited', inviteId: id, invitation, expires });
    } else if (message.type === 'revoke' && current.role === 'host' && typeof message.inviteId === 'string') {
      for (const [k, i] of room.invites) if (i.id === message.inviteId) room.invites.delete(k);
      send(ws, { type: 'revoked', inviteId: message.inviteId });
    } else if (message.type === 'kick' && current.role === 'host' && target && target.role === 'guest') {
      error(target.ws, 'REVOKED');
      target.ws.close(1000, 'revoked');
      removePeer(target.ws);
    } else if (message.type === 'request-peer' && current.role === 'host' && target && target.role === 'guest' && !room.allowed.has(pair(current.id, target.id))) {
      if (room.pending.size >= MAX_MEMBERS) return error(ws, 'FULL');
      const requestId = shortId();
      room.pending.set(requestId, { from: current.id, to: target.id });
      send(target.ws, { type: 'peer-request', peerId: current.id, requestId });
    } else if (message.type === 'consent' && typeof message.requestId === 'string' && typeof message.accept === 'boolean') {
      const pending = room.pending.get(message.requestId);
      if (!pending || pending.to !== current.id || !room.members.has(pending.from)) return error(ws, 'FORBIDDEN');
      room.pending.delete(message.requestId);
      const host = room.members.get(pending.from);
      if (message.accept) {
        room.allowed.add(pair(current.id, host.id));
        send(ws, { type: 'peer-allowed', peerId: host.id });
        send(host.ws, { type: 'peer-accepted', peerId: current.id });
      } else {
        send(host.ws, { type: 'peer-declined', peerId: current.id });
      }
    } else if (message.type === 'signal' && target && room.allowed.has(pair(current.id, target.id)) &&
      object(message.signal) && ['offer', 'answer', 'ice'].includes(message.signal.kind) &&
      JSON.stringify(message.signal).length <= MAX_SIGNAL_BYTES - 256) {
      send(target.ws, { type: 'signal', peerId: current.id, signal: message.signal });
    } else {
      error(ws, 'FORBIDDEN');
    }
  }
  wss.on('connection', ws => {
    let count = 0;
    let windowStart = now();
    // ws emits an error before closing an oversized frame; keep the broker alive.
    ws.on('error', () => {});
    ws.on('message', raw => {
      if (now() - windowStart >= 10_000) {
        windowStart = now();
        count = 0;
      }
      if (++count > 120) return ws.close(1008, 'rate exceeded');
      onMessage(ws, raw);
    });
    ws.on('close', () => removePeer(ws));
  });
  const server = createHttpServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'self'; connect-src 'self' ws://127.0.0.1:*; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'");
    if (req.method === 'POST' && url.pathname === '/rooms' && req.headers.origin === origin) {
      if (rooms.size >= 16) { res.writeHead(429).end(); return; }
      const room = { id: shortId(), hostKey: token(), expires: now() + roomTtlMs,
        members: new Map(), invites: new Map(), pending: new Map(), allowed: new Set() };
      rooms.set(room.id, room);
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ roomId: room.id, hostKey: room.hostKey, expires: room.expires }));
      return;
    }
    const route = req.method === 'GET' && { '/': 'index.html', '/client.js': 'client.js' }[url.pathname];
    if (route) {
      res.setHeader('Content-Type', route.endsWith('.js') ? 'text/javascript; charset=utf-8' : 'text/html; charset=utf-8');
      res.end(readFileSync(join(__dirname, route)));
    } else res.writeHead(404).end();
  });
  server.on('upgrade', (req, socket, head) => {
    if (req.url !== '/signal' || req.headers.origin !== origin || wss.clients.size >= 32) {
      socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
  });
  const expirySweep = setInterval(() => {
    for (const room of rooms.values()) validRoom(room);
  }, 1000);
  expirySweep.unref();
  return {
    async listen() {
      await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
      listener = server.address().port;
      origin = `http://127.0.0.1:${listener}`;
      return origin;
    },
    async close() {
      clearInterval(expirySweep);
      for (const ws of wss.clients) ws.terminate();
      await new Promise(resolve => server.close(resolve));
    },
    get origin() { return origin; }
  };
}

if (require.main === module) {
  makeBroker().listen().then(origin => process.stdout.write(`Disposable WebRTC experiment: ${origin}\n`));
}
module.exports = { makeBroker };
