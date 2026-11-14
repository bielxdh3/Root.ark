'use strict';

// Disposable loopback-only experiment. No Root.ark modules, storage, auth or keys.
const { createServer: createHttpServer } = require('node:http');
const { randomBytes } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const WebSocket = require('ws');

const MAX_MEMBERS = 4;
const ROOM_TTL_MS = 5 * 60_000;
const UNJOINED_ROOM_TTL_MS = 15_000;
const MAX_ACTIVE_ROOMS_PER_OWNER = 2;
const INVITE_TTL_MS = 60_000;
const MAX_SIGNAL_BYTES = 16_384;
const token = () => randomBytes(32).toString('hex');
const shortId = () => randomBytes(8).toString('hex');
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const roomMessageTypes = new Set(['join', 'invite', 'revoke', 'kick', 'request-peer', 'consent', 'signal']);

function ownDataSnapshot(value, fields) {
  if (!object(value) || Object.getPrototypeOf(value) !== Object.prototype) return null;
  // Read the properties exactly once through own data descriptors, never
  // through value.field (which can be a changing Proxy get trap).
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== fields.length) return null;
  const snapshot = {};
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) return null;
    snapshot[field] = descriptor.value;
  }
  return snapshot;
}

function immutableVersionSnapshot(value, expected) {
  const snapshot = ownDataSnapshot(value,
    ['owner', 'boundObject', 'pin', 'sha256', 'bytes', 'versionId']);
  if (!snapshot) return null;
  const boundObject = ownDataSnapshot(snapshot.boundObject, ['folderId', 'fileName']);
  if (!boundObject || snapshot.owner !== expected.owner ||
    boundObject.folderId !== expected.boundObject.folderId ||
    boundObject.fileName !== expected.boundObject.fileName ||
    snapshot.pin !== expected.pin || snapshot.sha256 !== expected.sha256 ||
    snapshot.bytes !== expected.bytes ||
    typeof snapshot.versionId !== 'string' ||
    !/^[a-zA-Z0-9_-]{16,128}$/.test(snapshot.versionId) ||
    /^\d+$/.test(snapshot.versionId) ||
    snapshot.versionId === expected.pin || snapshot.versionId === expected.sha256) return null;
  // All fields crossing awaits and entering the room are now detached
  // ordinary primitives; no callback-returned Proxy is retained or reread.
  return Object.freeze({ ...snapshot, boundObject: Object.freeze(boundObject) });
}

function makeBroker({ now = Date.now, inviteTtlMs = INVITE_TTL_MS, roomTtlMs = ROOM_TTL_MS,
  authenticateSession = null, sharedWss = null, authorizeRecipient = null,
  authorizeObject = null, authorizeSignalSnapshot = null,
  authorizeImmutableVersion = null } = {}) {
  const rooms = new Map();
  const pendingRoomCreatesByOwner = new Map();
  let pendingRoomCreates = 0;
  const participants = new Map();
  const wss = sharedWss || new WebSocket.WebSocketServer({
    noServer: true, maxPayload: MAX_SIGNAL_BYTES, perMessageDeflate: false
  });
  const authenticated = typeof authenticateSession === 'function';
  let origin = '';
  let listener;

  function identify(req) {
    if (!authenticated) return null;
    try {
      const user = authenticateSession(req);
      return user && typeof user.username === 'string' && user.username.length > 0 &&
        Number.isInteger(user.sessionVersion) && Number.isFinite(user.expiresAt) &&
        user.expiresAt > now() ? user : null;
    } catch { return null; }
  }
  function sessionCurrent(ws) {
    if (!authenticated) return true;
    const user = identify(ws.upgradeRequest);
    if (user && ws.identity && user.username === ws.identity.username &&
      user.sessionVersion === ws.identity.sessionVersion) return true;
    ws.close(1008, 'session revoked');
    removePeer(ws);
    return false;
  }
  function send(ws, data) {
    if (ws.readyState === WebSocket.OPEN && sessionCurrent(ws)) ws.send(JSON.stringify(data));
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
    // A room reserved by HTTP but never activated by its signed-session host
    // must not consume scarce global capacity for the full five-minute TTL.
    if (!room || now() >= room.expires ||
      (!room.hostJoined && now() >= room.hostJoinDeadline)) {
      if (room) expireRoom(room);
      return false;
    }
    return true;
  }
  async function objectAllowed(room, recipient = null) {
    if (!room.boundObject) return true;
    if (typeof authorizeObject !== 'function') return false;
    try {
      const current = await authorizeObject({
        owner: room.owner, recipient, boundObject: room.boundObject, pin: room.objectPin
      });
      return object(current) && typeof current.fingerprint === 'string' &&
        current.fingerprint === room.objectPin && current.sha256 === room.objectDigest &&
        current.bytes === room.objectSize;
    } catch { return false; }
  }
  async function recheckBoundRoom(room) {
    if (!room?.boundObject) return true;
    if (!await objectAllowed(room) || !validRoom(room) || rooms.get(room.id) !== room) {
      expireRoom(room);
      return false;
    }
    for (const peer of [...room.members.values()]) {
      if (peer.role !== 'guest') continue;
      if (await objectAllowed(room, peer.username) && validRoom(room) &&
        rooms.get(room.id) === room) continue;
      peer.ws.close(1008, 'object access revoked');
      removePeer(peer.ws);
    }
    return validRoom(room) && rooms.get(room.id) === room;
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
  function liveAdmission(ws, room) {
    return ws.readyState === WebSocket.OPEN && !participants.has(ws) &&
      validRoom(room) && rooms.get(room.id) === room && sessionCurrent(ws);
  }
  function activePeer(room, peer) {
    return Boolean(peer && rooms.get(room.id) === room && validRoom(room) &&
      room.members.get(peer.id) === peer && participants.get(peer.ws) === peer &&
      peer.ws.readyState === WebSocket.OPEN && sessionCurrent(peer.ws));
  }
  async function forwardLiveSignal(room, sender, recipient, signal) {
    if (!activePeer(room, sender) || !activePeer(room, recipient)) return;
    // Hash checks are useful fail-closed preflights, NOT an atomic ACL view.
    // An owner or guest can lose access during any later asynchronous check.
    for (const peer of [sender, recipient]) {
      if (!room.boundObject || peer.role !== 'guest') continue;
      if (!await objectAllowed(room, peer.username)) {
        if (activePeer(room, peer)) {
          peer.ws.close(1008, 'object access revoked');
          removePeer(peer.ws);
        }
        return;
      }
      if (!activePeer(room, sender) || !activePeer(room, recipient)) return;
    }
    if (room.boundObject && !await objectAllowed(room, null)) {
      if (rooms.get(room.id) === room) expireRoom(room);
      return;
    }
    if (room.boundObject) {
      // A protected signal requires an independently trusted, synchronous
      // all-party snapshot from one mutation-serialized authority. The broker
      // cannot manufacture this from sequential authorizeObject() promises.
      // The app's legacy JSON ACL adapter does NOT supply such a snapshot;
      // until a shared ACL mutation fence exists, deny protected signaling.
      const usernames = [...new Set([...room.members.values()]
        .filter(peer => peer.role === 'guest').map(peer => peer.username))].sort();
      let accepted = false;
      if (typeof authorizeSignalSnapshot === 'function') {
        try {
          const view = authorizeSignalSnapshot(Object.freeze({
            owner: room.owner,
            recipients: Object.freeze(usernames),
            boundObject: Object.freeze({ ...room.boundObject }),
            pin: room.objectPin, sha256: room.objectDigest, bytes: room.objectSize,
          }));
          // Strict sync result only. Reject Promise, accessors and partial/
          // self-asserted per-user decisions; the trusted adapter MUST read
          // all ACL writers' serialized authority in a single critical view.
          if (object(view) && Object.getPrototypeOf(view) === Object.prototype) {
            const fields = ['owner', 'recipients', 'pin', 'sha256', 'bytes', 'revision'];
            const descriptors = Object.getOwnPropertyDescriptors(view);
            if (Reflect.ownKeys(view).length === fields.length &&
              fields.every(key => descriptors[key] &&
                Object.hasOwn(descriptors[key], 'value'))) {
              const values = Object.fromEntries(fields.map(key => [key, descriptors[key].value]));
              accepted = values.owner === room.owner &&
                Array.isArray(values.recipients) &&
                values.recipients.length === usernames.length &&
                values.recipients.every((name, i) => name === usernames[i]) &&
                values.pin === room.objectPin && values.sha256 === room.objectDigest &&
                values.bytes === room.objectSize &&
                Number.isSafeInteger(values.revision) && values.revision >= 0 &&
                values.revision >= (room.signalAuthorityRevision ?? 0);
              if (accepted) room.signalAuthorityRevision = values.revision;
            }
          }
        } catch { accepted = false; }
      }
      if (!accepted) {
        if (rooms.get(room.id) === room) expireRoom(room);
        return;
      }
    }
    // No await between synchronous authority snapshot and final signal egress.
    if (activePeer(room, sender) && activePeer(room, recipient) &&
      room.allowed.has(pair(sender.id, recipient.id))) {
      send(recipient.ws, { type: 'signal', peerId: sender.id, signal });
    }
  }
  function cheapActionError(room, current, message) {
    // Rejection must precede expensive per-member ciphertext hashes. These are
    // only preflight checks; live ACL and room state are checked again before
    // every authorized action, especially SDP/ICE egress.
    const target = typeof message.to === 'string' && message.to.length === 16
      ? room.members.get(message.to) : null;
    switch (message.type) {
      case 'invite': {
        if (current.role !== 'host') return 'FORBIDDEN';
        const recipient = message.recipient;
        if (authenticated && (typeof recipient !== 'string' || recipient.length < 1 ||
          recipient.length > 128 || /[\x00-\x1f\x7f]/.test(recipient) ||
          recipient === current.username)) return 'BAD_RECIPIENT';
        if (typeof authorizeRecipient === 'function') {
          let grant = null;
          try { grant = authorizeRecipient(current.username, recipient); } catch { /* deny */ }
          if (grant !== true && (!object(grant) || grant.username !== recipient ||
            !Number.isSafeInteger(grant.sessionVersion) || grant.sessionVersion < 0)) {
            return 'BAD_RECIPIENT';
          }
        }
        const outstanding = [...room.invites.values()].filter(i => !i.used && i.expires > now()).length;
        return outstanding + room.members.size >= MAX_MEMBERS ? 'FULL' : null;
      }
      case 'revoke':
        return current.role === 'host' && typeof message.inviteId === 'string' &&
          /^[a-f0-9]{16}$/.test(message.inviteId) &&
          [...room.invites.values()].some(i => i.id === message.inviteId && i.expires > now())
          ? null : 'FORBIDDEN';
      case 'kick':
        return current.role === 'host' && target?.role === 'guest' ? null : 'FORBIDDEN';
      case 'request-peer':
        if (current.role !== 'host' || target?.role !== 'guest' ||
          room.allowed.has(pair(current.id, target.id))) return 'FORBIDDEN';
        return room.pending.size >= MAX_MEMBERS ? 'FULL' : null;
      case 'consent': {
        if (typeof message.requestId !== 'string' || message.requestId.length !== 16 ||
          typeof message.accept !== 'boolean') return 'FORBIDDEN';
        const pending = room.pending.get(message.requestId);
        return pending && pending.to === current.id && room.members.has(pending.from)
          ? null : 'FORBIDDEN';
      }
      case 'signal':
        return target && room.allowed.has(pair(current.id, target.id)) &&
          object(message.signal) && ['offer', 'answer', 'ice'].includes(message.signal.kind) &&
          JSON.stringify(message.signal).length <= MAX_SIGNAL_BYTES - 256
          ? null : 'FORBIDDEN';
      default:
        return 'FORBIDDEN';
    }
  }
  async function onMessage(ws, raw) {
    if (!sessionCurrent(ws)) return;
    if (raw.length > MAX_SIGNAL_BYTES) return ws.close(1009, 'too large');
    let message;
    try { message = JSON.parse(raw.toString()); } catch { return error(ws, 'BAD_MESSAGE'); }
    if (!object(message) || typeof message.type !== 'string') return error(ws, 'BAD_MESSAGE');
    const current = participants.get(ws);
    if (!current) {
      if (message.type !== 'join' || typeof message.roomId !== 'string') return error(ws, 'NOT_JOINED');
      const room = rooms.get(message.roomId);
      if (!validRoom(room)) return error(ws, 'INVALID_INVITE');
      // Cheap credential/capacity checks must precede hashing every bound
      // owner's and guest's current 32 MiB object. Invalid joins are untrusted.
      if (room.members.size >= MAX_MEMBERS) return error(ws, 'FULL');
      const hostEligible = message.hostKey === room.hostKey && (!authenticated || (room.owner === ws.identity.username &&
        room.ownerSessionVersion === ws.identity.sessionVersion)) &&
        ![...room.members.values()].some(p => p.role === 'host');
      const invite = !hostEligible && typeof message.invitation === 'string' &&
        room.invites.get(message.invitation);
      const inviteValid = () => Boolean(invite &&
        room.invites.get(message.invitation) === invite && !invite.used &&
        invite.expires > now() &&
        (!authenticated || (invite.recipient === ws.identity.username &&
          (!Number.isSafeInteger(invite.recipientSessionVersion) ||
            invite.recipientSessionVersion === ws.identity.sessionVersion))));
      if (!hostEligible && !inviteValid()) return error(ws, 'INVALID_INVITE');
      if (!await recheckBoundRoom(room)) return error(ws, 'INVALID_INVITE');
      if (!liveAdmission(ws, room)) return;
      if (room.members.size >= MAX_MEMBERS) return error(ws, 'FULL');
      let role;
      if (hostEligible && ![...room.members.values()].some(p => p.role === 'host')) {
        role = 'host';
      } else {
        if (!inviteValid() || !await objectAllowed(room, ws.identity?.username) ||
          !liveAdmission(ws, room) ||
          !inviteValid()) return error(ws, 'INVALID_INVITE');
        room.invites.delete(message.invitation); // One-time join, never eligible for replay.
        role = 'guest';
      }
      if (!liveAdmission(ws, room) || room.members.size >= MAX_MEMBERS) return;
      const id = shortId();
      const peer = { id, role, roomId: room.id, ws, username: ws.identity?.username };
      participants.set(ws, peer);
      room.members.set(id, peer);
      if (role === 'host') room.hostJoined = true;
      send(ws, { type: 'joined', peerId: id, role, username: peer.username,
        ...(room.boundObject ? { boundObject: { ...room.boundObject, sha256: room.objectDigest,
          size: room.objectSize, versionId: room.immutableVersionId } } : {}),
        members: [...room.members.values()].filter(p => p.id !== id).map(p => ({ peerId: p.id, role: p.role, username: p.username })) });
      for (const other of room.members.values()) if (other.id !== id) send(other.ws, { type: 'peer-joined', peerId: id, role, username: peer.username });
      return;
    }
    const room = roomOf(ws);
    if (!validRoom(room)) return error(ws, 'ROOM_CLOSED');
    if (!activePeer(room, current)) return;
    const cheapError = cheapActionError(room, current, message);
    if (cheapError) return error(ws, cheapError);
    if (!await recheckBoundRoom(room) || participants.get(ws) !== current ||
      !activePeer(room, current)) return;
    const target = typeof message.to === 'string' && room.members.get(message.to);
    switch (message.type) {
      case 'invite': {
        if (current.role !== 'host') return error(ws, 'FORBIDDEN');
        const recipient = message.recipient;
        if (authenticated && (typeof recipient !== 'string' || recipient.length < 1 ||
          recipient.length > 128 || /[\x00-\x1f\x7f]/.test(recipient) ||
          recipient === current.username)) return error(ws, 'BAD_RECIPIENT');
        let recipientSessionVersion = null;
        if (typeof authorizeRecipient === 'function') {
          let authority = null;
          try { authority = authorizeRecipient(current.username, recipient); } catch { /* fail closed */ }
          if (object(authority) && authority.username === recipient &&
            Number.isSafeInteger(authority.sessionVersion) && authority.sessionVersion >= 0) {
            recipientSessionVersion = authority.sessionVersion;
          } else if (authority !== true) return error(ws, 'BAD_RECIPIENT');
        }
        if (!await objectAllowed(room, recipient) || !sessionCurrent(ws) ||
          !validRoom(room)) return error(ws, 'OBJECT_ACCESS_DENIED');
        for (const [key, invite] of room.invites) if (invite.expires <= now()) room.invites.delete(key);
        const outstanding = [...room.invites.values()].filter(i => !i.used && i.expires > now()).length;
        if (outstanding + room.members.size >= MAX_MEMBERS) return error(ws, 'FULL');
        const invitation = token();
        const id = shortId();
        const expires = now() + inviteTtlMs;
        room.invites.set(invitation, { id, expires, used: false,
          recipient: authenticated ? recipient : null, recipientSessionVersion });
        send(ws, { type: 'invited', inviteId: id, invitation, expires, recipient: authenticated ? recipient : undefined });
        break;
      }
      case 'revoke': {
        if (current.role !== 'host' || typeof message.inviteId !== 'string') return error(ws, 'FORBIDDEN');
        const match = [...room.invites].find(([, invite]) =>
          invite.id === message.inviteId && invite.expires > now());
        if (!match) return error(ws, 'FORBIDDEN');
        room.invites.delete(match[0]);
        send(ws, { type: 'revoked', inviteId: message.inviteId });
        break;
      }
      case 'kick': {
        if (current.role !== 'host' || !target || target.role !== 'guest') return error(ws, 'FORBIDDEN');
        error(target.ws, 'REVOKED');
        target.ws.close(1000, 'revoked');
        removePeer(target.ws);
        break;
      }
      case 'request-peer': {
        if (current.role !== 'host' || !target || target.role !== 'guest' ||
          room.allowed.has(pair(current.id, target.id))) {
          return error(ws, 'FORBIDDEN');
        }
        if (room.pending.size >= MAX_MEMBERS) return error(ws, 'FULL');
        const requestId = shortId();
        room.pending.set(requestId, { from: current.id, to: target.id });
        send(target.ws, { type: 'peer-request', peerId: current.id, username: current.username, requestId });
        break;
      }
      case 'consent': {
        if (typeof message.requestId !== 'string' || typeof message.accept !== 'boolean') return error(ws, 'FORBIDDEN');
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
        break;
      }
      case 'signal': {
        if (!target || !room.allowed.has(pair(current.id, target.id)) ||
          !object(message.signal) || !['offer', 'answer', 'ice'].includes(message.signal.kind) ||
          JSON.stringify(message.signal).length > MAX_SIGNAL_BYTES - 256) {
          return error(ws, 'FORBIDDEN');
        }
        await forwardLiveSignal(room, current, target, message.signal);
        break;
      }
      default:
        error(ws, 'FORBIDDEN');
    }
  }
  function onConnection(ws, req) {
    if (sharedWss) {
      ws.upgradeRequest = req;
      ws.identity = identify(req);
    }
    let count = 0;
    let windowStart = now();
    // ws emits an error before closing an oversized frame; keep the broker alive.
    ws.on('error', () => {});
    ws.on('message', (raw, binary) => {
      let message;
      if (sharedWss) {
        // Reuse Root.ark's established /ws socket. Ignore the application's
        // ordinary event envelopes; only our explicit room protocol participates.
        if (binary || raw.length > MAX_SIGNAL_BYTES) return;
        try { message = JSON.parse(raw.toString()); } catch { return; }
        if (!object(message) || !roomMessageTypes.has(message.type)) return;
      }
      if (now() - windowStart >= 10_000) {
        windowStart = now();
        count = 0;
      }
      if (++count > 120) return ws.close(1008, 'rate exceeded');
      // Serialize room actions so awaits cannot reorder consent, revocation,
      // session admission or signals. Every authorization still hashes the
      // current bytes, but I/O yields the main Node event loop.
      if (!message) { try { message = JSON.parse(raw.toString()); } catch { /* onMessage reports parse error */ } }
      const roomId = participants.get(ws)?.roomId || message?.roomId;
      const room = rooms.get(roomId);
      if (!room) { void onMessage(ws, raw).catch(() => error(ws, 'FORBIDDEN')); return; }
      room.actionQueue = (room.actionQueue || Promise.resolve())
        .then(() => onMessage(ws, raw))
        .catch(() => { if (rooms.get(room.id) === room) expireRoom(room); });
    });
    ws.on('close', () => removePeer(ws));
  }
  wss.on('connection', onConnection);
  async function createRoom(req, response = null) {
    const user = identify(req);
    if (authenticated && !user) return { status: 401 };
    let boundObject = null;
    let objectPin = null;
    let objectDigest = null;
    let objectSize = null;
    let immutableVersionId = null;
    const body = req.body;
    if (body !== undefined && body !== null && (!object(body) ||
      (Object.keys(body).length > 0 && (Object.keys(body).length !== 1 || !Object.hasOwn(body, 'boundObject'))))) {
      return { status: 403 };
    }
    if (body && Object.hasOwn(body, 'boundObject')) {
      const input = body.boundObject;
      // This admission gate is intentionally stricter than the legacy hash
      // preflight. The Root.ark adapter presently has neither an immutable,
      // owner-authorized version authority nor a single mutation-serialized
      // all-party ACL snapshot. Do not read 32 MiB or allocate a P2P room
      // merely to discover later that protected signaling must fail closed.
      // Only startup-injected trusted callbacks can enable this path; request
      // JSON, hash results and self-asserted flags are never capabilities.
      if (!authenticated || typeof authorizeObject !== 'function' ||
        typeof authorizeImmutableVersion !== 'function' ||
        typeof authorizeSignalSnapshot !== 'function' ||
        !object(input) || Object.keys(input).length !== 2 ||
        typeof input.folderId !== 'string' || !/^[a-zA-Z0-9_-]{1,80}$/.test(input.folderId) ||
        typeof input.fileName !== 'string' || input.fileName.length > 100 ||
        !input.fileName || /[/\\\x00-\x1f\x7f]/.test(input.fileName) ||
        input.fileName === '.' || input.fileName === '..') return { status: 403 };
      boundObject = { folderId: input.folderId, fileName: input.fileName };
    }
    // Reserve capacity before any async hashing; simultaneous requests count.
    for (const room of rooms.values()) validRoom(room);
    const owner = user?.username;
    if (authenticated && [...rooms.values()].filter(room => room.owner === owner).length +
      (pendingRoomCreatesByOwner.get(owner) || 0) >= MAX_ACTIVE_ROOMS_PER_OWNER) return { status: 429 };
    if (rooms.size + pendingRoomCreates >= 16) return { status: 429 };
    pendingRoomCreates++;
    if (authenticated) pendingRoomCreatesByOwner.set(owner,
      (pendingRoomCreatesByOwner.get(owner) || 0) + 1);
    let createdRoom = null;
    let canceled = req.aborted === true ||
      (response?.destroyed === true && response.writableFinished !== true);
    // After the HTTP body has finished, IncomingMessage.aborted stays false.
    // A premature ServerResponse.close is the cancellation signal instead.
    const detachResponseListeners = () => {
      response?.off('close', onResponseClose);
      response?.off('finish', onResponseFinish);
    };
    const onResponseClose = () => {
      if (response.writableFinished !== true) {
        canceled = true;
        if (createdRoom && rooms.get(createdRoom.id) === createdRoom) expireRoom(createdRoom);
      }
      detachResponseListeners();
    };
    const onResponseFinish = () => detachResponseListeners();
    response?.once('close', onResponseClose);
    response?.once('finish', onResponseFinish);
    try {
      if (boundObject) {
        if (canceled) return { status: 403 };
        try {
          const grant = await authorizeObject({ owner: user.username, recipient: null, boundObject, pin: null });
          if (!object(grant) || typeof grant.fingerprint !== 'string' ||
            !/^[a-f0-9]{64}$/.test(grant.fingerprint) ||
            typeof grant.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(grant.sha256) ||
            !Number.isSafeInteger(grant.bytes) || grant.bytes < 1 ||
            grant.bytes > 32 * 1024 * 1024) return { status: 403 };
          objectPin = grant.fingerprint;
          objectDigest = grant.sha256;
          objectSize = grant.bytes;
          // A callback's mere presence or a hash of mutable legacy ciphertext
          // cannot authorize a version. Only a trusted startup-injected
          // authority may attest the exact owner/path/pin/digest/size tuple;
          // the adapter MUST independently verify owner-signed immutable
          // storage and custody before returning this record.
          const context = Object.freeze({
            owner, boundObject: Object.freeze({ ...boundObject }),
            pin: objectPin, sha256: objectDigest, bytes: objectSize,
          });
          const version = await authorizeImmutableVersion(context);
          const versionSnapshot = immutableVersionSnapshot(version, context);
          if (!versionSnapshot) return { status: 403 };
          immutableVersionId = versionSnapshot.versionId;
          // The async authority may overlap a revocation or ciphertext
          // replacement. Recheck the owner's live ACL and exact bytes after it
          // resolves; these preflights still cannot replace an atomic custody
          // and ACL mutation fence.
          const current = await authorizeObject({
            owner, recipient: null, boundObject, pin: objectPin,
          });
          if (!object(current) || current.fingerprint !== objectPin ||
            current.sha256 !== objectDigest || current.bytes !== objectSize) {
            return { status: 403 };
          }
        } catch { return { status: 403 }; }
      }
      // Hashing may complete after the HTTP request was canceled or the session
      // changed. Never turn that stale result into a room.
      if (req.aborted || canceled) return { status: 403 };
      if (authenticated) {
        const current = identify(req);
        if (!current || current.username !== owner ||
          current.sessionVersion !== user.sessionVersion) return { status: 401 };
      }
      const timestamp = now();
      const room = { id: shortId(), hostKey: token(), expires: timestamp + roomTtlMs,
        hostJoinDeadline: timestamp + (authenticated ? Math.min(roomTtlMs, UNJOINED_ROOM_TTL_MS) : roomTtlMs),
        hostJoined: false,
        owner: user?.username, ownerSessionVersion: user?.sessionVersion,
        boundObject, objectPin, objectDigest, objectSize, immutableVersionId,
        members: new Map(), invites: new Map(), pending: new Map(), allowed: new Set() };
      rooms.set(room.id, room);
      createdRoom = room;
      return { status: 200, roomId: room.id, hostKey: room.hostKey, expires: room.expires,
        ...(boundObject ? { boundObject: { ...boundObject, sha256: objectDigest,
          size: objectSize, versionId: immutableVersionId } } : {}) };
    } finally {
      // Retain close/finish listeners for an allocated room until HTTP delivery
      // completes. A disconnect before delivery then reclaims its orphan room.
      if (!createdRoom || canceled) detachResponseListeners();
      pendingRoomCreates--;
      if (authenticated) {
        const remaining = pendingRoomCreatesByOwner.get(owner) - 1;
        if (remaining) pendingRoomCreatesByOwner.set(owner, remaining);
        else pendingRoomCreatesByOwner.delete(owner);
      }
    }
  }
  const server = sharedWss ? null : createHttpServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'self'; connect-src 'self' ws://127.0.0.1:*; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'");
    if (req.method === 'POST' && url.pathname === '/rooms' && req.headers.origin === origin) {
      let result;
      try { result = await createRoom(req, res); }
      catch { if (!res.destroyed) res.writeHead(403).end(); return; }
      if (res.destroyed) return;
      if (result.status !== 200) { res.writeHead(result.status).end(); return; }
      res.setHeader('Content-Type', 'application/json');
      const { roomId, hostKey, expires } = result;
      res.end(JSON.stringify({ roomId, hostKey, expires }));
      return;
    }
    const route = req.method === 'GET' && {
      '/': 'index.html', '/client.js': 'client.js', '/transfer-protocol.js': 'transfer-protocol.js'
    }[url.pathname];
    if (route) {
      res.setHeader('Content-Type', route.endsWith('.js') ? 'text/javascript; charset=utf-8' : 'text/html; charset=utf-8');
      res.end(readFileSync(join(__dirname, route)));
    } else res.writeHead(404).end();
  });
  if (server) server.on('upgrade', (req, socket, head) => {
    if (req.url !== '/signal' || req.headers.origin !== origin || wss.clients.size >= 32) {
      socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    const identity = identify(req);
    if (authenticated && !identity) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, ws => {
      ws.identity = identity;
      ws.upgradeRequest = req;
      wss.emit('connection', ws, req);
    });
  });
  const expirySweep = setInterval(() => {
    for (const room of rooms.values()) if (validRoom(room) && !room.sweepPending) {
      room.sweepPending = true;
      room.actionQueue = (room.actionQueue || Promise.resolve())
        .then(async () => { if (validRoom(room)) await recheckBoundRoom(room); })
        .catch(() => { if (rooms.get(room.id) === room) expireRoom(room); })
        .finally(() => { room.sweepPending = false; });
    }
    if (authenticated) for (const ws of participants.keys()) sessionCurrent(ws);
  }, 1000);
  expirySweep.unref();
  return {
    createRoom,
    async listen() {
      if (!server) throw new Error('Room broker is mounted on an existing Root.ark server');
      await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
      listener = server.address().port;
      origin = `http://127.0.0.1:${listener}`;
      return origin;
    },
    async close() {
      clearInterval(expirySweep);
      if (sharedWss) {
        wss.removeListener('connection', onConnection);
        for (const ws of participants.keys()) ws.close(1000, 'room stopped');
      } else {
        for (const ws of wss.clients) ws.terminate();
        await new Promise(resolve => server.close(resolve));
      }
    },
    get origin() { return origin; }
  };
}

if (require.main === module) {
  makeBroker().listen().then(origin => process.stdout.write(`Disposable WebRTC experiment: ${origin}\n`));
}
module.exports = { makeBroker };
