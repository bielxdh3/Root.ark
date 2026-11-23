'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const net = require('node:net');
const WebSocket = require('ws');
const { makeBroker } = require('../server.cjs');

async function setup(t, opts) {
  const broker = makeBroker(opts);
  const origin = await broker.listen();
  const sockets = new Set();
  t.after(async () => {
    for (const ws of sockets) ws.terminate();
    await broker.close();
  });
  function connect() {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(origin.replace('http:', 'ws:') + '/signal', { headers: { Origin: origin } });
      sockets.add(ws);
      ws.once('open', () => {
        const queue = [], waiters = [];
        ws.on('message', bytes => {
          const message = JSON.parse(bytes.toString());
          const i = waiters.findIndex(w => w.type === message.type);
          if (i < 0) queue.push(message);
          else waiters.splice(i, 1)[0].resolve(message);
        });
        resolve({
          ws,
          send: value => ws.send(JSON.stringify(value)),
          next: (type) => new Promise((res, rej) => {
            const i = queue.findIndex(m => m.type === type);
            if (i >= 0) return res(queue.splice(i, 1)[0]);
            const waiter = { type, resolve: res };
            waiters.push(waiter);
            setTimeout(() => {
              const pending = waiters.indexOf(waiter);
              if (pending >= 0) { waiters.splice(pending, 1); rej(new Error('timeout for ' + type)); }
            }, 1500).unref();
          })
        });
      });
      ws.once('error', reject);
    });
  }
  async function room() {
    const response = await fetch(origin + '/rooms', { method: 'POST', headers: { Origin: origin } });
    assert.equal(response.status, 200);
    return response.json();
  }
  return { broker, origin, connect, room };
}

async function startIsolatedBroker(t) {
  const childScript = [
    "const http = require('node:http');",
    'const createServer = http.createServer;',
    "http.createServer = function (handler, ...args) {",
    "  return createServer.call(this, (req, res) => {",
    "    process.stdout.write('REQUEST_HANDLER ' + req.method + '\\n');",
    '    return handler(req, res);',
    '  }, ...args);',
    '};',
    "const { makeBroker } = require(process.argv[1]);",
    "makeBroker().listen().then(origin => process.stdout.write('READY ' + origin + '\\n'));"
  ].join('\n');
  const child = spawn(process.execPath, ['-e', childScript, require.resolve('../server.cjs')], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });

  const origin = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('isolated broker did not become ready')), 5000);
    child.stdout.on('data', () => {
      const line = stdout.split('\n').find(value => value.startsWith('READY '));
      if (!line) return;
      clearTimeout(timeout);
      resolve(line.slice('READY '.length));
    });
    child.once('error', error => {
      clearTimeout(timeout);
      reject(error);
    });
    child.once('exit', (code, signal) => {
      clearTimeout(timeout);
      reject(new Error('isolated broker exited before ready: ' + code + '/' + signal));
    });
  });

  t.after(async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    const exited = new Promise(resolve => child.once('exit', resolve));
    child.kill('SIGTERM');
    await Promise.race([exited, new Promise(resolve => setTimeout(resolve, 1000))]);
  });
  return {
    child, origin,
    get stdout() { return stdout; },
    get stderr() { return stderr; },
  };
}

async function connectIsolatedHost(origin) {
  const response = await fetch(origin + '/rooms', {
    method: 'POST', headers: { Origin: origin },
  });
  assert.equal(response.status, 200);
  const room = await response.json();
  const ws = new WebSocket(origin.replace('http:', 'ws:') + '/signal', {
    headers: { Origin: origin },
  });
  await new Promise((resolve, reject) => {
    ws.once('open', resolve);
    ws.once('error', reject);
  });
  const queue = [];
  const waiters = [];
  ws.on('message', bytes => {
    const message = JSON.parse(bytes.toString());
    const index = waiters.findIndex(waiter => waiter.type === message.type);
    if (index < 0) queue.push(message);
    else waiters.splice(index, 1)[0].resolve(message);
  });
  const host = {
    ws,
    send: message => ws.send(JSON.stringify(message)),
    next(type) {
      return new Promise((resolve, reject) => {
        const index = queue.findIndex(message => message.type === type);
        if (index >= 0) return resolve(queue.splice(index, 1)[0]);
        const waiter = { type, resolve };
        waiters.push(waiter);
        setTimeout(() => {
          const pending = waiters.indexOf(waiter);
          if (pending >= 0) {
            waiters.splice(pending, 1);
            reject(new Error('timeout for ' + type));
          }
        }, 1500).unref();
      });
    },
  };
  host.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
  assert.equal((await host.next('joined')).role, 'host');
  return host;
}

function sendRawRequest(origin, requestTarget) {
  const port = Number(new URL(origin).port);
  return new Promise(resolve => {
    const socket = net.connect(port, '127.0.0.1');
    let bytes = Buffer.alloc(0);
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      const raw = bytes.toString('latin1');
      const separator = raw.indexOf('\r\n\r\n');
      resolve({
        raw,
        statusLine: raw.split('\r\n')[0] || null,
        headers: separator < 0 ? '' : raw.slice(0, separator).toLowerCase(),
        body: separator < 0 ? '' : raw.slice(separator + 4),
      });
      socket.destroy();
    };
    const timeout = setTimeout(finish, 3000);
    socket.once('connect', () => socket.write(
      'GET ' + requestTarget + ' HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'));
    socket.on('data', chunk => { bytes = Buffer.concat([bytes, chunk]); });
    socket.once('end', finish);
    socket.once('close', finish);
    socket.once('error', finish);
  });
}

function waitForChildExit(child, timeoutMs = 150) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve(true);
  return new Promise(resolve => {
    const finish = exited => {
      clearTimeout(timeout);
      child.removeListener('exit', onExit);
      resolve(exited);
    };
    const onExit = () => finish(true);
    const timeout = setTimeout(() => finish(false), timeoutMs);
    child.once('exit', onExit);
  });
}

async function waitForOutput(readOutput, expected, timeoutMs = 500) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (readOutput().includes(expected)) return true;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  return readOutput().includes(expected);
}

test('P2: malformed HTTP request-targets return bounded 400 and preserve an existing room', async t => {
  for (const requestTarget of ['//', 'http://[']) {
    await t.test('GET ' + requestTarget, async t => {
      const isolated = await startIsolatedBroker(t);
      const host = await connectIsolatedHost(isolated.origin);
      t.after(() => host.ws.terminate());

      const response = await sendRawRequest(isolated.origin, requestTarget);
      const handlerReached = await waitForOutput(() => isolated.stdout, 'REQUEST_HANDLER GET');
      const exited = await waitForChildExit(isolated.child);
      let roomUsable = false;
      if (!exited && host.ws.readyState === WebSocket.OPEN) {
        const invited = host.next('invited');
        host.send({ type: 'invite' });
        roomUsable = Boolean((await invited).invitation);
      }
      const applicationUrlThrow = isolated.stderr.includes('ERR_INVALID_URL') &&
        /server\.cjs:\d+/.test(isolated.stderr);

      assert.equal(handlerReached, true,
        'raw target must reach the application handler; a parser-level rejection is not this regression');
      assert.equal(response.statusLine, 'HTTP/1.1 400 Bad Request',
        'expected bounded application 400; childExit=' + isolated.child.exitCode +
        '; applicationUrlThrow=' + applicationUrlThrow + '; roomUsable=' + roomUsable);
      assert.equal(exited, false, 'malformed request-target must not terminate the broker');
      assert.equal(roomUsable, true, 'a room admitted before the malformed request must remain usable');
      assert.match(response.headers, /content-length: 0/,
        'malformed request response must have an empty bounded body');
      assert.equal(response.body, '');
      assert.ok(response.raw.length <= 1024, 'malformed request response must stay bounded');
      assert.equal(response.body.includes(requestTarget), false,
        'response body must not reflect the attacker-controlled request-target');
      assert.equal(response.headers.includes('location:'), false,
        'malformed request must not create a redirect containing attacker input');
      const applicationOutput = isolated.stdout.split('\n')
        .filter(line => !line.startsWith('READY ')).join('\n');
      assert.equal(applicationOutput.includes(requestTarget), false,
        'application output must not log the attacker-controlled request-target');
      assert.equal(isolated.stderr.includes(requestTarget), false,
        'broker must not log the attacker-controlled request-target');
    });
  }
});

test('invites are unpredictable, single-use, expired and revocable', async t => {
  let time = 1000;
  const h = await setup(t, { now: () => time, inviteTtlMs: 500 });
  const { roomId, hostKey } = await h.room();
  const host = await h.connect();
  host.send({ type: 'join', roomId, hostKey });
  assert.equal((await host.next('joined')).role, 'host');

  const guessed = await h.connect();
  guessed.send({ type: 'join', roomId, invitation: 'easy-code' });
  assert.equal((await guessed.next('error')).code, 'INVALID_INVITE');

  host.send({ type: 'invite' });
  const invite = await host.next('invited');
  assert.match(invite.invitation, /^[0-9a-f]{64}$/);
  host.send({ type: 'revoke', inviteId: invite.inviteId });
  assert.equal((await host.next('revoked')).inviteId, invite.inviteId);
  guessed.send({ type: 'join', roomId, invitation: invite.invitation });
  assert.equal((await guessed.next('error')).code, 'INVALID_INVITE');

  host.send({ type: 'invite' });
  const expired = await host.next('invited');
  time += 501;
  guessed.send({ type: 'join', roomId, invitation: expired.invitation });
  assert.equal((await guessed.next('error')).code, 'INVALID_INVITE');

  host.send({ type: 'invite' });
  const live = await host.next('invited');
  guessed.send({ type: 'join', roomId, invitation: live.invitation });
  assert.equal((await guessed.next('joined')).role, 'guest');
  guessed.send({ type: 'join', roomId, invitation: live.invitation });
  assert.equal((await guessed.next('error')).code, 'FORBIDDEN');
  const replay = await h.connect();
  replay.send({ type: 'join', roomId, invitation: live.invitation });
  assert.equal((await replay.next('error')).code, 'INVALID_INVITE');
});

test('signal requires host request and recipient consent; revoke disconnects guest', async t => {
  const h = await setup(t);
  const { roomId, hostKey } = await h.room();
  const host = await h.connect();
  host.send({ type: 'join', roomId, hostKey });
  const hp = await host.next('joined');
  host.send({ type: 'invite' });
  const { invitation } = await host.next('invited');
  const guest = await h.connect();
  guest.send({ type: 'join', roomId, invitation });
  const gp = await guest.next('joined');
  await host.next('peer-joined');
  guest.send({ type: 'signal', to: hp.peerId, signal: { kind: 'offer', sdp: 'forged' } });
  assert.equal((await guest.next('error')).code, 'FORBIDDEN');
  guest.send({ type: 'invite' });
  assert.equal((await guest.next('error')).code, 'FORBIDDEN');
  host.send({ type: 'request-peer', to: gp.peerId });
  const request = await guest.next('peer-request');
  assert.equal(request.peerId, hp.peerId);
  guest.send({ type: 'consent', requestId: 'incorrect', accept: true });
  assert.equal((await guest.next('error')).code, 'FORBIDDEN');
  guest.send({ type: 'consent', requestId: request.requestId, accept: true });
  assert.equal((await host.next('peer-accepted')).peerId, gp.peerId);
  assert.equal((await guest.next('peer-allowed')).peerId, hp.peerId);
  host.send({ type: 'signal', to: gp.peerId, signal: { kind: 'ice', candidate: { candidate: 'fixture' } } });
  const forwarded = await guest.next('signal');
  assert.equal(forwarded.signal.candidate.candidate, 'fixture');
  host.send({ type: 'kick', to: gp.peerId });
  assert.equal((await guest.next('error')).code, 'REVOKED');
  assert.equal((await host.next('peer-left')).peerId, gp.peerId);
  guest.ws.terminate();
  const replay = await h.connect();
  replay.send({ type: 'join', roomId, invitation });
  assert.equal((await replay.next('error')).code, 'INVALID_INVITE');
});

test('room size, invalid origin and bounded WebSocket payload', async t => {
  const h = await setup(t);
  const { roomId, hostKey } = await h.room();
  const host = await h.connect();
  host.send({ type: 'join', roomId, hostKey });
  await host.next('joined');
  for (let i = 0; i < 3; i++) {
    host.send({ type: 'invite' });
    const { invitation } = await host.next('invited');
    const guest = await h.connect();
    guest.send({ type: 'join', roomId, invitation });
    await guest.next('joined');
  }
  host.send({ type: 'invite' });
  assert.equal((await host.next('error')).code, 'FULL');

  const wsBadOrigin = new WebSocket(h.origin.replace('http:', 'ws:') + '/signal', { headers: { Origin: 'http://invalid.test' } });
  wsBadOrigin.on('error', () => {});
  const status = await new Promise(resolve => wsBadOrigin.once('unexpected-response', (_req, res) => {
    res.resume();
    resolve(res.statusCode);
  }));
  assert.equal(status, 403);

  const oversized = await h.connect();
  const closed = new Promise(resolve => oversized.ws.once('close', code => resolve(code)));
  oversized.ws.send('x'.repeat(20_000));
  assert.equal(await closed, 1009);
});

test('room expires even when idle, and rejected consent cannot forward SDP', async t => {
  let now = 100;
  const h = await setup(t, { now: () => now, roomTtlMs: 300 });
  const { roomId, hostKey } = await h.room();
  const host = await h.connect();
  host.send({ type: 'join', roomId, hostKey });
  const hp = await host.next('joined');
  host.send({ type: 'invite' });
  const { invitation } = await host.next('invited');
  const guest = await h.connect();
  guest.send({ type: 'join', roomId, invitation });
  const gp = await guest.next('joined');
  host.send({ type: 'request-peer', to: gp.peerId });
  const req = await guest.next('peer-request');
  guest.send({ type: 'consent', requestId: req.requestId, accept: false });
  assert.equal((await host.next('peer-declined')).peerId, gp.peerId);
  host.send({ type: 'signal', to: gp.peerId, signal: { kind: 'offer', sdp: { type: 'offer', sdp: 'fixture' } } });
  assert.equal((await host.next('error')).code, 'FORBIDDEN');
  assert.equal(hp.role, 'host');
  now = 401;
  assert.equal((await host.next('error')).code, 'ROOM_CLOSED');
  assert.equal((await guest.next('error')).code, 'ROOM_CLOSED');
});

test('P2: a stalled signaling recipient is evicted without blocking healthy peers', async t => {
  const serverSockets = [];
  const originalEmit = WebSocket.WebSocketServer.prototype.emit;
  WebSocket.WebSocketServer.prototype.emit = function (name, ...args) {
    if (name === 'connection') serverSockets.push(args[0]);
    return originalEmit.call(this, name, ...args);
  };
  t.after(() => { WebSocket.WebSocketServer.prototype.emit = originalEmit; });

  const h = await setup(t);
  const { roomId, hostKey } = await h.room();
  const host = await h.connect();
  host.send({ type: 'join', roomId, hostKey });
  const hp = await host.next('joined');
  host.send({ type: 'invite' });
  const invite = await host.next('invited');
  const guest = await h.connect();
  guest.send({ type: 'join', roomId, invitation: invite.invitation });
  const gp = await guest.next('joined');
  await host.next('peer-joined');
  host.send({ type: 'request-peer', to: gp.peerId });
  const request = await guest.next('peer-request');
  guest.send({ type: 'consent', requestId: request.requestId, accept: true });
  await host.next('peer-accepted');
  await guest.next('peer-allowed');

  // Positive control: normal consented signaling reaches the recipient.
  host.send({ type: 'signal', to: gp.peerId, signal: { kind: 'ice', candidate: { candidate: 'normal' } } });
  assert.equal((await guest.next('signal')).signal.candidate.candidate, 'normal');

  // Model a remote client that has stopped consuming its transport: the server
  // sees a fixed queued-byte count, irrespective of socket/network scheduling.
  assert.equal(serverSockets.length, 2);
  Object.defineProperty(serverSockets[1], 'bufferedAmount', { configurable: true, value: 512 * 1024 });
  host.send({ type: 'signal', to: gp.peerId, signal: { kind: 'ice', candidate: { candidate: 'flood' } } });
  assert.equal((await host.next('peer-left')).peerId, gp.peerId,
    'stalled recipient must be evicted instead of accumulating an unbounded send queue');

  // The same room stays usable for a freshly invited, consenting recipient.
  host.send({ type: 'invite' });
  const replacementInvite = await host.next('invited');
  const replacement = await h.connect();
  replacement.send({ type: 'join', roomId, invitation: replacementInvite.invitation });
  const rp = await replacement.next('joined');
  await host.next('peer-joined');
  host.send({ type: 'request-peer', to: rp.peerId });
  const replacementRequest = await replacement.next('peer-request');
  replacement.send({ type: 'consent', requestId: replacementRequest.requestId, accept: true });
  await host.next('peer-accepted');
  await replacement.next('peer-allowed');
  host.send({ type: 'signal', to: rp.peerId, signal: { kind: 'ice', candidate: { candidate: 'healthy' } } });
  assert.equal((await replacement.next('signal')).signal.candidate.candidate, 'healthy');
  assert.equal(hp.role, 'host');
});
