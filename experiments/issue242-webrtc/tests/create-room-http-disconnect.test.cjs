'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createServer, request: httpRequest } = require('node:http');
const WebSocket = require('ws');
const { makeBroker } = require('../server.cjs');

const grant = { fingerprint: 'a'.repeat(64), sha256: 'b'.repeat(64), bytes: 32 * 1024 * 1024 };
const body = JSON.stringify({ boundObject: { folderId: 'root', fileName: 'sealed.bin' } });
function deferred() {
  let release;
  const promise = new Promise(resolve => { release = resolve; });
  return { promise, release };
}
function ownerRequest() {
  return { headers: { 'x-owner': 'alice' },
    body: JSON.parse(body) };
}

async function actualHttpFixture(t, { authorizeObject, beforeRespond = async () => {}, afterCreate = () => {} }) {
  const broker = makeBroker({
    sharedWss: new WebSocket.WebSocketServer({ noServer: true }),
    authenticateSession: req => ({
      username: req.headers['x-owner'], sessionVersion: 1, expiresAt: Date.now() + 60_000,
    }),
    authorizeObject,
    // Explicit synthetic authorities exercise response-close/finish races.
    // Root.ark's real adapter deliberately supplies neither capability.
    authorizeImmutableVersion: input => Object.freeze({
      ...input, boundObject: { ...input.boundObject }, versionId: 'test-immutable-v1',
    }),
    authorizeSignalSnapshot: () => null,
  });
  const closed = deferred();
  const processed = deferred();
  const server = createServer(async (req, res) => {
    try {
      const bytes = [];
      for await (const chunk of req) bytes.push(chunk);
      req.body = JSON.parse(Buffer.concat(bytes).toString('utf8'));
      res.once('close', () => closed.release({
        complete: req.complete, aborted: req.aborted, responseFinished: res.writableFinished,
      }));
      const result = await broker.createRoom(req, res);
      afterCreate(result);
      processed.release(result);
      await beforeRespond();
      if (!res.destroyed) res.writeHead(result.status).end(JSON.stringify(result));
    } catch (error) {
      processed.release({ error });
      if (!res.destroyed) res.writeHead(500).end();
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    await new Promise(resolve => server.close(resolve));
    await broker.close();
  });
  function post() {
    const port = server.address().port;
    const client = httpRequest({
      host: '127.0.0.1', port, path: '/rooms', method: 'POST',
      headers: { 'x-owner': 'alice', 'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body) },
    });
    client.on('error', () => {});
    client.end(body);
    return client;
  }
  return { broker, post, closed, processed };
}

test('completed HTTP POST followed by socket destroy must not create orphan room after slow hash',
  { timeout: 10_000 }, async t => {
    const hashing = deferred(), authorize = deferred();
    let checks = 0;
    const fixture = await actualHttpFixture(t, {
      authorizeObject: async () => {
        checks++;
        hashing.release();
        await authorize.promise;
        return grant;
      },
    });
    const client = fixture.post();
    try {
      await hashing.promise;
      client.destroy();
      const closed = await fixture.closed.promise;
      assert.equal(closed.complete, true, 'the actual HTTP request body must have completed');
      assert.equal(closed.aborted, false, 'IncomingMessage.aborted is false after a completed POST');
      assert.equal(closed.responseFinished, false, 'client closed before response finished');
    } finally {
      authorize.release();
    }
    assert.equal((await fixture.processed.promise).status, 403,
      'a disconnected HTTP response cannot authorize creation of an orphan room');
    assert.equal((await fixture.broker.createRoom(ownerRequest())).status, 200);
    assert.equal((await fixture.broker.createRoom(ownerRequest())).status, 200,
      'the disconnected request must leave no active room or pending reservation');
    assert.equal((await fixture.broker.createRoom(ownerRequest())).status, 429);
    assert.equal(checks, 6, 'the overflow request must not rehash ciphertext');
  });

test('response disconnected after room allocation but before send releases orphan capacity',
  { timeout: 10_000 }, async t => {
    const created = deferred(), allowResponse = deferred();
    const fixture = await actualHttpFixture(t, {
      authorizeObject: async () => grant,
      afterCreate: () => created.release(),
      beforeRespond: () => allowResponse.promise,
    });
    const client = fixture.post();
    try {
      await created.promise;
      assert.equal((await fixture.processed.promise).status, 200);
      client.destroy();
      const closed = await fixture.closed.promise;
      assert.equal(closed.responseFinished, false);
    } finally {
      allowResponse.release();
    }
    assert.equal((await fixture.broker.createRoom(ownerRequest())).status, 200);
    assert.equal((await fixture.broker.createRoom(ownerRequest())).status, 200,
      'room created for unacknowledged response must be reclaimed');
  });

test('normal HTTP response finish does not revoke a legitimately created room',
  { timeout: 10_000 }, async t => {
    const fixture = await actualHttpFixture(t, { authorizeObject: async () => grant });
    const client = fixture.post();
    const received = new Promise((resolve, reject) => {
      client.once('response', res => {
        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.once('end', () => resolve({ status: res.statusCode, data: JSON.parse(Buffer.concat(chunks)) }));
      });
      client.once('error', reject);
    });
    const result = await received;
    assert.equal(result.status, 200);
    assert.ok(result.data.roomId);
    const closed = await fixture.closed.promise;
    assert.equal(closed.responseFinished, true);
    assert.equal((await fixture.broker.createRoom(ownerRequest())).status, 200);
    assert.equal((await fixture.broker.createRoom(ownerRequest())).status, 429,
      'a response completed normally must retain the original room reservation');
  });
