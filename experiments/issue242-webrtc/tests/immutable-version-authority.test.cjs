'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const WebSocket = require('ws');
const { makeBroker } = require('../server.cjs');

const boundObject = Object.freeze({ folderId: 'root', fileName: 'sealed.bin' });
const pin = 'a'.repeat(64);
const sha256 = 'b'.repeat(64);
const bytes = 1024;
const versionId = 'test-immutable-version-0001';
const grant = Object.freeze({ fingerprint: pin, sha256, bytes });
const expectedContext = { owner: 'alice', boundObject, pin, sha256, bytes };
function req(owner = 'alice') {
  return { headers: { owner }, body: { boundObject: { ...boundObject } } };
}
function verified(input) {
  return { ...input, boundObject: { ...input.boundObject }, versionId };
}
function fixture(t, versionAuthority, options = {}) {
  let hashes = 0;
  const broker = makeBroker({
    authenticateSession: request => ({ username: request.headers.owner, sessionVersion: 1,
      expiresAt: Date.now() + 60_000 }),
    authorizeObject: async () => { hashes++; return grant; },
    authorizeSignalSnapshot: () => null,
    authorizeImmutableVersion: versionAuthority,
    ...options,
  });
  t.after(() => broker.close());
  return { broker, get hashes() { return hashes; } };
}
function denied(result) {
  assert.deepEqual(result, { status: 403 },
    'denied admission must disclose no room ID, capability token or object metadata');
}
function deferred() {
  let release;
  const promise = new Promise(resolve => { release = resolve; });
  return { release, promise };
}

test('synthetic authority is invoked with frozen exact version binding; admitted room carries pinned version', async t => {
  const contexts = [];
  const f = fixture(t, input => {
    contexts.push(input);
    assert.equal(Object.isFrozen(input), true);
    assert.equal(Object.isFrozen(input.boundObject), true);
    assert.deepEqual(input, expectedContext);
    return verified(input);
  });
  const result = await f.broker.createRoom(req());
  assert.equal(contexts.length, 1, 'factory callback must actually run');
  assert.equal(result.status, 200);
  assert.deepEqual(result.boundObject, { ...boundObject, sha256, size: bytes, versionId });
  assert.match(result.roomId, /^[a-f0-9]{16}$/);
  assert.match(result.hostKey, /^[a-f0-9]{64}$/);
  assert.equal(f.hashes, 2, 'owner ACL must be revalidated after awaited version authority');
  const origin = await f.broker.listen();
  const ws = new WebSocket(origin.replace('http:', 'ws:') + '/signal', {
    headers: { Origin: origin, owner: 'alice' },
  });
  t.after(() => ws.terminate());
  await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
  const joined = new Promise(resolve => ws.once('message', raw => resolve(JSON.parse(raw.toString()))));
  ws.send(JSON.stringify({ type: 'join', roomId: result.roomId, hostKey: result.hostKey }));
  assert.deepEqual((await joined).boundObject, { ...boundObject, sha256, size: bytes, versionId },
    'host and recipients must see the same pinned version digest and identity');
});

test('false, null, thrown, async rejection and incorrectly bound attestations all deny without a room', async t => {
  const cases = [
    ['false', () => false],
    ['true is not attestation', () => true],
    ['null', () => null],
    ['throw', () => { throw Error('no custody'); }],
    ['rejected promise', async () => { throw Error('no custody'); }],
    ['bare metadata', () => ({ versionId })],
    ['forged owner', input => ({ ...verified(input), owner: 'mallory' })],
    ['forged path', input => ({ ...verified(input), boundObject: { folderId: 'other', fileName: 'sealed.bin' } })],
    ['forged digest', input => ({ ...verified(input), sha256: 'c'.repeat(64) })],
    ['forged pin', input => ({ ...verified(input), pin: 'd'.repeat(64) })],
    ['forged size', input => ({ ...verified(input), bytes: bytes + 1 })],
    ['digest substituted as version', input => ({ ...verified(input), versionId: input.sha256 })],
    ['timestamp substituted as version', input => ({ ...verified(input), versionId: String(Date.now()) })],
    ['getter result', input => Object.defineProperty(verified(input), 'sha256', { get() { return sha256; } })],
    ['unexpected assertion fields', input => ({ ...verified(input), browserVerified: true })],
    ['async returned grant rejected', async () => Promise.reject(Error('no grant'))],
  ];
  for (const [name, callback] of cases) {
    await t.test(name, async sub => {
      const f = fixture(sub, callback);
      denied(await f.broker.createRoom(req()));
      assert.equal((await f.broker.createRoom({ headers: { owner: 'alice' } })).status, 200,
        'rejected bound attempt must not reserve permanent capacity');
    });
  }
});

test('callback sees only exact trusted request, never accepts browser metadata or unbound substitute', async t => {
  let invoked = 0;
  const f = fixture(t, input => { invoked++; return verified(input); });
  const malicious = req();
  malicious.body.boundObject.versionId = versionId;
  denied(await f.broker.createRoom(malicious));
  malicious.body.boundObject = { ...boundObject, ownerSignature: 'self-attested' };
  denied(await f.broker.createRoom(malicious));
  const unbound = await f.broker.createRoom({ headers: { owner: 'alice' } });
  assert.equal(unbound.status, 200);
  assert.equal(invoked, 0);
  assert.equal(f.hashes, 0);
});

test('failed callback allocates no room, emits no WebSocket announcements or capabilities', async t => {
  const f = fixture(t, () => false);
  const origin = await f.broker.listen();
  const ws = new WebSocket(origin.replace('http:', 'ws:') + '/signal', {
    headers: { Origin: origin, owner: 'alice' },
  });
  t.after(() => ws.terminate());
  await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
  const received = [];
  ws.on('message', raw => received.push(JSON.parse(raw.toString())));
  denied(await f.broker.createRoom(req()));
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.deepEqual(received, [], 'no joined, invite or signaling notification may be emitted');
  assert.equal((await f.broker.createRoom({ headers: { owner: 'alice' } })).status, 200);
});

test('owner access revoked while immutable callback awaits refuses stale grant without leaking room tokens', async t => {
  const entered = deferred();
  const resume = deferred();
  let revoked = false;
  let checks = 0;
  const f = fixture(t, async input => {
    entered.release();
    await resume.promise;
    return verified(input);
  }, { authorizeObject: async () => {
    checks++;
    return revoked ? null : grant;
  } });
  const pending = f.broker.createRoom(req());
  await entered.promise;
  revoked = true;
  resume.release();
  denied(await pending);
  assert.equal(checks, 2, 'revocation after first hash must be rechecked before room creation');
  assert.equal((await f.broker.createRoom({ headers: { owner: 'alice' } })).status, 200);
});

test('session version revoked while async immutable callback awaits prevents room allocation', async t => {
  const entered = deferred();
  const resume = deferred();
  let epoch = 1;
  const f = fixture(t, async input => {
    entered.release();
    await resume.promise;
    return verified(input);
  }, { authenticateSession: request => ({
    username: request.headers.owner, sessionVersion: epoch, expiresAt: Date.now() + 60_000,
  }) });
  const pending = f.broker.createRoom(req());
  await entered.promise;
  epoch++;
  resume.release();
  assert.deepEqual(await pending, { status: 401 });
  assert.equal((await f.broker.createRoom({ headers: { owner: 'alice' } })).status, 200);
});

test('Proxy versionId read changes after validation must not reach a room or overwrite the pinned version', async t => {
  let reads = 0;
  const f = fixture(t, input => new Proxy(verified(input), {
    get(target, field, receiver) {
      if (field === 'versionId') return ++reads <= 5 ? versionId : null;
      return Reflect.get(target, field, receiver);
    },
  }));
  const response = await f.broker.createRoom(req());
  assert.equal(response.status, 200);
  assert.equal(response.boundObject.versionId, versionId,
    'read of untrusted live Proxy value after validation must never pollute the room');
  assert.equal(reads, 0, 'the pinned version must come exclusively from a descriptor snapshot');
});

test('Proxy get traps for owner, path, pin, hash and size cannot alter a trusted descriptor snapshot', async t => {
  const fields = ['owner', 'boundObject', 'pin', 'sha256', 'bytes', 'versionId'];
  for (const field of fields) {
    await t.test(field, async sub => {
      let gets = 0;
      const f = fixture(sub, input => new Proxy(verified(input), {
        get(target, key, receiver) {
          if (key === field) {
            gets++;
            if (key === 'boundObject') return { folderId: 'elsewhere', fileName: 'wrong.bin' };
            return key === 'bytes' ? -1 : null;
          }
          return Reflect.get(target, key, receiver);
        },
      }));
      const response = await f.broker.createRoom(req());
      assert.equal(response.status, 200);
      assert.equal(response.boundObject.versionId, versionId);
      assert.equal(gets, 0, 'must not invoke an untrusted Proxy getter for ' + field);
    });
  }
  for (const field of ['folderId', 'fileName']) {
    await t.test('nested ' + field, async sub => {
      let gets = 0;
      const f = fixture(sub, input => ({
        ...verified(input), boundObject: new Proxy({ ...input.boundObject }, {
          get(target, key, receiver) {
            if (key === field) { gets++; return 'wrong-name'; }
            return Reflect.get(target, key, receiver);
          },
        }),
      }));
      const response = await f.broker.createRoom(req());
      assert.equal(response.status, 200);
      assert.equal(response.boundObject.versionId, versionId);
      assert.equal(gets, 0, 'nested values must be read through own data descriptors');
    });
  }
});

test('invalid Proxy descriptor snapshots deny even when direct property reads look authorized', async t => {
  const forged = [
    ['owner', 'intruder'],
    ['pin', 'c'.repeat(64)],
    ['sha256', 'd'.repeat(64)],
    ['bytes', 999],
    ['versionId', null],
    ['boundObject', { folderId: 'wrong', fileName: boundObject.fileName }],
  ];
  for (const [field, value] of forged) {
    await t.test(field, async sub => {
      const f = fixture(sub, input => new Proxy(verified(input), {
        getOwnPropertyDescriptor(target, key) {
          const descriptor = Reflect.getOwnPropertyDescriptor(target, key);
          if (key === field) return { ...descriptor, configurable: true, value };
          return descriptor;
        },
      }));
      denied(await f.broker.createRoom(req()));
    });
  }
});

test('descriptor accessors and throwing Proxy reflection traps are denied without capabilities', async t => {
  const variants = [
    ['top accessor', input => Object.defineProperty(verified(input), 'versionId', {
      configurable: true, get: () => versionId,
    })],
    ['nested accessor', input => Object.assign(verified(input), {
      boundObject: Object.defineProperty({ ...input.boundObject }, 'fileName', {
        configurable: true, get: () => boundObject.fileName,
      }),
    })],
    ...['getPrototypeOf', 'ownKeys', 'getOwnPropertyDescriptor'].map(trap => [
      'top trap ' + trap, input => new Proxy(verified(input), {
        [trap]() { throw new Error('trap denied'); },
      }),
    ]),
    ...['getPrototypeOf', 'ownKeys', 'getOwnPropertyDescriptor'].map(trap => [
      'nested trap ' + trap, input => ({
        ...verified(input), boundObject: new Proxy({ ...input.boundObject }, {
          [trap]() { throw new Error('trap denied'); },
        }),
      }),
    ]),
  ];
  for (const [name, factory] of variants) {
    await t.test(name, async sub => {
      const f = fixture(sub, factory);
      denied(await f.broker.createRoom(req()));
    });
  }
});

test('version snapshot is retained unchanged while later asynchronous owner ACL recheck yields', async t => {
  const entered = deferred();
  const resume = deferred();
  let reads = 0;
  let checks = 0;
  let target;
  const f = fixture(t, input => {
    target = verified(input);
    return new Proxy(target, {
      get(_object, key) { if (key === 'versionId') { reads++; return null; } return target[key]; },
    });
  }, { authorizeObject: async () => {
    if (++checks === 2) {
      entered.release();
      await resume.promise;
    }
    return grant;
  } });
  const pending = f.broker.createRoom(req());
  await entered.promise;
  target.versionId = null;
  resume.release();
  const response = await pending;
  assert.equal(response.status, 200);
  assert.equal(response.boundObject.versionId, versionId,
    'after await the broker must use detached immutable primitive snapshot');
  assert.equal(reads, 0, 'no direct Proxy reads after synchronous descriptor snapshot');
});
