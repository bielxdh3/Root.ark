"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const Database = require("better-sqlite3");
const z = require("../src/crypto/rootark-zk-1");
const inventory = require("../src/crypto/rootark-zk-content-inventory-v1");
const { Zk1DurableContentInventoryLedger } = require("../src/services/zk1DurableContentInventoryLedger");

const ROOT_DOMAIN = Buffer.from("Root.ark/zk-1/content-inventory-root/v1\0", "ascii");
const SIGNATURE_DOMAIN = Buffer.from("Root.ark/zk-1/content-inventory-snapshot/v1\0", "ascii");
const ENTRY_DOMAIN = Buffer.from("Root.ark/zk-1/content-inventory-entry/v1\0", "ascii");
const SNAPSHOT_TYPE = "rootark-content-inventory-snapshot/v1";
const ENTRY_TYPE = "rootark-content-inventory-entry/v1";

function makeScope() {
  return {
    account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("fixture-compartment"),
    keyring_id: crypto.randomBytes(16),
  };
}

function makeTuple(objectId, revision, epoch, digest = crypto.randomBytes(32)) {
  return {
    object_id: Buffer.isBuffer(objectId) ? Buffer.from(objectId) : Buffer.from(objectId),
    revision,
    epoch,
    ciphertext_sha256: Buffer.from(digest),
  };
}

function requestFor(tuple) {
  return {
    object_id: Buffer.from(tuple.object_id),
    revision: tuple.revision,
    epoch: tuple.epoch,
    ciphertext_sha256: Buffer.from(tuple.ciphertext_sha256),
  };
}

function sameTuple(a, b) {
  return Buffer.compare(a.object_id, b.object_id)
    || a.revision - b.revision
    || a.epoch - b.epoch
    || Buffer.compare(a.ciphertext_sha256, b.ciphertext_sha256);
}

async function rawSignedSnapshot({
  scope, signerKeyId, privateKey, sequence, previousRoot, entries, nonce,
}) {
  const rootBody = {
    type: SNAPSHOT_TYPE,
    version: 1,
    scope,
    sequence,
    previous_root: previousRoot,
    entries,
  };
  const root = crypto.createHash("sha256")
    .update(Buffer.concat([ROOT_DOMAIN, await z.encodeDeterministic(rootBody)]))
    .digest();
  const unsigned = { ...rootBody, signer_key_id: signerKeyId, root, nonce };
  const signature = crypto.sign(null, Buffer.concat([
    SIGNATURE_DOMAIN,
    await z.encodeDeterministic(unsigned),
  ]), privateKey);
  return z.encodeDeterministic({ ...unsigned, signature });
}

async function decodedSnapshot(serialized) {
  return z.decodeDeterministic(serialized);
}

async function testFixture(t) {
  const dir = t ? fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-content-inventory-")) : null;
  const keys = crypto.generateKeyPairSync("ed25519");
  const signerKeyId = crypto.randomBytes(16);
  const scope = makeScope();
  const filename = dir ? path.join(dir, "content-inventory.sqlite") : null;
  const ledgers = new Set();
  if (t) t.after(() => {
    for (const ledger of ledgers) {
      try { ledger.close(); } catch (_) { /* already closed */ }
    }
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const options = { signerKeyId, signerPrivateKey: keys.privateKey, scope };
  const open = async (overrides = {}) => {
    const ledger = await Zk1DurableContentInventoryLedger.open(filename, {
      ...options,
      bootstrapNew: false,
      ...overrides,
    });
    ledgers.add(ledger);
    return ledger;
  };
  const close = (ledger) => {
    ledger.close();
    ledgers.delete(ledger);
  };
  return {
    dir, filename, keys, signerKeyId, scope, options, open, close,
    async openNew(overrides = {}) {
      return open({ bootstrapNew: true, ...overrides });
    },
  };
}

async function signedGenesis(f) {
  return inventory.createSignedSnapshot({
    signerKeyId: f.signerKeyId,
    privateKey: f.keys.privateKey,
    scope: f.scope,
    sequence: 0,
    previousRoot: null,
    entries: [],
    nonce: crypto.randomBytes(32),
  });
}

function floorOf(snapshot) {
  return { sequence: snapshot.sequence, root: Buffer.from(snapshot.root) };
}

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

function operationMapForTest(operation) {
  return {
    operation_id: Buffer.from(operation.operation_id),
    expected_sequence: operation.expected_sequence,
    expected_root: Buffer.from(operation.expected_root),
    object_id: Buffer.from(operation.object_id),
    revision: operation.revision,
    epoch: operation.epoch,
    ciphertext_sha256: Buffer.from(operation.ciphertext_sha256),
  };
}

async function signedPendingCommitForTest(f, operation) {
  const entry = inventory.normalizeEntry({
    object_id: operation.object_id,
    revision: operation.revision,
    epoch: operation.epoch,
    ciphertext_sha256: operation.ciphertext_sha256,
  });
  const requestCbor = await z.encodeDeterministic(operationMapForTest(operation));
  const requestDigest = crypto.createHash("sha256").update(requestCbor).digest();
  const root = await inventory.computeRoot(f.scope, 1, operation.expected_root, [entry]);
  const unsigned = {
    type: ENTRY_TYPE,
    version: 1,
    signer_key_id: f.signerKeyId,
    scope: f.scope,
    sequence: 1,
    previous_root: Buffer.from(operation.expected_root),
    root,
    operation_id: Buffer.from(operation.operation_id),
    expected_sequence: operation.expected_sequence,
    expected_root: Buffer.from(operation.expected_root),
    request_digest: requestDigest,
    entry,
  };
  const signature = crypto.sign(null, Buffer.concat([
    ENTRY_DOMAIN,
    await z.encodeDeterministic(unsigned),
  ]), f.keys.privateKey);
  return { entry, requestCbor, requestDigest, root, signature };
}

function trackMaterializingReads(ledger, predicate) {
  const originalPrepare = ledger.db.prepare.bind(ledger.db);
  let calls = 0;
  ledger.db.prepare = (sql) => {
    const statement = originalPrepare(sql);
    if (!predicate(sql)) return statement;
    return new Proxy(statement, {
      get(target, property) {
        if (property === "all") return (...args) => {
          calls += 1;
          return target.all(...args);
        };
        if (property === "get") return (...args) => {
          calls += 1;
          return target.get(...args);
        };
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  };
  return {
    calls: () => calls,
    restore() { ledger.db.prepare = originalPrepare; },
  };
}

test("empty genesis authenticates absence with a fresh nonce and has no authorizing result", async () => {
  const f = await testFixture();
  const genesis = await signedGenesis(f);
  const decoded = await decodedSnapshot(genesis);
  const requested = requestFor(makeTuple(crypto.randomBytes(16), 1, 1));
  const result = await inventory.verifySnapshot({
    serialized: genesis,
    pinnedPublicKey: f.keys.publicKey,
    pinnedSignerKeyId: f.signerKeyId,
    expectedScope: f.scope,
    requested,
    minimumHead: floorOf(decoded),
    nonce: Buffer.from(decoded.nonce),
  });
  assert.equal(result.status, "VERIFIED_NONAUTHORIZING");
  assert.equal(result.outcome, "ABSENT");
  assert.equal(Object.hasOwn(result, "authorized"), false);
  assert.equal(Object.hasOwn(result, "go"), false);
});

test("present, historic, and unrelated-object absence derive from complete chained inventories", async () => {
  const f = await testFixture();
  const genesis = await signedGenesis(f);
  const genesisHead = floorOf(await decodedSnapshot(genesis));
  const first = makeTuple(Buffer.alloc(16, 1), 1, 1);
  const firstSnapshot = await inventory.createSignedSnapshot({
    signerKeyId: f.signerKeyId, privateKey: f.keys.privateKey, scope: f.scope,
    sequence: 1, previousRoot: genesisHead.root, entries: [first], nonce: crypto.randomBytes(32),
  });
  const firstBody = await decodedSnapshot(firstSnapshot);
  const secondVersion = makeTuple(first.object_id, 2, 2);
  const otherObject = makeTuple(Buffer.alloc(16, 2), 1, 1);
  const secondSnapshot = await inventory.createSignedSnapshot({
    signerKeyId: f.signerKeyId, privateKey: f.keys.privateKey, scope: f.scope,
    sequence: 2, previousRoot: firstBody.root,
    entries: [first, secondVersion], nonce: crypto.randomBytes(32),
  });
  const secondBody = await decodedSnapshot(secondSnapshot);
  const thirdSnapshot = await inventory.createSignedSnapshot({
    signerKeyId: f.signerKeyId, privateKey: f.keys.privateKey, scope: f.scope,
    sequence: 3, previousRoot: secondBody.root,
    entries: [first, secondVersion, otherObject].sort(sameTuple), nonce: crypto.randomBytes(32),
  });

  const check = async (serialized, requested, floor, prior) => {
    const body = await decodedSnapshot(serialized);
    return inventory.verifySnapshot({
      serialized,
      pinnedPublicKey: f.keys.publicKey,
      pinnedSignerKeyId: f.signerKeyId,
      expectedScope: f.scope,
      requested,
      minimumHead: floor,
      minimumSnapshot: prior,
      nonce: Buffer.from(body.nonce),
    });
  };
  assert.equal((await check(secondSnapshot, requestFor(first), floorOf(firstBody), firstSnapshot)).outcome,
    "PRESENT", "old versions remain in a complete snapshot");
  assert.equal((await check(thirdSnapshot, requestFor(otherObject), floorOf(secondBody), secondSnapshot)).outcome,
    "PRESENT");
  const absent = requestFor(makeTuple(Buffer.alloc(16, 3), 1, 1));
  assert.equal((await check(thirdSnapshot, absent, floorOf(secondBody), secondSnapshot)).outcome, "ABSENT");
});

test("snapshot signing rejects duplicate object revisions and non-chronological ordering", async () => {
  const f = await testFixture();
  const id = Buffer.alloc(16, 4);
  const one = makeTuple(id, 1, 1);
  const two = makeTuple(id, 2, 2);
  await assert.rejects(inventory.createSignedSnapshot({
    signerKeyId: f.signerKeyId, privateKey: f.keys.privateKey, scope: f.scope,
    sequence: 1, previousRoot: crypto.randomBytes(32), entries: [two, one], nonce: crypto.randomBytes(32),
  }), /INVENTORY_ORDER/);
  await assert.rejects(inventory.createSignedSnapshot({
    signerKeyId: f.signerKeyId, privateKey: f.keys.privateKey, scope: f.scope,
    sequence: 1, previousRoot: crypto.randomBytes(32), entries: [one, makeTuple(id, 1, 2)],
    nonce: crypto.randomBytes(32),
  }), /INVENTORY_DUPLICATE/);
});

test("snapshot signing rejects incomplete sequence counts and revision gaps", async () => {
  const f = await testFixture();
  const objectId = Buffer.alloc(16, 5);
  const one = makeTuple(objectId, 1, 1);
  await assert.rejects(inventory.createSignedSnapshot({
    signerKeyId: f.signerKeyId, privateKey: f.keys.privateKey, scope: f.scope,
    sequence: 1, previousRoot: crypto.randomBytes(32), entries: [], nonce: crypto.randomBytes(32),
  }), /INVENTORY_SEQUENCE/);
  await assert.rejects(inventory.createSignedSnapshot({
    signerKeyId: f.signerKeyId, privateKey: f.keys.privateKey, scope: f.scope,
    sequence: 2, previousRoot: crypto.randomBytes(32),
    entries: [one, makeTuple(objectId, 3, 2)], nonce: crypto.randomBytes(32),
  }), /INVENTORY_ORDER/);
  await assert.rejects(inventory.createSignedSnapshot({
    signerKeyId: f.signerKeyId, privateKey: f.keys.privateKey, scope: f.scope,
    sequence: 1, previousRoot: crypto.randomBytes(32),
    entries: [makeTuple(Buffer.alloc(16, 6), 1, 0)], nonce: crypto.randomBytes(32),
  }), /INVENTORY_INTEGER/);
});

test("validly signed duplicate or reordered rows are rejected before requested-item lookup", async () => {
  const f = await testFixture();
  const head = await signedGenesis(f);
  const genesisBody = await decodedSnapshot(head);
  const a1 = makeTuple(Buffer.alloc(16, 1), 1, 1);
  const a2 = makeTuple(Buffer.alloc(16, 1), 2, 2);
  for (const entries of [[a2, a1], [a1, makeTuple(a1.object_id, 1, 3)]]) {
    const forged = await rawSignedSnapshot({
      scope: f.scope, signerKeyId: f.signerKeyId, privateKey: f.keys.privateKey,
      sequence: 1, previousRoot: genesisBody.root, entries, nonce: crypto.randomBytes(32),
    });
    const body = await decodedSnapshot(forged);
    await assert.rejects(inventory.verifySnapshot({
      serialized: forged, pinnedPublicKey: f.keys.publicKey, pinnedSignerKeyId: f.signerKeyId,
      expectedScope: f.scope, requested: requestFor(a1), minimumHead: floorOf(genesisBody),
      minimumSnapshot: head, nonce: Buffer.from(body.nonce),
    }), /INVENTORY_(ORDER|DUPLICATE)/);
  }
});

test("forged signature and altered tuple/root bytes fail closed", async () => {
  const f = await testFixture();
  const genesis = await signedGenesis(f);
  const body = await decodedSnapshot(genesis);
  const forgedBody = { ...body, signature: Buffer.from(body.signature) };
  forgedBody.signature[0] ^= 0x80;
  const forged = await z.encodeDeterministic(forgedBody);
  await assert.rejects(inventory.verifySnapshot({
    serialized: forged, pinnedPublicKey: f.keys.publicKey, pinnedSignerKeyId: f.signerKeyId,
    expectedScope: f.scope, requested: requestFor(makeTuple(crypto.randomBytes(16), 1, 1)),
    minimumHead: floorOf(body), nonce: Buffer.from(body.nonce),
  }), /INVENTORY_SIGNATURE/);

  const tuple = makeTuple(Buffer.alloc(16, 7), 1, 1);
  const populated = await inventory.createSignedSnapshot({
    signerKeyId: f.signerKeyId, privateKey: f.keys.privateKey, scope: f.scope,
    sequence: 1, previousRoot: body.root, entries: [tuple], nonce: crypto.randomBytes(32),
  });
  const populatedBody = await decodedSnapshot(populated);
  const altered = { ...populatedBody, entries: [
    { ...populatedBody.entries[0], ciphertext_sha256: crypto.randomBytes(32) },
  ] };
  await assert.rejects(inventory.verifySnapshot({
    serialized: await z.encodeDeterministic(altered), pinnedPublicKey: f.keys.publicKey,
    pinnedSignerKeyId: f.signerKeyId, expectedScope: f.scope, requested: requestFor(tuple),
    minimumHead: floorOf(body), minimumSnapshot: genesis, nonce: Buffer.from(populatedBody.nonce),
  }), /INVENTORY_ROOT/);
});

test("wrong pinned scope, key ID, or nonce cannot verify a signed snapshot", async () => {
  const f = await testFixture();
  const genesis = await signedGenesis(f);
  const body = await decodedSnapshot(genesis);
  const base = {
    serialized: genesis, pinnedPublicKey: f.keys.publicKey, pinnedSignerKeyId: f.signerKeyId,
    expectedScope: f.scope, requested: requestFor(makeTuple(crypto.randomBytes(16), 1, 1)),
    minimumHead: floorOf(body), nonce: Buffer.from(body.nonce),
  };
  await assert.rejects(inventory.verifySnapshot({ ...base,
    expectedScope: { ...f.scope, keyring_id: crypto.randomBytes(16) },
  }), /INVENTORY_SCOPE/);
  await assert.rejects(inventory.verifySnapshot({ ...base, pinnedSignerKeyId: crypto.randomBytes(16) }),
    /INVENTORY_SIGNER/);
  await assert.rejects(inventory.verifySnapshot({ ...base, nonce: crypto.randomBytes(32) }),
    /INVENTORY_NONCE/);
});

test("a replayed head, stale snapshot, incorrect floor, and unlinked future head are rejected", async () => {
  const f = await testFixture();
  const genesis = await signedGenesis(f);
  const genesisBody = await decodedSnapshot(genesis);
  const tuple = makeTuple(Buffer.alloc(16, 8), 1, 1);
  const current = await inventory.createSignedSnapshot({
    signerKeyId: f.signerKeyId, privateKey: f.keys.privateKey, scope: f.scope,
    sequence: 1, previousRoot: genesisBody.root, entries: [tuple], nonce: crypto.randomBytes(32),
  });
  const body = await decodedSnapshot(current);
  const args = {
    serialized: current, pinnedPublicKey: f.keys.publicKey, pinnedSignerKeyId: f.signerKeyId,
    expectedScope: f.scope, requested: requestFor(tuple), nonce: Buffer.from(body.nonce),
  };
  await assert.rejects(inventory.verifySnapshot({ ...args, minimumHead: floorOf(body),
    minimumSnapshot: genesis, nonce: crypto.randomBytes(32),
  }), /INVENTORY_NONCE/);
  await assert.rejects(inventory.verifySnapshot({ ...args, serialized: genesis,
    minimumHead: floorOf(body), minimumSnapshot: genesis, nonce: Buffer.from(genesisBody.nonce),
  }), /INVENTORY_STALE/);
  await assert.rejects(inventory.verifySnapshot({ ...args,
    minimumHead: { sequence: 1, root: crypto.randomBytes(32) }, minimumSnapshot: genesis,
  }), /INVENTORY_FLOOR/);
  await assert.rejects(inventory.verifySnapshot({ ...args,
    minimumHead: { sequence: 2, root: crypto.randomBytes(32) }, minimumSnapshot: current,
  }), /INVENTORY_STALE/);

  const jump = await inventory.createSignedSnapshot({
    signerKeyId: f.signerKeyId, privateKey: f.keys.privateKey, scope: f.scope,
    sequence: 2, previousRoot: body.root, entries: [tuple, makeTuple(Buffer.alloc(16, 9), 1, 1)],
    nonce: crypto.randomBytes(32),
  });
  const jumpBody = await decodedSnapshot(jump);
  await assert.rejects(inventory.verifySnapshot({
    ...args, serialized: jump, nonce: Buffer.from(jumpBody.nonce), minimumHead: floorOf(genesisBody),
    minimumSnapshot: genesis,
  }), /INVENTORY_FLOOR_GAP/);
});

test("the caller's previous complete floor catches a signed omission after prior inclusion", async () => {
  const f = await testFixture();
  const genesis = await signedGenesis(f);
  const genesisBody = await decodedSnapshot(genesis);
  const formerlyPresent = makeTuple(Buffer.alloc(16, 10), 1, 1);
  const present = await inventory.createSignedSnapshot({
    signerKeyId: f.signerKeyId, privateKey: f.keys.privateKey, scope: f.scope,
    sequence: 1, previousRoot: genesisBody.root, entries: [formerlyPresent], nonce: crypto.randomBytes(32),
  });
  const presentBody = await decodedSnapshot(present);
  const unrelated = [
    makeTuple(Buffer.alloc(16, 11), 1, 1),
    makeTuple(Buffer.alloc(16, 12), 1, 1),
  ];
  const omission = await rawSignedSnapshot({
    scope: f.scope, signerKeyId: f.signerKeyId, privateKey: f.keys.privateKey,
    sequence: 2, previousRoot: presentBody.root, entries: unrelated, nonce: crypto.randomBytes(32),
  });
  const omissionBody = await decodedSnapshot(omission);
  await assert.rejects(inventory.verifySnapshot({
    serialized: omission, pinnedPublicKey: f.keys.publicKey, pinnedSignerKeyId: f.signerKeyId,
    expectedScope: f.scope, requested: requestFor(formerlyPresent),
    minimumHead: floorOf(presentBody), minimumSnapshot: present,
    nonce: Buffer.from(omissionBody.nonce),
  }), /INVENTORY_REMOVED/);
});

test("an advanced PRESENT cannot advance the floor across an unproven omission", async () => {
  const f = await testFixture();
  const genesis = await signedGenesis(f);
  const genesisBody = await decodedSnapshot(genesis);
  const formerlyPresent = makeTuple(Buffer.alloc(16, 20), 1, 1);
  const first = await inventory.createSignedSnapshot({
    signerKeyId: f.signerKeyId, privateKey: f.keys.privateKey, scope: f.scope,
    sequence: 1, previousRoot: genesisBody.root, entries: [formerlyPresent], nonce: crypto.randomBytes(32),
  });
  const firstBody = await decodedSnapshot(first);
  const survivors = [
    makeTuple(Buffer.alloc(16, 21), 1, 1),
    makeTuple(Buffer.alloc(16, 22), 1, 1),
  ];
  const omitted = await rawSignedSnapshot({
    scope: f.scope, signerKeyId: f.signerKeyId, privateKey: f.keys.privateKey,
    sequence: 2, previousRoot: firstBody.root, entries: survivors, nonce: crypto.randomBytes(32),
  });
  const omittedBody = await decodedSnapshot(omitted);
  const verifierInput = {
    pinnedPublicKey: f.keys.publicKey, pinnedSignerKeyId: f.signerKeyId,
    expectedScope: f.scope, minimumHead: floorOf(firstBody),
    nonce: Buffer.from(omittedBody.nonce),
  };
  await assert.rejects(inventory.verifySnapshot({
    ...verifierInput, serialized: omitted, requested: requestFor(survivors[0]),
  }), /INVENTORY_HISTORY_REQUIRED/);

  const later = await inventory.createSignedSnapshot({
    signerKeyId: f.signerKeyId, privateKey: f.keys.privateKey, scope: f.scope,
    sequence: 3, previousRoot: omittedBody.root,
    entries: [...survivors, makeTuple(Buffer.alloc(16, 23), 1, 1)], nonce: crypto.randomBytes(32),
  });
  const laterBody = await decodedSnapshot(later);
  await assert.rejects(inventory.verifySnapshot({
    ...verifierInput, serialized: later, requested: requestFor(formerlyPresent),
    nonce: Buffer.from(laterBody.nonce), minimumSnapshot: first,
  }), /INVENTORY_FLOOR_GAP/);
});

test("absence on an advanced floor needs the prior full snapshot, not only its hash", async () => {
  const f = await testFixture();
  const genesis = await signedGenesis(f);
  const genesisBody = await decodedSnapshot(genesis);
  const survivor = makeTuple(Buffer.alloc(16, 13), 1, 1);
  const current = await inventory.createSignedSnapshot({
    signerKeyId: f.signerKeyId, privateKey: f.keys.privateKey, scope: f.scope,
    sequence: 1, previousRoot: genesisBody.root, entries: [survivor], nonce: crypto.randomBytes(32),
  });
  const currentBody = await decodedSnapshot(current);
  await assert.rejects(inventory.verifySnapshot({
    serialized: current, pinnedPublicKey: f.keys.publicKey, pinnedSignerKeyId: f.signerKeyId,
    expectedScope: f.scope, requested: requestFor(makeTuple(crypto.randomBytes(16), 1, 1)),
    minimumHead: floorOf(genesisBody), nonce: Buffer.from(currentBody.nonce),
  }), /INVENTORY_HISTORY_REQUIRED/);
});

test("oversized snapshots and tuple buffers are rejected before copying", async () => {
  const f = await testFixture();
  const oversizedId = new Uint8Array(1024 * 1024);
  assert.throws(() => inventory.normalizeEntry({
    object_id: oversizedId, revision: 1, epoch: 1, ciphertext_sha256: crypto.randomBytes(32),
  }), /INVENTORY_LIMIT/);
  const tooMany = Array.from({ length: inventory.MAX_ENTRIES + 1 }, (_, i) =>
    makeTuple(Buffer.from(i.toString(16).padStart(32, "0"), "hex"), 1, 1));
  await assert.rejects(inventory.createSignedSnapshot({
    signerKeyId: f.signerKeyId, privateKey: f.keys.privateKey, scope: f.scope,
    sequence: 1, previousRoot: crypto.randomBytes(32), entries: tooMany, nonce: crypto.randomBytes(32),
  }), /INVENTORY_LIMIT/);
  const oversizedSnapshot = new Uint8Array(inventory.MAX_SNAPSHOT_BYTES + 1);
  await assert.rejects(inventory.verifySnapshot({
    serialized: oversizedSnapshot, pinnedPublicKey: f.keys.publicKey, pinnedSignerKeyId: f.signerKeyId,
    expectedScope: f.scope, requested: requestFor(makeTuple(crypto.randomBytes(16), 1, 1)),
    minimumHead: { sequence: 0, root: Buffer.alloc(32) }, nonce: crypto.randomBytes(32),
  }), /INVENTORY_LIMIT/);
});

test("durable ledger requires explicit bootstrap and signs an empty complete inventory", async (t) => {
  const f = await testFixture(t);
  await assert.rejects(Zk1DurableContentInventoryLedger.open(f.filename, {
    ...f.options, bootstrapNew: false,
  }), /INVENTORY_BOOTSTRAP_REQUIRED/);
  assert.equal(fs.existsSync(f.filename), false);
  const ledger = await f.openNew();
  const snapshot = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  assert.equal(snapshot.status, "snapshot");
  assert.equal(snapshot.sequence, 0);
  const body = await decodedSnapshot(snapshot.bytes);
  assert.deepEqual(body.entries, []);
  const queried = await ledger.query({
    nonce: crypto.randomBytes(32),
    requested: requestFor(makeTuple(crypto.randomBytes(16), 1, 1)),
    minimumHead: floorOf(body),
    pinnedPublicKey: f.keys.publicKey,
    pinnedSignerKeyId: f.signerKeyId,
  });
  assert.equal(queried.status, "VERIFIED_NONAUTHORIZING");
  assert.equal(queried.outcome, "ABSENT");
  f.close(ledger);
  await assert.rejects(f.openNew(), /INVENTORY_BOOTSTRAP_NEW_ONLY/);
  const reopened = await f.open();
  assert.equal((await reopened.getSnapshot({ nonce: crypto.randomBytes(32) })).status, "snapshot");
});

test("append preserves sorted complete membership, retry identity, and restart continuity", async (t) => {
  const f = await testFixture(t);
  let ledger = await f.openNew();
  const genesis = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const genesisBody = await decodedSnapshot(genesis.bytes);
  const first = makeTuple(Buffer.alloc(16, 1), 1, 1);
  const append = (tuple, operationId, expectedSequence, expectedRoot) => ledger.append({
    operation_id: operationId,
    expected_sequence: expectedSequence,
    expected_root: expectedRoot,
    ...tuple,
  });
  const operation1 = crypto.randomBytes(16);
  const committed1 = await append(first, operation1, 0, genesisBody.root);
  assert.equal(committed1.status, "committed");
  const exactRetry = await append(first, operation1, 0, genesisBody.root);
  assert.deepEqual(exactRetry, { ...committed1, replay: true });
  await assert.rejects(append({ ...first, ciphertext_sha256: crypto.randomBytes(32) }, operation1,
    0, genesisBody.root), /INVENTORY_OPERATION_CONFLICT/);

  const version2 = makeTuple(first.object_id, 2, 2);
  const committed2 = await append(version2, crypto.randomBytes(16), 1, committed1.root);
  assert.equal(committed2.sequence, 2);
  const secondHead = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const other = makeTuple(Buffer.alloc(16, 2), 1, 1);
  const committed3 = await append(other, crypto.randomBytes(16), 2, committed2.root);
  assert.equal(committed3.sequence, 3);
  const latest = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const latestBody = await decodedSnapshot(latest.bytes);
  assert.deepEqual(latestBody.entries.map((entry) => `${entry.object_id[0]}:${entry.revision}`),
    ["1:1", "1:2", "2:1"]);
  const historic = await ledger.query({
    nonce: crypto.randomBytes(32), requested: requestFor(first),
    minimumHead: floorOf(await decodedSnapshot(secondHead.bytes)), minimumSnapshot: secondHead.bytes,
    pinnedPublicKey: f.keys.publicKey, pinnedSignerKeyId: f.signerKeyId,
  });
  assert.equal(historic.outcome, "PRESENT");
  f.close(ledger);
  ledger = await f.open();
  const afterRestart = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  assert.equal(afterRestart.sequence, 3);
  assert.deepEqual(afterRestart.root, committed3.root);
  await inventory.verifySnapshot({
    serialized: afterRestart.bytes, pinnedPublicKey: f.keys.publicKey,
    pinnedSignerKeyId: f.signerKeyId, expectedScope: f.scope,
    requested: requestFor(version2), minimumHead: floorOf(latestBody),
    minimumSnapshot: latest.bytes,
    nonce: Buffer.from((await decodedSnapshot(afterRestart.bytes)).nonce),
  });
});

test("an advanced signed snapshot distinguishes unrelated absence from prior inclusion", async (t) => {
  const f = await testFixture(t);
  const ledger = await f.openNew();
  const genesis = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const genesisBody = await decodedSnapshot(genesis.bytes);
  const tuple = makeTuple(Buffer.alloc(16, 11), 1, 1);
  await ledger.append({
    operation_id: crypto.randomBytes(16), expected_sequence: 0, expected_root: genesisBody.root, ...tuple,
  });
  const current = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const absent = await ledger.query({
    nonce: crypto.randomBytes(32), requested: requestFor(makeTuple(Buffer.alloc(16, 12), 1, 1)),
    minimumHead: floorOf(genesisBody), minimumSnapshot: genesis.bytes,
    pinnedPublicKey: f.keys.publicKey, pinnedSignerKeyId: f.signerKeyId,
  });
  assert.equal(absent.outcome, "ABSENT");
  const present = await ledger.query({
    nonce: crypto.randomBytes(32), requested: requestFor(tuple),
    minimumHead: floorOf(genesisBody), minimumSnapshot: genesis.bytes,
    pinnedPublicKey: f.keys.publicKey, pinnedSignerKeyId: f.signerKeyId,
  });
  assert.equal(present.outcome, "PRESENT");
  assert.equal(current.status, "snapshot");
});

test("two concurrent expected-root appends commit one, terminalize the loser, and keep reads available", async (t) => {
  const f = await testFixture(t);
  let ledger = await f.openNew();
  const genesis = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const head = await decodedSnapshot(genesis.bytes);
  const candidates = [1, 2].map((n) => ({
    operation_id: crypto.randomBytes(16), expected_sequence: 0, expected_root: head.root,
    ...makeTuple(Buffer.alloc(16, n), 1, 1),
  }));
  const settled = await Promise.allSettled(candidates.map((operation) => ledger.append(operation)));
  assert.equal(settled.filter((result) => result.status === "rejected").length, 0);
  const results = settled.map((result) => result.value);
  assert.equal(results.filter((entry) => entry.status === "committed").length, 1);
  assert.equal(results.filter((entry) => entry.status === "not_committed_final").length, 1);
  const loserIndex = results.findIndex((entry) => entry.status === "not_committed_final");
  const loserOperation = candidates[loserIndex];
  const loserResult = results[loserIndex];
  assert.equal(typeof inventory.verifyTerminalProof, "function");
  assert.equal((await ledger.getSnapshot({ nonce: crypto.randomBytes(32) })).status, "snapshot");
  assert.equal((await ledger.query({
    nonce: crypto.randomBytes(32), requested: requestFor(candidates[0]), minimumHead: floorOf(head),
    minimumSnapshot: genesis.bytes,
    pinnedPublicKey: f.keys.publicKey, pinnedSignerKeyId: f.signerKeyId,
  })).status, "VERIFIED_NONAUTHORIZING");
  const proof = await inventory.verifyTerminalProof({
    serialized: loserResult.proof, pinnedPublicKey: f.keys.publicKey,
    pinnedSignerKeyId: f.signerKeyId, expectedScope: f.scope, operation: loserOperation,
  });
  assert.equal(proof.outcome, "NOT_COMMITTED_FINAL");
  const loserStatus = await ledger.getOperationStatus(loserOperation.operation_id);
  assert.equal(loserStatus.status, "not_committed_final");
  assert.equal(loserStatus.reason, loserResult.reason);
  assert.deepEqual(loserStatus.proof, loserResult.proof);
  assert.deepEqual(await ledger.getOperationStatus(Buffer.alloc(16, 0xff)), { status: "unknown" });
  f.close(ledger);
  ledger = await f.open();
  const afterRestart = await ledger.getOperationStatus(loserOperation.operation_id);
  assert.equal(afterRestart.status, "not_committed_final");
  assert.deepEqual(afterRestart.proof, loserResult.proof);
  assert.deepEqual(await ledger.append(loserOperation), { ...loserResult, replay: true });
  await assert.rejects(ledger.append({
    ...loserOperation, ciphertext_sha256: crypto.randomBytes(32),
  }), /INVENTORY_OPERATION_CONFLICT/);
  assert.equal((await ledger.getSnapshot({ nonce: crypto.randomBytes(32) })).status, "snapshot");
});

test("concurrent exact retries share one verified signed commit before and after restart", async (t) => {
  const f = await testFixture(t);
  let ledger = await f.openNew();
  const genesis = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const head = await decodedSnapshot(genesis.bytes);
  const operation = {
    operation_id: crypto.randomBytes(16), expected_sequence: 0, expected_root: head.root,
    ...makeTuple(Buffer.alloc(16, 38), 1, 1),
  };
  const originalComputeRoot = inventory.computeRoot;
  const bothReady = deferred();
  const release = deferred();
  const gateTimeout = setTimeout(() => bothReady.resolve(), 10000);
  let arrivals = 0;
  inventory.computeRoot = async (...args) => {
    const root = await originalComputeRoot(...args);
    arrivals += 1;
    if (arrivals === 2) bothReady.resolve();
    await release.promise;
    return root;
  };
  let results;
  try {
    const concurrent = Promise.all([ledger.append(operation), ledger.append(operation)]);
    await bothReady.promise;
    assert.equal(arrivals, 2, "both exact retries must reach the same pre-commit head");
    release.resolve();
    results = await concurrent;
  } finally {
    clearTimeout(gateTimeout);
    release.resolve();
    inventory.computeRoot = originalComputeRoot;
  }

  assert.equal(results.length, 2);
  assert.ok(results.every((result) => result.status === "committed" && result.sequence === 1));
  assert.deepEqual(results.map((result) => result.replay).sort(), [false, true]);
  assert.deepEqual(results[0].root, results[1].root);

  const state = await ledger.loadState();
  const verified = state.operations.get(operation.operation_id.toString("hex"));
  const requestBytes = await z.encodeDeterministic(operationMapForTest(operation));
  const requestDigest = crypto.createHash("sha256").update(requestBytes).digest();
  assert.equal(state.sequence, 1);
  assert.equal(state.entries.length, 1);
  assert.deepEqual(state.root, results[0].root);
  assert.equal(verified.status, "committed");
  assert.equal(verified.sequence, 1);
  assert.deepEqual(verified.root, results[0].root);
  assert.deepEqual(verified.encoded, requestBytes);
  assert.deepEqual(verified.digest, requestDigest);

  f.close(ledger);
  ledger = await f.open();
  const afterRestart = await ledger.append(operation);
  assert.deepEqual(afterRestart, { ...results[0], replay: true });
  const restartedState = await ledger.loadState();
  assert.equal(restartedState.sequence, 1);
  assert.equal(restartedState.entries.length, 1);
  assert.deepEqual(restartedState.root, results[0].root);
  assert.deepEqual(restartedState.operations.get(operation.operation_id.toString("hex")).digest, requestDigest);
});

test("stale-head and invalid-chronology operations get durable signed final identities", async (t) => {
  const f = await testFixture(t);
  let ledger = await f.openNew();
  const genesis = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const head = await decodedSnapshot(genesis.bytes);
  const stale = {
    operation_id: crypto.randomBytes(16), expected_sequence: 0, expected_root: crypto.randomBytes(32),
    ...makeTuple(Buffer.alloc(16, 24), 1, 1),
  };
  const staleResult = await ledger.append(stale);
  assert.equal(staleResult.status, "not_committed_final");
  assert.equal(staleResult.reason, "EXPECTED_HEAD_CHANGED");
  assert.equal((await inventory.verifyTerminalProof({
    serialized: staleResult.proof, pinnedPublicKey: f.keys.publicKey,
    pinnedSignerKeyId: f.signerKeyId, expectedScope: f.scope, operation: stale,
  })).outcome, "NOT_COMMITTED_FINAL");

  const invalid = {
    operation_id: crypto.randomBytes(16), expected_sequence: 0, expected_root: head.root,
    ...makeTuple(Buffer.alloc(16, 25), 2, 1),
  };
  const invalidResult = await ledger.append(invalid);
  assert.equal(invalidResult.status, "not_committed_final");
  assert.equal(invalidResult.reason, "INVALID_CHRONOLOGY");
  assert.equal((await ledger.getSnapshot({ nonce: crypto.randomBytes(32) })).status, "snapshot");
  const state = await ledger.getOperationStatus(stale.operation_id);
  assert.equal(state.status, "not_committed_final");
  assert.equal(state.reason, staleResult.reason);
  assert.deepEqual(state.proof, staleResult.proof);
  f.close(ledger);
  ledger = await f.open();
  assert.deepEqual(await ledger.append(stale), { ...staleResult, replay: true });
  await assert.rejects(ledger.append({
    ...stale, ciphertext_sha256: crypto.randomBytes(32),
  }), /INVENTORY_OPERATION_CONFLICT/);
});

test("durable intent survives restart without authorizing a snapshot and identical retry can seal it", async (t) => {
  const f = await testFixture(t);
  let ledger = await f.openNew();
  const genesis = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const head = await decodedSnapshot(genesis.bytes);
  const operation = {
    operation_id: crypto.randomBytes(16), expected_sequence: 0, expected_root: head.root,
    ...makeTuple(Buffer.alloc(16, 13), 1, 1),
  };
  assert.equal((await ledger.prepareAppend(operation)).status, "pending");
  const blocked = {
    operation_id: crypto.randomBytes(16), expected_sequence: 0, expected_root: head.root,
    ...makeTuple(Buffer.alloc(16, 26), 1, 1),
  };
  const blockedResult = await ledger.append(blocked);
  assert.equal(blockedResult.status, "not_committed_final");
  assert.equal(blockedResult.reason, "UNRESOLVED_PENDING");
  assert.equal(typeof inventory.verifyTerminalProof, "function");
  assert.equal((await inventory.verifyTerminalProof({
    serialized: blockedResult.proof, pinnedPublicKey: f.keys.publicKey,
    pinnedSignerKeyId: f.signerKeyId, expectedScope: f.scope, operation: blocked,
  })).outcome, "NOT_COMMITTED_FINAL");
  assert.deepEqual(await ledger.getOperationStatus(operation.operation_id), { status: "pending" });
  f.close(ledger);
  ledger = await f.open();
  assert.deepEqual(await ledger.getOperationStatus(operation.operation_id), { status: "pending" });
  assert.equal((await ledger.getSnapshot({ nonce: crypto.randomBytes(32) })).status, "pending");
  assert.deepEqual(await ledger.prepareAppend(operation), { status: "pending", replay: true });
  const sealed = await ledger.append(operation);
  assert.equal(sealed.status, "committed");
  assert.equal(sealed.sequence, 1);
  assert.equal((await ledger.getSnapshot({ nonce: crypto.randomBytes(32) })).status, "snapshot");
  assert.equal((await ledger.getOperationStatus(blocked.operation_id)).status, "not_committed_final");
});

test("wrong signer key ID, key material, and scope cannot reopen a durable ledger", async (t) => {
  const f = await testFixture(t);
  const ledger = await f.openNew();
  f.close(ledger);
  await assert.rejects(f.open({ signerKeyId: crypto.randomBytes(16) }), /INVENTORY_IDENTITY/);
  const otherKeys = crypto.generateKeyPairSync("ed25519");
  await assert.rejects(f.open({ signerPrivateKey: otherKeys.privateKey }), /INVENTORY_IDENTITY/);
  await assert.rejects(f.open({ scope: { ...f.scope, keyring_id: crypto.randomBytes(16) } }),
    /INVENTORY_SCOPE/);
});

test("malformed and unknown pre-existing SQLite files are refused without rewriting them", async (t) => {
  const f = await testFixture(t);
  const malformed = Buffer.from("not-a-sqlite-database");
  fs.writeFileSync(f.filename, malformed);
  await assert.rejects(f.openNew(), /INVENTORY_BOOTSTRAP_NEW_ONLY/);
  assert.deepEqual(fs.readFileSync(f.filename), malformed);
  fs.rmSync(f.filename);

  const unknown = new Database(f.filename);
  unknown.exec("CREATE TABLE foreign_state (secret BLOB)");
  unknown.close();
  const before = fs.readFileSync(f.filename);
  await assert.rejects(f.openNew(), /INVENTORY_BOOTSTRAP_NEW_ONLY/);
  assert.deepEqual(fs.readFileSync(f.filename), before);
});

test("committed log tampering and deleted history fail closed after restart", async (t) => {
  const f = await testFixture(t);
  const ledger = await f.openNew();
  const genesis = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const head = await decodedSnapshot(genesis.bytes);
  await ledger.append({
    operation_id: crypto.randomBytes(16), expected_sequence: 0, expected_root: head.root,
    ...makeTuple(Buffer.alloc(16, 14), 1, 1),
  });
  f.close(ledger);
  const tamper = new Database(f.filename);
  assert.throws(() => tamper.prepare("UPDATE content_entry SET ciphertext_sha256=? WHERE sequence=1")
    .run(crypto.randomBytes(32)), /immutable content entry/);
  tamper.exec("DROP TRIGGER content_entry_no_update");
  tamper.prepare("UPDATE content_entry SET ciphertext_sha256=? WHERE sequence=1")
    .run(crypto.randomBytes(32));
  tamper.exec(`CREATE TRIGGER content_entry_no_update BEFORE UPDATE ON content_entry
    BEGIN SELECT RAISE(ABORT, 'immutable content entry'); END`);
  tamper.close();
  await assert.rejects(f.open(), /INVENTORY_(LEDGER|SIGNATURE|ROOT|STATE)/);
});

test("local independent signer does not claim cross-host or production authorization", async (t) => {
  const f = await testFixture(t);
  const ledger = await f.openNew();
  const genesis = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const body = await decodedSnapshot(genesis.bytes);
  const verified = await inventory.verifySnapshot({
    serialized: genesis.bytes, pinnedPublicKey: f.keys.publicKey, pinnedSignerKeyId: f.signerKeyId,
    expectedScope: f.scope, requested: requestFor(makeTuple(crypto.randomBytes(16), 1, 1)),
    minimumHead: floorOf(body), nonce: Buffer.from(body.nonce),
  });
  assert.deepEqual(verified.status, "VERIFIED_NONAUTHORIZING");
  assert.equal(Object.hasOwn(ledger, "independently_operated"), false);
  assert.equal(Object.hasOwn(verified, "production_go"), false);
});

test("loadState keeps one SQLite snapshot while an independent handle commits an append", async (t) => {
  const f = await testFixture(t);
  const ledger = await f.openNew();
  const genesis = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const head = await decodedSnapshot(genesis.bytes);
  const operation = {
    operation_id: crypto.randomBytes(16), expected_sequence: 0, expected_root: head.root,
    ...makeTuple(Buffer.alloc(16, 31), 1, 1),
  };
  assert.equal((await ledger.prepareAppend(operation)).status, "pending");
  const signed = await signedPendingCommitForTest(f, operation);
  const writer = new Database(f.filename);
  const commit = writer.transaction(() => {
    writer.prepare(`INSERT INTO content_entry
      (sequence,operation_id,object_id,revision,epoch,ciphertext_sha256,expected_sequence,
       expected_root,previous_root,root,request_digest,signature)
      VALUES(1,?,?,?,?,?,?,?,?,?,?,?)`).run(
      operation.operation_id, signed.entry.object_id, signed.entry.revision, signed.entry.epoch,
      signed.entry.ciphertext_sha256, operation.expected_sequence, operation.expected_root,
      operation.expected_root, signed.root, signed.requestDigest, signed.signature,
    );
    writer.prepare("UPDATE content_head SET sequence=1,root=? WHERE id=1").run(signed.root);
    writer.prepare(`UPDATE content_operation SET status='committed',sequence=1,root=?
      WHERE operation_id=?`).run(signed.root, operation.operation_id);
  });
  const originalPrepare = ledger.db.prepare.bind(ledger.db);
  let committedBetweenReads = false;
  ledger.db.prepare = (sql) => {
    if (!committedBetweenReads && /FROM content_entry\b/.test(sql) && /ORDER BY sequence/.test(sql)) {
      committedBetweenReads = true;
      commit.immediate();
    }
    return originalPrepare(sql);
  };
  let captured;
  try {
    captured = await ledger.loadState();
  } finally {
    ledger.db.prepare = originalPrepare;
    writer.close();
  }
  assert.equal(committedBetweenReads, true);
  assert.equal(captured.sequence, 0);
  assert.equal(captured.pending.length, 1);
  const afterCommit = await ledger.loadState();
  assert.equal(afterCommit.sequence, 1);
  assert.equal(afterCommit.pending.length, 0);
  assert.deepEqual(afterCommit.root, signed.root);
});

test("oversized identity scope is rejected before identity row materialization", async (t) => {
  const f = await testFixture(t);
  const ledger = await f.openNew();
  const tamper = new Database(f.filename);
  try {
    tamper.exec("DROP TRIGGER content_identity_no_update");
    tamper.prepare("UPDATE content_identity SET scope_cbor=? WHERE id=1")
      .run(Buffer.alloc(1024 * 1024));
    tamper.exec(`CREATE TRIGGER content_identity_no_update BEFORE UPDATE ON content_identity
      BEGIN SELECT RAISE(ABORT, 'immutable content identity'); END`);
  } finally { tamper.close(); }
  const reads = trackMaterializingReads(ledger, (sql) =>
    /FROM content_identity\b/.test(sql) && !/COUNT\s*\(/i.test(sql));
  try {
    await assert.rejects(ledger.loadState(), /INVENTORY_(LEDGER_CORRUPT|SCOPE)/);
    assert.equal(reads.calls(), 0);
  } finally { reads.restore(); }
});

test("oversized operation record is rejected before operation rows are materialized", async (t) => {
  const f = await testFixture(t);
  const ledger = await f.openNew();
  const genesis = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const head = await decodedSnapshot(genesis.bytes);
  const operation = {
    operation_id: crypto.randomBytes(16), expected_sequence: 0, expected_root: head.root,
    ...makeTuple(Buffer.alloc(16, 38), 1, 1),
  };
  await ledger.prepareAppend(operation);
  const tamper = new Database(f.filename);
  try {
    tamper.exec("DROP TRIGGER content_operation_committed_no_update");
    tamper.prepare("UPDATE content_operation SET request_cbor=zeroblob(?) WHERE operation_id=?")
      .run(1025, operation.operation_id);
    tamper.exec(`CREATE TRIGGER content_operation_committed_no_update BEFORE UPDATE ON content_operation
      WHEN OLD.status='committed' OR NEW.status<>'committed'
        OR NEW.operation_id IS NOT OLD.operation_id OR NEW.request_cbor IS NOT OLD.request_cbor
        OR NEW.expected_sequence IS NOT OLD.expected_sequence OR NEW.expected_root IS NOT OLD.expected_root
      BEGIN SELECT RAISE(ABORT, 'immutable committed content operation'); END`);
  } finally { tamper.close(); }
  const reads = trackMaterializingReads(ledger, (sql) =>
    /FROM content_operation\b/.test(sql) && !/COUNT\s*\(/i.test(sql));
  try {
    await assert.rejects(ledger.loadState(), /INVENTORY_LEDGER_CORRUPT/);
    assert.equal(reads.calls(), 0);
  } finally { reads.restore(); }
});

test("entry count over the signed inventory cap is rejected before entry rows are materialized", async (t) => {
  const f = await testFixture(t);
  const ledger = await f.openNew();
  const tamper = new Database(f.filename);
  try {
    const addRows = tamper.transaction(() => {
      const insertOperation = tamper.prepare(`INSERT INTO content_operation
        (operation_id,request_cbor,expected_sequence,expected_root,status,sequence,root)
        VALUES(?,?,?,?,'committed',?,?)`);
      const insertEntry = tamper.prepare(`INSERT INTO content_entry
        (sequence,operation_id,object_id,revision,epoch,ciphertext_sha256,expected_sequence,
         expected_root,previous_root,root,request_digest,signature)
        VALUES(?,?,?,1,0,?,?,?, ?,?,?,?)`);
      const zeroRoot = Buffer.alloc(32);
      for (let sequence = 1; sequence <= inventory.MAX_ENTRIES + 1; sequence += 1) {
        const id = Buffer.alloc(16);
        id.writeUInt32BE(sequence, 12);
        const objectId = Buffer.alloc(16);
        objectId.writeUInt32BE(sequence, 12);
        insertOperation.run(id, Buffer.from([0]), sequence - 1, zeroRoot, sequence, zeroRoot);
        insertEntry.run(sequence, id, objectId, zeroRoot, sequence - 1, zeroRoot,
          zeroRoot, zeroRoot, zeroRoot, Buffer.alloc(64));
      }
    });
    addRows.immediate();
  } finally { tamper.close(); }
  const reads = trackMaterializingReads(ledger, (sql) =>
    /FROM content_entry\b/.test(sql) && !/COUNT\s*\(/i.test(sql));
  try {
    await assert.rejects(ledger.loadState(), /INVENTORY_LEDGER_CORRUPT/);
    assert.equal(reads.calls(), 0);
  } finally { reads.restore(); }
});

test("oversized signed proof is rejected before terminal rows are materialized", async (t) => {
  const f = await testFixture(t);
  const ledger = await f.openNew();
  await ledger.append({
    operation_id: crypto.randomBytes(16), expected_sequence: 0, expected_root: crypto.randomBytes(32),
    ...makeTuple(Buffer.alloc(16, 32), 1, 1),
  });
  const tamper = new Database(f.filename);
  try {
    tamper.exec("DROP TRIGGER content_terminal_no_update");
    tamper.prepare("UPDATE content_terminal_operation SET proof_cbor=zeroblob(?)")
      .run(inventory.MAX_TERMINAL_PROOF_BYTES + 1);
    tamper.exec(`CREATE TRIGGER content_terminal_no_update BEFORE UPDATE ON content_terminal_operation
      BEGIN SELECT RAISE(ABORT, 'immutable terminal content operation'); END`);
  } finally { tamper.close(); }
  const reads = trackMaterializingReads(ledger, (sql) =>
    /FROM content_terminal_operation\b/.test(sql) && !/COUNT\s*\(/i.test(sql));
  try {
    await assert.rejects(ledger.loadState(), /INVENTORY_LEDGER_CORRUPT/);
    assert.equal(reads.calls(), 0);
  } finally { reads.restore(); }
});

test("excess pending count fails before operation rows are materialized", async (t) => {
  const f = await testFixture(t);
  const ledger = await f.openNew();
  const genesis = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const head = await decodedSnapshot(genesis.bytes);
  const first = {
    operation_id: crypto.randomBytes(16), expected_sequence: 0, expected_root: head.root,
    ...makeTuple(Buffer.alloc(16, 33), 1, 1),
  };
  const second = {
    operation_id: crypto.randomBytes(16), expected_sequence: 0, expected_root: head.root,
    ...makeTuple(Buffer.alloc(16, 34), 1, 1),
  };
  await ledger.prepareAppend(first);
  const tamper = new Database(f.filename);
  try {
    const insert = tamper.prepare(`INSERT INTO content_operation
      (operation_id,request_cbor,expected_sequence,expected_root,status,sequence,root)
      VALUES(?,?,?,?,'pending',NULL,NULL)`);
    insert.run(second.operation_id, await z.encodeDeterministic(operationMapForTest(second)),
      second.expected_sequence, second.expected_root);
  } finally { tamper.close(); }
  const operationReads = trackMaterializingReads(ledger, (sql) =>
    /FROM content_operation\b/.test(sql) && !/COUNT\s*\(/i.test(sql));
  try {
    await assert.rejects(ledger.loadState(), /INVENTORY_LEDGER_CORRUPT/);
    assert.equal(operationReads.calls(), 0);
  } finally { operationReads.restore(); }
});

test("excess terminal count fails before terminal rows are materialized", async (t) => {
  const f = await testFixture(t);
  const ledger = await f.openNew();
  const tamper = new Database(f.filename);
  try {
    const addTerminals = tamper.transaction(() => {
      const insertTerminal = tamper.prepare(`INSERT INTO content_terminal_operation
        (operation_id,request_cbor,proof_cbor) VALUES(?,?,?)`);
      for (let index = 0; index <= inventory.MAX_ENTRIES; index += 1) {
        const id = Buffer.alloc(16);
        id.writeUInt32BE(index + 1, 12);
        insertTerminal.run(id, Buffer.from([0]), Buffer.from([0]));
      }
    });
    addTerminals.immediate();
  } finally { tamper.close(); }
  const terminalReads = trackMaterializingReads(ledger, (sql) =>
    /FROM content_terminal_operation\b/.test(sql) && !/COUNT\s*\(/i.test(sql));
  try {
    await assert.rejects(ledger.loadState(), /INVENTORY_LEDGER_CORRUPT/);
    assert.equal(terminalReads.calls(), 0);
  } finally { terminalReads.restore(); }
});

test("snapshot signing fails closed if a pending append appears before signing completes", async (t) => {
  const f = await testFixture(t);
  const ledger = await f.openNew();
  const genesis = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const head = await decodedSnapshot(genesis.bytes);
  const operation = {
    operation_id: crypto.randomBytes(16), expected_sequence: 0, expected_root: head.root,
    ...makeTuple(Buffer.alloc(16, 35), 1, 1),
  };
  const original = inventory.createSignedSnapshot;
  const started = deferred();
  const release = deferred();
  inventory.createSignedSnapshot = async (...args) => {
    started.resolve();
    await release.promise;
    return original(...args);
  };
  try {
    const snapshot = ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
    await started.promise;
    assert.equal((await ledger.prepareAppend(operation)).status, "pending");
    release.resolve();
    await assert.rejects(snapshot, /INVENTORY_STATE_CHANGED/);
  } finally {
    release.resolve();
    inventory.createSignedSnapshot = original;
  }
});

test("snapshot signing fails closed if the committed head changes before signing completes", async (t) => {
  const f = await testFixture(t);
  const ledger = await f.openNew();
  const genesis = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const head = await decodedSnapshot(genesis.bytes);
  const operation = {
    operation_id: crypto.randomBytes(16), expected_sequence: 0, expected_root: head.root,
    ...makeTuple(Buffer.alloc(16, 36), 1, 1),
  };
  const original = inventory.createSignedSnapshot;
  const started = deferred();
  const release = deferred();
  inventory.createSignedSnapshot = async (...args) => {
    started.resolve();
    await release.promise;
    return original(...args);
  };
  try {
    const snapshot = ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
    await started.promise;
    const committed = await ledger.append(operation);
    assert.equal(committed.status, "committed");
    release.resolve();
    await assert.rejects(snapshot, /INVENTORY_STATE_CHANGED/);
  } finally {
    release.resolve();
    inventory.createSignedSnapshot = original;
  }
});

test("sealAppend does not accept a raw committed row absent from its verified read", async (t) => {
  const f = await testFixture(t);
  const ledger = await f.openNew();
  const genesis = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const head = await decodedSnapshot(genesis.bytes);
  const operation = {
    operation_id: crypto.randomBytes(16), expected_sequence: 0, expected_root: head.root,
    ...makeTuple(Buffer.alloc(16, 37), 1, 1),
  };
  await ledger.prepareAppend(operation);
  const originalDecode = z.decodeDeterministic;
  const started = deferred();
  const release = deferred();
  let paused = false;
  z.decodeDeterministic = async (...args) => {
    if (!paused) {
      paused = true;
      started.resolve();
      await release.promise;
    }
    return originalDecode(...args);
  };
  const tamper = new Database(f.filename);
  try {
    const sealing = ledger.sealAppend(operation.operation_id);
    await started.promise;
    tamper.prepare(`UPDATE content_operation SET status='committed',sequence=1,root=?
      WHERE operation_id=?`).run(Buffer.alloc(32, 0xa5), operation.operation_id);
    release.resolve();
    await assert.rejects(sealing, /INVENTORY_LEDGER_CORRUPT/);
  } finally {
    release.resolve();
    z.decodeDeterministic = originalDecode;
    tamper.close();
  }
});
test("committed inventory receipts bind the exact operation ID and signed version tuple", async (t) => {
  const f = await testFixture(t);
  const ledger = await f.openNew();
  const genesis = await ledger.readLocalHead();
  const operation = {
    operation_id: crypto.randomBytes(16),
    expected_sequence: 0, expected_root: genesis.root,
    ...makeTuple(Buffer.alloc(16, 0x53), 1, 1),
  };
  const commit = await ledger.append(operation);
  assert.equal(commit.status, "committed");
  const receipt = await ledger.getOperationStatus(operation.operation_id);
  assert.equal(receipt.status, "committed");
  assert.ok(Buffer.isBuffer(receipt.proof));
  const input = {
    serialized: receipt.proof, pinnedPublicKey: f.keys.publicKey,
    pinnedSignerKeyId: f.signerKeyId, expectedScope: f.scope,
    operation,
  };
  const verified = await inventory.verifyCommittedEntryProof(input);
  assert.equal(verified.outcome, "COMMITTED_IN_SIGNED_LEDGER");
  assert.equal(verified.authorizesIo, false);
  assert.deepEqual(verified.root, commit.root);
  await assert.rejects(inventory.verifyCommittedEntryProof({
    ...input, operation: { ...operation, operation_id: crypto.randomBytes(16) },
  }));
  await assert.rejects(inventory.verifyCommittedEntryProof({
    ...input, operation: { ...operation, ciphertext_sha256: crypto.randomBytes(32) },
  }));
  const tampered = Buffer.from(receipt.proof);
  tampered[tampered.length - 1] ^= 1;
  await assert.rejects(inventory.verifyCommittedEntryProof({ ...input, serialized: tampered }));
  f.close(ledger);
  const reopened = await f.open();
  const again = await reopened.getOperationStatus(operation.operation_id);
  assert.deepEqual(again.proof, receipt.proof);
  assert.deepEqual((await inventory.verifyCommittedEntryProof({ ...input, serialized: again.proof })).root,
    commit.root);
});
