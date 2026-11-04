"use strict";

// TEST_UNRUN while the exclusive Windows Node22 gate remains closed.
// Real Ed25519 authorization must bind the protocol operation to the exact
// physical WebDAV event and payload before the durable direct journal write.
// This is a narrowly mocked auth/payload BOUNDARY unit suite, NOT a durable
// local journal or HTTP integration proof. Real fsync-backed E2E is covered
// separately by the signed-http-durable and signed-receipt-rollback suites.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");

const PUT_BYTES = Buffer.from("signed WebDAV bytes");

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function putEvent(label, bytes = PUT_BYTES) {
  const pathname = `/${label}.txt`;
  return {
    journalType: "webdav-mutation",
    kind: "put",
    operationId: `event-${label}`,
    path: pathname,
    source: pathname,
    destination: pathname,
    existed: false,
    putBytes: bytes.length,
    putSha256: sha256(bytes),
  };
}

function moveEvent(label) {
  return {
    journalType: "webdav-mutation",
    kind: "move",
    operationId: `event-${label}`,
    source: `/${label}-source.txt`,
    destination: `/${label}-destination.txt`,
  };
}

function deleteEvent(label) {
  return {
    journalType: "webdav-mutation",
    kind: "delete",
    operationId: `event-${label}`,
    source: `/${label}.txt`,
  };
}

function boundOperationId(event, operation, relativePath) {
  const namespace = (event.kind === "delete" && operation === "delete")
    || (event.kind === "move" && operation === "move" && !event.previousDestinationIdentity)
    ? "webdavsolo" : "webdav";
  return `${namespace}-${event.operationId}-${sha256(`${operation}:${relativePath}`).slice(0, 24)}`;
}

function unsigned(label, options = {}) {
  const plaintext = options.plaintext ?? PUT_BYTES;
  const event = options.event ?? putEvent(label, plaintext);
  const operationKind = options.operationKind || (event.kind === "move" ? "move"
    : event.kind === "delete" ? "delete" : event.existed ? "update" : "create");
  const relativePath = options.relativePath
    || (event.kind === "delete" ? event.source : event.destination || event.path).slice(1);
  const fileKey = options.fileKey || crypto.randomBytes(32);
  const encryptedBytes = operationKind === "move"
    ? protocol.encodeMovePayload(plaintext, fileKey) : plaintext;
  const metadata = { path: relativePath };
  if (event.kind === "put" && ["create", "update"].includes(operationKind)) {
    metadata.size = event.putBytes;
  }
  if (operationKind === "move") metadata.sourcePath = event.source.slice(1);
  const operation = protocol.createOperation({
    operation: operationKind,
    operationId: boundOperationId(event, operationKind, relativePath),
    objectId: `object-${label}`, fileId: `file-${label}`,
    versionId: `version-${label}`, deviceId: "device-a",
    keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" },
    metadata, plaintext: encryptedBytes, fileKey,
  });
  return { operation, event, fileKey };
}

async function sign(label, options = {}) {
  const fixture = unsigned(label, options);
  const pair = options.pair || crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ type: "spki", format: "der" })
    .toString("base64url");
  fixture.operation.authorization = await createAuthorizationProof(fixture.operation, {
    username: "alice", publicKey, privateKey: pair.privateKey,
    expiresAt: Date.now() + 60_000,
  });
  return fixture;
}

function resolverFor(...fixtures) {
  const keys = new Map(fixtures.map(({ operation, fileKey }) => [operation.fileId, fileKey]));
  return (operation) => keys.get(operation.fileId);
}

function journal() {
  const calls = [];
  return {
    calls,
    async enqueue(value) { calls.push([value]); },
    async enqueueMany(values) { calls.push(values); },
  };
}

function unitMutationReceiptWitness() {
  // This deliberately in-memory double isolates signature/payload policy
  // checks from fsync. It must have an actual independently exercised update
  // and pending readback; a no-op journal would falsely break new admission
  // and make every positive test fail for the wrong reason.
  const records = new Map();
  return {
    async update(operationId, patch) {
      records.set(operationId, { operationId, ...(records.get(operationId) || {}),
        ...JSON.parse(JSON.stringify(patch)) });
    },
    pending() { return JSON.parse(JSON.stringify([...records.values()])); },
  };
}

function bridge(translated, outbox, trustedProtocolPolicy, options = {}) {
  return new LocalSyncWebDavBridge({
    rootDir: options.rootDir || process.cwd(),
    token: "local-test-only-webdav-protocol-ingress",
    journal: unitMutationReceiptWitness(),
    protocolJournal: outbox,
    toProtocolOperation: async () => translated,
    requireSignedProtocolIngress: options.strict !== false,
    trustedProtocolPolicy,
    resolveProtectedFileKey: options.resolveProtectedFileKey,
  });
}

function policy(publicKey, revokedDeviceIds = []) {
  return {
    username: "alice",
    trustedDevicePublicKeys: { "device-a": publicKey },
    revokedDeviceIds,
  };
}

test("protected bridge refuses to start without a trusted current policy provider", () => {
  const outbox = journal();
  assert.throws(() => bridge({}, outbox, null), /trusted current device policy/);
  assert.deepEqual(outbox.calls, []);
});

test("genuine Ed25519 signed PUT reaches protected direct journal with canonical event ID and bytes", async () => {
  const genuine = await sign("pinned");
  const outbox = journal();
  let observations = 0;
  const b = bridge(genuine.operation, outbox, () => {
    observations += 1;
    return policy(genuine.operation.authorization.publicKey);
  }, { resolveProtectedFileKey: resolverFor(genuine) });
  assert.equal(genuine.operation.operationId,
    boundOperationId(genuine.event, "create", "pinned.txt"));
  assert.equal(await b.enqueueProtocol(genuine.event), true);
  assert.equal(observations, 3,
    "current device policy must also be rechecked after local receipt persistence");
  assert.equal(outbox.calls.length, 1);
  assert.equal(outbox.calls[0][0].authorization.signature,
    genuine.operation.authorization.signature);
  assert.deepEqual(outbox.calls[0][0].revision, genuine.operation.revision);
});

test("genuine signed update matches an existing WebDAV PUT with the same authenticated bytes", async () => {
  const event = { ...putEvent("existing-put"), existed: true };
  const signed = await sign("existing-put", { event, operationKind: "update" });
  const outbox = journal();
  const b = bridge(signed.operation, outbox,
    () => policy(signed.operation.authorization.publicKey),
    { resolveProtectedFileKey: resolverFor(signed) });
  assert.equal(await b.enqueueProtocol(event), true);
  assert.equal(outbox.calls[0][0].operation, "update");
  assert.equal(outbox.calls[0][0].operationId,
    boundOperationId(event, "update", "existing-put.txt"));
});

test("genuine signed DELETE matches its exact file source and requires no content resolver", async () => {
  const event = deleteEvent("delete-file");
  const signed = await sign("delete-file", { event });
  const outbox = journal();
  const b = bridge(signed.operation, outbox,
    () => policy(signed.operation.authorization.publicKey));
  assert.equal(await b.enqueueProtocol(event), true);
  assert.equal(outbox.calls.length, 1);
  assert.equal(outbox.calls[0][0].operationId,
    boundOperationId(event, "delete", "delete-file.txt"));
});

test("unsigned, unpinned, forged and revoked translations never reach protected outbox", async () => {
  const genuine = await sign("trusted");
  const rogue = await sign("rogue");
  const unsignedFixture = unsigned("unsigned");
  const forged = {
    ...genuine.operation,
    authorization: {
      ...genuine.operation.authorization,
      signature: crypto.randomBytes(64).toString("base64url"),
    },
  };
  for (const [label, candidate, event, trusted, fixture, expectedError] of [
    ["unsigned", unsignedFixture.operation, unsignedFixture.event,
      policy(genuine.operation.authorization.publicKey), unsignedFixture,
      { code: "authorization_required" }],
    ["foreign signed device", rogue.operation, rogue.event,
      policy(genuine.operation.authorization.publicKey), rogue,
      { code: "authorization_rejected" }],
    ["forged signature", forged, genuine.event,
      policy(genuine.operation.authorization.publicKey), genuine,
      { code: "authorization_signature" }],
    ["revoked genuine device", genuine.operation, genuine.event,
      policy(genuine.operation.authorization.publicKey, ["device-a"]), genuine,
      { code: "authorization_rejected" }],
  ]) {
    const outbox = journal();
    const b = bridge(candidate, outbox, () => trusted,
      { resolveProtectedFileKey: resolverFor(fixture) });
    await assert.rejects(b.enqueueProtocol(event), expectedError,
      `${label} must reject before persistent direct journal ingress`);
    assert.equal(outbox.calls.length, 0);
  }
});

test("missing revocation state and asynchronous authority are denied", async () => {
  const genuine = await sign("missing-state");
  for (const trustedPolicy of [
    () => ({
      username: "alice",
      trustedDevicePublicKeys: { "device-a": genuine.operation.authorization.publicKey },
    }),
    async () => policy(genuine.operation.authorization.publicKey),
  ]) {
    const outbox = journal();
    await assert.rejects(bridge(genuine.operation, outbox, trustedPolicy,
      { resolveProtectedFileKey: resolverFor(genuine) })
      .enqueueProtocol(genuine.event));
    assert.deepEqual(outbox.calls, []);
  }
});

test("revocation between crypto verification and second current policy check denies", async () => {
  const genuine = await sign("late-revocation");
  const outbox = journal();
  let observations = 0;
  const b = bridge(genuine.operation, outbox, () => policy(
    genuine.operation.authorization.publicKey,
    ++observations === 1 ? [] : ["device-a"],
  ), { resolveProtectedFileKey: resolverFor(genuine) });
  await assert.rejects(b.enqueueProtocol(genuine.event),
    { code: "authorization_rejected" });
  assert.equal(observations, 2);
  assert.deepEqual(outbox.calls, [], "no writes after a newly revoked device");
});

test("one unsigned item invalidates the entire signed batch before enqueueMany", async () => {
  const signed = await sign("first-of-batch");
  const outbox = journal();
  const b = bridge([signed.operation, unsigned("unsigned-second").operation],
    outbox, () => policy(signed.operation.authorization.publicKey),
    { resolveProtectedFileKey: resolverFor(signed) });
  await assert.rejects(b.enqueueProtocol(signed.event));
  assert.deepEqual(outbox.calls, [], "no partial signed batch may be durable");
});

test("late revocation after verifying both signed MOVE batch entries cancels the entire batch", async (t) => {
  // MOVE replacing an existing destination yields two distinct signed entries:
  // a tombstone for the old target and a move of source into that same target.
  // Both share the event ID; their operation kinds make canonical IDs distinct.
  const event = {
    journalType: "webdav-mutation", kind: "move", operationId: "move-batch",
    source: "/source.txt", destination: "/target.txt",
    // Two signed operations are valid only for a physical destination
    // replacement; a non-overwrite MOVE requires exactly one signed entry.
    previousDestinationIdentity: { dev: "1", ino: "1", type: "file" },
    trash: "/.rootark-trash/previous-target",
  };
  const bytes = Buffer.from("signed MOVE batch destination bytes");
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-signed-move-batch-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.writeFile(path.join(root, "target.txt"), bytes, { flag: "wx", mode: 0o600 });
  const first = await sign("batch-first", { event, operationKind: "delete" });
  const second = await sign("batch-second", {
    event, operationKind: "move", plaintext: bytes,
    pair: crypto.generateKeyPairSync("ed25519"),
  });
  assert.notEqual(first.operation.operationId, second.operation.operationId);
  const keys = new Map([
    [first.operation.operationId, first.operation.authorization.publicKey],
    [second.operation.operationId, second.operation.authorization.publicKey],
  ]);
  let reads = 0;
  const outbox = journal();
  const b = bridge([first.operation, second.operation], outbox, (operation) => {
    reads += 1;
    return policy(keys.get(operation.operationId), reads >= 3 ? ["device-a"] : []);
  }, { rootDir: root, resolveProtectedFileKey: resolverFor(second) });
  await assert.rejects(b.enqueueProtocol(event), { code: "authorization_rejected" });
  assert.equal(reads, 3, "both Ed25519 proofs must pass before final revocation check");
  assert.deepEqual(outbox.calls, [], "no partial batch after revocation");
});

test("policy callback cannot mutate signed metadata after exact-envelope validation", async () => {
  const signed = await sign("immutable-callback");
  const outbox = journal();
  const b = bridge(signed.operation, outbox, (operation) => {
    operation.metadata.path = "attacker-swapped.txt";
    return policy(signed.operation.authorization.publicKey);
  }, { resolveProtectedFileKey: resolverFor(signed) });
  await assert.rejects(b.enqueueProtocol(signed.event), TypeError);
  assert.deepEqual(outbox.calls, [], "an asynchronously verified envelope is immutable");
});

test("a genuine signature for an unrelated WebDAV event cannot be replayed", async () => {
  const genuine = await sign("unrelated-event");
  const outbox = journal();
  const b = bridge(genuine.operation, outbox,
    () => policy(genuine.operation.authorization.publicKey),
    { resolveProtectedFileKey: resolverFor(genuine) });
  const unrelated = { ...genuine.event, operationId: "some-other-webdav-event" };
  await assert.rejects(b.enqueueProtocol(unrelated),
    { code: "authorization_rejected" });
  assert.deepEqual(outbox.calls, []);
});

test("a genuine signature cannot authorize another canonical WebDAV destination", async () => {
  const genuine = await sign("wrong-path");
  const outbox = journal();
  const b = bridge(genuine.operation, outbox,
    () => policy(genuine.operation.authorization.publicKey),
    { resolveProtectedFileKey: resolverFor(genuine) });
  await assert.rejects(b.enqueueProtocol({
    ...genuine.event, path: "/foreign.txt",
    source: "/foreign.txt", destination: "/foreign.txt",
  }), { code: "authorization_rejected" });
  assert.deepEqual(outbox.calls, []);
});

test("signed operation opcode must agree with the actual WebDAV event kind", async () => {
  const event = putEvent("wrong-opcode");
  const signed = await sign("wrong-opcode", {
    event, operationKind: "delete",
  });
  const outbox = journal();
  const b = bridge(signed.operation, outbox,
    () => policy(signed.operation.authorization.publicKey),
    { resolveProtectedFileKey: resolverFor(signed) });
  await assert.rejects(b.enqueueProtocol(event),
    { code: "authorization_rejected" });
  assert.deepEqual(outbox.calls, []);
});

test("PUT create/update opcode must follow the event's actual existed flag", async () => {
  for (const [label, existed, wrongOpcode] of [
    ["create-denied-if-existing", true, "create"],
    ["update-denied-if-absent", false, "update"],
  ]) {
    const event = { ...putEvent(label), existed };
    const signed = await sign(label, { event, operationKind: wrongOpcode });
    const outbox = journal();
    const b = bridge(signed.operation, outbox,
      () => policy(signed.operation.authorization.publicKey),
      { resolveProtectedFileKey: resolverFor(signed) });
    await assert.rejects(b.enqueueProtocol(event),
      { code: "authorization_rejected" },
      "cryptographically authentic wrong opcode cannot authorize this mutation");
    assert.deepEqual(outbox.calls, []);
  }
});

test("protected PUT accepts exactly one valid signed entry per physical mutation", async () => {
  const signed = await sign("put-cardinality");
  const outbox = journal();
  const b = bridge([signed.operation, signed.operation], outbox,
    () => policy(signed.operation.authorization.publicKey),
    { resolveProtectedFileKey: resolverFor(signed) });
  await assert.rejects(b.enqueueProtocol(signed.event),
    { code: "authorization_rejected" });
  assert.deepEqual(outbox.calls, [], "two proofs must never double-commit one PUT");
});

test("protected DELETE requires one tombstone for the exact source path", async () => {
  const event = deleteEvent("delete-exact");
  const wrongPath = await sign("delete-subpath", {
    event, relativePath: "delete-exact.txt/unrelated.txt",
  });
  const outbox = journal();
  const b = bridge(wrongPath.operation, outbox,
    () => policy(wrongPath.operation.authorization.publicKey));
  await assert.rejects(b.enqueueProtocol(event),
    { code: "authorization_rejected" });
  assert.deepEqual(outbox.calls, [], "signed descendant is not the deleted file");

  const signed = await sign("delete-exact", { event });
  const batchOutbox = journal();
  const duplicated = bridge([signed.operation, signed.operation], batchOutbox,
    () => policy(signed.operation.authorization.publicKey));
  await assert.rejects(duplicated.enqueueProtocol(event),
    { code: "authorization_rejected" });
  assert.deepEqual(batchOutbox.calls, [], "DELETE must not admit two tombstones");
});

test("protected PUT rejects different plaintext even when metadata size, signature and event path agree", async () => {
  const event = putEvent("wrong-content", PUT_BYTES);
  const altered = Buffer.from(PUT_BYTES);
  altered[0] ^= 1; // Same length, different bytes: defeats size-only checking.
  const signed = await sign("wrong-content", { event, plaintext: altered });
  const outbox = journal();
  let keyResolutions = 0;
  const resolveKey = resolverFor(signed);
  const b = bridge(signed.operation, outbox,
    () => policy(signed.operation.authorization.publicKey),
    { resolveProtectedFileKey: (operation) => {
      keyResolutions += 1;
      return resolveKey(operation);
    } });
  await assert.rejects(b.enqueueProtocol(event),
    { code: "authorization_rejected" });
  assert.equal(keyResolutions, 1,
    "must reach real signed-payload decryption before rejecting the wrong bytes");
  assert.deepEqual(outbox.calls, [], "plaintext mismatch must fail before persistence");
});

test("protected PUT fails closed without independently provisioned file-key resolver", async () => {
  const genuine = await sign("no-resolver");
  const outbox = journal();
  const b = bridge(genuine.operation, outbox,
    () => policy(genuine.operation.authorization.publicKey));
  await assert.rejects(b.enqueueProtocol(genuine.event),
    { code: "authorization_rejected" });
  assert.deepEqual(outbox.calls, []);
});

test("protected ingress requires a complete canonical WebDAV mutation event", async () => {
  const genuine = await sign("event-shape");
  const outbox = journal();
  const b = bridge(genuine.operation, outbox,
    () => policy(genuine.operation.authorization.publicKey),
    { resolveProtectedFileKey: resolverFor(genuine) });
  for (const event of [
    { ...genuine.event, journalType: "other" },
    { ...genuine.event, kind: "unknown" },
    { ...genuine.event, operationId: undefined },
    { ...genuine.event, source: undefined, path: undefined },
    { ...genuine.event, destination: "/../unsafe" },
    { ...genuine.event, existed: undefined },
    { ...genuine.event, putSha256: undefined },
    { ...genuine.event, putBytes: undefined },
  ]) {
    await assert.rejects(b.enqueueProtocol(event),
      undefined, "incomplete or unsafe event must fail closed");
  }
  assert.deepEqual(outbox.calls, []);
});

test("signed MOVE decrypts authenticated file content and checks the installed destination bytes", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-signed-move-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const bytes = Buffer.from("physically moved and signed bytes");
  const genuine = await sign("move-binding", {
    event: moveEvent("move-binding"), plaintext: bytes,
  });
  await fs.writeFile(path.join(root, "move-binding-destination.txt"), bytes,
    { flag: "wx", mode: 0o600 });
  const outbox = journal();
  const b = bridge(genuine.operation, outbox,
    () => policy(genuine.operation.authorization.publicKey),
    { rootDir: root, resolveProtectedFileKey: resolverFor(genuine) });
  assert.equal(await b.enqueueProtocol(genuine.event), true);
  assert.equal(outbox.calls.length, 1);

  const altered = Buffer.from(bytes);
  altered[0] ^= 1;
  await fs.writeFile(path.join(root, "move-binding-destination.txt"), altered);
  await assert.rejects(b.enqueueProtocol(genuine.event),
    undefined, "a modified destination must reject its previously genuine signed MOVE");
  assert.equal(outbox.calls.length, 1, "modified MOVE cannot reach journal");
});

test("signed MOVE fails closed without a trusted resolver even when destination matches", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-signed-move-no-key-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const bytes = Buffer.from("signed MOVE with no independent file key");
  const signed = await sign("move-no-key", {
    event: moveEvent("move-no-key"), plaintext: bytes,
  });
  await fs.writeFile(path.join(root, "move-no-key-destination.txt"), bytes,
    { flag: "wx", mode: 0o600 });
  const outbox = journal();
  const b = bridge(signed.operation, outbox,
    () => policy(signed.operation.authorization.publicKey), { rootDir: root });
  await assert.rejects(b.enqueueProtocol(signed.event),
    { code: "authorization_rejected" });
  assert.deepEqual(outbox.calls, []);
});

test("MOVE cannot be represented by a signed destination delete alone", async () => {
  const event = moveEvent("delete-only");
  const signed = await sign("delete-only", { event, operationKind: "delete" });
  const outbox = journal();
  const b = bridge(signed.operation, outbox,
    () => policy(signed.operation.authorization.publicKey));
  await assert.rejects(b.enqueueProtocol(event),
    { code: "authorization_rejected" });
  assert.deepEqual(outbox.calls, [], "MOVE must include a signed destination mutation");
});

test("legacy unsigned bridge remains explicitly unchanged when strict ingress is disabled", async () => {
  const legacy = unsigned("legacy");
  const outbox = journal();
  const b = bridge(legacy.operation, outbox, null, { strict: false });
  assert.equal(await b.enqueueProtocol({ operationId: "legacy-mutation" }), true);
  assert.equal(outbox.calls.length, 1,
    "historical unprotected sync must not be silently broken by an opt-in gate");
});

test("even without strict flag, a signed translation requires independently pinned policy", async () => {
  const genuine = await sign("misconfigured-protected");
  const outbox = journal();
  const b = bridge(genuine.operation, outbox, null,
    { strict: false, resolveProtectedFileKey: resolverFor(genuine) });
  await assert.rejects(b.enqueueProtocol(genuine.event),
    /Protected WebDAV current device policy required/);
  assert.deepEqual(outbox.calls, [],
    "a signed operation may never be downgraded into an unverified legacy outbox");
});
