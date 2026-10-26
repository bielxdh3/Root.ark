"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const z = require("../src/crypto/rootark-zk-1");
const { Zk1DurableWitnessLedger } = require("../src/services/zk1DurableWitnessLedger");
const { inspectVerifiedWitnessReservationV1 } = require("../src/crypto/rootark-zk-witness-operation-wire-v1");
const { inspectVerifiedWitnessFreshHeadV1 } = require("../src/crypto/rootark-zk-witness-head-wire-v1");

const STATUS_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-cas-status/v1\0", "ascii");
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-issue65-witness-"));
  const connections = new Set();
  t.after(() => {
    for (const instance of connections) instance.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const witness = crypto.generateKeyPairSync("ed25519");
  const authority = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const casKeyId = crypto.randomBytes(16);
  const scope = {
    account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("main", "ascii"),
    keyring_id: crypto.randomBytes(16),
  };
  const operation = {
    ...scope,
    reservation_id: crypto.randomBytes(16),
    operation_id: crypto.randomBytes(16),
    expected_revision: null,
    expected_manifest_digest: null,
    proposed_revision: 1,
    proposed_manifest_digest: crypto.randomBytes(32),
    request_digest: crypto.randomBytes(32),
    package_envelope_digest: null,
    expires_at: 1000,
  };
  let outcome = "committed";
  let failProof = false;
  let terminalRequests = 0;
  let clock = 900;
  let forcedObservedAt = null;
  const now = () => clock;
  const statusProvider = {
    async getTerminalProof({ query, nonce }) {
      terminalRequests += 1;
      const base = {
        type: "rootark-recovery-cas-status/v1",
        status_authority_key_id: casKeyId,
        ...query,
        observed_revision: outcome === "committed" ? query.proposed_revision : query.expected_revision,
        observed_manifest_digest: outcome === "committed" ? query.proposed_manifest_digest : query.expected_manifest_digest,
        terminal_status: outcome,
        observed_at: forcedObservedAt ?? clock,
        nonce,
      };
      const signature = crypto.sign(null, Buffer.concat([STATUS_DOMAIN,
        await z.encodeDeterministic(base)]), failProof
        ? crypto.generateKeyPairSync("ed25519").privateKey : authority.privateKey);
      return Buffer.from(await z.encodeDeterministic({ ...base, signature }));
    },
  };
  const options = {
    bootstrapNew: true,
    witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusPinned: { keyId: casKeyId, publicKey: authority.publicKey },
    statusProvider, nowSeconds: now,
  };
  const filename = path.join(dir, "witness.sqlite");
  const make = (overrides = {}) => {
    const instance = new Zk1DurableWitnessLedger(filename, { ...options, ...overrides });
    connections.add(instance);
    return instance;
  };
  return {
    scope, operation, make, witnessKeyId, witnessKey: witness.publicKey,
    filename, options,
    changeOutcome(v) { outcome = v; }, forge(v) { failProof = v; },
    advance(value) { clock = value; },
    overrideObservedAt(value) { forcedObservedAt = value; },
    requests() { return terminalRequests; },
  };
}

test("reservation closes the head gate durably before response, including across witness restarts", async (t) => {
  const f = fixture(t);
  const service = f.make();
  const reservation = await service.reserve(f.operation);
  await inspectVerifiedWitnessReservationV1({
    raw: reservation,
    pinned: { keyId: f.witnessKeyId, publicKey: f.witnessKey },
    operation: f.operation,
  });
  const challenge = crypto.randomBytes(32);
  const pending = await service.freshHead({ scope: f.scope, nonce: challenge });
  const decoded = await z.decodeDeterministic(pending);
  assert.equal(decoded.status, "pending");
  assert.equal(decoded.current_revision, null);
  assert.deepEqual(Buffer.from(decoded.pending_reservation_id), f.operation.reservation_id);
  await assert.rejects(inspectVerifiedWitnessFreshHeadV1({
    raw: pending, scope: f.scope, nonce: challenge,
    pinned: { keyId: f.witnessKeyId, publicKey: f.witnessKey },
    minimumHead: { revision: 1, digest: f.operation.proposed_manifest_digest, witnessSequence: 1 },
  }));
  await assert.rejects(service.reserve({
    ...f.operation, reservation_id: crypto.randomBytes(16), operation_id: crypto.randomBytes(16),
  }), /WITNESS_PENDING/);
  service.close();
  const reopened = f.make();
  t.after(() => reopened.close());
  assert.equal((await z.decodeDeterministic(await reopened.freshHead({
    scope: f.scope, nonce: crypto.randomBytes(32),
  }))).status, "pending");
  const committed = await reopened.resolve({ scope: f.scope });
  assert.equal(committed.status, "committed");
  assert.equal(f.requests(), 1);
  const nextNonce = crypto.randomBytes(32);
  const fresh = await reopened.freshHead({ scope: f.scope, nonce: nextNonce });
  const checked = await inspectVerifiedWitnessFreshHeadV1({
    raw: fresh, scope: f.scope, nonce: nextNonce,
    pinned: { keyId: f.witnessKeyId, publicKey: f.witnessKey },
    minimumHead: { revision: 1, digest: f.operation.proposed_manifest_digest, witnessSequence: 1 },
  });
  assert.equal(checked.status, "committed");
  assert.equal(checked.current_revision, 1);
});

test("forged status proof and authority outage retain the pending gate without clearing it", async (t) => {
  const f = fixture(t);
  const service = f.make();
  t.after(() => service.close());
  await service.reserve(f.operation);
  f.forge(true);
  await assert.rejects(service.resolve({ scope: f.scope }), /WITNESS_UNRESOLVED/);
  f.forge(false);
  const diagnostic = service.db.prepare("SELECT revision,digest,pending_id FROM witness_scope LIMIT 1").get();
  const reserved = service.db.prepare("SELECT envelope FROM witness_events WHERE kind='reserved' LIMIT 1").get();
  const decodedOp = await z.decodeDeterministic(reserved.envelope);
  assert.equal(diagnostic.revision, null);
  assert.equal(diagnostic.digest, null);
  assert.equal(decodedOp.expected_manifest_digest, null);
  assert.equal(decodedOp.expected_revision, null);
  assert.deepEqual(Buffer.from(diagnostic.pending_id), Buffer.from(decodedOp.reservation_id));
  assert.equal((await z.decodeDeterministic(await service.freshHead({
    scope: f.scope, nonce: crypto.randomBytes(32),
  }))).status, "pending");
  assert.equal((await service.resolve({ scope: f.scope })).status, "committed");
});

test("terminal non-commit requires expired reservation and retains irreversible initialize tombstone", async (t) => {
  const f = fixture(t);
  const service = f.make();
  t.after(() => service.close());
  await service.reserve(f.operation);
  f.changeOutcome("not-committed-final");
  f.advance(1050);
  const cancelled = await service.resolve({ scope: f.scope });
  assert.equal(cancelled.status, "cancelled");
  assert.deepEqual((await z.decodeDeterministic(await service.freshHead({
    scope: f.scope, nonce: crypto.randomBytes(32),
  }))).status, "absent");
  await assert.rejects(service.reserve({
    ...f.operation, expires_at: 1100,
    reservation_id: crypto.randomBytes(16), operation_id: crypto.randomBytes(16),
  }), /WITNESS_TOMBSTONED/);
  await assert.rejects(service.reserve({
    ...f.operation, expires_at: 1100, keyring_id: crypto.randomBytes(16),
    reservation_id: crypto.randomBytes(16), operation_id: crypto.randomBytes(16),
  }), /WITNESS_TOMBSTONED/);
});

test("missing external signer or pinned authority refuses witness service construction", (t) => {
  const f = fixture(t);
  assert.throws(() => new Zk1DurableWitnessLedger("ignored.sqlite", {
    witnessKeyId: f.witnessKeyId, witnessPrivateKey: crypto.generateKeyPairSync("ed25519").privateKey,
  }));
});

test("witness refuses silent rebootstrap after missing database and duplicate signing authority", (t) => {
  const f = fixture(t);
  assert.throws(() => f.make({ bootstrapNew: false }), /WITNESS_BOOTSTRAP_REQUIRED/);
  const signer = f.options.witnessPrivateKey;
  const ownPublic = crypto.createPublicKey(signer);
  assert.throws(() => f.make({
    statusPinned: { keyId: crypto.randomBytes(16), publicKey: ownPublic },
  }), /WITNESS_IDENTITY_CONFLICT/);
});

test("after commit, a new reservation requires the exact previous witnessed head", async (t) => {
  const f = fixture(t);
  const service = f.make();
  await service.reserve(f.operation);
  await service.resolve({ scope: f.scope });
  const next = {
    ...f.operation,
    reservation_id: crypto.randomBytes(16),
    operation_id: crypto.randomBytes(16),
    expected_revision: 1,
    expected_manifest_digest: f.operation.proposed_manifest_digest,
    proposed_revision: 2,
    proposed_manifest_digest: crypto.randomBytes(32),
  };
  const pending = await service.reserve(next);
  await inspectVerifiedWitnessReservationV1({
    raw: pending, operation: next,
    pinned: { keyId: f.witnessKeyId, publicKey: f.witnessKey },
  });
  const stale = { ...next, reservation_id: crypto.randomBytes(16),
    operation_id: crypto.randomBytes(16), expected_revision: 1,
    expected_manifest_digest: crypto.randomBytes(32) };
  await assert.rejects(service.reserve(stale), /WITNESS_PENDING/);
  assert.equal((await z.decodeDeterministic(await service.freshHead({
    scope: f.scope, nonce: crypto.randomBytes(32),
  }))).status, "pending");
  assert.equal((await service.resolve({ scope: f.scope })).status, "committed");
  assert.equal((await z.decodeDeterministic(await service.freshHead({
    scope: f.scope, nonce: crypto.randomBytes(32),
  }))).current_revision, 2);
});

test("missing or altered durable reservation/event data never yields an acceptable witness head", async (t) => {
  const f = fixture(t);
  const service = f.make();
  await service.reserve(f.operation);
  service.db.prepare("DELETE FROM witness_events WHERE kind='reserved'").run();
  await assert.rejects(service.freshHead({
    scope: f.scope, nonce: crypto.randomBytes(32),
  }), /WITNESS_LEDGER_CORRUPT/);
  await assert.rejects(service.resolve({ scope: f.scope }), /WITNESS_LEDGER_CORRUPT|WITNESS_UNRESOLVED/);
});

test("missing terminal event after commit fails closed even when head row still looks committed", async (t) => {
  const f = fixture(t);
  const service = f.make();
  await service.reserve(f.operation);
  await service.resolve({ scope: f.scope });
  service.db.prepare("DELETE FROM witness_events WHERE kind='committed'").run();
  await assert.rejects(service.freshHead({
    scope: f.scope, nonce: crypto.randomBytes(32),
  }), /WITNESS_LEDGER_CORRUPT/);
});

test("witness must never return a signed committed head when another connection reserves during signing", async (t) => {
  const f = fixture(t);
  const first = f.make();
  await first.reserve(f.operation);
  await first.resolve({ scope: f.scope });
  const second = f.make();
  const next = {
    ...f.operation, reservation_id: crypto.randomBytes(16),
    operation_id: crypto.randomBytes(16),
    expected_revision: 1,
    expected_manifest_digest: f.operation.proposed_manifest_digest,
    proposed_revision: 2, proposed_manifest_digest: crypto.randomBytes(32),
  };
  const sign = first.sign.bind(first);
  first.sign = async (unsigned, domain) => {
    if (unsigned.type === "rootark-recovery-witness-head/v1") {
      await second.reserve(next);
    }
    return sign(unsigned, domain);
  };
  await assert.rejects(first.freshHead({
    scope: f.scope, nonce: crypto.randomBytes(32),
  }), /WITNESS_GATE_CHANGED/,
  "committed receipt must not be issued after pending reservation persisted");
  const now = await z.decodeDeterministic(await second.freshHead({
    scope: f.scope, nonce: crypto.randomBytes(32),
  }));
  assert.equal(now.status, "pending");
});

test("a hostile status transport cannot substitute nonce and replay a signed terminal proof", async (t) => {
  const f = fixture(t);
  const service = f.make();
  await service.reserve(f.operation);
  const original = f.options.statusProvider.getTerminalProof;
  f.options.statusProvider.getTerminalProof = async ({ query, nonce }) => {
    // This proof is correctly signed by the configured CAS test authority,
    // but is for a DIFFERENT challenge chosen by the transport.
    const substituted = crypto.randomBytes(32);
    nonce.set(substituted);
    return original({ query, nonce: substituted });
  };
  await assert.rejects(service.resolve({ scope: f.scope }), /WITNESS_UNRESOLVED/);
  assert.equal((await z.decodeDeterministic(await service.freshHead({
    scope: f.scope, nonce: crypto.randomBytes(32),
  }))).status, "pending");
});

test("a hostile transport cannot mutate the reserved manifest digest by changing its query argument", async (t) => {
  const f = fixture(t);
  const service = f.make();
  await service.reserve(f.operation);
  const original = f.options.statusProvider.getTerminalProof;
  f.options.statusProvider.getTerminalProof = async ({ query, nonce }) => {
    query.proposed_manifest_digest.fill(0xcd);
    return original({ query, nonce });
  };
  await assert.rejects(service.resolve({ scope: f.scope }), /WITNESS_UNRESOLVED/);
  assert.equal((await z.decodeDeterministic(await service.freshHead({
    scope: f.scope, nonce: crypto.randomBytes(32),
  }))).status, "pending");
});

test("status proof observed outside the 30-second clock-skew window cannot resolve pending", async (t) => {
  const f = fixture(t);
  const service = f.make();
  await service.reserve(f.operation);
  f.overrideObservedAt(1000);
  await assert.rejects(service.resolve({ scope: f.scope }), /WITNESS_UNRESOLVED/);
  assert.equal((await z.decodeDeterministic(await service.freshHead({
    scope: f.scope, nonce: crypto.randomBytes(32),
  }))).status, "pending");
  f.overrideObservedAt(null);
  assert.equal((await service.resolve({ scope: f.scope })).status, "committed");
});

test("witness cannot reserve a new operation without durable space for the eventual terminal event", async (t) => {
  const f = fixture(t);
  const service = f.make({ maxEventsPerScope: 2 });
  await service.reserve(f.operation);
  await service.resolve({ scope: f.scope });
  const next = {
    ...f.operation, reservation_id: crypto.randomBytes(16),
    operation_id: crypto.randomBytes(16), expected_revision: 1,
    expected_manifest_digest: f.operation.proposed_manifest_digest,
    proposed_revision: 2, proposed_manifest_digest: crypto.randomBytes(32),
  };
  await assert.rejects(service.reserve(next), /WITNESS_CAPACITY_EXHAUSTED/);
  const nonce = crypto.randomBytes(32);
  const head = await inspectVerifiedWitnessFreshHeadV1({
    raw: await service.freshHead({ scope: f.scope, nonce }),
    scope: f.scope, nonce,
    pinned: { keyId: f.witnessKeyId, publicKey: f.witnessKey },
    minimumHead: { revision: 1,
      digest: f.operation.proposed_manifest_digest, witnessSequence: 1 },
  });
  assert.equal(head.current_revision, 1,
    "capacity exhaustion must not create a permanent pending reservation");
});

test("ticket signing that completes after expiry never commits a pending reservation", async (t) => {
  const f = fixture(t);
  const service = f.make();
  const original = service.sign.bind(service);
  service.sign = async (...args) => {
    f.advance(1050);
    return original(...args);
  };
  await assert.rejects(service.reserve(f.operation), /WITNESS_EXPIRED/);
  await assert.rejects(service.freshHead({ scope: f.scope, nonce: crypto.randomBytes(32) }),
    /WITNESS_NO_HEAD/);
});

test("lost reservation ACK retries the identical operation and returns the original signed ticket after restart", async (t) => {
  const f = fixture(t);
  const first = f.make();
  const raw = await first.reserve(f.operation);
  first.close();
  const restarted = f.make({ bootstrapNew: false });
  const recovered = await restarted.reserve({ ...f.operation,
    reservation_id: Buffer.from(f.operation.reservation_id),
    request_digest: Buffer.from(f.operation.request_digest),
  });
  assert.deepEqual(recovered, raw);
  assert.equal(restarted.db.prepare("SELECT count(*) AS count FROM witness_events").get().count, 1,
    "same ticket replay cannot allocate a second ledger reservation");
  await assert.rejects(restarted.reserve({
    ...f.operation, request_digest: crypto.randomBytes(32),
  }), /WITNESS_PENDING/);
});
