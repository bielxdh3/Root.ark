"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const browser = require("../public/client/rootark-zk1-browser-authority-head-relay");

const prefix = (text) => Buffer.from("Root.ark/zk-1/" + text + "\0");
const D = { head: prefix("opaque-catalog-head/v1"),
  checkpoint: prefix("opaque-catalog-checkpoint-sign/v2"),
  digest: prefix("opaque-catalog-checkpoint-digest/v2"),
  leaf: prefix("opaque-catalog-archive-leaf/v2"),
  owner: prefix("opaque-checkpoint-remote/owner-approval/v2"),
  receipt: prefix("opaque-checkpoint-remote/receipt/v2"),
  grant: prefix("browser-owner-device-grant/v1"),
  historical: prefix("v2-historical-signer-endorsement/v1") };
const FIELDS = ["schema", "account_id", "compartment_id", "keyring_id",
  "sequence", "intent_sha256", "operation_id", "head_digest", "checkpoint_digest",
  "signer_device_id", "signer_public_key", "manifest_revision", "manifest_digest",
  "epoch", "genesis_digest", "witness_signer_spki_sha256"];
const GF = ["schema", "account_id", "compartment_id", "keyring_id",
  "device_id", "authorization_key_id", "authorization_public_key",
  "manifest_revision", "manifest_digest", "current_epoch", "enrolled_epoch", "revoked_at_epoch"];
const hash = (...parts) => crypto.createHash("sha256").update(Buffer.concat(parts)).digest();
const sign = (domain, bytes, key) => crypto.sign(null, Buffer.concat([domain, bytes]), key);
const raw = (key) => key.export({ type: "spki", format: "der" }).subarray(-32);
const fingerprint = (key) => hash(key.export({ type: "spki", format: "der" }));
const b64 = (v) => Buffer.from(v).toString("base64url");
function cborHead(type, n) {
  const tag = type << 5;
  if (n < 24) return Buffer.from([tag + n]);
  if (n <= 255) return Buffer.from([tag + 24, n]);
  if (n <= 65535) return Buffer.from([tag + 25, n >> 8, n & 255]);
  if (n <= 0xffffffff) return Buffer.from([tag + 26,
    (n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
  throw Error("test fixture too large");
}
function encoded(value) {
  if (value === null) return Buffer.from([0xf6]);
  if (Number.isSafeInteger(value) && value >= 0) return cborHead(0, value);
  if (typeof value === "string") {
    const b = Buffer.from(value); return Buffer.concat([cborHead(3, b.length), b]);
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const b = Buffer.from(value); return Buffer.concat([cborHead(2, b.length), b]);
  }
  if (Array.isArray(value)) return Buffer.concat([cborHead(4, value.length),
    ...value.map(encoded)]);
  if (value && typeof value === "object") {
    const parts = Object.keys(value).map((k) => [encoded(k), encoded(value[k])]);
    parts.sort(([a], [b]) => a.length - b.length || a.compare(b));
    return Buffer.concat([cborHead(5, parts.length), ...parts.flat()]);
  }
  throw Error("unsupported test CBOR fixture type");
}

test("owner-endorsed historical A129→B130→B131: exact CAS/FLOOR, forged grants/signers, replay, rollback", async () => {
  const actorA = crypto.generateKeyPairSync("ed25519");
  const actorB = crypto.generateKeyPairSync("ed25519");
  const owner = crypto.generateKeyPairSync("ed25519");
  const checkpointKey = crypto.generateKeyPairSync("ed25519");
  const cas = crypto.generateKeyPairSync("ed25519");
  const floor = crypto.generateKeyPairSync("ed25519");
  const genesis = crypto.randomBytes(32);
  const witnessPin = crypto.randomBytes(32);
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(16), keyring_id: crypto.randomBytes(16) };
  const scopeWire = Object.fromEntries(Object.entries(scope).map(([k, v]) => [k, b64(v)]));
  const fpCas = fingerprint(cas.publicKey), fpFloor = fingerprint(floor.publicKey);
  const fpCheckpoint = fingerprint(checkpointKey.publicKey);
  const ownerDigestA = crypto.randomBytes(32), ownerDigestB = crypto.randomBytes(32);
  let previous = crypto.randomBytes(32), previousCheckpoint = crypto.randomBytes(32);
  const baseline = Buffer.from(previous), baselineCheckpoint = Buffer.from(previousCheckpoint);
  let predecessor = null, priorOperation = null;
  const signedIntents = [], historicalSignerEndorsements = [];
  const now = Math.floor(Date.now() / 1000);
  function receipt(role, sequence, head, checkpoint, operation, nonce) {
    const unsigned = { type: "rootark-opaque-checkpoint-remote-receipt/v2",
      ...scope, role, state: "FINALIZED", sequence, head_digest: head,
      checkpoint_digest: checkpoint, operation_id: operation,
      cas_signer_fp: fpCas, floor_signer_fp: fpFloor, nonce,
      issued_at: now };
    return { ...unsigned, signature: sign(D.receipt, Buffer.from(encoded(unsigned)),
      role === "CAS" ? cas.privateKey : floor.privateKey) };
  }
  for (const [i, keys, deviceId, manifestDigest, epoch, revision] of [
    [0, actorA, "historical-A", ownerDigestA, 1, 2],
    [1, actorB, "current-B", ownerDigestB, 2, 3],
    [2, actorB, "current-B", ownerDigestB, 2, 3],
  ]) {
    const sequence = i + 129, operation = crypto.randomBytes(32);
    const header = { type: "rootark-zk1-opaque-catalog/v1", ...scope,
      sequence, previous_digest: previous, manifest_revision: revision,
      manifest_digest: manifestDigest, epoch, signer_device_id: deviceId,
      total_count: 0, page_digests: [], issued_at: now };
    const headerRaw = Buffer.from(encoded(header));
    const headerSignature = sign(D.head, headerRaw, keys.privateKey);
    const headDigest = hash(D.head, headerRaw, headerSignature);
    const record = { sequence, header: headerRaw, signature: headerSignature,
      page_bodies: [] };
    const checkpoint = { type: "rootark-zk1-opaque-catalog-checkpoint/v2",
      ...scope, previous_sequence: sequence - 1, previous_digest: previous,
      final_sequence: sequence, final_digest: headDigest,
      previous_checkpoint_digest: previousCheckpoint,
      archive_root: hash(D.leaf, Buffer.from(encoded(record))),
      record_count: 1, issued_at: now };
    const checkpointRaw = Buffer.from(encoded(checkpoint));
    const checkpointSignature = sign(D.checkpoint, checkpointRaw, checkpointKey.privateKey);
    const checkpointDigest = hash(D.digest, checkpointRaw, checkpointSignature);
    const approval = { type: "rootark-opaque-checkpoint-remote-owner-approval/v2",
      ...scope, operation_id: operation, checkpoint_digest: checkpointDigest,
      previous_sequence: sequence - 1, previous_digest: previous,
      previous_checkpoint_digest: previousCheckpoint, final_sequence: sequence,
      final_digest: headDigest, cas_signer_fp: fpCas, floor_signer_fp: fpFloor,
      checkpoint_signer_fp: fpCheckpoint, issued_at: now };
    const approvalRaw = Buffer.from(encoded(approval));
    const intent = { type: "rootark-opaque-checkpoint-remote-intent/v2", ...scope,
      operation_id: operation, checkpoint_bytes: checkpointRaw,
      checkpoint_signature: checkpointSignature, records: [record],
      previous_sequence: sequence - 1, previous_digest: previous,
      previous_checkpoint_digest: previousCheckpoint, owner_approval: approvalRaw,
      owner_signature: sign(D.owner, approvalRaw, actorB.privateKey),
      owner_evidence: Buffer.from(encoded({ baseManifest: [], baseReceipt: [],
        transitions: [], packageEnvelopes: [], witnessHeadRaw: Buffer.from([1]) })),
      ...(predecessor ? {
        predecessor_cas_receipt: Buffer.from(encoded(receipt("CAS", sequence - 1,
          predecessor.head, predecessor.checkpoint, priorOperation, crypto.randomBytes(32)))),
        predecessor_floor_receipt: Buffer.from(encoded(receipt("FLOOR", sequence - 1,
          predecessor.head, predecessor.checkpoint, priorOperation, crypto.randomBytes(32)))),
      } : {}),
    };
    const rawIntent = Buffer.from(encoded(intent));
    signedIntents.push(new Uint8Array(rawIntent));
    const statement = { schema: "rootark-zk1-v2-historical-signer-endorsement/v1",
      ...scopeWire, sequence, intent_sha256: b64(hash(rawIntent)),
      operation_id: b64(operation), head_digest: b64(headDigest),
      checkpoint_digest: b64(checkpointDigest), signer_device_id: deviceId,
      signer_public_key: b64(raw(keys.publicKey)), manifest_revision: revision,
      manifest_digest: b64(manifestDigest), epoch,
      genesis_digest: b64(genesis), witness_signer_spki_sha256: b64(witnessPin) };
    const statementRaw = Buffer.from(JSON.stringify(Object.fromEntries(
      FIELDS.map((f) => [f, statement[f]]))));
    historicalSignerEndorsements.push({ ...statement, signature: b64(sign(
      D.historical, statementRaw, owner.privateKey)) });
    previous = headDigest; previousCheckpoint = checkpointDigest;
    predecessor = { head: headDigest, checkpoint: checkpointDigest };
    priorOperation = operation;
  }
  const grantData = { schema: "rootark-zk1-browser-owner-device-grant/v1",
    ...scopeWire, device_id: "current-B", authorization_key_id: b64(crypto.randomBytes(16)),
    authorization_public_key: b64(raw(actorB.publicKey)), manifest_revision: 3,
    manifest_digest: b64(ownerDigestB), current_epoch: 2,
    enrolled_epoch: 2, revoked_at_epoch: null };
  const grant = { ...grantData, signature: b64(sign(D.grant,
    Buffer.from(JSON.stringify(Object.fromEntries(GF.map((f) => [f, grantData[f]])))),
    owner.privateKey)) };
  let observedFinal = 131;
  const input = { origin: "http://127.0.0.1:56877/", fetchImpl: async (_url, options) => {
    const nonce = Buffer.from(JSON.parse(options.body).nonce, "base64url");
    const index = observedFinal - 129;
    const current = historicalSignerEndorsements[index];
    const op = Buffer.from(current.operation_id, "base64url");
    const head = Buffer.from(current.head_digest, "base64url");
    const cp = Buffer.from(current.checkpoint_digest, "base64url");
    return new Response(JSON.stringify({
      casProofBase64: b64(encoded(receipt("CAS", observedFinal, head, cp, op, nonce))),
      floorProofBase64: b64(encoded(receipt("FLOOR", observedFinal, head, cp, op, nonce))),
    }), { status: 200, headers: { "content-type": "application/json" } });
  }, assertLive: () => {}, csrfToken: () => "csrf", scope: scopeWire,
  previousDigest: new Uint8Array(baseline),
  previousCheckpointDigest: new Uint8Array(baselineCheckpoint),
  ownerRevision: 3, ownerDigest: new Uint8Array(ownerDigestB), ownerEpoch: 2,
  ownerDeviceId: "current-B", signedIntent: signedIntents[2], signedIntents,
  casKeyRaw: new Uint8Array(raw(cas.publicKey)), casSpkiPin: new Uint8Array(fpCas),
  floorKeyRaw: new Uint8Array(raw(floor.publicKey)), floorSpkiPin: new Uint8Array(fpFloor),
  checkpointKeyRaw: new Uint8Array(raw(checkpointKey.publicKey)),
  checkpointSpkiPin: new Uint8Array(fpCheckpoint),
  deviceKeyRaw: new Uint8Array(raw(actorB.publicKey)),
  deviceSpkiPin: new Uint8Array(fingerprint(actorB.publicKey)),
  signedDeviceGrant: grant, ownerKeyRaw: new Uint8Array(raw(owner.publicKey)),
  ownerSpkiPin: new Uint8Array(fingerprint(owner.publicKey)),
  historicalSignerEndorsements, independentGenesisDigest: new Uint8Array(genesis),
  independentWitnessSpkiSha256: new Uint8Array(witnessPin) };
  const read = (options = {}) => browser.readFinalizedV2({ ...input, ...options });
  assert.equal((await read()).sequence, 131);
  await assert.rejects(read({ historicalSignerEndorsements: undefined }), /UNVERIFIED/);
  await assert.rejects(read({ historicalSignerEndorsements:
    [historicalSignerEndorsements[1], historicalSignerEndorsements[0],
      historicalSignerEndorsements[2]] }), /UNVERIFIED/, "replay/out-of-order endorsement");
  await assert.rejects(read({ historicalSignerEndorsements:
    [{ ...historicalSignerEndorsements[0], signer_public_key:
      b64(raw(crypto.generateKeyPairSync("ed25519").publicKey)) },
    ...historicalSignerEndorsements.slice(1)] }), /UNVERIFIED/, "forged signer");
  await assert.rejects(read({ independentGenesisDigest: new Uint8Array(crypto.randomBytes(32)) }),
    /UNVERIFIED/, "substituted independent genesis");
  await assert.rejects(read({ independentWitnessSpkiSha256: new Uint8Array(crypto.randomBytes(32)) }),
    /UNVERIFIED/, "substituted independently pinned witness");
  await assert.rejects(read({ signedDeviceGrant: { ...grant, revoked_at_epoch: 2 } }),
    /UNVERIFIED/, "current signer revocation");
  observedFinal = 130;
  await assert.rejects(read(), /UNVERIFIED/, "signed remote rollback cannot match 131");
  observedFinal = 131;
  await assert.rejects(read({ signedIntents: signedIntents.slice(0, 2),
    signedIntent: signedIntents[1], historicalSignerEndorsements:
      historicalSignerEndorsements.slice(0, 2) }), /UNVERIFIED/, "old chain cannot claim current remote head");
});
