"use strict";

const crypto = require("node:crypto");
const z = require("./rootark-zk-1");

const SNAPSHOT_TYPE = "rootark-content-inventory-snapshot/v1";
const VERSION = 1;
const ROOT_DOMAIN = Buffer.from("Root.ark/zk-1/content-inventory-root/v1\0", "ascii");
const SNAPSHOT_DOMAIN = Buffer.from("Root.ark/zk-1/content-inventory-snapshot/v1\0", "ascii");
const TERMINAL_TYPE = "rootark-content-inventory-terminal/v1";
const TERMINAL_DOMAIN = Buffer.from("Root.ark/zk-1/content-inventory-terminal/v1\0", "ascii");
const MAX_ENTRIES = 4096;
const MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024;
const MAX_TERMINAL_PROOF_BYTES = 4096;
const MAX_COMMITTED_PROOF_BYTES = 4096;
const ENTRY_TYPE = "rootark-content-inventory-entry/v1";
const ENTRY_DOMAIN = Buffer.from("Root.ark/zk-1/content-inventory-entry/v1\0", "ascii");
const COMMITTED_FIELDS = Object.freeze([
  "type", "version", "signer_key_id", "scope", "sequence", "previous_root", "root",
  "operation_id", "expected_sequence", "expected_root", "request_digest", "entry", "signature",
]);
const MAX_SEQUENCE = Number.MAX_SAFE_INTEGER;
const SCOPE_FIELDS = Object.freeze(["account_id", "compartment_id", "keyring_id"]);
const ENTRY_FIELDS = Object.freeze(["object_id", "revision", "epoch", "ciphertext_sha256"]);
const SNAPSHOT_FIELDS = Object.freeze([
  "type", "version", "signer_key_id", "scope", "sequence", "previous_root",
  "root", "nonce", "entries", "signature",
]);

class ContentInventoryError extends Error {
  constructor(code) {
    super(code);
    this.name = "ContentInventoryError";
    this.code = code;
  }
}

function fail(code) {
  throw new ContentInventoryError(code);
}

function isBytes(value) {
  return Buffer.isBuffer(value) || value instanceof Uint8Array;
}

function copyBytes(value, min, max = min) {
  if (!isBytes(value)) fail("INVENTORY_INVALID_BYTES");
  if (typeof SharedArrayBuffer !== "undefined" && value.buffer instanceof SharedArrayBuffer) {
    fail("INVENTORY_SHARED_BYTES");
  }
  const length = value.byteLength;
  if (!Number.isSafeInteger(length) || length < min || length > max) fail("INVENTORY_LIMIT");
  return Buffer.from(value);
}

function exactObject(value, names, code = "INVENTORY_FIELDS") {
  if (!value || typeof value !== "object" || Array.isArray(value) || isBytes(value)) fail(code);
  let proto;
  let keys;
  try {
    proto = Object.getPrototypeOf(value);
    keys = Reflect.ownKeys(value);
  } catch (_) { fail(code); }
  if ((proto !== Object.prototype && proto !== null)
    || keys.length !== names.length
    || names.some((name) => !keys.includes(name))) fail(code);
  const result = Object.create(null);
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) fail(code);
    result[name] = descriptor.value;
  }
  return result;
}

function objectWithOptional(value, required, optional, code) {
  if (!value || typeof value !== "object" || Array.isArray(value) || isBytes(value)) fail(code);
  let proto;
  let keys;
  try {
    proto = Object.getPrototypeOf(value);
    keys = Reflect.ownKeys(value);
  } catch (_) { fail(code); }
  if ((proto !== Object.prototype && proto !== null)
    || required.some((name) => !keys.includes(name))
    || keys.some((name) => !required.includes(name) && !optional.includes(name))) fail(code);
  const result = Object.create(null);
  for (const name of [...required, ...optional]) {
    if (!keys.includes(name)) {
      result[name] = undefined;
      continue;
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) fail(code);
    result[name] = descriptor.value;
  }
  return result;
}

function safeInteger(value, min, max = MAX_SEQUENCE) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail("INVENTORY_INTEGER");
  return value;
}

function normalizeScope(value) {
  const raw = exactObject(value, SCOPE_FIELDS, "INVENTORY_SCOPE");
  return {
    account_id: copyBytes(raw.account_id, 16),
    compartment_id: copyBytes(raw.compartment_id, 1, 128),
    keyring_id: copyBytes(raw.keyring_id, 16),
  };
}

function normalizeEntry(value) {
  const raw = exactObject(value, ENTRY_FIELDS, "INVENTORY_ENTRY");
  return {
    object_id: copyBytes(raw.object_id, 16),
    revision: safeInteger(raw.revision, 1),
    epoch: safeInteger(raw.epoch, 1),
    ciphertext_sha256: copyBytes(raw.ciphertext_sha256, 32),
  };
}

function normalizeEntries(value) {
  if (!Array.isArray(value)) fail("INVENTORY_ENTRIES");
  const length = value.length;
  if (length > MAX_ENTRIES) fail("INVENTORY_LIMIT");
  let keys;
  try { keys = Reflect.ownKeys(value); } catch (_) { fail("INVENTORY_ENTRIES"); }
  if (keys.length !== length + 1 || !keys.includes("length")) fail("INVENTORY_ENTRIES");
  const entries = new Array(length);
  let previous = null;
  for (let i = 0; i < length; i += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(i));
    if (!descriptor || !Object.hasOwn(descriptor, "value")) fail("INVENTORY_ENTRIES");
    const entry = normalizeEntry(descriptor.value);
    if (previous) {
      const objectOrder = Buffer.compare(previous.object_id, entry.object_id);
      if (objectOrder > 0) fail("INVENTORY_ORDER");
      if (objectOrder === 0) {
        if (entry.revision === previous.revision) fail("INVENTORY_DUPLICATE");
        if (entry.revision !== previous.revision + 1 || entry.epoch < previous.epoch) fail("INVENTORY_ORDER");
      } else if (entry.revision !== 1) {
        fail("INVENTORY_ORDER");
      }
    } else if (entry.revision !== 1) {
      fail("INVENTORY_ORDER");
    }
    entries[i] = entry;
    previous = entry;
  }
  return entries;
}

function normalizeSequence(value) {
  return safeInteger(value, 0);
}

function normalizePreviousRoot(value, sequence) {
  if (sequence === 0) {
    if (value !== null) fail("INVENTORY_PREVIOUS_ROOT");
    return null;
  }
  return copyBytes(value, 32);
}

function normalizeNonce(value) {
  return copyBytes(value, 32);
}

function normalizeRequested(value) {
  return normalizeEntry(value);
}

function normalizeTerminalOperation(value) {
  const raw = exactObject(value, [
    "operation_id", "expected_sequence", "expected_root", "object_id", "revision", "epoch", "ciphertext_sha256",
  ], "INVENTORY_TERMINAL_OPERATION");
  return {
    operation_id: copyBytes(raw.operation_id, 16),
    expected_sequence: normalizeSequence(raw.expected_sequence),
    expected_root: copyBytes(raw.expected_root, 32),
    object_id: copyBytes(raw.object_id, 16),
    revision: safeInteger(raw.revision, 1),
    epoch: safeInteger(raw.epoch, 1),
    ciphertext_sha256: copyBytes(raw.ciphertext_sha256, 32),
  };
}

function terminalBody(raw, operation) {
  return {
    type: TERMINAL_TYPE,
    version: VERSION,
    signer_key_id: raw.signerKeyId,
    scope: raw.scope,
    status: "NOT_COMMITTED_FINAL_LOCAL",
    reason: raw.reason,
    operation_id: operation.operation_id,
    request_digest: raw.requestDigest,
    expected_sequence: operation.expected_sequence,
    expected_root: operation.expected_root,
    observed_sequence: raw.observedSequence,
    observed_root: raw.observedRoot,
    prior_revision: raw.priorRevision,
    prior_epoch: raw.priorEpoch,
    blocking_operation_id: raw.blockingOperationId,
  };
}

async function createTerminalProof(input) {
  const raw = exactObject(input, [
    "signerKeyId", "privateKey", "scope", "operation", "observedSequence", "observedRoot",
    "priorRevision", "priorEpoch", "reason", "blockingOperationId",
  ], "INVENTORY_TERMINAL_INPUT");
  const signerKeyId = copyBytes(raw.signerKeyId, 16);
  const privateKey = validatePrivateKey(raw.privateKey);
  const scope = normalizeScope(raw.scope);
  const operation = normalizeTerminalOperation(raw.operation);
  const observedSequence = safeInteger(raw.observedSequence, 0, MAX_ENTRIES);
  const observedRoot = copyBytes(raw.observedRoot, 32);
  const priorRevision = safeInteger(raw.priorRevision, 0, MAX_ENTRIES);
  const priorEpoch = safeInteger(raw.priorEpoch, 0);
  const reasons = ["EXPECTED_HEAD_CHANGED", "INVALID_CHRONOLOGY", "UNRESOLVED_PENDING"];
  if (!reasons.includes(raw.reason)) fail("INVENTORY_TERMINAL_PROOF");
  let blockingOperationId = null;
  if (raw.reason === "UNRESOLVED_PENDING") {
    blockingOperationId = copyBytes(raw.blockingOperationId, 16);
    if (sameBytes(blockingOperationId, operation.operation_id)) fail("INVENTORY_TERMINAL_PROOF");
  } else if (raw.blockingOperationId !== null) {
    fail("INVENTORY_TERMINAL_PROOF");
  }
  if (raw.reason === "EXPECTED_HEAD_CHANGED"
    && operation.expected_sequence === observedSequence
    && sameBytes(operation.expected_root, observedRoot)) fail("INVENTORY_TERMINAL_PROOF");
  if (raw.reason === "INVALID_CHRONOLOGY"
    && (operation.expected_sequence !== observedSequence
      || !sameBytes(operation.expected_root, observedRoot)
      || (operation.revision === priorRevision + 1 && operation.epoch >= priorEpoch))) {
    fail("INVENTORY_TERMINAL_PROOF");
  }
  const encodedOperation = await z.encodeDeterministic(operation);
  const unsigned = terminalBody({
    signerKeyId, scope, reason: raw.reason, requestDigest: hash(encodedOperation),
    observedSequence, observedRoot, priorRevision, priorEpoch, blockingOperationId,
  }, operation);
  const signature = crypto.sign(null, Buffer.concat([
    TERMINAL_DOMAIN,
    await z.encodeDeterministic(unsigned),
  ]), privateKey);
  const serialized = await z.encodeDeterministic({ ...unsigned, signature });
  if (serialized.length > MAX_TERMINAL_PROOF_BYTES) fail("INVENTORY_LIMIT");
  return serialized;
}

async function verifyTerminalProof(input) {
  const raw = exactObject(input, [
    "serialized", "pinnedPublicKey", "pinnedSignerKeyId", "expectedScope", "operation",
  ], "INVENTORY_TERMINAL_VERIFY_INPUT");
  const serialized = copyBytes(raw.serialized, 1, MAX_TERMINAL_PROOF_BYTES);
  const publicKey = validatePublicKey(raw.pinnedPublicKey);
  const pinnedSignerKeyId = copyBytes(raw.pinnedSignerKeyId, 16);
  const expectedScope = normalizeScope(raw.expectedScope);
  const operation = normalizeTerminalOperation(raw.operation);
  let decoded;
  try { decoded = await z.decodeDeterministic(serialized); } catch (_) { fail("INVENTORY_ENCODING"); }
  const fields = [
    "type", "version", "signer_key_id", "scope", "status", "reason", "operation_id",
    "request_digest", "expected_sequence", "expected_root", "observed_sequence", "observed_root",
    "prior_revision", "prior_epoch", "blocking_operation_id", "signature",
  ];
  const proof = exactObject(decoded, fields, "INVENTORY_TERMINAL_PROOF");
  if (proof.type !== TERMINAL_TYPE || proof.version !== VERSION
    || proof.status !== "NOT_COMMITTED_FINAL_LOCAL") fail("INVENTORY_TERMINAL_PROOF");
  const signerKeyId = copyBytes(proof.signer_key_id, 16);
  if (!sameBytes(signerKeyId, pinnedSignerKeyId)) fail("INVENTORY_SIGNER");
  const scope = normalizeScope(proof.scope);
  if (!sameBytes(scope.account_id, expectedScope.account_id)
    || !sameBytes(scope.compartment_id, expectedScope.compartment_id)
    || !sameBytes(scope.keyring_id, expectedScope.keyring_id)) fail("INVENTORY_SCOPE");
  const operationId = copyBytes(proof.operation_id, 16);
  const requestDigest = copyBytes(proof.request_digest, 32);
  const expectedRoot = copyBytes(proof.expected_root, 32);
  const observedSequence = safeInteger(proof.observed_sequence, 0, MAX_ENTRIES);
  const observedRoot = copyBytes(proof.observed_root, 32);
  const priorRevision = safeInteger(proof.prior_revision, 0, MAX_ENTRIES);
  const priorEpoch = safeInteger(proof.prior_epoch, 0);
  const signature = copyBytes(proof.signature, 64);
  const blockingOperationId = proof.blocking_operation_id === null
    ? null : copyBytes(proof.blocking_operation_id, 16);
  const encodedOperation = await z.encodeDeterministic(operation);
  if (!sameBytes(operationId, operation.operation_id)
    || proof.expected_sequence !== operation.expected_sequence
    || !sameBytes(expectedRoot, operation.expected_root)
    || !sameBytes(requestDigest, hash(encodedOperation))) fail("INVENTORY_TERMINAL_OPERATION");
  if (proof.reason === "EXPECTED_HEAD_CHANGED") {
    if (operation.expected_sequence === observedSequence && sameBytes(operation.expected_root, observedRoot)) {
      fail("INVENTORY_TERMINAL_PROOF");
    }
    if (blockingOperationId !== null) fail("INVENTORY_TERMINAL_PROOF");
  } else if (proof.reason === "INVALID_CHRONOLOGY") {
    if (operation.expected_sequence !== observedSequence || !sameBytes(operation.expected_root, observedRoot)
      || (operation.revision === priorRevision + 1 && operation.epoch >= priorEpoch)
      || blockingOperationId !== null) fail("INVENTORY_TERMINAL_PROOF");
  } else if (proof.reason === "UNRESOLVED_PENDING") {
    if (!blockingOperationId || sameBytes(blockingOperationId, operation.operation_id)) {
      fail("INVENTORY_TERMINAL_PROOF");
    }
  } else {
    fail("INVENTORY_TERMINAL_PROOF");
  }
  const unsigned = { ...proof };
  delete unsigned.signature;
  let valid = false;
  try {
    valid = crypto.verify(null, Buffer.concat([
      TERMINAL_DOMAIN,
      await z.encodeDeterministic(unsigned),
    ]), publicKey, signature);
  } catch (_) { fail("INVENTORY_SIGNATURE"); }
  if (!valid) fail("INVENTORY_SIGNATURE");
  return {
    status: "VERIFIED_NONAUTHORIZING",
    outcome: "NOT_COMMITTED_FINAL",
    reason: proof.reason,
    operationId,
    expectedHead: { sequence: operation.expected_sequence, root: Buffer.from(operation.expected_root) },
    observedHead: { sequence: observedSequence, root: Buffer.from(observedRoot) },
    blockingOperationId: blockingOperationId === null ? null : Buffer.from(blockingOperationId),
  };
}

function normalizeMinimumHead(value) {
  const raw = exactObject(value, ["sequence", "root"], "INVENTORY_FLOOR");
  return { sequence: normalizeSequence(raw.sequence), root: copyBytes(raw.root, 32) };
}

async function verifyCommittedEntryProof(input) {
  const raw = exactObject(input, [
    "serialized", "pinnedPublicKey", "pinnedSignerKeyId", "expectedScope", "operation",
  ], "INVENTORY_COMMIT_VERIFY_INPUT");
  const serialized = copyBytes(raw.serialized, 1, MAX_COMMITTED_PROOF_BYTES);
  const publicKey = validatePublicKey(raw.pinnedPublicKey);
  const pinnedSignerKeyId = copyBytes(raw.pinnedSignerKeyId, 16);
  const scope = normalizeScope(raw.expectedScope);
  const operation = normalizeTerminalOperation(raw.operation);
  let decoded;
  try { decoded = await z.decodeDeterministic(serialized); }
  catch (_) { fail("INVENTORY_ENCODING"); }
  const proof = exactObject(decoded, COMMITTED_FIELDS, "INVENTORY_COMMIT_PROOF");
  if (proof.type !== ENTRY_TYPE || proof.version !== VERSION) fail("INVENTORY_COMMIT_PROOF");
  const signerKeyId = copyBytes(proof.signer_key_id, 16);
  if (!sameBytes(signerKeyId, pinnedSignerKeyId)) fail("INVENTORY_SIGNER");
  const signedScope = normalizeScope(proof.scope);
  if (!sameBytes(signedScope.account_id, scope.account_id)
    || !sameBytes(signedScope.compartment_id, scope.compartment_id)
    || !sameBytes(signedScope.keyring_id, scope.keyring_id)) fail("INVENTORY_SCOPE");
  const sequence = safeInteger(proof.sequence, 1, MAX_ENTRIES);
  const expectedSequence = safeInteger(proof.expected_sequence, 0, MAX_ENTRIES - 1);
  const previousRoot = copyBytes(proof.previous_root, 32);
  const root = copyBytes(proof.root, 32);
  const expectedRoot = copyBytes(proof.expected_root, 32);
  const operationId = copyBytes(proof.operation_id, 16);
  const requestDigest = copyBytes(proof.request_digest, 32);
  const entry = normalizeEntry(proof.entry);
  const signature = copyBytes(proof.signature, 64);
  if (sequence !== expectedSequence + 1 || expectedSequence !== operation.expected_sequence
    || !sameBytes(previousRoot, expectedRoot) || !sameBytes(expectedRoot, operation.expected_root)
    || !sameBytes(operationId, operation.operation_id)
    || !sameBytes(entry.object_id, operation.object_id)
    || entry.revision !== operation.revision || entry.epoch !== operation.epoch
    || !sameBytes(entry.ciphertext_sha256, operation.ciphertext_sha256)) {
    fail("INVENTORY_COMMIT_OPERATION");
  }
  const operationBytes = await z.encodeDeterministic(operation);
  if (!sameBytes(requestDigest, hash(operationBytes))) fail("INVENTORY_COMMIT_OPERATION");
  const unsigned = {
    type: ENTRY_TYPE, version: VERSION, signer_key_id: signerKeyId, scope: signedScope,
    sequence, previous_root: previousRoot, root, operation_id: operationId,
    expected_sequence: expectedSequence, expected_root: expectedRoot, request_digest: requestDigest, entry,
  };
  // Even a valid signature does not authorize noncanonical representations.
  if (!sameBytes(serialized, await z.encodeDeterministic({ ...unsigned, signature }))) {
    fail("INVENTORY_ENCODING");
  }
  if (!crypto.verify(null, Buffer.concat([ENTRY_DOMAIN,
    await z.encodeDeterministic(unsigned),
  ]), publicKey, signature)) fail("INVENTORY_SIGNATURE");
  return {
    status: "VERIFIED_NONAUTHORIZING",
    outcome: "COMMITTED_IN_SIGNED_LEDGER",
    operationId: Buffer.from(operationId),
    sequence, root: Buffer.from(root),
    tuple: { object_id: Buffer.from(entry.object_id), revision: entry.revision,
      epoch: entry.epoch, ciphertext_sha256: Buffer.from(entry.ciphertext_sha256) },
    authorizesIo: false,
  };
}

function sameBytes(a, b) {
  return Buffer.isBuffer(a) && Buffer.isBuffer(b)
    && a.length === b.length && crypto.timingSafeEqual(a, b);
}

function hash(value) {
  return crypto.createHash("sha256").update(value).digest();
}

function rootBody(scope, sequence, previousRoot, entries) {
  return {
    type: SNAPSHOT_TYPE,
    version: VERSION,
    scope,
    sequence,
    previous_root: previousRoot,
    entries,
  };
}

async function computeRoot(scopeValue, sequenceValue, previousRootValue, entriesValue) {
  const scope = normalizeScope(scopeValue);
  const sequence = normalizeSequence(sequenceValue);
  const previousRoot = normalizePreviousRoot(previousRootValue, sequence);
  const entries = normalizeEntries(entriesValue);
  if (sequence !== entries.length) fail("INVENTORY_SEQUENCE");
  if (sequence === 0 && entries.length !== 0) fail("INVENTORY_GENESIS");
  const canonical = await z.encodeDeterministic(rootBody(scope, sequence, previousRoot, entries));
  return hash(Buffer.concat([ROOT_DOMAIN, canonical]));
}

function validatePrivateKey(value) {
  if (!(value instanceof crypto.KeyObject)
    || value.type !== "private" || value.asymmetricKeyType !== "ed25519") fail("INVENTORY_SIGNER_KEY");
  return value;
}

function validatePublicKey(value) {
  if (!(value instanceof crypto.KeyObject)
    || value.type !== "public" || value.asymmetricKeyType !== "ed25519") fail("INVENTORY_SIGNER_KEY");
  return value;
}

async function createSignedSnapshot(input) {
  const raw = exactObject(input, [
    "signerKeyId", "privateKey", "scope", "sequence", "previousRoot", "entries", "nonce",
  ]);
  const signerKeyId = copyBytes(raw.signerKeyId, 16);
  const privateKey = validatePrivateKey(raw.privateKey);
  const scope = normalizeScope(raw.scope);
  const sequence = normalizeSequence(raw.sequence);
  const previousRoot = normalizePreviousRoot(raw.previousRoot, sequence);
  const entries = normalizeEntries(raw.entries);
  const nonce = normalizeNonce(raw.nonce);
  if (sequence !== entries.length) fail("INVENTORY_SEQUENCE");
  if (sequence === 0 && entries.length !== 0) fail("INVENTORY_GENESIS");

  const body = rootBody(scope, sequence, previousRoot, entries);
  const root = hash(Buffer.concat([ROOT_DOMAIN, await z.encodeDeterministic(body)]));
  const unsigned = {
    ...body,
    signer_key_id: signerKeyId,
    root,
    nonce,
  };
  const signature = crypto.sign(null, Buffer.concat([
    SNAPSHOT_DOMAIN,
    await z.encodeDeterministic(unsigned),
  ]), privateKey);
  const serialized = await z.encodeDeterministic({ ...unsigned, signature });
  if (serialized.length > MAX_SNAPSHOT_BYTES) fail("INVENTORY_LIMIT");
  return serialized;
}

async function parseAndVerifySnapshot(serializedValue, publicKey, pinnedSignerKeyId, expectedScope) {
  const serialized = copyBytes(serializedValue, 1, MAX_SNAPSHOT_BYTES);
  let decoded;
  try { decoded = await z.decodeDeterministic(serialized); } catch (_) { fail("INVENTORY_ENCODING"); }
  const raw = exactObject(decoded, SNAPSHOT_FIELDS, "INVENTORY_FIELDS");
  if (raw.type !== SNAPSHOT_TYPE || raw.version !== VERSION) fail("INVENTORY_VERSION");
  const signerKeyId = copyBytes(raw.signer_key_id, 16);
  if (!sameBytes(signerKeyId, pinnedSignerKeyId)) fail("INVENTORY_SIGNER");
  const scope = normalizeScope(raw.scope);
  if (!sameBytes(scope.account_id, expectedScope.account_id)
    || !sameBytes(scope.compartment_id, expectedScope.compartment_id)
    || !sameBytes(scope.keyring_id, expectedScope.keyring_id)) fail("INVENTORY_SCOPE");
  const sequence = normalizeSequence(raw.sequence);
  const previousRoot = normalizePreviousRoot(raw.previous_root, sequence);
  const root = copyBytes(raw.root, 32);
  const nonce = normalizeNonce(raw.nonce);
  const signature = copyBytes(raw.signature, 64);
  const entries = normalizeEntries(raw.entries);
  if (sequence !== entries.length) fail("INVENTORY_SEQUENCE");
  if (sequence === 0 && entries.length !== 0) fail("INVENTORY_GENESIS");

  const body = rootBody(scope, sequence, previousRoot, entries);
  const calculatedRoot = hash(Buffer.concat([ROOT_DOMAIN, await z.encodeDeterministic(body)]));
  if (!sameBytes(root, calculatedRoot)) fail("INVENTORY_ROOT");
  const unsigned = { ...body, signer_key_id: signerKeyId, root, nonce };
  let valid = false;
  try {
    valid = crypto.verify(null, Buffer.concat([
      SNAPSHOT_DOMAIN,
      await z.encodeDeterministic(unsigned),
    ]), publicKey, signature);
  } catch (_) { fail("INVENTORY_SIGNATURE"); }
  if (!valid) fail("INVENTORY_SIGNATURE");
  return { sequence, previousRoot, root, nonce, entries, scope, signerKeyId, serialized };
}

function assertSuperset(currentEntries, previousEntries) {
  const current = new Map(currentEntries.map((entry) => [
    `${entry.object_id.toString("hex")}:${entry.revision}`,
    entry,
  ]));
  for (const previous of previousEntries) {
    const key = `${previous.object_id.toString("hex")}:${previous.revision}`;
    const entry = current.get(key);
    if (!entry) fail("INVENTORY_REMOVED");
    if (entry.epoch !== previous.epoch || !sameBytes(entry.ciphertext_sha256, previous.ciphertext_sha256)) {
      fail("INVENTORY_MUTATED");
    }
  }
}

async function verifySnapshot(input) {
  const raw = objectWithOptional(input, [
    "serialized", "pinnedPublicKey", "pinnedSignerKeyId", "expectedScope", "requested",
    "minimumHead", "nonce",
  ], ["minimumSnapshot"], "INVENTORY_VERIFY_INPUT");
  const publicKey = validatePublicKey(raw.pinnedPublicKey);
  const pinnedSignerKeyId = copyBytes(raw.pinnedSignerKeyId, 16);
  const expectedScope = normalizeScope(raw.expectedScope);
  const requested = normalizeRequested(raw.requested);
  const minimumHead = normalizeMinimumHead(raw.minimumHead);
  const nonce = normalizeNonce(raw.nonce);
  const serialized = copyBytes(raw.serialized, 1, MAX_SNAPSHOT_BYTES);
  const minimumSnapshot = raw.minimumSnapshot === null || raw.minimumSnapshot === undefined
    ? null : copyBytes(raw.minimumSnapshot, 1, MAX_SNAPSHOT_BYTES);

  const current = await parseAndVerifySnapshot(serialized, publicKey, pinnedSignerKeyId, expectedScope);
  if (!sameBytes(current.nonce, nonce)) fail("INVENTORY_NONCE");
  if (current.sequence < minimumHead.sequence) fail("INVENTORY_STALE");

  let previous = null;
  if (current.sequence === minimumHead.sequence) {
    if (!sameBytes(current.root, minimumHead.root)) fail("INVENTORY_FLOOR");
  } else {
    if (current.sequence !== minimumHead.sequence + 1) fail("INVENTORY_FLOOR_GAP");
    if (!current.previousRoot || !sameBytes(current.previousRoot, minimumHead.root)) {
      fail("INVENTORY_CHAIN");
    }
    if (!minimumSnapshot) fail("INVENTORY_HISTORY_REQUIRED");
    previous = await parseAndVerifySnapshot(minimumSnapshot, publicKey, pinnedSignerKeyId, expectedScope);
    if (previous.sequence !== minimumHead.sequence || !sameBytes(previous.root, minimumHead.root)) {
      fail("INVENTORY_FLOOR_PROOF");
    }
    assertSuperset(current.entries, previous.entries);
  }

  let matched = null;
  for (const entry of current.entries) {
    const order = Buffer.compare(entry.object_id, requested.object_id);
    if (order > 0) break;
    if (order === 0 && entry.revision === requested.revision) {
      if (entry.epoch !== requested.epoch
        || !sameBytes(entry.ciphertext_sha256, requested.ciphertext_sha256)) fail("INVENTORY_ITEM_MISMATCH");
      matched = entry;
      break;
    }
  }
  return {
    status: "VERIFIED_NONAUTHORIZING",
    outcome: matched ? "PRESENT" : "ABSENT",
    sequence: current.sequence,
    root: Buffer.from(current.root),
    scope: {
      account_id: Buffer.from(current.scope.account_id),
      compartment_id: Buffer.from(current.scope.compartment_id),
      keyring_id: Buffer.from(current.scope.keyring_id),
    },
    tuple: matched ? {
      object_id: Buffer.from(matched.object_id),
      revision: matched.revision,
      epoch: matched.epoch,
      ciphertext_sha256: Buffer.from(matched.ciphertext_sha256),
    } : null,
  };
}

module.exports = {
  SNAPSHOT_TYPE,
  VERSION,
  MAX_ENTRIES,
  MAX_SNAPSHOT_BYTES,
  MAX_TERMINAL_PROOF_BYTES,
  MAX_COMMITTED_PROOF_BYTES,
  MAX_SEQUENCE,
  ContentInventoryError,
  normalizeScope,
  normalizeEntry,
  normalizeEntries,
  normalizeNonce,
  normalizeRequested,
  normalizeMinimumHead,
  computeRoot,
  createSignedSnapshot,
  createTerminalProof,
  verifyTerminalProof,
  verifyCommittedEntryProof,
  verifySnapshot,
};
