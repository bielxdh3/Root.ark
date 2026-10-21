'use strict';

// Pure, synthetic contract vectors only. This is NOT a production signer,
// verifier, trusted device, live authority, or cryptographic deployment audit.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const z = require('../src/crypto/rootark-zk-1');

const registry = JSON.parse(fs.readFileSync(path.join(__dirname,
  '../docs/superpowers/specs/2026-10-20-rootark-zk1-v1-wire-type-registry.json'), 'utf8'));
const definitions = Object.freeze({
  fresh_witness_head: ['rootark-recovery-witness-head/v1', 'Root.ark/zk-1/recovery-witness-head/v1'],
  cas_terminal_status: ['rootark-recovery-cas-status/v1', 'Root.ark/zk-1/recovery-cas-status/v1'],
  witness_reservation: ['rootark-recovery-witness-reservation/v1', 'Root.ark/zk-1/recovery-witness-reservation/v1'],
  witness_commit: ['rootark-recovery-witness-commit/v1', 'Root.ark/zk-1/recovery-witness-commit/v1'],
  witness_cancel: ['rootark-recovery-witness-cancel/v1', 'Root.ark/zk-1/recovery-witness-cancel/v1'],
});
const fields = Object.freeze({
  cas_terminal_status: [
    'type', 'status_authority_key_id', 'account_id', 'compartment_id', 'keyring_id',
    'reservation_id', 'operation_id', 'request_digest', 'package_envelope_digest',
    'expected_revision', 'expected_manifest_digest', 'proposed_revision', 'proposed_manifest_digest',
    'observed_revision', 'observed_manifest_digest', 'terminal_status', 'observed_at', 'nonce', 'signature',
  ],
  witness_reservation: [
    'type', 'reservation_id', 'witness_key_id', 'account_id', 'compartment_id', 'keyring_id',
    'expected_revision', 'expected_manifest_digest', 'proposed_revision', 'proposed_manifest_digest',
    'operation_id', 'request_digest', 'package_envelope_digest', 'expires_at', 'signature',
  ],
  witness_commit: [
    'type', 'reservation_id', 'account_id', 'compartment_id', 'keyring_id', 'committed_revision',
    'committed_manifest_digest', 'operation_id', 'witness_sequence', 'status', 'signature',
  ],
  witness_cancel: [
    'type', 'witness_key_id', 'account_id', 'compartment_id', 'keyring_id', 'reservation_id',
    'operation_id', 'status_authority_proof_digest', 'resolved_at', 'status', 'signature',
  ],
});
const b16 = Buffer.alloc(16, 0x11);
const b32 = Buffer.alloc(32, 0x22);
const scoped = {
  account_id: b16, compartment_id: Buffer.from('fixture', 'ascii'), keyring_id: b16,
};
function unsignedFor(kind) {
  const type = definitions[kind][0];
  if (kind === 'cas_terminal_status') {
    return {
      type, status_authority_key_id: b16, ...scoped, reservation_id: b16, operation_id: b16,
      request_digest: b32, package_envelope_digest: null, expected_revision: 1,
      expected_manifest_digest: b32, proposed_revision: 2, proposed_manifest_digest: b32,
      observed_revision: 1, observed_manifest_digest: b32, terminal_status: 'not-committed-final',
      observed_at: 1760000000, nonce: Buffer.alloc(32, 0x33),
    };
  }
  if (kind === 'witness_reservation') {
    return {
      type, reservation_id: b16, witness_key_id: b16, ...scoped, expected_revision: 1,
      expected_manifest_digest: b32, proposed_revision: 2, proposed_manifest_digest: b32,
      operation_id: b16, request_digest: b32, package_envelope_digest: null, expires_at: 1760000300,
    };
  }
  if (kind === 'witness_commit') {
    return {
      type, reservation_id: b16, ...scoped, committed_revision: 2, committed_manifest_digest: b32,
      operation_id: b16, witness_sequence: 2, status: 'committed',
    };
  }
  return {
    type, witness_key_id: b16, ...scoped, reservation_id: b16, operation_id: b16,
    status_authority_proof_digest: b32, resolved_at: 1760000350, status: 'cancelled',
  };
}
async function signedBytes(kind, value, domain = definitions[kind][1]) {
  return Buffer.concat([
    Buffer.from(domain + '\0', 'ascii'),
    await z.encodeDeterministic(value),
  ]);
}
async function sign(kind, unsigned, key, domain) {
  const signature = crypto.sign(null, await signedBytes(kind, unsigned, domain), key);
  return { ...unsigned, signature };
}
function bytesOfLength(value, length) {
  return (Buffer.isBuffer(value) || value instanceof Uint8Array) && value.byteLength === length;
}
function sameBytes(left, right) {
  return bytesOfLength(left, right?.byteLength) && (Buffer.isBuffer(right) || right instanceof Uint8Array)
    && crypto.timingSafeEqual(Buffer.from(left), Buffer.from(right));
}
function unsignedInteger(value, lower = 0n) {
  const n = typeof value === 'bigint' ? value : Number.isSafeInteger(value) ? BigInt(value) : -1n;
  return n >= lower && n <= 0xffffffffffffffffn;
}
function equalRevision(left, right) {
  return unsignedInteger(left) && unsignedInteger(right) && BigInt(left) === BigInt(right);
}
function nextRevision(expected, proposed) {
  if (!unsignedInteger(proposed, 1n)) return false;
  if (expected === null) return BigInt(proposed) === 1n;
  return unsignedInteger(expected, 1n) && BigInt(expected) < 0xffffffffffffffffn
    && BigInt(proposed) === BigInt(expected) + 1n;
}
function validScope(receipt) {
  return bytesOfLength(receipt.account_id, 16)
    && (Buffer.isBuffer(receipt.compartment_id) || receipt.compartment_id instanceof Uint8Array)
    && receipt.compartment_id.byteLength >= 1 && receipt.compartment_id.byteLength <= 128
    && bytesOfLength(receipt.keyring_id, 16)
    && bytesOfLength(receipt.operation_id, 16)
    && bytesOfLength(receipt.reservation_id, 16);
}
function validContractFields(kind, receipt) {
  if (!validScope(receipt)) return false;
  if (kind === 'cas_terminal_status' || kind === 'witness_reservation') {
    if (!bytesOfLength(receipt.request_digest, 32)
      || (receipt.package_envelope_digest !== null && !bytesOfLength(receipt.package_envelope_digest, 32))
      || !bytesOfLength(receipt.proposed_manifest_digest, 32)
      || !nextRevision(receipt.expected_revision, receipt.proposed_revision)) return false;
    const initialized = receipt.expected_revision === null;
    if (initialized !== (receipt.expected_manifest_digest === null)) return false;
    if (!initialized && !bytesOfLength(receipt.expected_manifest_digest, 32)) return false;
  }
  if (kind === 'cas_terminal_status') {
    if (!bytesOfLength(receipt.status_authority_key_id, 16)
      || !bytesOfLength(receipt.nonce, 32)
      || !unsignedInteger(receipt.observed_at)) return false;
    if ((receipt.observed_revision === null) !== (receipt.observed_manifest_digest === null)) return false;
    if (receipt.observed_revision !== null && (!unsignedInteger(receipt.observed_revision, 1n)
      || !bytesOfLength(receipt.observed_manifest_digest, 32))) return false;
    if (receipt.terminal_status === 'committed') {
      return equalRevision(receipt.observed_revision, receipt.proposed_revision)
        && sameBytes(receipt.observed_manifest_digest, receipt.proposed_manifest_digest);
    }
    return receipt.terminal_status === 'not-committed-final'
      && (receipt.expected_revision === null
        ? receipt.observed_revision === null
        : equalRevision(receipt.observed_revision, receipt.expected_revision)
          && sameBytes(receipt.observed_manifest_digest, receipt.expected_manifest_digest));
  }
  if (kind === 'witness_reservation') {
    return bytesOfLength(receipt.witness_key_id, 16) && unsignedInteger(receipt.expires_at);
  }
  if (kind === 'witness_commit') {
    return receipt.status === 'committed' && unsignedInteger(receipt.committed_revision, 1n)
      && equalRevision(receipt.witness_sequence, receipt.committed_revision)
      && bytesOfLength(receipt.committed_manifest_digest, 32);
  }
  return kind === 'witness_cancel' && receipt.status === 'cancelled'
    && bytesOfLength(receipt.witness_key_id, 16)
    && bytesOfLength(receipt.status_authority_proof_digest, 32)
    && unsignedInteger(receipt.resolved_at);
}
const TERMINAL_QUERY_FIELDS = Object.freeze([
  'account_id', 'compartment_id', 'keyring_id', 'reservation_id', 'operation_id',
  'request_digest', 'package_envelope_digest', 'expected_revision',
  'expected_manifest_digest', 'proposed_revision', 'proposed_manifest_digest',
]);
function exactWireValue(actual, expected) {
  if (actual === null || expected === null) return actual === expected;
  if (Buffer.isBuffer(expected) || expected instanceof Uint8Array) {
    return sameBytes(actual, expected);
  }
  if (typeof expected === 'number' || typeof expected === 'bigint') {
    return equalRevision(actual, expected);
  }
  return typeof actual === typeof expected && actual === expected;
}
async function verifyContract(kind, receipt, publicKey, overrides = {}) {
  const keys = Reflect.ownKeys(receipt);
  if (keys.length !== fields[kind].length || fields[kind].some((name) => !Object.hasOwn(receipt, name))
      || keys.some((name) => !fields[kind].includes(name))) return false;
  if (typeof receipt.type !== 'string' || receipt.type !== definitions[kind][0]) return false;
  if (!bytesOfLength(receipt.signature, 64) || !validContractFields(kind, receipt)) return false;
  if (kind === 'cas_terminal_status') {
    if (!overrides.exactQuery || !bytesOfLength(overrides.challenge, 32)
      || !sameBytes(receipt.nonce, overrides.challenge)) return false;
    if (TERMINAL_QUERY_FIELDS.some((field) => !Object.hasOwn(overrides.exactQuery, field)
      || !exactWireValue(receipt[field], overrides.exactQuery[field]))) return false;
  }
  if (kind === 'witness_cancel' && (!bytesOfLength(overrides.proofDigest, 32)
    || !sameBytes(receipt.status_authority_proof_digest, overrides.proofDigest))) return false;
  const { signature, ...unsigned } = receipt;
  return crypto.verify(null, await signedBytes(kind, unsigned), publicKey, signature);
}
function bindingFor(kind, unsigned) {
  if (kind === 'cas_terminal_status') {
    return { challenge: unsigned.nonce, exactQuery: unsigned };
  }
  if (kind === 'witness_cancel') {
    return { proofDigest: unsigned.status_authority_proof_digest };
  }
  return {};
}

test('registry freezes the five noncolliding type/domain pairs; withdrawn draft is excluded', () => {
  assert.deepEqual(Object.keys(registry.objects).sort(), Object.keys(definitions).sort());
  const types = new Set(), domains = new Set();
  for (const [name, [type, domain]] of Object.entries(definitions)) {
    assert.deepEqual(registry.objects[name], { type, domain });
    assert.match(type, /^rootark-recovery-[a-z-]+\/v1$/);
    assert.match(domain, /^Root\.ark\/zk-1\/recovery-[a-z-]+\/v1$/);
    assert.ok(!types.has(type) && !domains.has(domain));
    types.add(type);
    domains.add(domain);
  }
  assert.ok(!types.has('rootark-cas-terminal-status/v1'));
  assert.ok(!domains.has('Root.ark/zk-1/cas-terminal-status/v1'));
});

test('real deterministic CBOR / Ed25519 test vectors bind exact type, domain, fields and bytes', async () => {
  const authority = crypto.generateKeyPairSync('ed25519');
  const witness = crypto.generateKeyPairSync('ed25519');
  for (const kind of Object.keys(fields)) {
    const keys = kind === 'cas_terminal_status' ? authority : witness;
    const unsigned = unsignedFor(kind);
    const signed = await sign(kind, unsigned, keys.privateKey);
    const context = bindingFor(kind, unsigned);
    assert.equal(await verifyContract(kind, signed, keys.publicKey, context), true, kind);
    assert.equal(await verifyContract(kind, { ...signed, type: 'wrong-type/v1' }, keys.publicKey, context), false);
    const differentType = kind === 'cas_terminal_status'
      ? definitions.witness_reservation[0] : definitions.cas_terminal_status[0];
    assert.equal(await verifyContract(kind, await sign(kind, { ...unsigned, type: differentType },
      keys.privateKey), keys.publicKey, context), false, 'valid signature under pinned domain must not bypass type guard');
    assert.equal(await verifyContract(kind, { ...signed, extra: 'unexpected' }, keys.publicKey, context), false);
    assert.equal(await verifyContract(kind, { ...signed, signature: Buffer.alloc(64) }, keys.publicKey, context), false);
    assert.equal(await verifyContract(kind, await sign(kind, unsigned, keys.privateKey,
      'Root.ark/zk-1/other-signing-context/v1'), keys.publicKey, context), false);
    const altered = { ...signed, operation_id: Buffer.alloc(16, 0x99) };
    assert.equal(await verifyContract(kind, altered, keys.publicKey, context), false);
    assert.equal(await verifyContract(kind, signed, kind === 'cas_terminal_status'
      ? witness.publicKey : authority.publicKey, context), false);
  }
});

test('status challenge and cancellation proof digest bind full signed canonical CAS proof', async () => {
  const statusKey = crypto.generateKeyPairSync('ed25519');
  const witnessKey = crypto.generateKeyPairSync('ed25519');
  const proof = await sign('cas_terminal_status', unsignedFor('cas_terminal_status'), statusKey.privateKey);
  const proofDigest = crypto.createHash('sha256').update(await z.encodeDeterministic(proof)).digest();
  const cancellation = await sign('witness_cancel', {
    ...unsignedFor('witness_cancel'), status_authority_proof_digest: proofDigest,
  }, witnessKey.privateKey);
  assert.equal(await verifyContract('cas_terminal_status', proof, statusKey.publicKey,
    { challenge: Buffer.alloc(32, 0x33), exactQuery: unsignedFor('cas_terminal_status') }), true);
  assert.equal(await verifyContract('cas_terminal_status', proof, statusKey.publicKey,
    { challenge: Buffer.alloc(32, 0x34), exactQuery: unsignedFor('cas_terminal_status') }), false);
  assert.equal(await verifyContract('witness_cancel', cancellation, witnessKey.publicKey, { proofDigest }), true);
  const otherProofDigest = crypto.createHash('sha256').update(
    await z.encodeDeterministic({ ...proof, signature: Buffer.alloc(64, 0x01) })).digest();
  assert.equal(await verifyContract('witness_cancel', cancellation, witnessKey.publicKey,
    { proofDigest: otherProofDigest }), false);
});

test('valid signatures cannot authorize invalid scope, byte widths, revisions or status semantics', async () => {
  const authority = crypto.generateKeyPairSync('ed25519');
  const witness = crypto.generateKeyPairSync('ed25519');
  const invalid = {
    cas_terminal_status: [
      { account_id: Buffer.alloc(15) },
      { compartment_id: Buffer.alloc(129) },
      { status_authority_key_id: Buffer.alloc(17) },
      { expected_revision: null },
      { proposed_revision: 4 },
      { observed_manifest_digest: Buffer.alloc(31) },
      { terminal_status: 'pending' },
      { nonce: Buffer.alloc(31) },
      { observed_at: -1 },
    ],
    witness_reservation: [
      { witness_key_id: Buffer.alloc(14) },
      { package_envelope_digest: Buffer.alloc(31) },
      { expected_manifest_digest: null },
      { proposed_revision: 3 },
      { expires_at: -1 },
    ],
    witness_commit: [
      { status: 'pending' },
      { committed_manifest_digest: Buffer.alloc(31) },
      { witness_sequence: 0 },
    ],
    witness_cancel: [
      { status: 'committed' },
      { status_authority_proof_digest: Buffer.alloc(31) },
      { resolved_at: -1 },
    ],
  };
  for (const [kind, mutations] of Object.entries(invalid)) {
    const key = kind === 'cas_terminal_status' ? authority : witness;
    const unsigned = unsignedFor(kind);
    for (const changed of mutations) {
      const mutated = { ...unsigned, ...changed };
      if (Object.values(changed).some((value) => value === -1)) {
        await assert.rejects(sign(kind, mutated, key.privateKey),
          (error) => error.code === 'UNSUPPORTED_CBOR_VALUE');
        continue;
      }
      const signed = await sign(kind, mutated, key.privateKey);
      assert.equal(await verifyContract(kind, signed, key.publicKey, bindingFor(kind, mutated)), false,
        kind + ' must reject signed invalid field ' + Object.keys(changed)[0]);
    }
  }
});

test('hostile raw CBOR fails closed and a canonical signed wire object round-trips', async () => {
  const malformedWire = [
    ['duplicate map keys', 'a2616101616102'],
    ['noncanonical map key order', 'a2616202616101'],
    ['nonminimal integer', '1801'],
    ['indefinite map', 'bfff'],
    ['trailing CBOR item', 'f6f6'],
    ['forbidden prototype map key', 'a1695f5f70726f746f5f5f01'],
  ];
  for (const [name, hex] of malformedWire) {
    await assert.rejects(z.decodeDeterministic(Buffer.from(hex, 'hex')),
      (error) => error instanceof z.RootarkZkError, name);
  }

  const statusKey = crypto.generateKeyPairSync('ed25519');
  const signed = await sign('cas_terminal_status', unsignedFor('cas_terminal_status'), statusKey.privateKey);
  const rawBytes = await z.encodeDeterministic(signed);
  const parsed = await z.decodeDeterministic(rawBytes);
  assert.equal(await verifyContract('cas_terminal_status', parsed, statusKey.publicKey,
    bindingFor('cas_terminal_status', parsed)), true);
  const { signature: oldSignature, ...unsignedWrongType } = {
    ...parsed, type: definitions.witness_commit[0],
  };
  assert.equal(oldSignature.byteLength, 64);
  const reSignedWrongType = await sign('cas_terminal_status', unsignedWrongType, statusKey.privateKey);
  assert.equal(await verifyContract('cas_terminal_status',
    await z.decodeDeterministic(await z.encodeDeterministic(reSignedWrongType)),
    statusKey.publicKey, bindingFor('cas_terminal_status', parsed)), false);
});

test('a validly signed status proof for a different query must not authorize this request', async () => {
  const pair = crypto.generateKeyPairSync('ed25519');
  const requested = unsignedFor('cas_terminal_status');
  const validProof = await sign('cas_terminal_status', requested, pair.privateKey);
  assert.equal(await verifyContract('cas_terminal_status', validProof, pair.publicKey,
    { challenge: requested.nonce, exactQuery: requested }), true);
  for (const [field, replacement] of [
    ['account_id', Buffer.alloc(16, 0x55)],
    ['reservation_id', Buffer.alloc(16, 0x56)],
    ['operation_id', Buffer.alloc(16, 0x57)],
    ['request_digest', Buffer.alloc(32, 0x58)],
    ['package_envelope_digest', Buffer.alloc(32, 0x59)],
    ['expected_manifest_digest', Buffer.alloc(32, 0x5a)],
    ['proposed_manifest_digest', Buffer.alloc(32, 0x5b)],
  ]) {
    const changed = { ...requested, [field]: replacement };
    if (field === 'expected_manifest_digest') changed.observed_manifest_digest = replacement;
    const otherValidProof = await sign('cas_terminal_status', changed, pair.privateKey);
    assert.equal(await verifyContract('cas_terminal_status', otherValidProof, pair.publicKey,
      { challenge: requested.nonce, exactQuery: requested }), false,
    'must bind signed '+ field +' to original query');
  }
});

test('no status proof or cancellation receipt is accepted without its required external binding', async () => {
  const statusKey = crypto.generateKeyPairSync('ed25519');
  const witnessKey = crypto.generateKeyPairSync('ed25519');
  const statusUnsigned = unsignedFor('cas_terminal_status');
  const statusProof = await sign('cas_terminal_status', statusUnsigned, statusKey.privateKey);
  assert.equal(await verifyContract('cas_terminal_status', statusProof, statusKey.publicKey), false,
    'status receipt without nonce/query context must fail closed');
  assert.equal(await verifyContract('cas_terminal_status', statusProof, statusKey.publicKey,
    { challenge: statusUnsigned.nonce }), false, 'nonce alone cannot bind the operation tuple');
  assert.equal(await verifyContract('cas_terminal_status', statusProof, statusKey.publicKey,
    { exactQuery: statusUnsigned }), false, 'query without challenge cannot prove freshness');
  const cancellationUnsigned = unsignedFor('witness_cancel');
  const cancellation = await sign('witness_cancel', cancellationUnsigned, witnessKey.privateKey);
  assert.equal(await verifyContract('witness_cancel', cancellation, witnessKey.publicKey), false,
    'cancellation without a verified status proof digest must fail closed');
});
