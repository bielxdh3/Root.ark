"use strict";

// Standalone opt-in operator service. Must run outside the CAS/FLOOR processes.
// Even a valid receipt is NEVER a capability to write, restore or cut over.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const z = require("../crypto/rootark-zk-1");
const { nativeEd25519Spki } = require("../crypto/rootark-zk1-native-ed25519-public-key");
const { inspectLegacyArchiveReadback, verifyLegacyArchiveDualReadback } =
  require("./zk1OpaqueCheckpointV2Remote");
const { assertPrivateSqliteFile, assertPrivateSqliteAuthorityDirectory } =
  require("./zk1PrivateSqlitePath");
const { assertSafeSqliteSidecars } = require("./zk1OpaqueCheckpointV2SqliteGuard");

const SUBJECT_DOMAIN = Buffer.from(
  "Root.ark/zk-1/opaque-checkpoint-v2-legacy-stage-witness-subject/v1\0");
const RECEIPT_DOMAIN = Buffer.from(
  "Root.ark/zk-1/opaque-checkpoint-v2-independent-stage-ledger/v2\0");
// A ledger head can only be minted from live, pinned independent owner/V1/V2
// verification. An offline CAS/FLOOR signature alone cannot attest owner
// revision, epoch or digest. Never import v1 receipts as live evidence.
const PROVENANCE = Object.freeze({
  STAGED: "LIVE_OWNER_V1_V2_READBACK",
  WITHDRAWN: "OPERATOR_WITHDRAWAL_OF_LIVE_STAGE",
});
const GENESIS = Buffer.alloc(32).toString("base64url");
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const PINS = ["ownerPublicKey", "archiveCheckpointPublicKey", "v1CasPublicKey",
  "v1FloorPublicKey", "v2CasPublicKey", "v2FloorPublicKey"];
const OWNER_WITNESS_PIN_FIELDS = ["pinnedWitness", "minimumHead"];
const SUBJECT_FIELDS = ["type", ...SCOPE, "legacy_sequence", "owner_revision",
  "owner_digest", "owner_epoch", "cas_signer_fp", "floor_signer_fp",
  "legacy_base_digest", "legacy_base_checkpoint", "legacy_head_digest",
  "legacy_checkpoint_digest", "legacy_operation_id", "full_archive_root",
  "full_archive_checkpoint", "owner_consent_hash"];
const BINDINGS = ["legacy_base_digest", "legacy_base_checkpoint",
  "legacy_head_digest", "legacy_checkpoint_digest", "legacy_operation_id",
  "full_archive_root", "full_archive_checkpoint", "owner_consent_hash"];
const RECEIPT_FIELDS = ["type", "generation", "action", "subjectDigest",
  "previousHash", "trustHash", "provenance", "issuedAt"];
const SCHEMA = `
CREATE TABLE stage_config (
  marker INTEGER PRIMARY KEY CHECK(marker=1), trust_hash TEXT NOT NULL
);
CREATE TRIGGER config_no_update BEFORE UPDATE ON stage_config
BEGIN SELECT RAISE(ABORT,'IMMUTABLE_STAGE_TRUST'); END;
CREATE TRIGGER config_no_delete BEFORE DELETE ON stage_config
BEGIN SELECT RAISE(ABORT,'IMMUTABLE_STAGE_TRUST'); END;
CREATE TABLE stage_receipts (
  generation INTEGER PRIMARY KEY CHECK(generation BETWEEN 1 AND 1000000),
  action TEXT NOT NULL CHECK(action IN ('STAGED','WITHDRAWN')),
  subject_digest TEXT NOT NULL,
  previous_hash TEXT NOT NULL,
  receipt_hash TEXT NOT NULL UNIQUE,
  signed_receipt BLOB NOT NULL
);
CREATE TRIGGER receipts_no_update BEFORE UPDATE ON stage_receipts
BEGIN SELECT RAISE(ABORT,'IMMUTABLE_STAGE_WITNESS'); END;
CREATE TRIGGER receipts_no_delete BEFORE DELETE ON stage_receipts
BEGIN SELECT RAISE(ABORT,'IMMUTABLE_STAGE_WITNESS'); END;
CREATE TRIGGER receipts_sequential BEFORE INSERT ON stage_receipts
WHEN NEW.generation != (SELECT COALESCE(MAX(generation),0)+1 FROM stage_receipts)
BEGIN SELECT RAISE(ABORT,'STAGE_WITNESS_SEQUENCE'); END;
`;

function deny() { const e = Error("ZK_LEGACY_STAGE_WITNESS_DENIED"); e.code = e.message; throw e; }
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))) deny();
}
function b64(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)
    || Buffer.from(value, "base64url").toString("base64url") !== value) deny();
  return Buffer.from(value, "base64url");
}
function digest(...parts) { const h = crypto.createHash("sha256");
  for (const part of parts) h.update(part); return h.digest("base64url"); }
function fingerprint(k) {
  if (!(k instanceof crypto.KeyObject) || k.type !== "public"
    || k.asymmetricKeyType !== "ed25519") deny();
  return digest(nativeEd25519Spki(k));
}
function validReceipt(raw, publicKey) {
  if (!Buffer.isBuffer(raw) || raw.length < 20 || raw.length > 4096) deny();
  let parsed;
  try { parsed = JSON.parse(raw.toString("utf8")); } catch (_) { deny(); }
  exact(parsed, [...RECEIPT_FIELDS, "signature"]);
  const { signature, ...statement } = parsed;
  exact(statement, RECEIPT_FIELDS);
  if (statement.type !== "rootark-zk1-independent-legacy-stage-ledger/v2"
    || !Number.isSafeInteger(statement.generation) || statement.generation < 1
    || statement.generation > 1000000
    || !["STAGED", "WITHDRAWN"].includes(statement.action)
    || statement.provenance !== PROVENANCE[statement.action]
    || !Number.isSafeInteger(statement.issuedAt) || statement.issuedAt < 1) deny();
  b64(statement.subjectDigest); b64(statement.previousHash);
  const message = Buffer.from(JSON.stringify(statement));
  if (!crypto.verify(null, Buffer.concat([RECEIPT_DOMAIN, message]), publicKey,
    Buffer.from(signature, "base64url"))
    || Buffer.from(signature, "base64url").length !== 64
    || Buffer.from(JSON.stringify(parsed)).compare(raw) !== 0) deny();
  return statement;
}
function rejectAuthorization(report) {
  return Object.freeze({ ...report, v2WriteAuthorized: false,
    restoreAuthorized: false, destructiveCutoverAuthorized: false,
    independentMonotonicStageWitnessProven: false,
    externalProviderDurabilityProven: false });
}

class Zk1LegacyArchiveStageWitness {
  constructor({ filename, bootstrapNew, privateKey, witnessPublicKey,
    trustedScope, operatorPins, trustedOwnerWitness }) {
    if (!path.isAbsolute(filename) || typeof bootstrapNew !== "boolean"
      || !(privateKey instanceof crypto.KeyObject) || privateKey.type !== "private"
      || privateKey.asymmetricKeyType !== "ed25519") deny();
    exact(operatorPins, PINS);
    this.pins = Object.freeze(Object.fromEntries(PINS.map((name) =>
      [name, operatorPins[name]])));
    const signerPin = fingerprint(witnessPublicKey);
    if (fingerprint(crypto.createPublicKey(privateKey)) !== signerPin) deny();
    if (new Set([...PINS.map((name) => fingerprint(this.pins[name])), signerPin]).size !== 7) deny();
    // The signed owner witness is a SEVENTH independently provisioned
    // authority, not an input supplied by the readback request. Pin its
    // signer, key id and externally retained minimum before opening SQLite.
    exact(trustedOwnerWitness, OWNER_WITNESS_PIN_FIELDS);
    exact(trustedOwnerWitness.pinnedWitness, ["publicKey", "keyId"]);
    exact(trustedOwnerWitness.minimumHead, ["revision", "witnessSequence", "digest"]);
    const witnessFp = fingerprint(trustedOwnerWitness.pinnedWitness.publicKey);
    const keyId = trustedOwnerWitness.pinnedWitness.keyId;
    const minimum = trustedOwnerWitness.minimumHead;
    if (!(keyId instanceof Uint8Array) || keyId.length !== 16
      || !(minimum.digest instanceof Uint8Array) || minimum.digest.length !== 32
      || !Number.isSafeInteger(minimum.revision) || minimum.revision < 1
      || !Number.isSafeInteger(minimum.witnessSequence) || minimum.witnessSequence < 1
      || new Set([...PINS.map((name) => fingerprint(this.pins[name])), signerPin,
        witnessFp]).size !== 8) deny();
    this.trustedOwnerWitness = Object.freeze({
      publicKey: trustedOwnerWitness.pinnedWitness.publicKey,
      fingerprint: witnessFp, keyId: Buffer.from(keyId).toString("base64url"),
      revision: minimum.revision, witnessSequence: minimum.witnessSequence,
      digest: Buffer.from(minimum.digest).toString("base64url"),
    });
    exact(trustedScope, SCOPE);
    this.scope = Object.fromEntries(SCOPE.map((name) => [name,
      Buffer.from(trustedScope[name])]));
    for (const name of SCOPE) {
      if (this.scope[name].length < 1 || this.scope[name].length > 128
        || (name !== "compartment_id" && this.scope[name].length !== 16)) deny();
    }
    this.trustHash = digest(RECEIPT_DOMAIN, ...SCOPE.map((name) => this.scope[name]),
      ...PINS.map((name) => b64(fingerprint(this.pins[name]))), b64(signerPin),
      Buffer.from(JSON.stringify([this.trustedOwnerWitness.fingerprint,
        this.trustedOwnerWitness.keyId, this.trustedOwnerWitness.revision,
        this.trustedOwnerWitness.witnessSequence, this.trustedOwnerWitness.digest])));
    this.privateKey = privateKey;
    this.publicKey = witnessPublicKey;
    this.filename = filename;
    this.bootstrapNew = bootstrapNew;
    assertPrivateSqliteAuthorityDirectory(filename);
    if (bootstrapNew) {
      if (fs.existsSync(filename)) deny();
      const fd = fs.openSync(filename, fs.constants.O_CREAT | fs.constants.O_EXCL
        | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0), 0o600);
      fs.closeSync(fd);
    }
    assertPrivateSqliteFile(filename);
    assertSafeSqliteSidecars(filename, deny);
    this.db = new Database(filename, { fileMustExist: true, timeout: 1500 });
    try {
      this.db.pragma("journal_mode = WAL");
      this.db.pragma("synchronous = FULL");
      if (bootstrapNew) {
        this.db.exec(SCHEMA);
        this.db.prepare("INSERT INTO stage_config (marker,trust_hash) VALUES (1,?)")
          .run(this.trustHash);
      }
      this.assertSchema();
      this.audit();
    } catch (error) {
      this.db.close();
      throw error;
    }
  }
  assertSchema() {
    assertPrivateSqliteAuthorityDirectory(this.filename);
    assertPrivateSqliteFile(this.filename);
    assertSafeSqliteSidecars(this.filename, deny);
    const actual = this.db.prepare(`SELECT type,name,sql FROM sqlite_master
      WHERE name IN ('stage_config','config_no_update','config_no_delete',
        'stage_receipts','receipts_no_update',
        'receipts_no_delete','receipts_sequential') ORDER BY name`).all();
    if (actual.length !== 7 || new Set(actual.map((v) => v.name)).size !== 7
      || actual.filter((v) => v.type === "trigger").length !== 5
      || actual.filter((v) => v.type === "table").length !== 2) deny();
    // Detect trigger removal/replacement without writing to the customer's ledger.
    const reference = new Database(":memory:");
    try {
      reference.exec(SCHEMA);
      const expected = reference.prepare(`SELECT type,name,sql FROM sqlite_master
        WHERE name IN ('stage_config','config_no_update','config_no_delete',
          'stage_receipts','receipts_no_update',
          'receipts_no_delete','receipts_sequential') ORDER BY name`).all();
      if (JSON.stringify(actual) !== JSON.stringify(expected)) deny();
    } finally { reference.close(); }
    const settings = this.db.prepare("SELECT * FROM stage_config").all();
    if (settings.length !== 1 || settings[0].marker !== 1
      || settings[0].trust_hash !== this.trustHash) deny();
  }
  audit(minimumHead = null) {
    this.assertSchema();
    const rows = this.db.prepare("SELECT * FROM stage_receipts ORDER BY generation").all();
    if (rows.length > 1000000) deny();
    let head = null;
    for (const row of rows) {
      const parsed = validReceipt(row.signed_receipt, this.publicKey);
      const expectedGeneration = head ? head.generation + 1 : 1;
      if (row.generation !== expectedGeneration || parsed.generation !== row.generation
        || parsed.action !== row.action || parsed.subjectDigest !== row.subject_digest
        || parsed.trustHash !== this.trustHash
        || parsed.previousHash !== row.previous_hash
        || row.previous_hash !== (head ? head.hash : GENESIS)
        || (row.action === "WITHDRAWN" && (!head || head.action !== "STAGED"
          || head.subjectDigest !== row.subject_digest))
        || (row.action === "STAGED" && head?.action === "STAGED")
        || parsed.provenance !== PROVENANCE[row.action]) deny();
      const hash = digest(RECEIPT_DOMAIN, row.signed_receipt);
      if (hash !== row.receipt_hash) deny();
      head = { ...parsed, hash, raw: Buffer.from(row.signed_receipt).toString("base64url") };
    }
    if (minimumHead !== null) {
      const floor = this.validateHead(minimumHead);
      const atFloor = rows[floor.generation - 1];
      if (!atFloor || atFloor.receipt_hash !== floor.hash) deny();
    }
    return head ? Object.freeze(head) : null;
  }
  validateHead(head) {
    exact(head, [...RECEIPT_FIELDS, "hash", "raw"]);
    const raw = Buffer.from(head.raw, "base64url");
    const verified = validReceipt(raw, this.publicKey);
    if (Object.entries(verified).some(([k, value]) => k !== "type" && head[k] !== value)
      || digest(RECEIPT_DOMAIN, raw) !== head.hash) deny();
    return head;
  }
  #append(action, subjectDigest, expectedHead, provenance) {
    b64(subjectDigest);
    if (provenance !== PROVENANCE[action]) deny();
    if (expectedHead !== null) this.validateHead(expectedHead);
    return this.db.transaction(() => {
      const head = this.audit();
      if ((expectedHead === null) !== (head === null)
        || (head && (expectedHead.hash !== head.hash
          || expectedHead.generation !== head.generation))) deny();
      if (head && (head.action === "STAGED" && (action !== "WITHDRAWN"
        || head.subjectDigest !== subjectDigest)
        || head.action === "WITHDRAWN" && action !== "STAGED")) deny();
      const statement = { type: "rootark-zk1-independent-legacy-stage-ledger/v2",
        generation: head ? head.generation + 1 : 1, action, subjectDigest,
        previousHash: head ? head.hash : GENESIS,
        trustHash: this.trustHash,
        provenance,
        issuedAt: Math.floor(Date.now() / 1000) };
      if (statement.generation > 1000000) deny();
      const unsigned = Buffer.from(JSON.stringify(statement));
      const signature = crypto.sign(null, Buffer.concat([RECEIPT_DOMAIN, unsigned]),
        this.privateKey).toString("base64url");
      const raw = Buffer.from(JSON.stringify({ ...statement, signature }));
      this.db.prepare(`INSERT INTO stage_receipts
        (generation, action, subject_digest, previous_hash, receipt_hash, signed_receipt)
        VALUES (?,?,?,?,?,?)`).run(statement.generation, action, subjectDigest,
          statement.previousHash, digest(RECEIPT_DOMAIN, raw), raw);
      return this.audit();
    }).immediate();
  }
  async #verifyCandidate(candidate) {
    exact(candidate, ["subject", "subjectDigest", "casSignedStage", "floorSignedStage"]);
    if (typeof candidate.subject !== "string" || candidate.subject.length > 4096) deny();
    const raw = Buffer.from(candidate.subject, "base64url");
    if (raw.toString("base64url") !== candidate.subject
      || digest(SUBJECT_DOMAIN, raw) !== candidate.subjectDigest) deny();
    const subject = await z.decodeDeterministic(raw);
    exact(subject, SUBJECT_FIELDS);
    if (subject.type !== "rootark-opaque-checkpoint-v2-legacy-stage-witness-subject/v1"
      || !(await z.encodeDeterministic(subject)).equals(raw)
      || !Number.isSafeInteger(subject.legacy_sequence) || subject.legacy_sequence < 128
      || subject.legacy_sequence > 1152
      || !Number.isSafeInteger(subject.owner_revision) || subject.owner_revision < 1
      || !Number.isSafeInteger(subject.owner_epoch) || subject.owner_epoch < 1) deny();
    for (const name of SCOPE) if (!(subject[name] instanceof Uint8Array)
      || !Buffer.from(subject[name]).equals(this.scope[name])) deny();
    for (const name of [...BINDINGS, "owner_digest", "cas_signer_fp", "floor_signer_fp"])
      if (!(subject[name] instanceof Uint8Array) || subject[name].length !== 32) deny();
    if (!Buffer.from(subject.cas_signer_fp).equals(b64(fingerprint(this.pins.v2CasPublicKey)))
      || !Buffer.from(subject.floor_signer_fp).equals(b64(fingerprint(this.pins.v2FloorPublicKey)))) deny();
    for (const [field, keyName, role] of [["casSignedStage", "v2CasPublicKey", "CAS"],
      ["floorSignedStage", "v2FloorPublicKey", "FLOOR"]]) {
      const signed = Buffer.from(candidate[field], "base64url");
      if (signed.toString("base64url") !== candidate[field]) deny();
      const parsed = await z.decodeDeterministic(signed);
      const checked = await inspectLegacyArchiveReadback(signed, {
        scope: this.scope, signer: this.pins[keyName], role,
        casFp: subject.cas_signer_fp, floorFp: subject.floor_signer_fp,
        nonce: parsed.nonce });
      if (checked.legacy_sequence !== subject.legacy_sequence
        || BINDINGS.some((name) => !Buffer.from(checked[name]).equals(
          Buffer.from(subject[name])))) deny();
    }
    return candidate.subjectDigest;
  }
  async stageSignedEvidence() {
    // Archived CAS/FLOOR receipts authenticate only authority signatures,
    // not the unsigned owner fields inside the supplied subject. It is
    // impossible to promote this offline proof into a witness-signed stage
    // without an independently verified live owner assertion. Fail closed,
    // even if the offline payload is otherwise well formed or genuine.
    deny();
  }
  #trustedReadbackInput(input) {
    const supplied = input?.ownerTrust;
    const pin = supplied?.pinnedWitness;
    const minimum = supplied?.minimumHead;
    const trusted = this.trustedOwnerWitness;
    if (!pin || !minimum || typeof supplied.freshWitnessHead !== "function"
      || fingerprint(pin.publicKey) !== trusted.fingerprint
      || !(pin.keyId instanceof Uint8Array)
      || Buffer.from(pin.keyId).toString("base64url") !== trusted.keyId
      || minimum.revision !== trusted.revision
      || minimum.witnessSequence !== trusted.witnessSequence
      || !(minimum.digest instanceof Uint8Array)
      || Buffer.from(minimum.digest).toString("base64url") !== trusted.digest) deny();
    // Never let a mutable request select the verification key or rollback
    // floor after an await. Always use fresh private copies of constructor
    // trust instead of trusting the request's identical-looking objects.
    return { ...input, operatorPins: this.pins,
      ownerTrust: {
        pinnedWitness: { publicKey: trusted.publicKey,
          keyId: Buffer.from(trusted.keyId, "base64url") },
        minimumHead: { revision: trusted.revision,
          witnessSequence: trusted.witnessSequence,
          digest: Buffer.from(trusted.digest, "base64url") },
        freshWitnessHead: ({ scope, nonce }) => supplied.freshWitnessHead({ scope, nonce }),
      } };
  }
  async stageFromLiveReadback({ readbackInput, expectedHead }) {
    try {
      if (!readbackInput || PINS.some((name) =>
        fingerprint(readbackInput.operatorPins?.[name])
          !== fingerprint(this.pins[name]))) deny();
      const pinnedInput = this.#trustedReadbackInput(readbackInput);
      const live = await verifyLegacyArchiveDualReadback(pinnedInput);
      const subjectDigest = await this.#verifyCandidate(live.witnessCandidate);
      // CBOR decoding and signature verification are asynchronous. Owner
      // revision can advance during that work; demand one last complete
      // independent live readback, whose final action is a fresh owner witness
      // check, immediately before the synchronous ledger CAS.
      const final = await verifyLegacyArchiveDualReadback(pinnedInput);
      if (final.witnessCandidate.subjectDigest !== subjectDigest) deny();
      const head = this.#append("STAGED", subjectDigest, expectedHead,
        PROVENANCE.STAGED);
      return rejectAuthorization({ state: "LIVE_READBACK_STAGE_RECORDED", head });
    } catch (_) { deny(); }
  }
  withdraw({ expectedHead }) {
    try {
      this.validateHead(expectedHead);
      if (expectedHead.action !== "STAGED") deny();
      const head = this.#append("WITHDRAWN", expectedHead.subjectDigest, expectedHead,
        PROVENANCE.WITHDRAWN);
      return rejectAuthorization({ state: "STAGE_EVIDENCE_WITHDRAWN", head });
    } catch (_) { deny(); }
  }
  close() { this.db.close(); }
}

module.exports = { Zk1LegacyArchiveStageWitness };
