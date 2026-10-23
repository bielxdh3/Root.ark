"use strict";

// Opt-in device-side V1->V2 transition. A durable pending owner-signed intent
// precedes remote publication; only two freshly signed FINALIZED remote heads
// authorize readback. This is a local client API, not browser activation.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const z = require("../crypto/rootark-zk-1");
const archive = require("../crypto/rootark-zk1-opaque-catalog-checkpoint-v2");
const { createOpaqueCheckpointV2Coordinator, signCheckpointOwnerApprovalV2,
  inspectIntent } = require("./zk1OpaqueCheckpointV2Remote");
const { assertSafeSqliteSidecars, requireCheckpointV2Triggers,
  withReadonlySqliteSnapshot } =
  require("./zk1OpaqueCheckpointV2SqliteGuard");
const { assertPrivateSqliteDirectory, assertPrivateSqliteFile } =
  require("./zk1PrivateSqlitePath");
const { syncPrivateParent, publishStagedJournal } =
  require("./zk1V2DurableJournalMigration");
const { FIELDS: SIGNER_ENDORSEMENT_FIELDS, LEGACY_FIELDS: LEGACY_SIGNER_ENDORSEMENT_FIELDS } =
  require("../crypto/rootark-zk1-v2-historical-signer-endorsement");

const APPROVAL_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-checkpoint-remote/owner-approval/v2\0");
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const ZERO = Buffer.alloc(32);
const SIGNER_GRANT_DOMAIN = Buffer.from("Root.ark/zk-1/v2-historical-signer-endorsement/v2\0");
const LEGACY_SIGNER_GRANT_DOMAIN = Buffer.from("Root.ark/zk-1/v2-historical-signer-endorsement/v1\0");
const HEAD_DIGEST_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0");
const CHECKPOINT_DIGEST_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-checkpoint-digest/v2\0");
const SIGNER_GRANT_SCHEMA = `CREATE TABLE IF NOT EXISTS signer_grants (
    sequence INTEGER PRIMARY KEY CHECK(sequence BETWEEN 129 AND 1000000),
    grant BLOB NOT NULL, signer_spki BLOB NOT NULL);
  CREATE TRIGGER IF NOT EXISTS signer_grants_immutable_update BEFORE UPDATE ON signer_grants
    BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS signer_grants_immutable_delete BEFORE DELETE ON signer_grants
    BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS signer_grants_no_gap BEFORE INSERT ON signer_grants WHEN
    NEW.sequence!=(SELECT COALESCE(MAX(sequence),128)+1 FROM signer_grants)
    OR (NEW.sequence=129 AND (SELECT COUNT(*) FROM intent WHERE id=1)!=1)
    OR (NEW.sequence>129 AND (SELECT COUNT(*) FROM successors WHERE sequence=NEW.sequence)!=1)
    BEGIN SELECT RAISE(ABORT,'NONCONTIGUOUS_SIGNER'); END;`;
const SIGNER_GRANT_TRIGGERS = [
  ["signer_grants_immutable_update", "signer_grants"],
  ["signer_grants_immutable_delete", "signer_grants"],
  ["signer_grants_no_gap", "signer_grants"],
];
const SUCCESSOR_SCHEMA = `CREATE TABLE IF NOT EXISTS successors (
    sequence INTEGER PRIMARY KEY CHECK(sequence BETWEEN 130 AND 1000000),
    bytes BLOB NOT NULL);
  CREATE TRIGGER IF NOT EXISTS successors_immutable_update BEFORE UPDATE ON successors
    BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS successors_immutable_delete BEFORE DELETE ON successors
    BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS successors_no_gap BEFORE INSERT ON successors WHEN
    (SELECT COUNT(*) FROM intent WHERE id=1)!=1
    OR NEW.sequence!=(SELECT COALESCE(MAX(sequence),129)+1 FROM successors)
    BEGIN SELECT RAISE(ABORT,'NONCONTIGUOUS_CHECKPOINT'); END;`;
const SUCCESSOR_TRIGGERS = [
  ["successors_immutable_update", "successors"],
  ["successors_immutable_delete", "successors"],
  ["successors_no_gap", "successors"],
];
const INTENT_GUARD_SCHEMA = `
  CREATE TRIGGER IF NOT EXISTS intent_immutable_update BEFORE UPDATE ON intent
    BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS intent_immutable_delete BEFORE DELETE ON intent
    BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;`;
const INTENT_TRIGGERS = [
  ["intent_immutable_update", "intent"],
  ["intent_immutable_delete", "intent"],
];
const MAX_LOCAL_PREFLIGHT_BYTES = 32 * 1024 * 1024;
// Historical pre-successor schema must be authenticated before owner-authorized
// migration, never opened writable or upgraded in place.
const LEGACY_129_SCHEMA = `CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), pins BLOB NOT NULL);
  CREATE TABLE intent (id INTEGER PRIMARY KEY CHECK(id=1), bytes BLOB NOT NULL);
  ${INTENT_GUARD_SCHEMA}`;
const LEGACY_129_TRIGGERS = INTENT_TRIGGERS;
function deny() {
  const err = new Error("ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE");
  err.code = "ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE";
  throw err;
}
function key(k, type = "public") {
  if (!(k instanceof crypto.KeyObject) || k.type !== type
    || k.asymmetricKeyType !== "ed25519") deny();
  return k;
}
function bytes(input, size) {
  if ((!Buffer.isBuffer(input) && !(input instanceof Uint8Array))
    || input.byteLength !== size) deny();
  return Buffer.from(input);
}
function equal(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function fp(k) {
  return crypto.createHash("sha256").update(key(k)
    .export({ type: "spki", format: "der" })).digest();
}
function b64(value, size) {
  if (typeof value !== "string" || value.length > 512
    || !/^[A-Za-z0-9_-]+$/.test(value)) deny();
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== size || decoded.toString("base64url") !== value) deny();
  return decoded;
}
async function verifiedSignerGrant(raw, intent, t, intentRaw) {
  if (!t.signerGrantRootKey || (!Buffer.isBuffer(raw) && !(raw instanceof Uint8Array))
    || raw.length < 1 || raw.length > 4096) deny();
  let grant;
  try { grant = JSON.parse(Buffer.from(raw).toString("utf8")); }
  catch (_) { deny(); }
  const legacy = grant?.schema === "rootark-zk1-v2-historical-signer-endorsement/v1";
  const names = legacy ? LEGACY_SIGNER_ENDORSEMENT_FIELDS : SIGNER_ENDORSEMENT_FIELDS;
  if (!grant || Object.getPrototypeOf(grant) !== Object.prototype
    || Reflect.ownKeys(grant).length !== names.length + 1
    || [...names, "signature"].some((name) =>
      !Object.hasOwn(grant, name))) deny();
  const statement = Object.fromEntries(names.map((name) => [name, grant[name]]));
  const canonical = Buffer.from(JSON.stringify({ ...statement, signature: grant.signature }));
  if (!equal(canonical, Buffer.from(raw))) deny();
  const headerBytes = intent.records[0].header;
  if ((!Buffer.isBuffer(headerBytes) && !(headerBytes instanceof Uint8Array))
    || headerBytes.length < 1 || headerBytes.length > 16384) deny();
  const header = await z.decodeDeterministic(headerBytes);
  if (grant.schema !== (legacy ? "rootark-zk1-v2-historical-signer-endorsement/v1"
    : "rootark-zk1-v2-historical-signer-endorsement/v2")
    || grant.sequence !== intent.records[0].sequence
    || !equal(b64(grant.intent_sha256, 32), crypto.createHash("sha256").update(intentRaw).digest())
    || !equal(b64(grant.operation_id, 32), bytes(intent.operation_id, 32))
    || !equal(b64(grant.head_digest, 32), crypto.createHash("sha256")
      .update(HEAD_DIGEST_DOMAIN).update(intent.records[0].header)
      .update(intent.records[0].signature).digest())
    || !equal(b64(grant.checkpoint_digest, 32), crypto.createHash("sha256")
      .update(CHECKPOINT_DIGEST_DOMAIN).update(intent.checkpoint_bytes)
      .update(intent.checkpoint_signature).digest())
    || grant.signer_device_id !== header.signer_device_id
    || grant.manifest_revision !== header.manifest_revision
    || !equal(b64(grant.manifest_digest, 32), bytes(header.manifest_digest, 32))
    || grant.epoch !== header.epoch
    || !equal(b64(grant.genesis_digest, 32), bytes(t.ownerTrust.genesisDigest, 32))
    || !equal(b64(grant.witness_signer_spki_sha256, 32), fp(t.ownerTrust.pinnedWitness.publicKey))
    || SCOPE.some((name) => !equal(b64(grant[name], t.scope[name].length), t.scope[name]))) deny();
  if (!crypto.verify(null, Buffer.concat([legacy ? LEGACY_SIGNER_GRANT_DOMAIN : SIGNER_GRANT_DOMAIN,
    Buffer.from(JSON.stringify(statement))]), t.signerGrantRootKey,
  b64(grant.signature, 64))) deny();
  const signer = crypto.createPublicKey({ key: Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    b64(grant.signer_public_key, 32)]), format: "der", type: "spki" });
  const approvalSigner = legacy ? t.ownerKey : crypto.createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"),
      b64(grant.approval_signer_public_key, 32)]), format: "der", type: "spki" });
  return { raw: canonical, signer, approvalSigner };
}
function scopeOf(v) {
  if (!v || Reflect.ownKeys(v).length !== 3) deny();
  return Object.fromEntries(SCOPE.map((n) => {
    if (!Buffer.isBuffer(v[n]) && !(v[n] instanceof Uint8Array)) deny();
    const b = Buffer.from(v[n]);
    if (b.length < (n === "compartment_id" ? 1 : 16)
      || b.length > (n === "compartment_id" ? 128 : 16)) deny();
    return [n, b];
  }));
}
function privateFile(filename, bootstrapNew) {
  if (typeof filename !== "string" || !path.isAbsolute(filename)) deny();
  assertPrivateSqliteDirectory(filename);
  const parent = fs.lstatSync(path.dirname(filename));
  if (!parent.isDirectory() || parent.isSymbolicLink()
    || (process.platform !== "win32"
      && (parent.uid !== process.getuid() || parent.mode & 0o077))) deny();
  const exists = fs.existsSync(filename);
  if (exists === bootstrapNew) deny();
  if (exists) {
    const st = fs.lstatSync(filename);
    if (!st.isFile() || st.isSymbolicLink() || st.nlink !== 1
      || (process.platform !== "win32"
        && (st.uid !== process.getuid() || st.mode & 0o077))) deny();
  } else {
    const fd = fs.openSync(filename, fs.constants.O_EXCL | fs.constants.O_CREAT
      | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0), 0o600);
    try {
      // Pin the inode returned by exclusive creation, not the pathname after
      // close. A swapped private, single-link SQLite must never receive our
      // WAL, bootstrap tables or immutable journal authority.
      const created = fs.fstatSync(fd, { bigint: true });
      if (!created.isFile() || created.nlink !== 1n
        || (process.platform !== "win32"
          && (created.uid !== BigInt(process.getuid())
            || (created.mode & 0o077n) !== 0n))) deny();
      return Object.freeze({ dev: created.dev, ino: created.ino });
    } finally { fs.closeSync(fd); }
  }
}
function verifyJournal(db, identity, requireSignerGrants = false) {
  if (db.pragma("quick_check", { simple: true }) !== "ok"
    || !db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='intent'").get()
    || !db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='identity'").get()) deny();
  requireCheckpointV2Triggers(db, INTENT_GUARD_SCHEMA, INTENT_TRIGGERS, deny);
  requireCheckpointV2Triggers(db, SUCCESSOR_SCHEMA, SUCCESSOR_TRIGGERS, deny);
  const pinned = db.prepare("SELECT pins FROM identity WHERE id=1").get();
  if (!pinned || !equal(pinned.pins, identity)) deny();
  const table = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='signer_grants'").get();
  if (!table && requireSignerGrants) deny();
  if (!table) return;
  requireCheckpointV2Triggers(db, SIGNER_GRANT_SCHEMA, SIGNER_GRANT_TRIGGERS, deny);
  const expected = SIGNER_GRANT_SCHEMA.match(/CREATE TABLE IF NOT EXISTS signer_grants \([\s\S]*?\);/)[0];
  const normalize = (sql) => sql.replace(/IF NOT EXISTS /g, "")
    .trim().replace(/\s+/g, " ").replace(/;$/, "");
  if (!table?.sql || normalize(table.sql) !== normalize(expected)) deny();
}

function privateNewDestination(filename) {
  if (typeof filename !== "string" || !path.isAbsolute(filename)
    || fs.existsSync(filename)
    || ["-wal", "-shm", "-journal"].some((suffix) => fs.existsSync(filename + suffix))) deny();
  assertPrivateSqliteDirectory(filename);
  const parent = path.dirname(filename);
  const stat = fs.lstatSync(parent);
  if (!stat.isDirectory() || stat.isSymbolicLink()
    || (process.platform !== "win32"
      && (stat.uid !== process.getuid() || (stat.mode & 0o077)))) deny();
}

function inspectedLegacy129(db, identity) {
  requireCheckpointV2Triggers(db, LEGACY_129_SCHEMA, LEGACY_129_TRIGGERS, deny);
  if (db.pragma("journal_mode", { simple: true }) !== "wal"
    || db.pragma("user_version", { simple: true }) !== 0
    || db.pragma("application_id", { simple: true }) !== 0) deny();
  const objects = db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").all();
  if (objects.length !== 4) deny();
  const canonical = (sql) => sql.trim().replace(/\s+/g, " ").replace(/;$/, "");
  const expectedTables = [...LEGACY_129_SCHEMA.matchAll(/CREATE TABLE ([a-z_]+)\s*\([\s\S]*?\);/g)];
  if (expectedTables.length !== 2) deny();
  for (const ddl of expectedTables) {
    const stored = objects.find((entry) => entry.name === ddl[1]);
    if (stored?.type !== "table" || stored.tbl_name !== ddl[1]
      || canonical(stored.sql) !== canonical(ddl[0])) deny();
  }
  const pins = db.prepare("SELECT id,pins FROM identity").all();
  const intents = db.prepare("SELECT id,bytes FROM intent").all();
  if (pins.length !== 1 || pins[0].id !== 1
    || !Buffer.isBuffer(pins[0].pins) || !equal(pins[0].pins, identity)
    || intents.length !== 1 || intents[0].id !== 1
    || !Buffer.isBuffer(intents[0].bytes)
    || intents[0].bytes.length < 1 || intents[0].bytes.length > 10 * 1024 * 1024) deny();
  return Buffer.from(intents[0].bytes);
}

class Zk1OpaqueCheckpointV2Client {
  #db;
  #trust;
  #coordinator;
  #queue = Promise.resolve();
  // Explicit owner-held migration of an authenticated immutable #129 journal.
  // The old DB and WAL are never opened writable; only a fully verified,
  // locally fsynced successor-capable DB is published at a fresh destination.
  static async migrateLegacy129({ legacyJournalPath, migrationOptIn,
    ownerPrivateKey, ...options } = {}) {
    let staged;
    let scratch;
    try {
      const { journalPath, trustedScope, expectedV1Digest, expectedV1Checkpoint,
        casClient, floorClient, checkpointPublicKey, ownerPublicKey, catalogPublicKey } = options;
      if (migrationOptIn !== true || options.bootstrapNew !== false
        || typeof legacyJournalPath !== "string" || !path.isAbsolute(legacyJournalPath)
        || typeof journalPath !== "string" || !path.isAbsolute(journalPath)
        || path.resolve(legacyJournalPath).toLowerCase() === path.resolve(journalPath).toLowerCase()
        || fs.existsSync(journalPath)
        || !equal(fp(crypto.createPublicKey(key(ownerPrivateKey, "private"))),
          fp(key(ownerPublicKey)))) deny();
      privateFile(legacyJournalPath, false);
      const scope = scopeOf(trustedScope);
      // Source #129 was written before grant-root pinning. Authenticate its
      // original five-key identity, then publish a separately pinned journal.
      const pins = [key(casClient.publicKey), key(floorClient.publicKey),
        key(checkpointPublicKey), key(ownerPublicKey), key(catalogPublicKey)].map(fp);
      const identity = encodeIdentity(scope, bytes(expectedV1Digest, 32),
        bytes(expectedV1Checkpoint, 32), pins);
      const readSource = () => {
        let captured;
        withReadonlySqliteSnapshot(legacyJournalPath,
          (db) => { captured = inspectedLegacy129(db, identity); }, deny,
          2 * 10 * 1024 * 1024 + 8 * 1024 * 1024);
        return captured;
      };
      const old = readSource();
      privateNewDestination(journalPath);
      // Probe the actual directory durability barrier BEFORE creating even a
      // temporary journal. Unsupported Windows directory fsync fails closed.
      syncPrivateParent(journalPath);
      staged = path.join(path.dirname(journalPath),
        `.zk65-v2-129-migration-${crypto.randomBytes(16).toString("hex")}.sqlite`);
      scratch = new Zk1OpaqueCheckpointV2Client({ ...options,
        journalPath: staged, bootstrapNew: true });
      // Fresh witnessed owner authorization of the exact signed #129 bytes,
      // followed by independent CAS/FLOOR FINALIZED proof before admission.
      const examined = await scratch.#inspect(old, true, undefined, options.migrationSignerGrant);
      if (examined.body.previous_sequence !== 128) deny();
      await scratch.importSignedIntent(old, { signerGrant: options.migrationSignerGrant });
      const state = await scratch.read();
      if (state.sequence !== 129) deny();
      scratch.close();
      scratch = null;
      if (!equal(readSource(), old)) deny();
      // A lost ACK, later remote successor, or swapped authority blocks commit.
      const checked = new Zk1OpaqueCheckpointV2Client({ ...options,
        journalPath: staged, bootstrapNew: false });
      try { if ((await checked.read()).sequence !== 129) deny(); }
      finally { checked.close(); }
      assertSafeSqliteSidecars(staged, deny);
      if (["-wal", "-shm", "-journal"].some((suffix) => fs.existsSync(staged + suffix))) deny();
      privateNewDestination(journalPath);
      // The helper fsyncs the staged file, the new staging directory entry,
      // the published hardlink, and removal of the staging name. Any failed
      // barrier rejects and attempts exact-inode rollback; old #129 untouched.
      const migrated = publishStagedJournal(staged, journalPath,
        () => new Zk1OpaqueCheckpointV2Client({ ...options,
          journalPath, bootstrapNew: false }));
      staged = null;
      return migrated;
    } catch (_) { deny(); }
    finally {
      scratch?.close();
      if (staged) {
        let removed = false;
        for (const suffix of ["", "-wal", "-shm", "-journal"]) {
          try { fs.unlinkSync(staged + suffix); removed = true; }
          catch (error) { if (error.code !== "ENOENT") deny(); }
        }
        if (removed) syncPrivateParent(staged);
      }
    }
  }
  constructor({ journalPath, bootstrapNew, trustedScope, expectedV1Digest,
    expectedV1Checkpoint, v1CasClient, v1FloorClient, casClient, floorClient,
    checkpointPublicKey, ownerPublicKey, catalogPublicKey, ownerTrust,
    signerGrantRootPublicKey }) {
    const scope = scopeOf(trustedScope);
    const digest = bytes(expectedV1Digest, 32);
    const checkpoint = bytes(expectedV1Checkpoint, 32);
    if (equal(digest, ZERO) || equal(checkpoint, ZERO)
      || !casClient || !floorClient) deny();
    const cas = key(casClient.publicKey), floor = key(floorClient.publicKey);
    const checkpointKey = key(checkpointPublicKey);
    const ownerKey = key(ownerPublicKey);
    const catalogKey = key(catalogPublicKey);
    const signerGrantRootKey = signerGrantRootPublicKey
      ? key(signerGrantRootPublicKey) : null;
    const fingerprints = [cas, floor, checkpointKey, ownerKey, catalogKey,
      ...(signerGrantRootKey ? [signerGrantRootKey] : [])].map(fp);
    // The owner-approved device may also sign the catalog header.
    if (new Set(fingerprints.slice(0, 4).map((b) => b.toString("hex"))).size !== 4
      || fingerprints.slice(0, 3).some((b) => equal(b, fingerprints[4]))
      // The independently pinned historical grant authority cannot be any
      // currently active device or checkpoint/CAS/FLOOR signer. In particular,
      // catalog-key aliasing would let a device certify its own history.
      || (signerGrantRootKey && fingerprints.slice(0, 5)
        .some((b) => equal(b, fingerprints[5])))
      || !ownerTrust?.pinnedWitness || !ownerTrust?.minimumHead
      || typeof ownerTrust?.freshWitnessHead !== "function") deny();
    const coordinator = createOpaqueCheckpointV2Coordinator({
      casClient, floorClient, trustedScope: scope,
      expectedV1Digest: digest, expectedV1Checkpoint: checkpoint,
      v1CasClient, v1FloorClient,
    });
    const creationPin = privateFile(journalPath, bootstrapNew);
    const identity = Buffer.from(encodeIdentity(scope, digest, checkpoint, fingerprints));
    // Foreign WAL/SHM aliases and unknown schemas must be refused before any
    // writable SQLite open, journal-mode change or sidecar creation.
    const pinned = bootstrapNew ? creationPin
      : withReadonlySqliteSnapshot(journalPath,
        (probe) => verifyJournal(probe, identity, !!signerGrantRootKey), deny,
        MAX_LOCAL_PREFLIGHT_BYTES);
    const current = assertPrivateSqliteFile(journalPath);
    if (pinned.dev !== current.dev || pinned.ino !== current.ino) deny();
    assertSafeSqliteSidecars(journalPath, deny);
    const db = new Database(journalPath, { fileMustExist: true, timeout: 3000 });
    try {
      const opened = assertPrivateSqliteFile(journalPath);
      if (opened.dev !== pinned.dev || opened.ino !== pinned.ino) deny();
      assertSafeSqliteSidecars(journalPath, deny);
      if (!bootstrapNew) verifyJournal(db, identity, !!signerGrantRootKey);
      db.pragma("journal_mode=WAL");
      db.pragma("synchronous=FULL");
      if (bootstrapNew) {
        db.exec(`CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), pins BLOB NOT NULL);
          CREATE TABLE intent (id INTEGER PRIMARY KEY CHECK(id=1), bytes BLOB NOT NULL);
          CREATE TRIGGER intent_immutable_update BEFORE UPDATE ON intent
            BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;
          CREATE TRIGGER intent_immutable_delete BEFORE DELETE ON intent
            BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;`);
        db.prepare("INSERT INTO identity VALUES(1,?)").run(identity);
      }
      if (bootstrapNew) db.exec(SUCCESSOR_SCHEMA + SIGNER_GRANT_SCHEMA);
    } catch (error) { db.close(); throw error; }
    this.#db = db;
    this.#coordinator = coordinator;
    this.#trust = { scope, digest, checkpoint, casFp: fingerprints[0],
      floorFp: fingerprints[1], casKey: cas, floorKey: floor,
      checkpointFp: fingerprints[2],
      checkpointKey, ownerKey, catalogKey, ownerTrust, signerGrantRootKey };
  }
  #serial(fn) {
    const result = this.#queue.then(fn);
    this.#queue = result.catch(() => {});
    return result;
  }
  #saved() {
    const row = this.#db.prepare("SELECT bytes FROM successors ORDER BY sequence DESC LIMIT 1").get()
      || this.#db.prepare("SELECT bytes FROM intent WHERE id=1").get();
    return row ? Buffer.from(row.bytes) : null;
  }
  async #inspect(raw, freshOwner, previous = { sequence: 128,
    digest: this.#trust.digest, checkpointDigest: this.#trust.checkpoint,
    operationId: ZERO }, grantEvidence) {
    const t = this.#trust;
    const body = await z.decodeDeterministic(raw);
    let grant = null;
    if (t.signerGrantRootKey) {
      if (!grantEvidence) deny();
      if (!Buffer.isBuffer(grantEvidence) && !(grantEvidence instanceof Uint8Array)
        && (!grantEvidence || typeof grantEvidence !== "object"
          || Array.isArray(grantEvidence))) deny();
      const captured = (Buffer.isBuffer(grantEvidence) || grantEvidence instanceof Uint8Array)
        ? Buffer.from(grantEvidence) : Buffer.from(JSON.stringify(grantEvidence));
      grant = await verifiedSignerGrant(captured, body, t, raw);
    } else if (grantEvidence) deny();
    const inspected = await inspectIntent(raw, {
      scope: t.scope, baseDigest: previous.digest,
      baseCheckpoint: previous.checkpointDigest,
      casFp: t.casFp, floorFp: t.floorFp, checkpointFp: t.checkpointFp,
      checkpointKey: t.checkpointKey, ownerKey: t.ownerKey,
      ownerTrust: t.ownerTrust, cachedSigner: grant ? grant.signer : t.catalogKey,
      casKey: t.casKey, floorKey: t.floorKey,
      previousOperationId: previous.operationId,
    }, { freshOwner });
    if (grant && (!equal(grant.signer.export({ type: "spki", format: "der" }),
      inspected.signerSpki)
      || (freshOwner && (!inspected.ownerApprovalSignerSpki
        || !equal(grant.approvalSigner.export({ type: "spki", format: "der" }),
          bytes(inspected.ownerApprovalSignerSpki, 44)))))) deny();
    // Historical reads cannot demand a fresh witness from a device that was
    // revoked AFTER publication. Preserve the signed owner approval binding.
    const approval = await z.decodeDeterministic(inspected.body.owner_approval);
    if (approval.type !== "rootark-opaque-checkpoint-remote-owner-approval/v2"
      || SCOPE.some((name) => !equal(bytes(approval[name], t.scope[name].length), t.scope[name]))
      || !Number.isSafeInteger(approval.issued_at)
      || approval.issued_at < 0
      || !crypto.verify(null, Buffer.concat([APPROVAL_DOMAIN,
      Buffer.from(inspected.body.owner_approval)]), grant?.approvalSigner || t.ownerKey,
      bytes(inspected.body.owner_signature, 64))
      || !equal(bytes(approval.operation_id, 32), inspected.operationId)
      || !equal(bytes(approval.checkpoint_digest, 32), inspected.checkpointDigest)
      || !equal(bytes(approval.final_digest, 32), inspected.finalDigest)
      || !equal(bytes(approval.cas_signer_fp, 32), t.casFp)
      || !equal(bytes(approval.floor_signer_fp, 32), t.floorFp)
      || !equal(bytes(approval.checkpoint_signer_fp, 32), t.checkpointFp)
      || !equal(bytes(approval.previous_digest, 32), previous.digest)
      || !equal(bytes(approval.previous_checkpoint_digest, 32), previous.checkpointDigest)
      || approval.previous_sequence !== previous.sequence
      || approval.final_sequence !== previous.sequence + 1) deny();
    return { ...inspected, grant };
  }
  async #chain() {
    const first = this.#db.prepare("SELECT bytes FROM intent WHERE id=1").get();
    const successors = this.#db.prepare("SELECT sequence,bytes FROM successors ORDER BY sequence").all();
    const grants = this.#db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='signer_grants'").get()
      ? this.#db.prepare("SELECT sequence,grant,signer_spki FROM signer_grants ORDER BY sequence").all()
      : [];
    if (!first && successors.length) deny();
    let previous = { sequence: 128, digest: this.#trust.digest,
      checkpointDigest: this.#trust.checkpoint, operationId: ZERO };
    const chain = first ? [{ sequence: 129, bytes: first.bytes }, ...successors] : [];
    if (grants.length !== (this.#trust.signerGrantRootKey ? chain.length : 0)) deny();
    for (const [index, item] of chain.entries()) {
      if (item.sequence !== previous.sequence + 1) deny();
      const stored = grants[index];
      if (this.#trust.signerGrantRootKey && (stored.sequence !== item.sequence
        || !Buffer.isBuffer(stored.grant) || !Buffer.isBuffer(stored.signer_spki))) deny();
      const inspected = await this.#inspect(item.bytes, false, previous, stored?.grant);
      if (stored && !equal(stored.signer_spki, inspected.signerSpki)) deny();
      previous = { sequence: item.sequence, digest: inspected.finalDigest,
        checkpointDigest: inspected.checkpointDigest,
        operationId: inspected.operationId, inspected };
    }
    return previous;
  }
  async #read() {
    const raw = this.#saved();
    if (!raw) deny();
    const last = await this.#chain();
    const checked = last.inspected;
    const state = await this.#coordinator.readConsistent(raw);
    if (state.sequence !== last.sequence
      || !equal(bytes(state.checkpointDigest, 32), checked.checkpointDigest)) deny();
    const record = checked.body.records[0];
    const head = await z.decodeDeterministic(record.header);
    const pages = [];
    for (const p of record.page_bodies) pages.push(await z.decodeDeterministic(p));
    return Object.freeze({ sequence: last.sequence, digest: checked.finalDigest,
      checkpointDigest: checked.checkpointDigest, head,
      pages, state: "V2_BOTH_FINALIZED", remoteCloudDurabilityProven: false });
  }
  async publish({ record, checkpointPrivateKey, ownerPrivateKey, signerGrantIssuer,
    ownerEvidence, operationId = crypto.randomBytes(32),
    issuedAt = Math.floor(Date.now() / 1000), ownerIssuedAt = issuedAt }) {
    return this.#serial(async () => {
      const t = this.#trust;
      const prior = await this.#chain();
      const existing = this.#saved();
      // An earlier pending intent must be reconciled before any new owner intent.
      const endorsements = existing
        ? await this.#coordinator.predecessorEndorsements(existing) : null;
      if (prior.sequence >= 1000000) deny();
      if (!equal(fp(crypto.createPublicKey(key(checkpointPrivateKey, "private"))),
        t.checkpointFp) || !equal(fp(crypto.createPublicKey(key(ownerPrivateKey, "private"))),
        fp(t.ownerKey))) deny();
      // An external owner issuer sees the complete signed intent, verifies the
      // independently witnessed history and returns an endorsement before any
      // local append or network mutation. The caller cannot self-authorize.
      if (t.signerGrantRootKey && typeof signerGrantIssuer !== "function") deny();
      const archived = await archive.createAuthenticatedOpaqueCatalogArchiveV2({
        scope: t.scope, records: [record], previousSequence: prior.sequence,
        previousDigest: prior.digest,
        previousCheckpointDigest: prior.checkpointDigest,
        resolveCatalogSigner: async () => t.catalogKey,
        checkpointPrivateKey, issuedAt,
      });
      if (archived.records[0].sequence !== prior.sequence + 1) deny();
      const approval = await signCheckpointOwnerApprovalV2({
        type: "rootark-opaque-checkpoint-remote-owner-approval/v2",
        ...t.scope, operation_id: bytes(operationId, 32),
        checkpoint_digest: archived.checkpointDigest,
        previous_sequence: prior.sequence, previous_digest: prior.digest,
        previous_checkpoint_digest: prior.checkpointDigest,
        final_sequence: prior.sequence + 1,
        final_digest: crypto.createHash("sha256")
          .update(Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0"))
          .update(archived.records[0].header).update(archived.records[0].signature).digest(),
        cas_signer_fp: t.casFp, floor_signer_fp: t.floorFp,
        checkpoint_signer_fp: t.checkpointFp, issued_at: ownerIssuedAt,
      }, ownerPrivateKey);
      const raw = Buffer.from(await z.encodeDeterministic({
        type: "rootark-opaque-checkpoint-remote-intent/v2", ...t.scope,
        operation_id: bytes(operationId, 32), checkpoint_bytes: archived.checkpointBytes,
        checkpoint_signature: archived.checkpointSignature, records: archived.records,
        previous_sequence: prior.sequence, previous_digest: prior.digest,
        previous_checkpoint_digest: prior.checkpointDigest,
        owner_approval: approval.raw, owner_signature: approval.signature,
        owner_evidence: Buffer.from(ownerEvidence),
        ...(endorsements || {}),
      }));
      const signedSignerGrant = t.signerGrantRootKey
        ? await signerGrantIssuer(Buffer.from(raw)) : null;
      const inspected = await this.#inspect(raw, true, prior, signedSignerGrant);
      this.#append(raw, prior.sequence + 1, inspected.grant);
      await this.#coordinator.publish(raw);
      return this.#read();
    });
  }
  publishSignedIntent(signedIntent, { signerGrant } = {}) {
    return this.#serial(async () => {
      const raw = Buffer.from(signedIntent);
      const saved = this.#saved();
      const prior = await this.#chain();
      if (!saved || !equal(saved, raw)) {
        if (saved) await this.#coordinator.readConsistent(saved);
        const inspected = await this.#inspect(raw, true, prior, signerGrant);
        this.#append(raw, prior.sequence + 1, inspected.grant);
        if (inspected.body.previous_sequence !== prior.sequence) deny();
      } else {
        await this.#chain();
      }
      await this.#coordinator.publish(raw);
      return this.#read();
    });
  }
  // A second device can import an authenticated chain before reading. The
  // remote signed heads still decide whether the final imported entry is
  // current; a local imported journal alone never grants a metadata read.
  importSignedIntent(signedIntent, { signerGrant } = {}) {
    return this.#serial(async () => {
      if ((!Buffer.isBuffer(signedIntent) && !(signedIntent instanceof Uint8Array))
        || signedIntent.byteLength < 1 || signedIntent.byteLength > 10 * 1024 * 1024)
        deny();
      const raw = Buffer.from(signedIntent);
      const prior = await this.#chain();
      const inspected = await this.#inspect(raw, false, prior, signerGrant);
      this.#append(raw, prior.sequence + 1, inspected.grant);
      return { importedSequence: prior.sequence + 1, remotelyFinalized: false };
    });
  }
  exportSignedIntents() {
    return this.#serial(async () => {
      await this.#chain();
      const first = this.#db.prepare("SELECT bytes FROM intent WHERE id=1").get();
      return (first ? [first] : []).concat(this.#db.prepare(
        "SELECT bytes FROM successors ORDER BY sequence").all())
        .map((entry) => Buffer.from(entry.bytes));
    });
  }
  recover() {
    return this.#serial(async () => {
      const raw = this.#saved();
      if (!raw) deny();
      await this.#chain();
      await this.#coordinator.reconcile(raw);
      return this.#read();
    });
  }
  read() { return this.#serial(() => this.#read()); }
  #append(raw, sequence, grant) {
    this.#db.transaction(() => {
      if (sequence === 129) this.#db.prepare("INSERT INTO intent(id,bytes) VALUES(1,?)").run(raw);
      else this.#db.prepare("INSERT INTO successors(sequence,bytes) VALUES(?,?)")
        .run(sequence, raw);
      if (grant) this.#db.prepare("INSERT INTO signer_grants(sequence,grant,signer_spki) VALUES(?,?,?)")
        .run(sequence, grant.raw, grant.signer.export({ format: "der", type: "spki" }));
    })();
  }
  close() { if (this.#db.open) this.#db.close(); }
}
function encodeIdentity(scope, digest, checkpoint, fingerprints) {
  return Buffer.concat([...SCOPE.map((name) => scope[name]), digest, checkpoint,
    ...fingerprints]);
}

module.exports = { Zk1OpaqueCheckpointV2Client };
