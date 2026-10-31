"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const Database = require("better-sqlite3");
const z = require("../src/crypto/rootark-zk-1");
const {
  Zk1OpaqueCatalog, catalogOperationObjectId, catalogHeaderMessage,
  catalogHeadDigest, catalogPageDigest, catalogCasDomain,
} = require("../src/services/zk1OpaqueCatalog");

const SNAPSHOT_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-snapshot-fetch/v1\0");
const RAW_KEY = (key) => key.export({ type: "spki", format: "der" }).subarray(-32);
const encode = async (value) => Buffer.from(await z.encodeDeterministic(value));

async function fixture() {
  const db = new Database(":memory:");
  db.exec(`CREATE TABLE zk_content_version (
    scope TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL,
    epoch INTEGER NOT NULL, ciphertext BLOB NOT NULL, ciphertext_digest BLOB NOT NULL,
    PRIMARY KEY(scope,id,revision)
  );
  CREATE TABLE zk_content_head(scope TEXT PRIMARY KEY,revision INTEGER,digest BLOB);
  CREATE TABLE zk_content_clock(scope TEXT PRIMARY KEY,last_at INTEGER);
  CREATE TABLE zk_content_nonce(scope TEXT,nonce BLOB,expires_at INTEGER,PRIMARY KEY(scope,nonce));`);
  const scope = {
    account_id: crypto.randomBytes(16), compartment_id: Buffer.from("lost-ack"),
    keyring_id: crypto.randomBytes(16),
  };
  const key = [scope.account_id, scope.compartment_id, scope.keyring_id]
    .map((part) => part.toString("hex")).join(":");
  const signer = crypto.generateKeyPairSync("ed25519");
  const authoritySigner = crypto.generateKeyPairSync("ed25519");
  const manifestDigest = crypto.randomBytes(32);
  const now = 1000;
  const ids = [crypto.randomBytes(16).toString("base64url"),
    crypto.randomBytes(16).toString("base64url")].sort();
  const versions = ids.map((object_id, index) => {
    const ciphertext = Buffer.from("opaque-physical-ciphertext-" + index);
    return {
      object_id, revision: 1, epoch: 1, ciphertext,
      ciphertext_digest: crypto.createHash("sha256").update(ciphertext).digest(),
      metadata_ciphertext: Buffer.alloc(284, index + 1),
    };
  });
  const addPhysical = (version) => db.prepare(
    "INSERT INTO zk_content_version(scope,id,revision,epoch,ciphertext,ciphertext_digest) VALUES(?,?,?,?,?,?)"
  ).run(key, version.object_id, version.revision, version.epoch,
    version.ciphertext, version.ciphertext_digest);
  addPhysical(versions[0]);
  async function signHead(sequence, previous_digest, entries) {
    const pages = entries.length ? [entries.map(({ ciphertext, ...v }) => v)] : [];
    const header = {
      type: "rootark-zk1-opaque-catalog/v1", ...scope,
      sequence, previous_digest, manifest_revision: 1, manifest_digest: manifestDigest,
      epoch: 1, signer_device_id: "owner-device",
      total_count: entries.length, page_digests: await Promise.all(pages.map(catalogPageDigest)),
      issued_at: now,
    };
    const bytes = await encode(header);
    const signature = crypto.sign(null, await catalogHeaderMessage(header), signer.privateKey);
    return { header, bytes, signature, digest: catalogHeadDigest(bytes, signature),
      bodies: await Promise.all(pages.map(encode)), pages };
  }
  const first = await signHead(1, Buffer.alloc(32), [versions[0]]);
  let authoritative = { sequence: 1, digest: first.digest };
  let readHeadCount = 0;
  let onReadHead = () => {};
  const signedCas = async (nonce) => {
    const statement = {
      type: "rootark-zk1-opaque-catalog-cas/v1", ...scope,
      sequence: authoritative.sequence, digest: authoritative.digest, nonce, observed_at: now,
    };
    return encode({ ...statement, signature: crypto.sign(null,
      Buffer.concat([catalogCasDomain, await encode(statement)]), authoritySigner.privateKey) });
  };
  const authority = {
    publicKey: authoritySigner.publicKey,
    readHead: async ({ nonce }) => {
      onReadHead(++readHeadCount);
      return signedCas(nonce);
    },
    fetchSnapshot: async ({ nonce }) => {
      const statement = {
        type: "rootark-zk1-opaque-catalog-snapshot-fetch/v1", ...scope,
        sequence: 1, digest: first.digest, head_sequence: 1, head_digest: first.digest,
        nonce, observed_at: now, header: first.bytes,
        header_signature: first.signature, page_bodies: first.bodies,
      };
      return encode({ ...statement, signature: crypto.sign(null,
        Buffer.concat([SNAPSHOT_DOMAIN, await encode(statement)]), authoritySigner.privateKey) });
    },
    compareAndSwap: async ({ expectedSequence, expectedDigest, nextSequence,
      nextDigest, nonce, headBytes, headSignature, pageBodies }) => {
      assert.equal(expectedSequence, authoritative.sequence);
      assert.deepEqual(expectedDigest, authoritative.digest);
      assert.equal(nextSequence, expectedSequence + 1);
      assert.deepEqual(catalogHeadDigest(headBytes, headSignature), nextDigest);
      assert.equal(pageBodies.length, 1);
      authoritative = { sequence: nextSequence, digest: nextDigest };
      return signedCas(nonce);
    },
  };
  const store = {
    signedHistoryRequired: true, admissionRequired: true, db, trustedScope: scope,
    nowSeconds: () => now,
    minimumHead: { revision: 1, digest: manifestDigest },
    clockRow: db.prepare("SELECT last_at FROM zk_content_clock WHERE scope=?"),
    getHead: db.prepare("SELECT revision,digest FROM zk_content_head WHERE scope=?"),
    nonceCount: db.prepare("SELECT COUNT(*) n FROM zk_content_nonce WHERE scope=?"),
  };
  const manifest = {
    revision: 1, current_epoch: 1,
    devices: [{ device_id: "owner-device", enrolled_epoch: 1,
      revoked_at_epoch: null, authorization_public_key: RAW_KEY(signer.publicKey) }],
  };
  let auth;
  store.runCatalogWithAdmission = async (_input, _operation, run) => run(auth);
  const catalog = new Zk1OpaqueCatalog({ store, authority });
  const authorize = (operation, sequence, digest) => {
    const nonce = crypto.randomBytes(32);
    auth = {
      key, head: { current_revision: 1, current_manifest_digest: manifestDigest },
      verifiedHeadManifest: manifest, deviceAuthorizationPublicKey: RAW_KEY(signer.publicKey),
      request: {
        nonce, manifest_revision: 1, manifest_digest: manifestDigest,
        epoch: 1, issued_at: now, expires_at: now + 30, device_id: "owner-device",
        object_id: catalogOperationObjectId(scope, operation),
        expected_object_revision: operation === "catalog-commit" ? sequence - 1 : sequence,
        ciphertext_digest: digest,
      },
    };
    return auth;
  };
  return { db, key, scope, catalog, versions, addPhysical, signHead,
    authorize, first, signer, authority, setAuthoritative: (v) => { authoritative = v; },
    onReadHead: (fn) => { onReadHead = fn; } };
}

test("committed CAS head recovers after ACK loss even after a later immutable PUT; read and next commit work", async () => {
  const f = await fixture();
  try {
    f.addPhysical(f.versions[1]); // committed external head was not locally recorded
    f.authorize("catalog-read", 1, f.first.digest);
    const result = await f.catalog.read({ scope: f.scope, authorization: null,
      signature: null, pageIndex: 0 });
    assert.equal(result.sequence, 1);
    assert.equal(result.entries.length, 1);
    assert.equal(result.entries[0].objectId, f.versions[0].object_id);
    assert.equal(f.catalog.head.get(f.key).sequence, 1);
    assert.equal(f.db.prepare("SELECT COUNT(*) n FROM zk_content_nonce WHERE scope=?")
      .get(f.key).n, 1);
    const omitted = await f.signHead(2, f.first.digest, [f.versions[0]]);
    f.authorize("catalog-commit", 2, omitted.digest);
    await assert.rejects(f.catalog.commit({
      scope: f.scope, authorization: null, signature: null,
      header: omitted.header, headerSignature: omitted.signature,
      pages: omitted.pages, ownerEvidence: Buffer.from("disposable-test-evidence"),
    }), /ZK_CATALOG_CONFLICT/);
    assert.equal(f.catalog.head.get(f.key).sequence, 1);
    const second = await f.signHead(2, f.first.digest, f.versions);
    f.authorize("catalog-commit", 2, second.digest);
    const committed = await f.catalog.commit({
      scope: f.scope, authorization: null, signature: null,
      header: second.header, headerSignature: second.signature,
      pages: second.pages, ownerEvidence: Buffer.from("disposable-test-evidence"),
    });
    assert.equal(committed.sequence, 2);
    assert.equal(f.catalog.head.get(f.key).sequence, 2);
    assert.equal(f.db.prepare("SELECT COUNT(*) n FROM zk_content_catalog_snapshot WHERE scope=?")
      .get(f.key).n, 2);
  } finally { f.db.close(); }
});

test("PUT between signed snapshot check and SQLite commit does not block ACK reconciliation", async () => {
  const f = await fixture();
  try {
    f.onReadHead((n) => {
      // read() checks the external head once; recovery checks it again after
      // verifying the signed snapshot but before the local SQLite transaction.
      if (n === 2) f.addPhysical(f.versions[1]);
    });
    f.authorize("catalog-read", 1, f.first.digest);
    const result = await f.catalog.read({ scope: f.scope, authorization: null,
      signature: null, pageIndex: 0 });
    assert.equal(result.sequence, 1);
    assert.equal(result.entries.length, 1);
    assert.equal(f.catalog.head.get(f.key).sequence, 1);
    assert.equal(f.db.prepare("SELECT COUNT(*) n FROM zk_content_version WHERE scope=?")
      .get(f.key).n, 2);
  } finally { f.db.close(); }
});

test("later PUT of revision 2 of the same object survives recovery and is included in the next signed head", async () => {
  const f = await fixture();
  try {
    const later = { ...f.versions[1], object_id: f.versions[0].object_id, revision: 2 };
    f.addPhysical(later);
    f.authorize("catalog-read", 1, f.first.digest);
    const prior = await f.catalog.read({ scope: f.scope, authorization: null,
      signature: null, pageIndex: 0 });
    assert.equal(prior.entries.length, 1);
    const next = await f.signHead(2, f.first.digest, [f.versions[0], later]);
    f.authorize("catalog-commit", 2, next.digest);
    const committed = await f.catalog.commit({
      scope: f.scope, authorization: null, signature: null,
      header: next.header, headerSignature: next.signature,
      pages: next.pages, ownerEvidence: Buffer.from("disposable-test-evidence"),
    });
    assert.equal(committed.sequence, 2);
    assert.equal(f.db.prepare("SELECT COUNT(*) n FROM zk_content_catalog_page WHERE scope=? AND sequence=2")
      .get(f.key).n, 1);
  } finally { f.db.close(); }
});

test("physical tampering during external CAS recheck cannot enter the recovered catalog", async () => {
  const f = await fixture();
  try {
    f.onReadHead((n) => {
      if (n === 2) f.db.prepare("UPDATE zk_content_version SET ciphertext=? WHERE scope=? AND id=?")
        .run(Buffer.from("corrupted-while-waiting"), f.key, f.versions[0].object_id);
    });
    f.authorize("catalog-read", 1, f.first.digest);
    await assert.rejects(f.catalog.read({ scope: f.scope, authorization: null,
      signature: null, pageIndex: 0 }), /ZK_CATALOG_UNAVAILABLE/);
    assert.equal(f.catalog.head.get(f.key), undefined);
  } finally { f.db.close(); }
});

test("recovery refuses missing or corrupted signed physical versions, even with later versions", async (t) => {
  for (const kind of ["missing", "altered"]) await t.test(kind, async () => {
    const f = await fixture();
    try {
      f.addPhysical(f.versions[1]);
      if (kind === "missing") f.db.prepare(
        "DELETE FROM zk_content_version WHERE scope=? AND id=?"
      ).run(f.key, f.versions[0].object_id);
      else f.db.prepare("UPDATE zk_content_version SET ciphertext=? WHERE scope=? AND id=?")
        .run(Buffer.from("tampered"), f.key, f.versions[0].object_id);
      const auth = f.authorize("catalog-read", 1, f.first.digest);
      await assert.rejects(f.catalog.reconcileMissing(f.key,
        { sequence: 1, digest: f.first.digest }, auth), /ZK_CATALOG_UNAVAILABLE/);
      assert.equal(f.catalog.head.get(f.key), undefined);
    } finally { f.db.close(); }
  });
});

test("recovery fails closed on independently signed rollback and same-sequence fork", async (t) => {
  for (const kind of ["rollback", "fork"]) await t.test(kind, async () => {
    const f = await fixture();
    try {
      f.addPhysical(f.versions[1]);
      const auth = f.authorize("catalog-read", 1, f.first.digest);
      await f.catalog.reconcileMissing(f.key, { sequence: 1, digest: f.first.digest }, auth);
      f.setAuthoritative(kind === "rollback"
        ? { sequence: 0, digest: Buffer.alloc(32) }
        : { sequence: 1, digest: crypto.randomBytes(32) });
      f.authorize("catalog-read", 1, f.first.digest);
      await assert.rejects(f.catalog.read({ scope: f.scope, authorization: null,
        signature: null, pageIndex: 0 }), /ZK_CATALOG_UNAVAILABLE/);
    } finally { f.db.close(); }
  });
});
