"use strict";
// TEST ONLY. This process is NOT a production owner-policy provider nor an
// independent physical CAS witness. It owns distinct Ed25519 keys, a separate
// disposable SQLite store, and a genuine TLS 1.3 mutual-TLS listener.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const z = require("../../src/crypto/rootark-zk-1");
const { createCatalogAuthorityHttpsServer, CATALOG_PHYSICAL_DOMAIN } =
  require("../../src/services/zk1CatalogExternalAuthorityHttps");
let server;
let db;
let physical;
let stateDir;
const send = (payload) => { if (process.connected) process.send(payload); };
function stop() {
  try { server?.closeAllConnections(); server?.close(); db?.close(); } catch (_) { /* test cleanup */ }
  process.exit(0);
}
process.once("disconnect", stop);
process.on("message", async (msg) => {
  try {
    if (msg?.kind === "init" && !server && path.isAbsolute(msg.dir)) {
      stateDir = msg.dir;
      const read = (name) => fs.readFileSync(path.join(stateDir, name));
      const policy = crypto.generateKeyPairSync("ed25519");
      const floor = crypto.generateKeyPairSync("ed25519");
      physical = crypto.generateKeyPairSync("ed25519");
      const witnessKey = crypto.createPublicKey({ key: Buffer.from(msg.witnessSpki, "base64url"),
        format: "der", type: "spki" });
      db = new Database(path.join(stateDir, "separate-operator-simulated-authority.sqlite"));
      db.pragma("journal_mode=WAL");
      db.pragma("synchronous=FULL");
      db.exec(`CREATE TABLE owner_state (id INTEGER PRIMARY KEY CHECK(id=1),
        enabled INTEGER NOT NULL, payload TEXT NOT NULL);
        CREATE TABLE committed_physical (ticket_hash TEXT PRIMARY KEY,
        committed_at INTEGER NOT NULL)`);
      const allowedClient = new crypto.X509Certificate(read("allowed.pem")).fingerprint256;
      server = createCatalogAuthorityHttpsServer({
        key: read("server.key"), cert: read("server.pem"), clientCa: read("ca.pem"),
        authorizedClientFingerprint256: allowedClient,
        policyPrivateKey: policy.privateKey, floorPrivateKey: floor.privateKey,
        witnessPublicKey: witnessKey, physicalPublicKey: physical.publicKey,
        trustedOwnerPolicy: async () => {
          const row = db.prepare("SELECT enabled,payload FROM owner_state WHERE id=1").get();
          if (!row || row.enabled !== 1) throw Error("OWNER_POLICY_NOT_AUTHORIZED");
          const obj = JSON.parse(row.payload);
          for (const field of ["account_id", "compartment_id", "keyring_id",
            "owner_digest", "operation_id", "signer_device_id", "catalog_digest",
            "cas_signer_spki_sha256"]) obj[field] = Buffer.from(obj[field], "base64url");
          return obj;
        },
        trustedPhysicalProof: async (ticket) => {
          const row = db.prepare("SELECT committed_at FROM committed_physical WHERE ticket_hash=?")
            .get(crypto.createHash("sha256").update(Buffer.from(
              await z.encodeDeterministic(ticket))).digest("hex"));
          if (!row) throw Error("PHYSICAL_COMMIT_NOT_PROVEN");
          const body = {
            type: "rootark-zk1-catalog-physical-operation-terminal/v1",
            ...Object.fromEntries(["account_id", "compartment_id", "keyring_id",
              "admission_id", "operation_id", "owner_revision", "owner_digest",
              "signer_device_id", "epoch", "sequence", "catalog_digest",
              "cas_signer_spki_sha256", "floor_nonce", "expires_at", "principal"]
              .map((field) => [field, ticket[field]])),
            observed_at: row.committed_at, committed: true,
          };
          const signature = crypto.sign(null, Buffer.concat([CATALOG_PHYSICAL_DOMAIN,
            Buffer.from(await z.encodeDeterministic(body))]), physical.privateKey);
          return Buffer.from(await z.encodeDeterministic({ ...body, signature }));
        },
      });
      await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
      send({ kind: "ready", port: server.address().port,
        policySpki: policy.publicKey.export({ format: "der", type: "spki" }).toString("base64url"),
        floorSpki: floor.publicKey.export({ format: "der", type: "spki" }).toString("base64url"),
        physicalSpki: physical.publicKey.export({ format: "der", type: "spki" }).toString("base64url") });
    } else if (msg?.kind === "authorize" && db) {
      db.prepare("INSERT INTO owner_state VALUES(1,1,?)").run(JSON.stringify(msg.policy));
      send({ kind: "authorized" });
    } else if (msg?.kind === "revoke" && db) {
      db.prepare("UPDATE owner_state SET enabled=0 WHERE id=1").run();
      send({ kind: "revoked" });
    } else if (msg?.kind === "physicalCommit" && db) {
      const raw = Buffer.from(msg.ticket, "base64url");
      const ticket = await z.decodeDeterministic(raw);
      const { signature, ...body } = ticket;
      const hash = crypto.createHash("sha256")
        .update(Buffer.from(await z.encodeDeterministic(body))).digest("hex");
      db.prepare("INSERT INTO committed_physical VALUES(?,?)")
        .run(hash, Math.floor(Date.now() / 1000));
      send({ kind: "physicalCommitted" });
    } else if (msg?.kind === "stop") {
      stop();
    } else { throw Error("INVALID_FIXTURE_COMMAND"); }
  } catch (_) { send({ kind: "failed" }); }
});
