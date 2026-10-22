"use strict";

// Disposable independent witness/CAS-floor authority process. Real SQLite
// WAL-backed witness floor, TLS listener and Ed25519 signing private key stay
// in this process. The test orchestrator receives public pins only.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { Zk1WitnessCasAnchorFloor } = require("../../src/services/zk1WitnessCasAnchorFloor");
const { Zk1CasTerminalAnchor } = require("../../src/services/zk1CasTerminalAnchor");
const { createZk1WitnessHttpsServer, drainZk1WitnessHttpsServer } =
  require("../../src/services/zk1WitnessHttpsServer");

if (process.connected) process.send({ kind: "stage", step: "modules-loaded" });

let server;
let floor;
let anchor;
let stage = "boot";
const respond = (message) => { if (process.connected) process.send(message); };
function quit() { if (server) server.closeAllConnections(); floor?.close(); process.exit(0); }
process.once("disconnect", quit);
process.on("message", async (message) => {
  try {
    if (message?.kind === "init" && !server
      && typeof message.dir === "string" && path.isAbsolute(message.dir)) {
      respond({ kind: "stage", step: "init-received" });
      stage = "read-fixture";
      const dir = message.dir;
      const read = (name) => fs.readFileSync(path.join(dir, name));
      const witness = crypto.generateKeyPairSync("ed25519");
      const status = crypto.generateKeyPairSync("ed25519");
      const witnessKeyId = crypto.randomBytes(16);
      const statusKeyId = crypto.randomBytes(16);
      stage = "sqlite-bootstrap";
      floor = new Zk1WitnessCasAnchorFloor(path.join(dir, "floor.sqlite"), {
        bootstrapNew: true, witnessPrivateKey: witness.privateKey,
        witnessKeyId, statusKeyId, statusPublicKey: status.publicKey,
      });
      respond({ kind: "stage", step: "sqlite-floor-ready" });
      stage = "cas-bootstrap";
      anchor = new Zk1CasTerminalAnchor(path.join(dir, "anchor.log"), {
        bootstrapNew: true, statusKeyId, statusPrivateKey: status.privateKey,
      });
      const fingerprint = new crypto.X509Certificate(read("allowed.pem")).fingerprint256;
      const unavailable = async () => { throw Error("UNREACHABLE_WITNESS_ROUTE"); };
      const ledger = { reserve: unavailable, freshHead: unavailable,
        resolve: unavailable, prepareQuiesce: unavailable,
        cancelExpiredQuiesce: unavailable, beginIoAdmission: unavailable,
        finishIoAdmission: unavailable };
      server = createZk1WitnessHttpsServer({ key: read("server.key"),
        cert: read("server.pem"), clientCa: read("ca.pem"), ledger,
        casAnchorFloor: floor, principals: {
          [fingerprint]: { roles: ["cas-anchor"], scopes: [] },
        } });
      stage = "tls-listen";
      await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
      respond({ kind: "stage", step: "listening-ready" });
      respond({ kind: "listening", host: server.address().address,
        port: server.address().port,
        witnessSpki: witness.publicKey.export({ format: "der", type: "spki" }).toString("base64url"),
        witnessKeyId: witnessKeyId.toString("base64url"),
        statusKeyId: statusKeyId.toString("base64url") });
    } else if (message?.kind === "advance" && anchor) {
      const scope = { account_id: crypto.randomBytes(16),
        compartment_id: Buffer.from("fixture"), keyring_id: crypto.randomBytes(16),
        reservation_id: crypto.randomBytes(16) };
      const ticket = crypto.randomBytes(100);
      const manifest = crypto.randomBytes(100);
      anchor.prepare(scope, ticket, "committed", manifest);
      await anchor.append(scope, ticket, "committed", manifest, crypto.randomBytes(64));
      const result = floor.advance({ records: anchor.signedRecordPage({ afterSequence: 0 }) });
      respond({ kind: "advanced", sequence: result.sequence });
    } else if (message?.kind === "stop") {
      await drainZk1WitnessHttpsServer(server);
      quit();
    } else process.exit(2);
  } catch (_) { respond({ kind: "failed", stage }); process.exitCode = 2; }
});
