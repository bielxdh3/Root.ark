"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const path = require("node:path");
const Database = require("better-sqlite3");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { Zk1WitnessCasAnchorFloor } = require("../src/services/zk1WitnessCasAnchorFloor");
const { createZk1WitnessHttpsServer, drainZk1WitnessHttpsServer } =
  require("../src/services/zk1WitnessHttpsServer");

const DOMAIN = Buffer.from("Root.ark/zk-1/cas-terminal-anchor/v1\0");
const digest = (value) => crypto.createHash("sha256").update(value).digest("hex");

function seedSignedHistory(filename, signingKey, count) {
  const db = new Database(filename);
  try {
    const insert = db.prepare("INSERT INTO witness_cas_floor_event VALUES (?,?,?,?)");
    db.transaction(() => {
      let previousHash = "0".repeat(64);
      const unique = Buffer.alloc(16);
      for (let sequence = 1; sequence <= count; sequence++) {
        unique.writeUInt32BE(sequence, 12);
        const record = { sequence, reservation: unique.toString("base64url"),
          scope: "a".repeat(32) + ":4:74657374:" + "b".repeat(32),
          status: "not-committed-final", ticketHash: digest(unique), manifestHash: null,
          terminalSeal: Buffer.alloc(64, 42).toString("base64url"), previousHash };
        record.signature = crypto.sign(null,
          Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(record))]), signingKey).toString("base64url");
        const line = JSON.stringify(record);
        const hash = digest(line);
        insert.run(sequence, line, hash, previousHash);
        previousHash = hash;
      }
    }).immediate();
  } finally { db.close(); }
}

function post(port, certificates, name, route, body) {
  const read = (file) => fs.readFileSync(path.join(certificates, file));
  return new Promise((resolve, reject) => {
    const req = https.request({ host: "localhost", port, path: route,
      method: "POST", ca: read("ca.pem"), key: read(name + ".key"),
      cert: read(name + ".pem"), headers: { "content-type": "application/json" } }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.once("end", () => resolve({ status: res.statusCode,
        body: JSON.parse(Buffer.concat(chunks).toString("utf8")) }));
    });
    req.once("error", reject);
    req.end(JSON.stringify(body));
  });
}

test("100k signed events: HTTPS anchor head stays nonce-bound, serves other witness routes while scanning, rejects earlier-row tamper and rollback", { timeout: 120000 }, async (t) => {
  const dir = require("./support/issue-65-private-authority-fixture")
    .createPrivateAuthorityFixture("rootark-async-anchor-");
  let floor;
  let server;
  t.after(async () => {
    if (server?.listening) await drainZk1WitnessHttpsServer(server);
    floor?.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  generateNativeFixtureCertificates(dir, { caSubject: "Anchor Async CA",
    servers: ["server"], clients: ["anchor", "reader"] });
  const witness = crypto.generateKeyPairSync("ed25519");
  const status = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const statusKeyId = crypto.randomBytes(16);
  const filename = path.join(dir, "floor.sqlite");
  const opts = { witnessPrivateKey: witness.privateKey, witnessKeyId,
    statusKeyId, statusPublicKey: status.publicKey };
  const bootstrap = new Zk1WitnessCasAnchorFloor(filename, { ...opts, bootstrapNew: true });
  bootstrap.close();
  const count = Number(process.env.TEST_CAS_FLOOR_EVENTS || 100000);
  seedSignedHistory(filename, status.privateKey, count);
  floor = new Zk1WitnessCasAnchorFloor(filename, { ...opts, bootstrapNew: false });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const fingerprint = (name) => new crypto.X509Certificate(read(name + ".pem")).fingerprint256;
  const scope = { account_id: crypto.randomBytes(16).toString("base64url"),
    compartment_id: Buffer.from("reader").toString("base64url"),
    keyring_id: crypto.randomBytes(16).toString("base64url") };
  const unavailable = async () => { throw new Error("UNEXPECTED"); };
  const ledger = { reserve: async () => Buffer.from([1]), freshHead: async () => Buffer.from([1]),
    resolve: unavailable, prepareQuiesce: unavailable, cancelExpiredQuiesce: unavailable,
    beginIoAdmission: unavailable, finishIoAdmission: unavailable };
  server = createZk1WitnessHttpsServer({
    key: read("server.key"), cert: read("server.pem"), clientCa: read("ca.pem"),
    ledger, casAnchorFloor: floor, principals: {
      [fingerprint("anchor")]: { roles: ["cas-anchor"], scopes: [] },
      [fingerprint("reader")]: { roles: ["head", "reserve"], scopes: [scope] },
    },
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  const challenge = crypto.randomBytes(32);
  const started = performance.now();
  let headSettled = false;
  const slowHead = post(port, dir, "anchor", "/v1/cas-anchor/head", {
    nonce: challenge.toString("base64url"),
  }).finally(() => { headSettled = true; });
  // Delay until the worker has started, without blocking the event loop.
  await new Promise((resolve) => setTimeout(resolve, 20));
  const fastStart = performance.now();
  const unrelated = await post(port, dir, "reader", "/v1/head", {
    scope, nonce: crypto.randomBytes(32).toString("base64url"),
  });
  const reserve = await post(port, dir, "reader", "/v1/reserve", { operation: {
    ...scope, reservation_id: crypto.randomBytes(16).toString("base64url"),
    operation_id: crypto.randomBytes(16).toString("base64url"),
    expected_revision: 1,
    expected_manifest_digest: crypto.randomBytes(32).toString("base64url"),
    proposed_revision: 2,
    proposed_manifest_digest: crypto.randomBytes(32).toString("base64url"),
    request_digest: crypto.randomBytes(32).toString("base64url"),
    package_envelope_digest: null, expires_at: Math.floor(Date.now() / 1000) + 60,
  } });
  const unrelatedMs = performance.now() - fastStart;
  assert.equal(headSettled, false,
    "the unrelated HTTPS witness route must finish while the 100k-row verification is still pending");
  const head = await slowHead;
  const totalMs = performance.now() - started;
  assert.equal(unrelated.status, 200);
  assert.equal(reserve.status, 201);
  assert.equal(head.status, 200);
  assert.equal(head.body.head.sequence, count);
  assert.equal(head.body.head.nonce, challenge.toString("base64url"));
  assert.equal(crypto.verify(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/witness-cas-anchor-floor/v1\0"),
    Buffer.from(JSON.stringify(Object.fromEntries(Object.entries(head.body.head)
      .filter(([key]) => key !== "signature")))),
  ]), witness.publicKey, Buffer.from(head.body.head.signature, "base64url")), true);
  assert.ok(totalMs > unrelatedMs + 30,
    `unrelated witness route should finish during async scan: total=${totalMs.toFixed(1)}ms other=${unrelatedMs.toFixed(1)}ms`);
  t.diagnostic(`100k head latency ${totalMs.toFixed(1)}ms; concurrent witness route ${unrelatedMs.toFixed(1)}ms`);
  // Signed SQL head untouched, but a historical SQL-only row is corrupt.
  const admin = new Database(filename);
  try {
    const twoConcurrent = [floor.freshHeadAsync({ nonce: crypto.randomBytes(32) }),
      floor.freshHeadAsync({ nonce: crypto.randomBytes(32) })];
    await assert.rejects(floor.freshHeadAsync({ nonce: crypto.randomBytes(32) }),
      /WITNESS_CAS_FLOOR_DENIED/, "worker concurrency must be bounded");
    await Promise.all(twoConcurrent);
    const concurrentEdit = floor.freshHeadAsync({ nonce: crypto.randomBytes(32) });
    await new Promise((resolve) => setTimeout(resolve, 20));
    const current = admin.prepare("SELECT line FROM witness_cas_floor_event WHERE sequence=1").get().line;
    admin.prepare("UPDATE witness_cas_floor_event SET line=? WHERE sequence=1").run(current + " ");
    await assert.rejects(concurrentEdit, /WITNESS_CAS_FLOOR_DENIED/,
      "external edit during worker snapshot must prevent signing");
    admin.prepare("UPDATE witness_cas_floor_event SET line=? WHERE sequence=1").run(current);
    const original = admin.prepare("SELECT line FROM witness_cas_floor_event WHERE sequence=1").get().line;
    admin.prepare("UPDATE witness_cas_floor_event SET line=? WHERE sequence=1").run(original + " ");
    await assert.rejects(floor.freshHeadAsync({ nonce: crypto.randomBytes(32) }),
      /WITNESS_CAS_FLOOR_DENIED/);
    admin.prepare("UPDATE witness_cas_floor_event SET line=? WHERE sequence=1").run(original);
    assert.equal((await floor.freshHeadAsync({ nonce: crypto.randomBytes(32) })).sequence, count);
    admin.prepare("DELETE FROM witness_cas_floor_event WHERE sequence=?").run(count);
    await assert.rejects(floor.freshHeadAsync({ nonce: crypto.randomBytes(32) }),
      /WITNESS_CAS_FLOOR_DENIED/);
  } finally { admin.close(); }
});
