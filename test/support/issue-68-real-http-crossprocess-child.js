"use strict";

// Disposable two-process transport fixture. Ed25519 HTTP authentication here
// is test-only; production device/witness authentication is exercised by the
// separate signed /zk-1/v1/share/read integration test.
// Node --test discovers this support file too. Only a fork with an IPC channel
// may launch the disposable HTTP/SQLite fixture; direct discovery stays inert.
if (typeof process.send === "function") {
const crypto = require("node:crypto");
const http = require("node:http");
const Database = require("better-sqlite3");
const { Zk1ProtectedCiphertextSharing } =
  require("../../src/services/zk1ProtectedCiphertextSharing");

if (!["guest", "owner"].includes(process.argv[2])
  || ["W3_DB", "W3_SCOPE", "W3_GRANT", "W3_GUEST_PUBLIC", "W3_OWNER_PUBLIC"]
    .some((name) => typeof process.env[name] !== "string" || !process.env[name])) {
  throw new Error("ZK_SHARE_HTTP_FIXTURE_INVALID_IPC_ENV");
}
const db = new Database(process.env.W3_DB);
db.pragma("journal_mode = WAL");
db.pragma("busy_timeout = 50");
let now = 1400;
const scope = Object.fromEntries(Object.entries(JSON.parse(process.env.W3_SCOPE))
  .map(([field, value]) => [field, Buffer.from(value, "hex")]));
const share = new Zk1ProtectedCiphertextSharing({
  db, signedHistoryRequired: true, admissionRequired: true,
  nowSeconds: () => now,
  runWithAdmission() { throw new Error("use real signed HTTP fixture for full admission"); },
});
const role = process.argv[2];
const domain = Buffer.from("Root.ark/issue-68/two-process-http-fixture/v1\0");
const keys = {
  guest: crypto.createPublicKey({ key: Buffer.from(process.env.W3_GUEST_PUBLIC, "base64"),
    format: "der", type: "spki" }),
  owner: crypto.createPublicKey({ key: Buffer.from(process.env.W3_OWNER_PUBLIC, "base64"),
    format: "der", type: "spki" }),
};
const seen = new Set();
const notify = (kind, fields = {}) => process.send?.({ kind, pid: process.pid, ...fields });
function authenticated(request, expected) {
  const nonce = request.headers["x-fixture-nonce"];
  const signature = request.headers["x-fixture-signature"];
  if (request.headers["x-fixture-account"] !== expected
    || typeof nonce !== "string" || !/^[a-f0-9]{32}$/.test(nonce)
    || typeof signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(signature)
    || seen.has(nonce)) return false;
  const bytes = Buffer.from(signature, "base64url");
  const message = Buffer.concat([domain, Buffer.from(`${expected}:${nonce}`, "ascii")]);
  if (bytes.length !== 64 || !crypto.verify(null, message, keys[expected], bytes)) return false;
  seen.add(nonce);
  return true;
}
let heldResponse = null;
const server = http.createServer((request, response) => {
  if (role === "guest") {
    if (request.method !== "GET" || request.url !== "/ciphertext"
      || !authenticated(request, "guest")) {
      response.writeHead(403).end(); return;
    }
    try {
      share.getGrant(scope, process.env.W3_GRANT, "recipient");
      if (heldResponse) { response.writeHead(429).end(); return; }
      heldResponse = response;
      let terminal = false;
      const emit = () => new Promise((resolve) => {
        const finish = () => { terminal = true; resolve(); };
        response.once("finish", finish);
        response.once("close", finish);
        response.writeHead(200, { "content-type": "application/octet-stream",
          "cache-control": "no-store" });
        response.flushHeaders();
        notify("admitted");
      });
      emit.isTerminal = () => terminal || response.destroyed || response.writableFinished;
      emit.abort = () => response.destroy();
      share.emitTracked(scope, process.env.W3_GRANT, emit,
        { ciphertextBase64: "disposable-fixture-only" }).then(
        () => notify("settled", { ok: true, busyTimeout: db.pragma("busy_timeout", { simple: true }) }),
        (error) => notify("settled", { ok: false, code: error.code,
          busyTimeout: db.pragma("busy_timeout", { simple: true }) }));
    } catch (_) { if (!response.headersSent) response.writeHead(403).end(); }
    return;
  }
  if (role !== "owner" || request.method !== "POST" || request.url !== "/revoke"
    || !authenticated(request, "owner")) {
    response.writeHead(403).end(); return;
  }
  share.revokeAndDrain(scope, process.env.W3_GRANT, "owner").then(
    () => { response.writeHead(200).end("revoked"); notify("revokeDone", { status: 200 }); },
    (error) => { response.writeHead(error.code === "ZK_SHARE_UNAVAILABLE" ? 503 : 403)
      .end("unavailable"); notify("revokeDone", { status: error.code === "ZK_SHARE_UNAVAILABLE" ? 503 : 403 }); });
});
process.on("message", (message) => {
  if (message?.kind === "release" && role === "guest" && heldResponse) {
    heldResponse.end("ciphertext-only");
  } else if (message?.kind === "clock" && Number.isSafeInteger(message.now)) {
    now = message.now;
    notify("clockSet", { now });
  }
});
server.listen(0, "127.0.0.1", () => notify("ready", { port: server.address().port }));
}
