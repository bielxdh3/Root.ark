"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const path = require("node:path");
const v8 = require("node:v8");
const { spawnSync } = require("node:child_process");
const { readConfig, invokeRemote } =
  require("../src/services/zk1HistoricalRecoveryOperatorHttps");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");

test("a renamed untrusted Windows config cannot reach a real pinned TLS 1.3 mTLS endpoint after the private-file guard", {
  skip: process.platform !== "win32",
}, async (t) => {
  const dir = createPrivateAuthorityFixture("zk65-w90-race-");
  t.after(() => {
    try { fs.rmSync(dir, { recursive: true, force: true }); }
    catch (error) { if (error.code !== "EPERM") throw error; }
  });
  generateNativeFixtureCertificates(dir, {
    caSubject: "Historical Operator Race Fixture", servers: ["operator"],
    clients: ["witness"],
  });
  const file = (name) => path.join(dir, name);
  const serverFingerprint = new crypto.X509Certificate(
    fs.readFileSync(file("operator.pem"))).fingerprint256;
  const witnessFingerprint = new crypto.X509Certificate(
    fs.readFileSync(file("witness.pem"))).fingerprint256;
  let reached = 0;
  const server = https.createServer({
    key: fs.readFileSync(file("operator.key")),
    cert: fs.readFileSync(file("operator.pem")),
    ca: fs.readFileSync(file("ca.pem")),
    requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
  }, (req, res) => {
    if (req.socket.authorized && req.socket.getPeerCertificate().fingerprint256 === witnessFingerprint) {
      reached++;
    }
    const bytes = v8.serialize({ ok: true, value: { reached: true } });
    res.writeHead(200, { "Content-Type": "application/octet-stream" });
    res.end(bytes);
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await new Promise((resolve) => server.listen(0, resolve));
  const client = (port) => ({ client: {
    hostname: "localhost", port,
    keyPath: file("witness.key"), certPath: file("witness.pem"),
    serverCaPath: file("ca.pem"), serverFingerprint,
  } });
  const protectedPath = file("protected.json");
  const unsafePath = file("unsafe.json");
  const priorPath = file("prior.json");
  fs.writeFileSync(protectedPath, JSON.stringify(client(1)), { flag: "wx" });
  fs.writeFileSync(unsafePath, JSON.stringify(client(server.address().port)), { flag: "wx" });
  const icacls = spawnSync("icacls.exe", [unsafePath, "/grant", "*S-1-1-0:(F)"], {
    encoding: "utf8", timeout: 10000, windowsHide: true,
  });
  assert.equal(icacls.status, 0, "Windows must persist the intentionally unsafe DACL");
  assert.equal(readConfig(protectedPath).client.port, 1);
  assert.throws(() => readConfig(unsafePath),
    "the untrusted replacement is independently rejected by the actual native ACL guard");

  // Scheduling hook only: the native ACL verification, filesystem rename,
  // actual file open/read, and live HTTPS/TLS exchange all execute normally.
  const originalReadFileSync = fs.readFileSync;
  const originalReadSync = fs.readSync;
  let swapped = false;
  const swap = () => {
    swapped = true;
    fs.renameSync(protectedPath, priorPath);
    fs.renameSync(unsafePath, protectedPath);
  };
  fs.readFileSync = function readWithRealRename(target, ...args) {
    if (target === protectedPath && !swapped) swap();
    return originalReadFileSync.call(this, target, ...args);
  };
  fs.readSync = function readPinnedWithRealRename(fd, ...args) {
    if (!swapped && fs.fstatSync(fd, { bigint: true }).ino
      === fs.lstatSync(protectedPath, { bigint: true }).ino) swap();
    return originalReadSync.call(this, fd, ...args);
  };
  try {
    await assert.rejects(async () => invokeRemote(protectedPath, "loadHead", []),
      "untrusted config swapped after the guard must never reach HTTPS");
  } finally {
    fs.readFileSync = originalReadFileSync;
    fs.readSync = originalReadSync;
  }
  assert.equal(swapped, true, "the scheduled real rename must have run");
  assert.equal(reached, 0, "no mTLS request may reach the operator sink");
  const goodPath = file("good.json");
  fs.writeFileSync(goodPath, JSON.stringify(client(server.address().port)), { flag: "wx" });
  assert.deepEqual(await invokeRemote(goodPath, "loadHead", []), { reached: true },
    "private config and genuine pinned client/server mTLS must continue to work");
  assert.equal(reached, 1);
});
