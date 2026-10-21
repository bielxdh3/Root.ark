"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawn } = require("node:child_process");
const https = require("node:https");
const test = require("node:test");
const { Zk1DurableWitnessLedger } = require("../src/services/zk1DurableWitnessLedger");
const { createZk1WitnessHttpsServer, drainZk1WitnessHttpsServer } = require("../src/services/zk1WitnessHttpsServer");
const { createZk1CasStatusHttpsClient } = require("../src/services/zk1CasStatusHttpsClient");
const { createZk1WitnessHttpsClient } = require("../src/services/zk1WitnessHttpsClient");
const z = require("../src/crypto/rootark-zk-1");
const { inspectVerifiedWitnessReservationV1 } = require("../src/crypto/rootark-zk-witness-operation-wire-v1");

const DOMAIN = Buffer.from("Root.ark/zk-1/recovery-cas-status/v1\0", "ascii");
const GENESIS_DOMAIN = Buffer.from("Root.ark/zk-1/witness-genesis-authorization/v1\0", "ascii");
function createCertificates(dir) {
  const commands = [
    "set -eu",
    'openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -subj "/CN=Rootark Test CA" -days 1 >/dev/null 2>&1',
    'openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost" >/dev/null 2>&1',
    'printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" > server.ext',
    'openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 1 -extfile server.ext >/dev/null 2>&1',
    'for name in allowed denied; do openssl req -newkey rsa:2048 -nodes -keyout "$name.key" -out "$name.csr" -subj "/CN=$name" >/dev/null 2>&1; printf "extendedKeyUsage=clientAuth\n" > "$name.ext"; openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -out "$name.pem" -days 1 -extfile "$name.ext" >/dev/null 2>&1; done',
  ].join("\n");
  if (process.platform === "win32") {
    const unixDir = execFileSync("wsl.exe", ["-e", "wslpath", "-a", dir], { encoding: "utf8" }).trim();
    execFileSync("wsl.exe", ["-e", "bash", "-lc", "cd " + JSON.stringify(unixDir) + "; " + commands],
      { stdio: "pipe", timeout: 20000 });
  } else {
    execFileSync("bash", ["-lc", commands], { cwd: dir, stdio: "pipe", timeout: 20000 });
  }
  const read = (name) => fs.readFileSync(path.join(dir, name));
  return { ca: read("ca.pem"), serverKey: read("server.key"), serverCert: read("server.pem"),
    clientKey: read("allowed.key"), clientCert: read("allowed.pem"),
    forbiddenKey: read("denied.key"), forbiddenCert: read("denied.pem") };
}
function send(port, tls, pathname, body, identity = "allowed") {
  const key = identity === "allowed" ? tls.clientKey : identity === "denied" ? tls.forbiddenKey : undefined;
  const cert = identity === "allowed" ? tls.clientCert : identity === "denied" ? tls.forbiddenCert : undefined;
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = https.request({
      host: "127.0.0.1", port, path: pathname, method: "POST", ca: tls.ca, key, cert,
      rejectUnauthorized: true, servername: "localhost",
      headers: { "content-type": "application/json", "content-length": Buffer.byteLength(payload) },
      timeout: 5000,
    }, (res) => {
      const chunks = [];
      res.on("data", (piece) => chunks.push(piece));
      res.on("end", () => {
        const raw = Buffer.concat(chunks);
        try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); }
        catch (error) { reject(error); }
      });
    });
    req.on("error", reject);
    req.end(payload);
  });
}

test("mTLS standalone witness listener rejects unknown principals and returns signed pending/committed receipts", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-witness-mtls-"));
  const tls = createCertificates(dir);
  const witnessKey = crypto.generateKeyPairSync("ed25519");
  const authorityKey = crypto.generateKeyPairSync("ed25519");
  const initializerKey = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const statusKeyId = crypto.randomBytes(16);
  const scope = {
    account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("main"),
    keyring_id: crypto.randomBytes(16),
  };
  const op = {
    ...scope, reservation_id: crypto.randomBytes(16), operation_id: crypto.randomBytes(16),
    expected_revision: null, expected_manifest_digest: null, proposed_revision: 1,
    proposed_manifest_digest: crypto.randomBytes(32), request_digest: crypto.randomBytes(32),
    package_envelope_digest: null, expires_at: 1100,
  };
  const processOp = {
    ...op, keyring_id: crypto.randomBytes(16),
    reservation_id: crypto.randomBytes(16),
    operation_id: crypto.randomBytes(16),
    expires_at: Math.floor(Date.now() / 1000) + 240,
  };
  const enc = (input) => Buffer.from(input).toString("base64url");
  const toScopeJson = (source) => Object.fromEntries(
    ["account_id", "compartment_id", "keyring_id"].map((key) => [key, enc(source[key])]));
  const scopeJson = toScopeJson(scope);
  const processScopeJson = toScopeJson(processOp);
  const allowedScopes = [scopeJson, processScopeJson];
  const grant = {
    roles: ["head", "reserve", "resolve", "admit"], scopes: allowedScopes,
    initializeKeys: allowedScopes.map((item) => ({
      scope: item,
      publicKeyPem: initializerKey.publicKey.export({ format: "pem", type: "spki" }).toString(),
    })),
  };
  async function signGenesis(operation) {
    return enc(crypto.sign(null, Buffer.concat([GENESIS_DOMAIN,
      Buffer.from(await z.encodeDeterministic(operation))]), initializerKey.privateKey));
  }
  let casResponseMode = "normal";
  // Actual HTTPS request to a separate CAS-status listener, not a direct
  // callback: independent signed CAS proof travels over certificate-pinned
  // mutually authenticated TLS (these are still synthetic test identities).
  const casServer = https.createServer({
    key: tls.serverKey, cert: tls.serverCert, ca: tls.ca,
    requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
  }, async (req, res) => {
    try {
      if (req.method !== "POST" || req.url !== "/v1/terminal" || !req.socket.authorized) {
        res.writeHead(403).end();
        return;
      }
      if (casResponseMode === "redirect") {
        res.writeHead(302, { location: "https://localhost/" });
        res.end();
        return;
      }
      const chunks = [];
      for await (const part of req) chunks.push(part);
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      const query = Object.fromEntries(Object.entries(body.query).map(([k, v]) => [
        k, typeof v === "string" ? Buffer.from(v, "base64url") : v,
      ]));
      const nonce = Buffer.from(body.nonce, "base64url");
      const obj = { type: "rootark-recovery-cas-status/v1",
        status_authority_key_id: statusKeyId, ...query, observed_revision: query.proposed_revision,
        observed_manifest_digest: query.proposed_manifest_digest, terminal_status: "committed",
        observed_at: Buffer.from(query.keyring_id).equals(op.keyring_id)
          ? 950 : Math.floor(Date.now() / 1000), nonce };
      const signature = crypto.sign(null, Buffer.concat([DOMAIN, await z.encodeDeterministic(obj)]),
        authorityKey.privateKey);
      const raw = await z.encodeDeterministic({ ...obj, signature });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ proofBase64: Buffer.from(raw).toString("base64url") }));
    } catch (_) { res.writeHead(500).end(); }
  });
  await new Promise((resolve) => casServer.listen(0, "127.0.0.1", resolve));
  const casPort = casServer.address().port;
  const casClient = createZk1CasStatusHttpsClient({
    endpoint: "https://localhost:" + casPort + "/v1/terminal",
    ca: tls.ca, clientKey: tls.clientKey, clientCert: tls.clientCert,
    serverFingerprint256: new crypto.X509Certificate(tls.serverCert).fingerprint256,
  });
  const ledger = new Zk1DurableWitnessLedger(path.join(dir, "witness.sqlite"), {
    bootstrapNew: true, witnessKeyId, witnessPrivateKey: witnessKey.privateKey,
    statusPinned: { keyId: statusKeyId, publicKey: authorityKey.publicKey },
    statusProvider: casClient,
    nowSeconds: () => 950,
  });
  const fingerprint = new crypto.X509Certificate(tls.clientCert).fingerprint256;
  const wrongPin = createZk1CasStatusHttpsClient({
    endpoint: "https://localhost:" + casPort + "/v1/terminal",
    ca: tls.ca, clientKey: tls.clientKey, clientCert: tls.clientCert,
    serverFingerprint256: "00:".repeat(31) + "00",
  });
  const casQuery = Object.fromEntries(Object.entries(op)
    .filter(([name]) => name !== "expires_at"));
  await assert.rejects(wrongPin.getTerminalProof({
    query: casQuery, nonce: crypto.randomBytes(32),
  }), /CAS_STATUS_TRANSPORT_UNAVAILABLE/);
  const service = createZk1WitnessHttpsServer({
    key: tls.serverKey, cert: tls.serverCert, clientCa: tls.ca,
    ledger, principals: { [fingerprint]: grant },
  });
  await new Promise((resolve) => service.listen(0, "127.0.0.1", resolve));
  const port = service.address().port;
  const remoteWitness = createZk1WitnessHttpsClient({
    endpoint: "https://localhost:" + port,
    ca: tls.ca, clientKey: tls.clientKey, clientCert: tls.clientCert,
    serverFingerprint256: new crypto.X509Certificate(tls.serverCert).fingerprint256,
  });
  await assert.rejects(createZk1WitnessHttpsClient({
    endpoint: "https://localhost:" + port,
    ca: tls.ca, clientKey: tls.clientKey, clientCert: tls.clientCert,
    serverFingerprint256: "00:".repeat(31) + "00",
  }).freshHead({ scope, nonce: crypto.randomBytes(32) }),
  /WITNESS_TRANSPORT_UNAVAILABLE/, "caller must pin witness TLS server certificate");
  const ownedChildren = new Set();
  t.after(async () => {
    for (const child of ownedChildren) {
      if (child.exitCode === null) {
        const stopped = new Promise((resolve) => child.once("exit", resolve));
        child.kill("SIGTERM");
        await stopped;
      }
    }
    await new Promise((resolve) => service.close(resolve));
    await new Promise((resolve) => casServer.close(resolve));
    ledger.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const opJson = Object.fromEntries(Object.entries(op).map(([key, val]) =>
    [key, val instanceof Uint8Array ? enc(val) : val]));
  const processOpJson = Object.fromEntries(Object.entries(processOp).map(([key, val]) =>
    [key, val instanceof Uint8Array ? enc(val) : val]));
  assert.equal((await send(port, tls, "/v1/head", { scope: scopeJson, nonce: enc(crypto.randomBytes(32)) },
    "denied")).status, 403);
  await assert.rejects(send(port, tls, "/v1/head", { scope: scopeJson,
    nonce: enc(crypto.randomBytes(32)) }, "none"));
  assert.equal((await send(port, tls, "/v1/head", { scope: scopeJson,
    nonce: enc(crypto.randomBytes(32)) })).status, 404);
  const alienOperation = {
    ...opJson,
    keyring_id: enc(crypto.randomBytes(16)),
    reservation_id: enc(crypto.randomBytes(16)),
    operation_id: enc(crypto.randomBytes(16)),
  };
  assert.equal((await send(port, tls, "/v1/reserve", {
    operation: alienOperation,
  })).status, 403, "even a pinned mTLS client cannot reserve unrelated keyrings");
  assert.equal((await send(port, tls, "/v1/head", {
    scope: toScopeJson({ ...scope, keyring_id: crypto.randomBytes(16) }),
    nonce: enc(crypto.randomBytes(32)),
  })).status, 403, "head lookup cannot cross keyring ACL");
  assert.equal((await send(port, tls, "/v1/resolve", {
    scope: toScopeJson({ ...scope, keyring_id: crypto.randomBytes(16) }),
  })).status, 403, "resolve cannot cross keyring ACL");
  assert.equal((await send(port, tls, "/v1/reserve", { operation: opJson })).status, 403,
    "mTLS scope alone cannot authorize genesis without an owner/provisioner signature");
  const initializeSignature = await signGenesis(op);
  assert.equal((await send(port, tls, "/v1/reserve", {
    operation: opJson, initializeSignature: enc(crypto.randomBytes(64)),
  })).status, 403, "forged genesis authorization must be rejected");
  assert.equal((await send(port, tls, "/v1/reserve", {
    operation: { ...opJson, proposed_manifest_digest: enc(crypto.randomBytes(32)) },
    initializeSignature,
  })).status, 403, "signed genesis must bind the exact proposed manifest digest");
  const reserved = await remoteWitness.reserve({
    operation: op, initializeSignature: Buffer.from(initializeSignature, "base64url"),
  });
  assert.equal((await inspectVerifiedWitnessReservationV1({
    raw: reserved, pinned: { keyId: witnessKeyId, publicKey: witnessKey.publicKey },
    operation: op,
  })).verifiedSignatureOnly, true,
  "remote client transports only bytes; signing identity is verified separately");
  const localPending = await send(port, tls, "/v1/head", {
    scope: scopeJson, nonce: enc(crypto.randomBytes(32)),
  });
  assert.equal(localPending.status, 200, JSON.stringify(localPending.body));
  const remotePending = await z.decodeDeterministic(await remoteWitness.freshHead({
    scope, nonce: crypto.randomBytes(32),
  }));
  assert.equal(remotePending.status, "pending", "real pinned mTLS witness client reads pending head");
  casResponseMode = "redirect";
  assert.equal((await send(port, tls, "/v1/resolve", { scope: scopeJson })).status, 503,
    "CAS redirects must never resolve a witness reservation");
  const pending = await send(port, tls, "/v1/head", { scope: scopeJson,
    nonce: enc(crypto.randomBytes(32)) });
  assert.equal(pending.status, 200);
  assert.equal((await z.decodeDeterministic(Buffer.from(pending.body.receiptBase64, "base64url"))).status, "pending");
  casResponseMode = "normal";
  const resolved = await remoteWitness.resolve({ scope });
  assert.equal(resolved.status, "committed");
  assert.ok(resolved.receipt.length > 64, "remote client transports signed terminal receipt");
  const remoteCommitted = await z.decodeDeterministic(await remoteWitness.freshHead({
    scope, nonce: crypto.randomBytes(32),
  }));
  assert.equal(remoteCommitted.status, "committed", "pinned client reads finalized witness head");
  const fresh = await send(port, tls, "/v1/head", { scope: scopeJson,
    nonce: enc(crypto.randomBytes(32)) });
  assert.equal((await z.decodeDeterministic(Buffer.from(fresh.body.receiptBase64, "base64url"))).status, "committed");
  assert.equal((await send(port, tls, "/v1/reserve", {
    operation: opJson, initializeSignature,
  })).status, 409);

  const workerId = crypto.randomBytes(16);
  const ioRequest = { scope, revision: 1, digest: op.proposed_manifest_digest,
    action: "get", objectId: crypto.randomBytes(16).toString("base64url"), workerId };
  const alienIo = { ...ioRequest,
    scope: { ...scope, keyring_id: crypto.randomBytes(16) } };
  await assert.rejects(remoteWitness.beginIoAdmission(alienIo),
    /WITNESS_TRANSPORT_UNAVAILABLE/, "mTLS gate cannot authorize alien scopes");
  const admitted = await remoteWitness.beginIoAdmission(ioRequest);
  assert.equal(admitted.admissionId.length, 16);
  const retried = await remoteWitness.beginIoAdmission(ioRequest);
  assert.deepEqual(retried, admitted, "lost admission ACK is idempotent across mTLS");
  const nextOperation = {
    ...op, reservation_id: crypto.randomBytes(16), operation_id: crypto.randomBytes(16),
    expected_revision: 1, expected_manifest_digest: op.proposed_manifest_digest,
    proposed_revision: 2, proposed_manifest_digest: crypto.randomBytes(32),
    request_digest: crypto.randomBytes(32),
  };
  assert.equal((await send(port, tls, "/v1/reserve", {
    operation: Object.fromEntries(Object.entries(nextOperation).map(([key, value]) =>
      [key, value instanceof Uint8Array ? enc(value) : value])),
  })).status, 409, "the witness must deny revocation while HTTP egress holds an active gate");
  assert.deepEqual(await remoteWitness.finishIoAdmission({ scope,
    admissionId: admitted.admissionId, workerId }), { status: "completed" });
  await assert.rejects(remoteWitness.beginIoAdmission(ioRequest),
    /WITNESS_TRANSPORT_UNAVAILABLE/, "completed admission cannot replay");

  // A valid mTLS client can send an incomplete POST. It must not hold the
  // listener (and consequently the standalone ledger) open indefinitely.
  const slowServer = createZk1WitnessHttpsServer({
    key: tls.serverKey, cert: tls.serverCert, clientCa: tls.ca,
    ledger, principals: { [fingerprint]: grant },
  });
  await new Promise((resolve) => slowServer.listen(0, "127.0.0.1", resolve));
  const sawRequest = new Promise((resolve) => slowServer.once("request", resolve));
  const partial = https.request({
    host: "127.0.0.1", port: slowServer.address().port, path: "/v1/head",
    method: "POST", ca: tls.ca, key: tls.clientKey, cert: tls.clientCert,
    rejectUnauthorized: true, servername: "localhost",
    headers: { "content-type": "application/json", "content-length": "512" },
  });
  partial.on("error", () => {});
  partial.write("{");
  await sawRequest;
  try {
    const result = await Promise.race([
      drainZk1WitnessHttpsServer(slowServer, { deadlineMs: 125 }).then(() => "drained"),
      new Promise((resolve) => setTimeout(() => resolve("stalled"), 1000)),
    ]);
    assert.equal(result, "drained", "authenticated slow POST must not stall shutdown");
  } finally {
    partial.destroy();
    slowServer.closeAllConnections();
    if (slowServer.listening) {
      await new Promise((resolve) => slowServer.close(resolve));
    }
  }

  // Separate OS process boot/restart using only explicitly configured
  // filesystem key paths; do not persist signing keys in any tracked file.
  const keyFile = path.join(dir, "witness-private.pem");
  const pubFile = path.join(dir, "cas-signing-public.pem");
  fs.writeFileSync(keyFile, witnessKey.privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  fs.writeFileSync(pubFile, authorityKey.publicKey.export({ format: "pem", type: "spki" }));
  const configFile = path.join(dir, "witness-config.json");
  const dbFile = path.join(dir, "witness-process.sqlite");
  const config = {
    listenHost: "127.0.0.1", listenPort: 0, bootstrapNew: true,
    dbPath: dbFile, witnessKeyId: enc(witnessKeyId),
    witnessPrivateKeyPath: keyFile, statusKeyId: enc(statusKeyId),
    statusPublicKeyPath: pubFile,
    serverKeyPath: path.join(dir, "server.key"),
    serverCertPath: path.join(dir, "server.pem"),
    clientCaPath: path.join(dir, "ca.pem"),
    principals: { [fingerprint]: grant },
    cas: {
      endpoint: "https://localhost:" + casPort + "/v1/terminal",
      caPath: path.join(dir, "ca.pem"),
      clientKeyPath: path.join(dir, "allowed.key"),
      clientCertPath: path.join(dir, "allowed.pem"),
      serverFingerprint256: new crypto.X509Certificate(tls.serverCert).fingerprint256,
    },
  };
  async function launch() {
    fs.writeFileSync(configFile, JSON.stringify(config), { mode: 0o600 });
    const child = spawn(process.execPath, [
      path.resolve(__dirname, "../scripts/zk1-witness-standalone.js"), "--config", configFile,
    ], {
      cwd: path.resolve(__dirname, ".."), stdio: ["ignore", "pipe", "pipe", "ipc"],
      windowsHide: true,
    });
    ownedChildren.add(child);
    const result = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("WITNESS_PROCESS_START_TIMEOUT")), 5000);
      child.once("message", (msg) => {
        clearTimeout(timer);
        if (msg?.type === "ready" && Number.isSafeInteger(msg.port)) resolve(msg.port);
        else reject(new Error("WITNESS_PROCESS_START_INVALID"));
      });
      child.once("exit", (code) => {
        clearTimeout(timer);
        reject(new Error("WITNESS_PROCESS_EXIT_" + code));
      });
    });
    const stop = async () => {
      if (child.exitCode !== null) return;
      const exited = new Promise((resolve) => child.once("exit", resolve));
      child.kill("SIGTERM");
      await exited;
      ownedChildren.delete(child);
    };
    return { port: result, stop };
  }
  const firstProcess = await launch();
  assert.equal((await send(firstProcess.port, tls, "/v1/reserve", {
    operation: processOpJson, initializeSignature: await signGenesis(processOp),
  })).status, 201);
  await firstProcess.stop();
  config.bootstrapNew = false;
  const restarted = await launch();
  const duringRestart = await send(restarted.port, tls, "/v1/head", { scope: processScopeJson,
    nonce: enc(crypto.randomBytes(32)) });
  assert.equal((await z.decodeDeterministic(
    Buffer.from(duringRestart.body.receiptBase64, "base64url"))).status, "pending");
  assert.equal((await send(restarted.port, tls, "/v1/resolve", {
    scope: processScopeJson,
  })).status, 200);
  await restarted.stop();
});
