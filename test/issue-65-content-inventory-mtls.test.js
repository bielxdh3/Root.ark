"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const https = require("node:https");
const { execFileSync, spawn } = require("node:child_process");
const { Zk1DurableContentInventoryLedger } =
  require("../src/services/zk1DurableContentInventoryLedger");
const {
  createZk1ContentInventoryHttpsServer,
  drainZk1ContentInventoryHttpsServer,
} = require("../src/services/zk1ContentInventoryHttpsServer");
const { createZk1ContentInventoryHttpsClient } =
  require("../src/services/zk1ContentInventoryHttpsClient");

const SCOPE = Object.freeze({
  account_id: Buffer.alloc(16, 0x11),
  compartment_id: Buffer.from("issue-65-mtls-fixture"),
  keyring_id: Buffer.alloc(16, 0x22),
});
const OTHER_SCOPE = Object.freeze({
  account_id: Buffer.alloc(16, 0x11),
  compartment_id: Buffer.from("issue-65-mtls-fixture"),
  keyring_id: Buffer.alloc(16, 0x33),
});

function scopeJson(scope) {
  return Object.fromEntries(Object.entries(scope).map(([name, bytes]) =>
    [name, Buffer.from(bytes).toString("base64url")]));
}

function openSslPath() {
  if (process.platform !== "win32") return "openssl";
  const candidates = [
    path.join(process.env.ProgramFiles || "C:\\Program Files", "Git", "usr", "bin", "openssl.exe"),
    path.join(process.env.ProgramFiles || "C:\\Program Files", "Git", "mingw64", "bin", "openssl.exe"),
  ];
  return candidates.find((candidate) => fs.existsSync(candidate)) || "openssl.exe";
}

function runOpenSsl(cwd, args) {
  execFileSync(openSslPath(), args, {
    cwd,
    stdio: "ignore",
    timeout: 30000,
    windowsHide: true,
  });
}

function makeCertificates(dir) {
  const createCa = (name) => runOpenSsl(dir, [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", `${name}-ca.key`, "-out", `${name}-ca.pem`,
    "-subj", `/CN=${name} fixture CA`, "-days", "1",
  ]);
  const sign = (name, caName, usage, server = false) => {
    runOpenSsl(dir, [
      "req", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`,
      "-out", `${name}.csr`, "-subj", `/CN=${server ? "localhost" : name}`,
    ]);
    const extensions = [
      usage,
      "keyUsage=digitalSignature,keyEncipherment",
      ...(server ? ["subjectAltName=DNS:localhost,IP:127.0.0.1"] : []),
    ].join("\n") + "\n";
    fs.writeFileSync(path.join(dir, `${name}.ext`), extensions, { flag: "wx", mode: 0o600 });
    runOpenSsl(dir, [
      "x509", "-req", "-in", `${name}.csr`, "-CA", `${caName}-ca.pem`,
      "-CAkey", `${caName}-ca.key`, "-CAcreateserial", "-out", `${name}.pem`,
      "-days", "1", "-extfile", `${name}.ext`,
    ]);
  };

  createCa("trusted");
  createCa("untrusted");
  sign("inventory-server", "trusted", "extendedKeyUsage=serverAuth", true);
  sign("reader", "trusted", "extendedKeyUsage=clientAuth");
  sign("writer", "trusted", "extendedKeyUsage=clientAuth");
  sign("status-reader", "trusted", "extendedKeyUsage=clientAuth");
  sign("unlisted", "trusted", "extendedKeyUsage=clientAuth");
  sign("foreign-client", "untrusted", "extendedKeyUsage=clientAuth");

  const read = (name) => fs.readFileSync(path.join(dir, name));
  const certificate = (name) => read(`${name}.pem`);
  return {
    ca: read("trusted-ca.pem"),
    untrustedCa: read("untrusted-ca.pem"),
    serverKey: read("inventory-server.key"),
    serverCert: certificate("inventory-server"),
    serverFingerprint256: new crypto.X509Certificate(certificate("inventory-server")).fingerprint256,
    clients: Object.fromEntries(["reader", "writer", "status-reader", "unlisted", "foreign-client"]
      .map((name) => [name, { key: read(`${name}.key`), cert: certificate(name) }])),
    clientFingerprints: Object.fromEntries(["reader", "writer", "status-reader"]
      .map((name) => [name, new crypto.X509Certificate(certificate(name)).fingerprint256])),
  };
}

function encodeOperation(operation) {
  return {
    operation_id: Buffer.from(operation.operation_id).toString("base64url"),
    expected_sequence: operation.expected_sequence,
    expected_root: Buffer.from(operation.expected_root).toString("base64url"),
    object_id: Buffer.from(operation.object_id).toString("base64url"),
    revision: operation.revision,
    epoch: operation.epoch,
    ciphertext_sha256: Buffer.from(operation.ciphertext_sha256).toString("base64url"),
  };
}

function newOperation({ sequence = 0, root, objectId = Buffer.alloc(16, 0x44), revision = 1 } = {}) {
  return {
    operation_id: crypto.randomBytes(16),
    expected_sequence: sequence,
    expected_root: Buffer.from(root),
    object_id: Buffer.from(objectId),
    revision,
    epoch: 1,
    ciphertext_sha256: crypto.createHash("sha256").update(`ciphertext-${revision}`).digest(),
  };
}

function requested(operation) {
  return {
    object_id: Buffer.from(operation.object_id),
    revision: operation.revision,
    epoch: operation.epoch,
    ciphertext_sha256: Buffer.from(operation.ciphertext_sha256),
  };
}

function rawRequest({ port, tls, route, body, headers = {}, method = "POST" }) {
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(body || "");
  return new Promise((resolve, reject) => {
    const request = https.request({
      hostname: "localhost",
      port,
      path: route,
      method,
      agent: false,
      ca: tls.ca,
      cert: tls.clients.reader.cert,
      key: tls.clients.reader.key,
      minVersion: "TLSv1.3",
      rejectUnauthorized: true,
      servername: "localhost",
      headers: {
        "content-type": "application/json",
        "content-length": String(bytes.length),
        ...headers,
      },
    }, (response) => {
      const parts = [];
      response.on("data", (part) => parts.push(part));
      response.on("end", () => resolve({
        status: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(parts),
      }));
      response.on("error", reject);
    });
    request.on("error", reject);
    request.end(bytes);
  });
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return server.address().port;
}

function waitForChildPort(childProcess) {
  return new Promise((resolve, reject) => {
    let output = "";
    const timer = setTimeout(() => reject(new Error("fixture child did not start")), 10000);
    childProcess.once("error", () => {
      clearTimeout(timer);
      reject(new Error("fixture child could not start"));
    });
    childProcess.once("exit", () => {
      clearTimeout(timer);
      reject(new Error("fixture child exited before listen"));
    });
    childProcess.stdout.setEncoding("utf8");
    childProcess.stdout.on("data", (chunk) => {
      output += chunk;
      const end = output.indexOf("\n");
      if (end < 0) return;
      const port = Number(output.slice(0, end));
      clearTimeout(timer);
      if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
        reject(new Error("fixture child returned an invalid port"));
      } else resolve(port);
    });
  });
}

async function stopChild(childProcess) {
  if (childProcess.exitCode !== null || childProcess.signalCode !== null) return;
  await new Promise((resolve) => {
    const timer = setTimeout(() => {
      childProcess.kill();
      resolve();
    }, 3000);
    childProcess.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
    childProcess.kill();
  });
}

test("Root.ark #65 standalone mTLS inventory transport verifies signed, nonauthorizing results", async (t) => {
  const tlsDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-issue65-mtls-certs-"));
  const tls = makeCertificates(tlsDir);
  t.after(() => fs.rmSync(tlsDir, { recursive: true, force: true, maxRetries: 10 }));

  async function harness(child, { scope = SCOPE } = {}) {
    const dbPath = path.join(tlsDir, `inventory-${crypto.randomBytes(8).toString("hex")}.sqlite`);
    const signer = crypto.generateKeyPairSync("ed25519");
    const signerKeyId = crypto.randomBytes(16);
    const scopeBytes = {
      account_id: Buffer.from(scope.account_id),
      compartment_id: Buffer.from(scope.compartment_id),
      keyring_id: Buffer.from(scope.keyring_id),
    };
    let ledger = await Zk1DurableContentInventoryLedger.open(dbPath, {
      bootstrapNew: true,
      signerKeyId,
      signerPrivateKey: signer.privateKey,
      scope: scopeBytes,
    });
    const ledgerProxy = {
      get scope() { return ledger.scope; },
      getSnapshot: (...args) => ledger.getSnapshot(...args),
      append: (...args) => ledger.append(...args),
      getOperationStatus: (...args) => ledger.getOperationStatus(...args),
    };
    const scopes = [scopeJson(scopeBytes)];
    const principals = {
      [tls.clientFingerprints.reader]: { roles: ["read"], scopes },
      [tls.clientFingerprints.writer]: { roles: ["append"], scopes },
      [tls.clientFingerprints["status-reader"]]: { roles: ["status"], scopes },
    };
    const makeServer = () => createZk1ContentInventoryHttpsServer({
      key: tls.serverKey,
      cert: tls.serverCert,
      clientCa: tls.ca,
      ledger: ledgerProxy,
      principals,
    });
    let server = makeServer();
    let port = await listen(server);
    const makeClient = (identity = "reader", options = {}) => createZk1ContentInventoryHttpsClient({
      endpoint: `https://localhost:${options.port || port}`,
      ca: options.ca || tls.ca,
      clientKey: tls.clients[identity].key,
      clientCert: tls.clients[identity].cert,
      serverFingerprint256: options.serverFingerprint256 || tls.serverFingerprint256,
      inventoryPublicKey: options.inventoryPublicKey || signer.publicKey,
      inventorySignerKeyId: options.inventorySignerKeyId || signerKeyId,
      idleTimeoutMs: options.idleTimeoutMs,
      wallTimeoutMs: options.wallTimeoutMs,
    });
    const closeCurrent = async () => {
      if (server) {
        const closing = server;
        server = null;
        await drainZk1ContentInventoryHttpsServer(closing);
      }
      if (ledger) {
        ledger.close();
        ledger = null;
      }
    };
    child.after(closeCurrent);
    return {
      dbPath,
      get ledger() { return ledger; },
      get server() { return server; },
      get port() { return port; },
      signer,
      signerKeyId,
      scope: scopeBytes,
      makeClient,
      stop: closeCurrent,
    };
  }

  await t.test("fresh nonce proves absence, append inclusion, and historical revision over TLS 1.3", async (child) => {
    const h = await harness(child);
    const reader = h.makeClient("reader");
    const writer = h.makeClient("writer");
    const genesis = await h.ledger.readLocalHead();
    const operation1 = newOperation({ root: genesis.root });
    const floor0 = { sequence: 0, root: genesis.root };
    const absent = await reader.getSnapshot({
      scope: h.scope,
      nonce: crypto.randomBytes(32),
      requested: requested(operation1),
      minimumHead: floor0,
    });
    assert.equal(absent.status, "VERIFIED_NONAUTHORIZING");
    assert.equal(absent.outcome, "ABSENT");
    assert.equal(absent.authorizesIo, false);

    const first = await writer.append({
      scope: h.scope,
      operation: operation1,
      nonce: crypto.randomBytes(32),
      minimumHead: floor0,
      minimumSnapshot: absent.serializedSnapshot,
    });
    assert.equal(first.status, "committed");
    assert.equal(first.signedLedgerOperationCommitted, true);
    assert.equal(first.authorizesIo, false);
    assert.equal(first.verification.outcome, "PRESENT");
    assert.equal(first.authorizesIo, false);

    const operation2 = newOperation({
      sequence: 1,
      root: first.root,
      objectId: operation1.object_id,
      revision: 2,
    });
    const second = await writer.append({
      scope: h.scope,
      operation: operation2,
      nonce: crypto.randomBytes(32),
      minimumHead: { sequence: 1, root: first.root },
      minimumSnapshot: first.serializedSnapshot,
    });
    assert.equal(second.sequence, 2);
    assert.equal(second.verification.outcome, "PRESENT");
    assert.equal(second.signedLedgerOperationCommitted, true);
    const historical = await reader.getSnapshot({
      scope: h.scope,
      nonce: crypto.randomBytes(32),
      requested: requested(operation1),
      minimumHead: { sequence: 1, root: first.root },
      minimumSnapshot: first.serializedSnapshot,
    });
    assert.equal(historical.sequence, 2);
    assert.equal(historical.outcome, "PRESENT");
    assert.equal(historical.tuple.revision, 1);
  });

  await t.test("client verifies multi-step signed receipts against a fresh mTLS snapshot, rejecting gaps", async (child) => {
    const h = await harness(child);
    const reader = h.makeClient("reader");
    const genesis = await h.ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
    const floor = await h.ledger.readLocalHead();
    const receipts = [];
    let head = floor;
    let last;
    for (let i = 1; i <= 3; i += 1) {
      last = newOperation({ sequence: head.sequence, root: head.root,
        objectId: Buffer.alloc(16, 0x80 + i) });
      const commit = await h.ledger.append(last);
      assert.equal(commit.status, "committed");
      receipts.push((await h.ledger.getOperationStatus(last.operation_id)).proof);
      head = { sequence: commit.sequence, root: commit.root };
    }
    const query = {
      scope: h.scope, requested: requested(last),
      minimumHead: floor, minimumSnapshot: genesis.bytes,
    };
    await assert.rejects(reader.getSnapshot({ ...query, nonce: crypto.randomBytes(32) }),
      { code: "INVENTORY_HTTP_UNAVAILABLE" });
    const inputReceipts = receipts.map((proof) => Buffer.from(proof));
    const verifiedPromise = reader.getSnapshot({
      ...query, nonce: crypto.randomBytes(32), committedProofChain: inputReceipts,
    });
    inputReceipts[0].fill(0);
    inputReceipts.reverse();
    const verified = await verifiedPromise;
    assert.equal(verified.outcome, "PRESENT");
    assert.equal(verified.verifiedInterveningReceipts, 3);
    assert.deepEqual(verified.root, head.root);
    await assert.rejects(reader.getSnapshot({
      ...query, nonce: crypto.randomBytes(32), committedProofChain: receipts.slice(1),
    }), { code: "INVENTORY_HTTP_UNAVAILABLE" });
  });

  await t.test("exact append retry stays one signed head and replays after service and SQLite restart", async (child) => {
    const h = await harness(child);
    const writer = h.makeClient("writer");
    const reader = h.makeClient("reader");
    const genesis = await h.ledger.readLocalHead();
    const operation = newOperation({ root: genesis.root });
    const floor = { sequence: 0, root: genesis.root };
    const genesisSnapshot = await reader.getSnapshot({
      scope: h.scope,
      nonce: crypto.randomBytes(32),
      requested: requested(operation),
      minimumHead: floor,
    });
    const first = await writer.append({
      scope: h.scope, operation, nonce: crypto.randomBytes(32), minimumHead: floor,
      minimumSnapshot: genesisSnapshot.serializedSnapshot,
    });
    const retry = await writer.append({
      scope: h.scope, operation, nonce: crypto.randomBytes(32), minimumHead: floor,
      minimumSnapshot: genesisSnapshot.serializedSnapshot,
    });
    assert.equal(first.transportReplayReported, false);
    assert.equal(retry.transportReplayReported, true);
    assert.equal(first.signedLedgerOperationCommitted, true);
    assert.equal(retry.signedLedgerOperationCommitted, true);
    assert.deepEqual(retry.verifiedReceipt.operationId, operation.operation_id);
    assert.equal(retry.sequence, first.sequence);
    assert.deepEqual(retry.root, first.root);
    assert.deepEqual(retry.verification.root, first.verification.root);

    await h.stop();
    const signerKeyPath = path.join(tlsDir, `signer-${crypto.randomBytes(8).toString("hex")}.pem`);
    fs.writeFileSync(signerKeyPath, h.signer.privateKey.export({ format: "pem", type: "pkcs8" }), {
      flag: "wx",
      mode: 0o600,
    });
    const childScript = String.raw`
      "use strict";
      const crypto = require("node:crypto");
      const fs = require("node:fs");
      const { Zk1DurableContentInventoryLedger } = require("./src/services/zk1DurableContentInventoryLedger");
      const { createZk1ContentInventoryHttpsServer, drainZk1ContentInventoryHttpsServer } = require("./src/services/zk1ContentInventoryHttpsServer");
      (async () => {
        const config = JSON.parse(process.argv[1]);
        const scope = Object.fromEntries(Object.entries(config.scope).map(([name, value]) => [name, Buffer.from(value, "base64url")]));
        const signerKeyId = Buffer.from(config.signerKeyId, "base64url");
        const ledger = await Zk1DurableContentInventoryLedger.open(config.dbPath, {
          bootstrapNew: false,
          signerKeyId,
          signerPrivateKey: crypto.createPrivateKey(fs.readFileSync(config.signerKeyPath)),
          scope,
        });
        const principals = Object.fromEntries(Object.entries(config.fingerprints).map(([fingerprint, role]) => [
          fingerprint, { roles: [role], scopes: [config.scopeJson] },
        ]));
        const server = createZk1ContentInventoryHttpsServer({
          key: fs.readFileSync(config.serverKeyPath),
          cert: fs.readFileSync(config.serverCertPath),
          clientCa: fs.readFileSync(config.caPath),
          ledger,
          principals,
        });
        await new Promise((resolve, reject) => {
          server.once("error", reject);
          server.listen(0, "127.0.0.1", resolve);
        });
        process.stdout.write(String(server.address().port) + "\n");
        process.once("SIGTERM", async () => {
          try {
            await drainZk1ContentInventoryHttpsServer(server);
            ledger.close();
            process.exit(0);
          } catch (_) { process.exit(1); }
        });
      })().catch(() => process.exit(1));
    `;
    const childConfig = {
      dbPath: h.dbPath,
      signerKeyPath,
      signerKeyId: h.signerKeyId.toString("base64url"),
      scope: scopeJson(h.scope),
      scopeJson: scopeJson(h.scope),
      fingerprints: {
        [tls.clientFingerprints.reader]: "read",
        [tls.clientFingerprints.writer]: "append",
        [tls.clientFingerprints["status-reader"]]: "status",
      },
      serverKeyPath: path.join(tlsDir, "inventory-server.key"),
      serverCertPath: path.join(tlsDir, "inventory-server.pem"),
      caPath: path.join(tlsDir, "trusted-ca.pem"),
    };
    const restartedProcess = spawn(process.execPath, ["-e", childScript, JSON.stringify(childConfig)], {
      cwd: path.resolve("."),
      stdio: ["ignore", "pipe", "ignore"],
      windowsHide: true,
    });
    child.after(() => stopChild(restartedProcess));
    const restartedPort = await waitForChildPort(restartedProcess);
    const afterRestart = await h.makeClient("writer", { port: restartedPort }).append({
      scope: h.scope, operation, nonce: crypto.randomBytes(32), minimumHead: floor,
      minimumSnapshot: genesisSnapshot.serializedSnapshot,
    });
    assert.equal(afterRestart.status, "committed");
    assert.equal(afterRestart.transportReplayReported, true);
    assert.equal(afterRestart.signedLedgerOperationCommitted, true);
    assert.equal(afterRestart.sequence, first.sequence);
    assert.deepEqual(afterRestart.root, first.root);
    assert.equal(afterRestart.verification.outcome, "PRESENT");
    const verified = await h.makeClient("reader", { port: restartedPort }).getSnapshot({
      scope: h.scope,
      nonce: crypto.randomBytes(32),
      requested: requested(operation),
      minimumHead: floor,
      minimumSnapshot: genesisSnapshot.serializedSnapshot,
    });
    assert.equal(verified.sequence, 1);
    assert.equal(verified.outcome, "PRESENT");
  });

  await t.test("terminal noncommit proof is independently verified for the exact operation", async (child) => {
    const h = await harness(child);
    const genesis = await h.ledger.readLocalHead();
    const invalid = newOperation({ root: genesis.root, revision: 2 });
    const result = await h.makeClient("writer").append({
      scope: h.scope,
      operation: invalid,
      nonce: crypto.randomBytes(32),
      minimumHead: { sequence: 0, root: genesis.root },
    });
    assert.equal(result.status, "not_committed_final");
    assert.equal(result.verified, true);
    assert.equal(result.authorizesIo, false);
    const status = await h.makeClient("status-reader").getOperationStatus({
      scope: h.scope,
      operation: invalid,
    });
    assert.equal(status.status, "not_committed_final");
    assert.equal(status.verified, true);
    assert.equal(status.authorizesIo, false);
  });

  await t.test("pending intent remains pending and nonauthorizing on snapshot and status routes", async (child) => {
    const h = await harness(child);
    const genesis = await h.ledger.readLocalHead();
    const operation = newOperation({ root: genesis.root });
    assert.equal((await h.ledger.prepareAppend(operation)).status, "pending");
    const result = await h.makeClient("reader").getSnapshot({
      scope: h.scope,
      nonce: crypto.randomBytes(32),
      requested: requested(operation),
      minimumHead: { sequence: 0, root: genesis.root },
    });
    assert.equal(result.status, "pending");
    assert.equal(result.authorizesIo, false);
    const status = await h.makeClient("status-reader").getOperationStatus({
      scope: h.scope,
      operation,
    });
    assert.equal(status.status, "pending");
    assert.equal(status.authorizesIo, false);
    assert.equal(status.transportReportedCommittedOnly, false);
  });

  await t.test("principal, role, and exact scope mismatches are refused", async (child) => {
    const h = await harness(child);
    const genesis = await h.ledger.readLocalHead();
    const operation = newOperation({ root: genesis.root });
    const reader = h.makeClient("reader");
    await assert.rejects(reader.getSnapshot({
      scope: OTHER_SCOPE,
      nonce: crypto.randomBytes(32),
      requested: requested(operation),
      minimumHead: { sequence: 0, root: genesis.root },
    }), { code: "INVENTORY_HTTP_UNAVAILABLE" });
    await assert.rejects(reader.append({
      scope: h.scope,
      operation,
      nonce: crypto.randomBytes(32),
      minimumHead: { sequence: 0, root: genesis.root },
    }), { code: "INVENTORY_HTTP_UNAVAILABLE" }, "read principal cannot use append route");
    await assert.rejects(h.makeClient("unlisted").getSnapshot({
      scope: h.scope,
      nonce: crypto.randomBytes(32),
      requested: requested(operation),
      minimumHead: { sequence: 0, root: genesis.root },
    }), { code: "INVENTORY_HTTP_UNAVAILABLE" }, "a CA-valid but unmapped certificate has no role");
    await assert.rejects(h.makeClient("foreign-client").getSnapshot({
      scope: h.scope,
      nonce: crypto.randomBytes(32),
      requested: requested(operation),
      minimumHead: { sequence: 0, root: genesis.root },
    }), { code: "INVENTORY_HTTP_UNAVAILABLE" });
  });

  await t.test("wrong server pin, wrong Ed25519 signer, and stale floor fail closed", async (child) => {
    const h = await harness(child);
    const genesis = await h.ledger.readLocalHead();
    const operation = newOperation({ root: genesis.root });
    const query = {
      scope: h.scope,
      nonce: crypto.randomBytes(32),
      requested: requested(operation),
      minimumHead: { sequence: 0, root: genesis.root },
    };
    await assert.rejects(h.makeClient("reader", {
      serverFingerprint256: "00:".repeat(31) + "00",
    }).getSnapshot(query), { code: "INVENTORY_HTTP_UNAVAILABLE" });
    const otherSigner = crypto.generateKeyPairSync("ed25519");
    await assert.rejects(h.makeClient("reader", {
      inventoryPublicKey: otherSigner.publicKey,
    }).getSnapshot(query), { code: "INVENTORY_HTTP_UNAVAILABLE" });
    await assert.rejects(h.makeClient("reader").getSnapshot({
      ...query,
      nonce: crypto.randomBytes(32),
      minimumHead: { sequence: 1, root: Buffer.alloc(32, 0x99) },
    }), { code: "INVENTORY_HTTP_UNAVAILABLE" });
  });

  await t.test("replayed nonce and HTTP 200 signed-payload tampering are rejected", async (child) => {
    const h = await harness(child);
    const genesis = await h.ledger.readLocalHead();
    const operation = newOperation({ root: genesis.root });
    const reader = h.makeClient("reader");
    const first = await reader.getSnapshot({
      scope: h.scope,
      nonce: crypto.randomBytes(32),
      requested: requested(operation),
      minimumHead: { sequence: 0, root: genesis.root },
    });
    const original = h.ledger.getSnapshot.bind(h.ledger);
    h.ledger.getSnapshot = async () => ({ status: "snapshot", bytes: Buffer.from(first.serializedSnapshot) });
    await assert.rejects(reader.getSnapshot({
      scope: h.scope,
      nonce: crypto.randomBytes(32),
      requested: requested(operation),
      minimumHead: { sequence: 0, root: genesis.root },
    }), { code: "INVENTORY_HTTP_UNAVAILABLE" }, "a prior signed response cannot answer a fresh nonce");

    h.ledger.getSnapshot = async (input) => {
      const snapshot = await original(input);
      if (snapshot.status === "snapshot") {
        snapshot.bytes = Buffer.from(snapshot.bytes);
        snapshot.bytes[snapshot.bytes.length - 1] ^= 1;
      }
      return snapshot;
    };
    await assert.rejects(reader.getSnapshot({
      scope: h.scope,
      nonce: crypto.randomBytes(32),
      requested: requested(operation),
      minimumHead: { sequence: 0, root: genesis.root },
    }), { code: "INVENTORY_HTTP_UNAVAILABLE" }, "HTTP 200 does not replace the pinned Ed25519 signature");
  });

  await t.test("malformed JSON, unknown fields, bad content type, oversized body and header are rejected", async (child) => {
    const h = await harness(child);
    const scope = scopeJson(h.scope);
    const base = { scope, nonce: crypto.randomBytes(32).toString("base64url") };
    const malformed = await rawRequest({
      port: h.port, tls, route: "/v1/inventory/snapshot", body: "{",
    });
    assert.equal(malformed.status, 400);
    const unknownField = await rawRequest({
      port: h.port, tls, route: "/v1/inventory/snapshot",
      body: JSON.stringify({ ...base, extra: true }),
    });
    assert.equal(unknownField.status, 400);
    const badType = await rawRequest({
      port: h.port, tls, route: "/v1/inventory/snapshot", body: JSON.stringify(base),
      headers: { "content-type": "text/plain" },
    });
    assert.equal(badType.status, 400);
    const nonCanonicalNonce = await rawRequest({
      port: h.port, tls, route: "/v1/inventory/snapshot",
      body: JSON.stringify({ ...base, nonce: `${base.nonce}=` }),
    });
    assert.equal(nonCanonicalNonce.status, 400);
    const oversizedBody = await rawRequest({
      port: h.port, tls, route: "/v1/inventory/snapshot", body: Buffer.alloc(4097, 0x20),
    });
    assert.equal(oversizedBody.status, 400);
    const wrongMethod = await rawRequest({
      port: h.port, tls, route: "/v1/inventory/snapshot", method: "GET",
    });
    assert.equal(wrongMethod.status, 404);
    const unknownRoute = await rawRequest({
      port: h.port, tls, route: "/v1/inventory/unknown", body: "{}",
    });
    assert.equal(unknownRoute.status, 404);
    const oversizedHeader = await rawRequest({
      port: h.port, tls, route: "/v1/inventory/snapshot", body: JSON.stringify(base),
      headers: { "x-oversized": "x".repeat(12000) },
    });
    assert.equal(oversizedHeader.status, 431);
  });

  await t.test("committed operation status requires the exact independently signed ledger entry", async (child) => {
    const h = await harness(child);
    const genesis = await h.ledger.readLocalHead();
    const operation = newOperation({ root: genesis.root });
    const genesisSnapshot = await h.makeClient("reader").getSnapshot({
      scope: h.scope,
      nonce: crypto.randomBytes(32),
      requested: requested(operation),
      minimumHead: { sequence: 0, root: genesis.root },
    });
    await h.makeClient("writer").append({
      scope: h.scope,
      operation,
      nonce: crypto.randomBytes(32),
      minimumHead: { sequence: 0, root: genesis.root },
      minimumSnapshot: genesisSnapshot.serializedSnapshot,
    });
    const status = await h.makeClient("status-reader").getOperationStatus({
      scope: h.scope,
      operation,
    });
    assert.equal(status.status, "committed");
    assert.equal(status.signedLedgerOperationCommitted, true);
    assert.equal(status.transportReportedCommittedOnly, false);
    assert.equal(status.authorizesIo, false);
    assert.equal(status.sequence, 1);
    assert.deepEqual(status.verifiedReceipt.operationId, operation.operation_id);
    assert.equal(status.externalDurabilityProven, false);
  });

  await t.test("HTTP 200 status cannot reuse a valid receipt under another operation ID", async (child) => {
    const h = await harness(child);
    const genesis = await h.ledger.readLocalHead();
    const genuine = newOperation({ root: genesis.root });
    assert.equal((await h.ledger.append(genuine)).status, "committed");
    const authentic = await h.ledger.getOperationStatus(genuine.operation_id);
    h.ledger.getOperationStatus = async () => authentic;
    await assert.rejects(h.makeClient("status-reader").getOperationStatus({
      scope: h.scope,
      operation: { ...genuine, operation_id: crypto.randomBytes(16) },
    }), { code: "INVENTORY_HTTP_UNAVAILABLE" });
    await assert.rejects(h.makeClient("status-reader").getOperationStatus({
      scope: h.scope,
      operation: { ...genuine, ciphertext_sha256: crypto.randomBytes(32) },
    }), { code: "INVENTORY_HTTP_UNAVAILABLE" });
  });

  await t.test("forged append ACK cannot turn a signed ABSENT snapshot into a commit", async (child) => {
    const h = await harness(child);
    const head = await h.ledger.readLocalHead();
    const unrelated = newOperation({ root: head.root, objectId: Buffer.alloc(16, 0x71) });
    assert.equal((await h.ledger.append(unrelated)).status, "committed");
    const floor = await h.ledger.readLocalHead();
    const targeted = newOperation({
      sequence: floor.sequence, root: floor.root, objectId: Buffer.alloc(16, 0x72),
    });
    h.ledger.append = async () => ({
      status: "committed", replay: false, sequence: floor.sequence, root: floor.root,
    });
    await assert.rejects(h.makeClient("writer").append({
      scope: h.scope,
      operation: targeted,
      nonce: crypto.randomBytes(32),
      minimumHead: { sequence: floor.sequence, root: floor.root },
    }), { code: "INVENTORY_HTTP_UNAVAILABLE" });
  });

  await t.test("signed PRESENT snapshot is never treated as signed proof of append operation ID", async (child) => {
    const h = await harness(child);
    const head = await h.ledger.readLocalHead();
    const genuine = newOperation({ root: head.root });
    assert.equal((await h.ledger.append(genuine)).status, "committed");
    const authenticStatus = await h.ledger.getOperationStatus(genuine.operation_id);
    const floor = await h.ledger.readLocalHead();
    const forged = { ...genuine, operation_id: crypto.randomBytes(16) };
    h.ledger.append = async () => ({
      status: "committed", replay: true, sequence: floor.sequence, root: floor.root,
    });
    h.ledger.getOperationStatus = async () => authenticStatus;
    await assert.rejects(h.makeClient("writer").append({
      scope: h.scope, operation: forged,
      nonce: crypto.randomBytes(32),
      minimumHead: { sequence: floor.sequence, root: floor.root },
    }), { code: "INVENTORY_HTTP_UNAVAILABLE" });
  });

  await t.test("altered signed append receipt fails while genuine signed snapshot remains valid", async (child) => {
    const h = await harness(child);
    const genesis = await h.ledger.readLocalHead();
    const operation = newOperation({ root: genesis.root });
    const realAppend = h.ledger.append.bind(h.ledger);
    const realStatus = h.ledger.getOperationStatus.bind(h.ledger);
    h.ledger.append = async (value) => {
      const result = await realAppend(value);
      h.ledger.getOperationStatus = async (id) => {
        const row = await realStatus(id);
        if (row.status !== "committed") return row;
        const proof = Buffer.from(row.proof);
        proof[proof.length - 1] ^= 1;
        return { ...row, proof };
      };
      return result;
    };
    await assert.rejects(h.makeClient("writer").append({
      scope: h.scope, operation, nonce: crypto.randomBytes(32),
      minimumHead: { sequence: 0, root: genesis.root },
    }), { code: "INVENTORY_HTTP_UNAVAILABLE" });
  });

  await t.test("rejected HTTP status cannot keep a pinned TLS response streaming after client rejection", async (child) => {
    const h = await harness(child);
    let closeResponse;
    const closed = new Promise((resolve) => { closeResponse = resolve; });
    const badServer = https.createServer({
      key: tls.serverKey, cert: tls.serverCert, ca: tls.ca,
      requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
    }, (_request, response) => {
      response.writeHead(503, { "content-type": "application/json", "transfer-encoding": "chunked" });
      const trickle = setInterval(() => response.write("x"), 30);
      response.once("close", () => {
        clearInterval(trickle);
        closeResponse(true);
      });
      response.write("x");
    });
    const port = await listen(badServer);
    child.after(() => drainZk1ContentInventoryHttpsServer(badServer));
    const head = await h.ledger.readLocalHead();
    const operation = newOperation({ root: head.root });
    await assert.rejects(h.makeClient("reader", {
      port, idleTimeoutMs: 120, wallTimeoutMs: 260,
    }).getSnapshot({
      scope: h.scope, nonce: crypto.randomBytes(32),
      requested: requested(operation),
      minimumHead: { sequence: head.sequence, root: head.root },
    }), { code: "INVENTORY_HTTP_UNAVAILABLE" });
    const dropped = await Promise.race([
      closed, new Promise((resolve) => setTimeout(() => resolve(false), 380)),
    ]);
    assert.equal(dropped, true, "client rejection must physically destroy the streaming TLS socket");
  });

  await t.test("absolute slow-drip timeout closes that socket and a fresh TLS request succeeds", async (child) => {
    const h = await harness(child);
    let requests = 0;
    let secureConnections = 0;
    const dripServer = https.createServer({
      key: tls.serverKey,
      cert: tls.serverCert,
      ca: tls.ca,
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: "TLSv1.3",
      maxHeaderSize: 8192,
    }, async (request, response) => {
      requests += 1;
      if (requests === 1) return;
      if (requests === 2) {
        response.writeHead(200, { "content-type": "application/json", "transfer-encoding": "chunked" });
        const prefix = Buffer.from('{"status":"snapshot","snapshotBase64":"');
        let offset = 0;
        const drip = setInterval(() => {
          if (offset < prefix.length) response.write(prefix.subarray(offset, offset + 1));
          else response.write("A");
          offset += 1;
        }, 35);
        response.on("close", () => clearInterval(drip));
        return;
      }
      const parts = [];
      for await (const part of request) parts.push(part);
      const body = JSON.parse(Buffer.concat(parts).toString("utf8"));
      const snapshot = await h.ledger.getSnapshot({ nonce: Buffer.from(body.nonce, "base64url") });
      const bytes = Buffer.from(JSON.stringify({
        status: "snapshot",
        snapshotBase64: snapshot.bytes.toString("base64url"),
      }));
      response.writeHead(200, {
        "content-type": "application/json",
        "content-length": String(bytes.length),
      });
      response.end(bytes);
    });
    dripServer.on("secureConnection", () => { secureConnections += 1; });
    const port = await listen(dripServer);
    child.after(() => drainZk1ContentInventoryHttpsServer(dripServer));
    const client = h.makeClient("reader", {
      port,
      idleTimeoutMs: 120,
      wallTimeoutMs: 260,
    });
    const genesis = await h.ledger.readLocalHead();
    const operation = newOperation({ root: genesis.root });
    const query = {
      scope: h.scope,
      requested: requested(operation),
      minimumHead: { sequence: 0, root: genesis.root },
    };
    await assert.rejects(client.getSnapshot({ ...query, nonce: crypto.randomBytes(32) }),
      { code: "INVENTORY_HTTP_UNAVAILABLE" }, "idle response must be bounded");
    await assert.rejects(client.getSnapshot({ ...query, nonce: crypto.randomBytes(32) }),
      { code: "INVENTORY_HTTP_UNAVAILABLE" });
    const fresh = await client.getSnapshot({ ...query, nonce: crypto.randomBytes(32) });
    assert.equal(fresh.outcome, "ABSENT");
    assert.equal(requests, 3);
    assert.equal(secureConnections, 3, "requests after both timeouts must use fresh TLS connections");
  });

  await t.test("chunked client responses are size-limited before JSON accumulation", async (child) => {
    const h = await harness(child);
    const oversizedServer = https.createServer({
      key: tls.serverKey,
      cert: tls.serverCert,
      ca: tls.ca,
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: "TLSv1.3",
      maxHeaderSize: 8192,
    }, (_request, response) => {
      response.writeHead(200, { "content-type": "application/json", "transfer-encoding": "chunked" });
      response.end(Buffer.alloc(17 * 1024, 0x41));
    });
    const port = await listen(oversizedServer);
    child.after(() => drainZk1ContentInventoryHttpsServer(oversizedServer));
    const operation = newOperation({ root: (await h.ledger.readLocalHead()).root });
    await assert.rejects(h.makeClient("status-reader", { port }).getOperationStatus({
      scope: h.scope,
      operation,
    }), { code: "INVENTORY_HTTP_UNAVAILABLE" });
  });
});
