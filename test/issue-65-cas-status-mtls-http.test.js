"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const https = require("node:https");
const { execFileSync, spawn } = require("node:child_process");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const test = require("node:test");
const z = require("../src/crypto/rootark-zk-1");
const v2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const { Zk1DurableCasStatusLedger } = require("../src/services/zk1DurableCasStatusLedger");
const { Zk1DurableWitnessLedger } = require("../src/services/zk1DurableWitnessLedger");
const { createZk1CasStatusHttpsServer, drainZk1CasStatusHttpsServer } = require("../src/services/zk1CasStatusHttpsServer");
const { createZk1CasStatusHttpsClient } = require("../src/services/zk1CasStatusHttpsClient");
const { createZk1CasWriteHttpsClient } = require("../src/services/zk1CasWriteHttpsClient");
const { createZk1CasManifestHttpsClient } = require("../src/services/zk1CasManifestHttpsClient");

function createCertificates(dir) {
  const commands = [
    "set -eu",
    'openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -subj "/CN=Rootark Test CA" -days 1 >/dev/null 2>&1',
    'openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost" >/dev/null 2>&1',
    'printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" > server.ext',
    'openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 1 -extfile server.ext >/dev/null 2>&1',
    'for name in allowed denied witness; do openssl req -newkey rsa:2048 -nodes -keyout "$name.key" -out "$name.csr" -subj "/CN=$name" >/dev/null 2>&1; printf "extendedKeyUsage=clientAuth\n" > "$name.ext"; openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -out "$name.pem" -days 1 -extfile "$name.ext" >/dev/null 2>&1; done',
  ].join("\n");
  if (process.platform === "win32") {
    generateNativeFixtureCertificates(dir, {
      caSubject: "Rootark Test CA", servers: ["server"],
      clients: ["allowed", "denied", "witness"],
    });
  } else {
    execFileSync("bash", ["-lc", commands], { cwd: dir, stdio: "pipe", timeout: 20000 });
  }
  const read = (file) => fs.readFileSync(path.join(dir, file));
  return { ca: read("ca.pem"), serverKey: read("server.key"), serverCert: read("server.pem"),
    allowedKey: read("allowed.key"), allowedCert: read("allowed.pem"),
    deniedKey: read("denied.key"), deniedCert: read("denied.pem"),
    witnessClientKey: read("witness.key"), witnessClientCert: read("witness.pem") };
}
function send(port, tls, route, body, identity = "allowed") {
  const data = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const request = https.request({
      host: "127.0.0.1", port, path: route, method: "POST",
      ca: tls.ca, servername: "localhost", rejectUnauthorized: true,
      key: identity === "allowed" ? tls.allowedKey
        : identity === "denied" ? tls.deniedKey
          : identity === "witness" ? tls.witnessClientKey : undefined,
      cert: identity === "allowed" ? tls.allowedCert
        : identity === "denied" ? tls.deniedCert
          : identity === "witness" ? tls.witnessClientCert : undefined,
      headers: { "content-type": "application/json", "content-length": data.byteLength },
      timeout: 5000,
    }, (res) => {
      const chunks = [];
      res.on("data", (part) => chunks.push(part));
      res.on("end", () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString()) }); }
        catch (error) { reject(error); }
      });
    });
    request.on("timeout", () => request.destroy());
    request.on("error", reject);
    request.end(data);
  });
}

test("real mTLS CAS endpoint handles signed v2 commit, rejects alien scope, and witnesses remote signed status", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-cas-mtls-"));
  const connections = new Set();
  const ownedChildren = new Set();
  let server;
  t.after(async () => {
    for (const child of ownedChildren) {
      if (child.exitCode === null) {
        const done = new Promise((resolve) => child.once("exit", resolve));
        child.kill("SIGTERM");
        await done;
      }
    }
    if (server?.listening) await drainZk1CasStatusHttpsServer(server);
    for (const conn of connections) conn.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const tls = createCertificates(dir);
  const statusKeys = crypto.generateKeyPairSync("ed25519");
  const witnessKeys = crypto.generateKeyPairSync("ed25519");
  const statusKeyId = crypto.randomBytes(16);
  const witnessKeyId = crypto.randomBytes(16);
  const state = await fixtures.createInitialState(1);
  const manifest = state.headManifest;
  const raw = Buffer.from(await z.encodeDeterministic(manifest));
  const operation = {
    ...state.scope, reservation_id: crypto.randomBytes(16),
    operation_id: Buffer.from(manifest.operation.operation_id),
    request_digest: Buffer.from(manifest.operation.request_digest),
    proposed_manifest_digest: Buffer.from(await v2.recoveryManifestDigestV2(manifest)),
    expected_revision: null, expected_manifest_digest: null, proposed_revision: 1,
    package_envelope_digest: null, expires_at: Number(manifest.operation.expires_at),
  };
  const enc = (value) => Buffer.from(value).toString("base64url");
  const scopeJson = Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
    .map((field) => [field, enc(operation[field])]));
  const query = Object.fromEntries(Object.entries(operation).filter(([name]) => name !== "expires_at"));
  const fingerprint = new crypto.X509Certificate(tls.allowedCert).fingerprint256;
  const witnessFingerprint = new crypto.X509Certificate(tls.witnessClientCert).fingerprint256;
  const manifestFingerprint = new crypto.X509Certificate(tls.deniedCert).fingerprint256;
  const cas = new Zk1DurableCasStatusLedger(path.join(dir, "cas.sqlite"), {
    bootstrapNew: true, statusPrivateKey: statusKeys.privateKey,
    anchorPath: path.join(dir, "cas-terminal-anchor.log"),
    statusKeyId, witnessPinned: { keyId: witnessKeyId, publicKey: witnessKeys.publicKey },
    nowSeconds: () => 1100,
  });
  connections.add(cas);
  server = createZk1CasStatusHttpsServer({
    key: tls.serverKey, cert: tls.serverCert, clientCa: tls.ca, ledger: cas,
    principals: { [fingerprint]: {
      roles: ["register", "commit"], scopes: [scopeJson],
    }, [witnessFingerprint]: { roles: ["terminal"], scopes: [scopeJson] },
    [manifestFingerprint]: { roles: ["manifest"], scopes: [scopeJson] } },
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  const client = createZk1CasStatusHttpsClient({
    endpoint: "https://localhost:" + port + "/v1/terminal",
    ca: tls.ca, clientKey: tls.witnessClientKey, clientCert: tls.witnessClientCert,
    serverFingerprint256: new crypto.X509Certificate(tls.serverCert).fingerprint256,
  });
  const writeClient = createZk1CasWriteHttpsClient({
    endpoint: "https://localhost:" + port,
    ca: tls.ca, clientKey: tls.allowedKey, clientCert: tls.allowedCert,
    serverFingerprint256: new crypto.X509Certificate(tls.serverCert).fingerprint256,
  });
  const manifestClient = createZk1CasManifestHttpsClient({
    endpoint: "https://localhost:" + port + "/v1/manifest",
    ca: tls.ca, clientKey: tls.deniedKey, clientCert: tls.deniedCert,
    serverFingerprint256: new crypto.X509Certificate(tls.serverCert).fingerprint256,
  });
  const scopeFields = ["account_id", "compartment_id", "keyring_id"];
  const readScope = Object.fromEntries(scopeFields.map((field) => [field, operation[field]]));
  await assert.rejects(manifestClient.getCommittedManifest({ scope: readScope }),
    /CAS_MANIFEST_TRANSPORT_UNAVAILABLE/);
  const witness = new Zk1DurableWitnessLedger(path.join(dir, "witness.sqlite"), {
    bootstrapNew: true, witnessPrivateKey: witnessKeys.privateKey,
    witnessKeyId, statusPinned: { keyId: statusKeyId, publicKey: statusKeys.publicKey },
    statusProvider: client, nowSeconds: () => 1100,
  });
  connections.add(witness);
  const ticket = await witness.reserve(operation);
  const registerBody = { receiptBase64: enc(ticket) };
  assert.equal((await send(port, tls, "/v1/register", registerBody, "denied")).status, 403);
  assert.equal((await send(port, tls, "/v1/register", registerBody, "witness")).status, 403,
    "witness status caller must never register or mutate CAS");
  await assert.rejects(send(port, tls, "/v1/register", registerBody, "none"));
  assert.equal((await writeClient.register({ receipt: ticket })).status, "pending");
  const commitBody = { ...registerBody, manifestBase64: enc(raw) };
  assert.deepEqual(await writeClient.commit({ receipt: ticket, manifestBytes: raw }),
    { status: "committed", replay: false });
  assert.deepEqual(await manifestClient.getCommittedManifest({ scope: readScope }), raw);
  const historyPage = await manifestClient.getCommittedHistoryPage({
    scope: readScope, startRevision: 1,
  });
  assert.equal(historyPage.headRevision, 1);
  assert.deepEqual(historyPage.headDigest, await v2.recoveryManifestDigestV2(manifest));
  assert.equal(historyPage.startRevision, 1);
  assert.equal(historyPage.nextRevision, null);
  assert.deepEqual(historyPage.entries, [raw],
    "manifest history bytes must be available for independent signed-chain verification");
  const originalForPages = cas.getCommittedHistoryPage.bind(cas);
  try {
    const changingScope = Object.fromEntries(Object.entries(readScope)
      .map(([key, value]) => [key, Buffer.from(value)]));
    let pageRequests = 0;
    cas.getCommittedHistoryPage = async ({ startRevision }) => {
      pageRequests += 1;
      if (pageRequests === 1) {
        // Deliberately mutate the caller's input after the first authorized
        // HTTP request is in flight but before page 2 can be dispatched.
        changingScope.account_id.fill(0x11);
        changingScope.compartment_id.fill(0x22);
        changingScope.keyring_id.fill(0x33);
      }
      return {
        headRevision: 3,
        headDigest: await v2.recoveryManifestDigestV2(manifest),
        startRevision,
        nextRevision: startRevision < 3 ? startRevision + 1 : null,
        entries: [raw],
      };
    };
    const downloaded = await manifestClient.getCommittedHistory({ scope: changingScope });
    assert.equal(downloaded.headRevision, 3);
    assert.equal(pageRequests, 3, "every page must use the original, pinned scope");
    assert.equal(downloaded.entries.length, 3,
      "a client may not silently interpret the first response as the complete signed history");
    assert.deepEqual(downloaded.entries, [raw, raw, raw]);
    // Exercise a real >8 MiB transfer spread across two HTTP/TLS pages,
    // not just three tiny manifests. The bytes are deliberately synthetic
    // and untrusted; no signature/recovery authorization is implied.
    const largeFirst = Buffer.alloc(5 * 1024 * 1024, 0x41);
    const largeSecond = Buffer.alloc(4 * 1024 * 1024, 0x42);
    cas.getCommittedHistoryPage = async ({ startRevision }) => ({
      headRevision: 2,
      headDigest: await v2.recoveryManifestDigestV2(manifest),
      startRevision, nextRevision: startRevision === 1 ? 2 : null,
      entries: [startRevision === 1 ? largeFirst : largeSecond],
    });
    const largePageChain = await manifestClient.getCommittedHistory({ scope: readScope });
    assert.equal(largePageChain.entries.length, 2);
    assert.deepEqual(largePageChain.entries[0], largeFirst);
    assert.deepEqual(largePageChain.entries[1], largeSecond);
    cas.getCommittedHistoryPage = async ({ startRevision }) => ({
      headRevision: 1,
      headDigest: await v2.recoveryManifestDigestV2(manifest),
      startRevision, nextRevision: null,
      entries: [Buffer.alloc(8 * 1024 * 1024 + 1)],
    });
    await assert.rejects(manifestClient.getCommittedHistory({ scope: readScope }),
      /CAS_MANIFEST_TRANSPORT_UNAVAILABLE/,
      "a trusted mTLS peer still cannot exceed the 8 MiB raw page limit");
    let pages = 0;
    cas.getCommittedHistoryPage = async ({ startRevision }) => {
      pages += 1;
      return {
        headRevision: 3,
        headDigest: pages === 1
          ? await v2.recoveryManifestDigestV2(manifest) : crypto.randomBytes(32),
        startRevision,
        nextRevision: startRevision < 3 ? startRevision + 1 : null,
        entries: [raw],
      };
    };
    await assert.rejects(manifestClient.getCommittedHistory({ scope: readScope }),
      /CAS_MANIFEST_TRANSPORT_UNAVAILABLE/,
      "a newer, forked or substituted CAS head across pages must fail closed");
  } finally {
    cas.getCommittedHistoryPage = originalForPages;
  }
  await assert.rejects(manifestClient.getCommittedHistoryPage({
    scope: readScope, startRevision: 2,
  }), /CAS_MANIFEST_TRANSPORT_UNAVAILABLE/,
  "a client cannot request history beyond the committed head");
  assert.equal((await send(port, tls, "/v1/history", {
    scope: scopeJson, startRevision: 1,
  })).status, 403, "CAS writer must not read signed history via another endpoint");
  assert.equal((await send(port, tls, "/v1/history", {
    scope: scopeJson, startRevision: 1,
  }, "witness")).status, 403, "CAS status witness cannot read the manifest chain");
  assert.equal((await send(port, tls, "/v1/history", {
    scope: { ...scopeJson, keyring_id: enc(crypto.randomBytes(16)) },
    startRevision: 1,
  }, "denied")).status, 403, "manifest reader may not read a foreign keyring's history");
  assert.equal((await send(port, tls, "/v1/history", {
    scope: scopeJson, startRevision: 0,
  }, "denied")).status, 400, "invalid revision cannot be truncated to an earlier manifest");
  const originalPage = cas.getCommittedHistoryPage.bind(cas);
  try {
    cas.getCommittedHistoryPage = async (args) => ({
      ...await originalPage(args), nextRevision: 2,
    });
    await assert.rejects(manifestClient.getCommittedHistoryPage({
      scope: readScope, startRevision: 1,
    }), /CAS_MANIFEST_TRANSPORT_UNAVAILABLE/,
    "a valid mTLS peer's inconsistent page continuation is not accepted");
  } finally {
    cas.getCommittedHistoryPage = originalPage;
  }
  assert.equal((await send(port, tls, "/v1/manifest", { scope: scopeJson })).status, 403,
    "the CAS writer certificate must not read protected manifest history");
  assert.equal((await send(port, tls, "/v1/manifest", { scope: scopeJson }, "witness")).status, 403,
    "witness terminality identity must not inherit manifest reader authority");
  assert.equal((await send(port, tls, "/v1/manifest", { scope: {
    ...scopeJson, compartment_id: enc(Buffer.from("alien")),
  } }, "denied")).status, 403);
  assert.equal((await writeClient.commit({ receipt: ticket, manifestBytes: raw })).replay, true);
  assert.equal((await send(port, tls, "/v1/commit", { ...commitBody,
    manifestBase64: enc(Buffer.from("malicious")) })).status, 409);
  const alienQuery = { ...query, keyring_id: crypto.randomBytes(16) };
  const queryJson = (source) => Object.fromEntries(Object.entries(source)
    .map(([name, value]) => [name, Buffer.isBuffer(value) ? enc(value) : value]));
  assert.equal((await send(port, tls, "/v1/terminal", {
    query: queryJson(alienQuery), nonce: enc(crypto.randomBytes(32)),
  }, "witness")).status, 403);
  assert.equal((await send(port, tls, "/v1/terminal", {
    query: queryJson(query), nonce: enc(crypto.randomBytes(32)),
  })).status, 403, "writer identity must not query terminal status as a witness");
  const observed = await client.getTerminalProof({ query, nonce: crypto.randomBytes(32) });
  assert.equal((await z.decodeDeterministic(observed)).terminal_status, "committed");
  const witnessResolution = await witness.resolve({ scope: operation });
  assert.equal(witnessResolution.status, "committed");
  assert.equal((await z.decodeDeterministic(await witness.freshHead({
    scope: operation, nonce: crypto.randomBytes(32),
  }))).status, "committed");
  await assert.rejects(createZk1CasStatusHttpsClient({
    endpoint: "https://localhost:" + port + "/v1/terminal",
    ca: tls.ca, clientKey: tls.witnessClientKey, clientCert: tls.witnessClientCert,
    serverFingerprint256: "00:".repeat(31) + "00",
  }).getTerminalProof({ query, nonce: crypto.randomBytes(32) }), /CAS_STATUS_TRANSPORT_UNAVAILABLE/);

  // Restore the exact committed status from a *separate Node OS process*.
  // The private signer, witness public root and TLS identities are explicitly
  // provisioned as temporary fixtures, never written to the Git worktree.
  await drainZk1CasStatusHttpsServer(server);
  server = null;
  cas.close();
  const statusKeyPath = path.join(dir, "status-private.pem");
  const witnessPubPath = path.join(dir, "witness-public.pem");
  const configPath = path.join(dir, "cas-config.json");
  fs.writeFileSync(statusKeyPath, statusKeys.privateKey.export({
    format: "pem", type: "pkcs8",
  }), { mode: 0o600 });
  fs.writeFileSync(witnessPubPath, witnessKeys.publicKey.export({
    format: "pem", type: "spki",
  }));
  const config = {
    listenHost: "127.0.0.1", listenPort: 0, bootstrapNew: false,
    dbPath: path.join(dir, "cas.sqlite"), statusKeyId: enc(statusKeyId),
    anchorPath: path.join(dir, "cas-terminal-anchor.log"),
    statusPrivateKeyPath: statusKeyPath,
    witnessKeyId: enc(witnessKeyId), witnessPublicKeyPath: witnessPubPath,
    serverKeyPath: path.join(dir, "server.key"),
    serverCertPath: path.join(dir, "server.pem"),
    clientCaPath: path.join(dir, "ca.pem"),
    principals: { [fingerprint]: {
      roles: ["register", "commit"], scopes: [scopeJson],
    }, [witnessFingerprint]: { roles: ["terminal"], scopes: [scopeJson] },
    [manifestFingerprint]: { roles: ["manifest"], scopes: [scopeJson] } },
  };
  async function launch() {
    fs.writeFileSync(configPath, JSON.stringify(config), { mode: 0o600 });
    const child = spawn(process.execPath, [
      path.resolve(__dirname, "../scripts/zk1-cas-status-standalone.js"),
      "--config", configPath,
    ], {
      cwd: path.resolve(__dirname, ".."),
      stdio: ["ignore", "pipe", "pipe", "ipc"], windowsHide: true,
    });
    ownedChildren.add(child);
    const newPort = await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("CAS_PROCESS_READY_TIMEOUT")), 5000);
      child.once("message", (message) => {
        clearTimeout(timeout);
        if (message?.type === "ready" && Number.isSafeInteger(message.port)) resolve(message.port);
        else reject(new Error("CAS_PROCESS_READY_INVALID"));
      });
      child.once("exit", (code) => {
        clearTimeout(timeout);
        reject(new Error("CAS_PROCESS_EXIT_" + code));
      });
    });
    return {
      port: newPort,
      async stop() {
        if (child.exitCode !== null) return;
        const done = new Promise((resolve) => child.once("exit", resolve));
        child.kill("SIGTERM");
        await done;
        ownedChildren.delete(child);
      },
    };
  }
  const restarted = await launch();
  const remoteClient = createZk1CasStatusHttpsClient({
    endpoint: "https://localhost:" + restarted.port + "/v1/terminal",
    ca: tls.ca, clientKey: tls.witnessClientKey, clientCert: tls.witnessClientCert,
    serverFingerprint256: new crypto.X509Certificate(tls.serverCert).fingerprint256,
  });
  assert.equal((await z.decodeDeterministic(await remoteClient.getTerminalProof({
    query, nonce: crypto.randomBytes(32),
  }))).terminal_status, "committed", "independent Node process must recover durable terminal history");
  assert.deepEqual(await createZk1CasManifestHttpsClient({
    endpoint: "https://localhost:" + restarted.port + "/v1/manifest",
    ca: tls.ca, clientKey: tls.deniedKey, clientCert: tls.deniedCert,
    serverFingerprint256: new crypto.X509Certificate(tls.serverCert).fingerprint256,
  }).getCommittedManifest({ scope: readScope }), raw);
  await restarted.stop();
});
