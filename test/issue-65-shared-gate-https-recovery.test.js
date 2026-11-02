"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { createZk1SharedPgGateHttpsServer } =
  require("../src/services/zk1SharedPgGateHttpsServer");
const { createZk1SharedPgGateHttpsClient } =
  require("../src/services/zk1SharedPgGateHttpsClient");
const { Zk1SharedPgCiphertextSink } =
  require("../src/services/zk1SharedPgCiphertextSink");
const { computeZk1CiphertextRoot } =
  require("../src/crypto/rootark-zk-chunk-root-v1");

function openssl() {
  if (process.platform !== "win32") return "openssl";
  return [path.join(process.env.ProgramFiles || "C:\\Program Files", "Git", "usr", "bin", "openssl.exe"),
    path.join(process.env.ProgramFiles || "C:\\Program Files", "Git", "mingw64", "bin", "openssl.exe")]
    .find((name) => fs.existsSync(name)) || "openssl.exe";
}
function certs(dir) {
  const run = (args) => execFileSync(openssl(), args,
    { cwd: dir, stdio: "ignore", timeout: 30000, windowsHide: true });
  run(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key",
    "-out", "ca.pem", "-subj", "/CN=local zk65 test CA", "-days", "1"]);
  for (const [name, server] of [["server", true], ["writer", false], ["foreign", false]]) {
    run(["req", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`,
      "-out", `${name}.csr`, "-subj", `/CN=${server ? "localhost" : name}`]);
    fs.writeFileSync(path.join(dir, `${name}.ext`),
      [server ? "extendedKeyUsage=serverAuth" : "extendedKeyUsage=clientAuth",
        "keyUsage=digitalSignature,keyEncipherment",
        ...(server ? ["subjectAltName=DNS:localhost,IP:127.0.0.1"] : [])].join("\n") + "\n");
    run(["x509", "-req", "-in", `${name}.csr`, "-CA", "ca.pem",
      "-CAkey", "ca.key", "-CAcreateserial", "-out", `${name}.pem`,
      "-days", "1", "-extfile", `${name}.ext`]);
  }
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const fingerprint = (name) => new crypto.X509Certificate(read(`${name}.pem`)).fingerprint256;
  return { ca: read("ca.pem"), key: read("server.key"), cert: read("server.pem"),
    fingerprint: fingerprint("server"), writerFingerprint: fingerprint("writer"),
    writer: { key: read("writer.key"), cert: read("writer.pem") },
    foreign: { key: read("foreign.key"), cert: read("foreign.pem") } };
}
const b64Scope = (scope) => Object.fromEntries(Object.entries(scope)
  .map(([k, v]) => [k, Buffer.from(v).toString("base64url")]));

test("real mTLS gateway restart preserves immutable prewrite admission after chunk outage", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-retry-mtls-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));
  const tls = certs(dir);
  const parts = [crypto.randomBytes(54), crypto.randomBytes(27)];
  const input = { scope: { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("vault"), keyring_id: crypto.randomBytes(16) },
  objectId: crypto.randomBytes(16).toString("base64url"), revision: 1,
  digest: crypto.randomBytes(32), chunks: parts, expectedChunkCount: 2,
  expectedRootHash: computeZk1CiphertextRoot(parts), operationId: crypto.randomBytes(16) };
  const admissionId = crypto.randomBytes(16);
  const persisted = { state: null, workerId: null, principal: null,
    chunks: new Map(), sealed: false, finishCount: 0, outage: true };
  const same = (io) => persisted.workerId?.equals(io.workerId)
    && io.principal === persisted.principal && io.objectId === input.objectId
    && io.revision === input.revision && io.digest.equals(input.digest);
  const gate = {
    requiresTrustedLocalStop: async () => false,
    async beginIoAdmission(io) {
      if (persisted.state === null) {
        persisted.state = "ACTIVE";
        persisted.workerId = Buffer.from(io.workerId);
        persisted.principal = io.principal;
      } else if (!same(io) || persisted.state !== "ACTIVE") throw Error("ZK_GATE_DENIED");
      return { admissionId: Buffer.from(admissionId), generation: 1, proceed: true };
    },
    async putCiphertextChunk(io, index, ciphertext) {
      if (!same(io) || persisted.state !== "ACTIVE"
        || !io.admissionId.equals(admissionId) || io.generation !== 1) throw Error("ZK_GATE_DENIED");
      if (persisted.outage && index === 1) throw Error("simulated transport outage");
      if (persisted.chunks.has(index)) {
        if (!persisted.chunks.get(index).equals(ciphertext)) throw Error("ZK_GATE_CHUNK_CONFLICT");
        return { stored: false };
      }
      persisted.chunks.set(index, Buffer.from(ciphertext));
      return { stored: true };
    },
    async finishIoAdmission({ workerId, admissionId: received, principal }) {
      if (!persisted.workerId.equals(workerId) || !received.equals(admissionId)
        || principal !== persisted.principal || !persisted.sealed) throw Error("ZK_GATE_DENIED");
      persisted.finishCount += 1;
      persisted.state = "FINISHED";
      return { status: "FINISHED" };
    },
    async beginQuiesce() { throw Error("unexpected quiesce"); },
    async markPending() { throw Error("unexpected pending"); },
  };
  const sealedStore = { async seal(io) {
    if (!same(io) || persisted.state !== "ACTIVE"
      || !io.admissionId.equals(admissionId) || persisted.chunks.size !== 2) {
      throw Error("ZK_GATE_SEAL_DENIED");
    }
    const all = [persisted.chunks.get(0), persisted.chunks.get(1)];
    if (!computeZk1CiphertextRoot(all).equals(io.expectedRootHash)) {
      throw Error("ZK_GATE_SEAL_DENIED");
    }
    persisted.sealed = true;
    return { status: "SEALED", chunkCount: 2 };
  } };
  const principals = { [tls.writerFingerprint]: { roles: ["admit", "put", "seal"],
    scopes: [b64Scope(input.scope)] } };
  async function open() {
    const server = createZk1SharedPgGateHttpsServer({ key: tls.key, cert: tls.cert,
      clientCa: tls.ca, gate, sealedStore, principals });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const endpoint = `https://127.0.0.1:${server.address().port}`;
    return { server, client: (identity) => createZk1SharedPgGateHttpsClient({ endpoint,
      ca: tls.ca, clientKey: identity.key, clientCert: identity.cert,
      serverFingerprint256: tls.fingerprint, timeoutMs: 1000 }) };
  }
  const first = await open();
  t.after(async () => { if (first.server.listening) await new Promise((resolve) => first.server.close(resolve)); });
  await assert.rejects(new Zk1SharedPgCiphertextSink({ gateClient: first.client(tls.writer) })
    .putSealed(input), /ZK_GATE_SINK_UNAVAILABLE/);
  assert.equal(persisted.state, "ACTIVE");
  assert.equal(persisted.finishCount, 0);
  assert.deepEqual(persisted.chunks.get(0), parts[0]);
  await new Promise((resolve) => first.server.close(resolve));
  const next = await open();
  t.after(async () => { if (next.server.listening) await new Promise((resolve) => next.server.close(resolve)); });
  const wrong = { scope: input.scope, workerId: crypto.randomBytes(16),
    action: "put", objectId: input.objectId, revision: input.revision, digest: input.digest };
  await assert.rejects(next.client(tls.writer).beginIoAdmission(wrong),
    /ZK_GATE_TRANSPORT_UNAVAILABLE/, "a distinct worker cannot take the same operation");
  await assert.rejects(next.client(tls.foreign).beginIoAdmission(wrong),
    /ZK_GATE_TRANSPORT_UNAVAILABLE/, "unlisted mTLS principal cannot resume");
  persisted.outage = false;
  assert.deepEqual(await new Zk1SharedPgCiphertextSink({ gateClient: next.client(tls.writer) })
    .putSealed(input), { status: "SEALED", chunkCount: 2 });
  assert.equal(persisted.finishCount, 1);
  assert.equal(persisted.state, "FINISHED");
  assert.equal(persisted.sealed, true);
});
