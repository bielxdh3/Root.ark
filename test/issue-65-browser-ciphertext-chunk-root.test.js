"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");
const { computeZk1CiphertextRoot } = require("../src/crypto/rootark-zk-chunk-root-v1");
const fileCrypto = require("../public/client/rootark-zk1-file-content");
const browserRoot = require("../public/client/rootark-zk1-ciphertext-chunk-root");

function bytes(count) {
  return crypto.randomBytes(count);
}

test("browser WebCrypto ciphertext chunks match server domain-separated SHA-256 exactly", async () => {
  const chunks = [bytes(1), bytes(213), bytes(512 * 1024), bytes(19)];
  const b = browserRoot.createCiphertextRootBuilder(chunks.length);
  for (const part of chunks) {
    assert.equal((await b.append(part)).written, true);
  }
  const calculated = await b.finish();
  assert.deepEqual(Buffer.from(calculated), computeZk1CiphertextRoot(chunks));
  assert.notDeepEqual(Buffer.from(await browserRoot.computeCiphertextRoot(chunks.slice().reverse())),
    computeZk1CiphertextRoot(chunks), "ordering is part of the commitment");
  assert.notDeepEqual(Buffer.from(await browserRoot.computeCiphertextRoot([Buffer.concat(chunks)])),
    computeZk1CiphertextRoot(chunks), "chunk boundaries are authenticated");
});

test("client-only encrypted file bytes produce same root as PostgreSQL sealed ciphertext protocol", async () => {
  const cek = await fileCrypto.generateFileCek();
  const id = () => bytes(16).toString("base64url");
  const metadata = { account_id: id(), compartment_id: id(), keyring_id: id(),
    object_id: id(), version_id: id(), parent_version_id: null, epoch: 1, kind: "file" };
  const plaintext = bytes(1024 * 1024);
  const envelope = await fileCrypto.encryptFile({ cek, metadata,
    name: "private-name.txt", mediaType: "text/plain", data: plaintext });
  const ciphertext = Buffer.from(envelope);
  const pieces = [];
  const size = 256 * 1024;
  for (let offset = 0; offset < ciphertext.length; offset += size) {
    pieces.push(ciphertext.subarray(offset, Math.min(offset + size, ciphertext.length)));
  }
  const root = await browserRoot.computeCiphertextRoot(pieces);
  assert.deepEqual(Buffer.from(root), computeZk1CiphertextRoot(pieces));
  assert.equal(ciphertext.includes(Buffer.from("private-name.txt", "utf8")), false);
  const decrypted = await fileCrypto.decryptFile({ cek, metadata, envelopeBytes: ciphertext });
  assert.equal(decrypted.name, "private-name.txt");
  assert.deepEqual(Buffer.from(decrypted.data), plaintext);
  decrypted.data.fill(0);
});

test("WebCrypto digest snapshots caller-owned bytes across async digest and rejects concurrent append", async () => {
  let unblock;
  const gate = new Promise((resolve) => { unblock = resolve; });
  const real = crypto.webcrypto;
  const delayed = {
    getRandomValues: (n) => real.getRandomValues(n),
    subtle: {
      digest: async (_kind, data) => {
        await gate;
        return real.subtle.digest("SHA-256", data);
      },
    },
  };
  const builder = browserRoot.createCiphertextRootBuilder(1, delayed);
  const original = bytes(127);
  const kept = Buffer.from(original);
  const appending = builder.append(original);
  original.fill(0);
  await assert.rejects(builder.append(bytes(24)), /ZK_CHUNK_ROOT_INVALID/,
    "a pending digest cannot be overtaken by another append");
  unblock();
  assert.equal((await appending).written, true);
  assert.deepEqual(Buffer.from(await builder.finish()), computeZk1CiphertextRoot([kept]));
  await assert.rejects(builder.append(bytes(2)), /ZK_CHUNK_ROOT_INVALID/);
  await assert.rejects(builder.finish(), /ZK_CHUNK_ROOT_INVALID/);
});

test("incomplete/ambiguous/malformed chunk streams fail closed and refuse noncanonical input", async () => {
  for (const bad of [0, 4097, -1, 1.3, Number.NaN, "1"]) {
    assert.throws(() => browserRoot.createCiphertextRootBuilder(bad), /ZK_CHUNK_ROOT_INVALID/);
  }
  for (const bad of [[], [Buffer.alloc(0)], [Buffer.alloc(4 * 1024 * 1024 + 1)]]) {
    await assert.rejects(browserRoot.computeCiphertextRoot(bad), /ZK_CHUNK_ROOT_INVALID/);
  }
  const b = browserRoot.createCiphertextRootBuilder(2);
  await b.append(bytes(10));
  await assert.rejects(b.finish(), /ZK_CHUNK_ROOT_INVALID/);
  await b.append(bytes(1));
  const root = await b.finish();
  assert.equal(root.length, 32);
  await assert.rejects(b.finish(), /ZK_CHUNK_ROOT_INVALID/);
  await assert.rejects(b.append(bytes(10)), /ZK_CHUNK_ROOT_INVALID/);
  await assert.rejects(browserRoot.computeCiphertextRoot([123]), /ZK_CHUNK_ROOT_INVALID/);
});

test("browser-global script runs without Node require/Buffer or access to local encryption keys", async () => {
  const source = fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-ciphertext-chunk-root.js"), "utf8");
  const context = { crypto: crypto.webcrypto, TextEncoder };
  context.window = context;
  vm.runInNewContext(source, context, { timeout: 1000 });
  assert.equal(typeof context.RootarkZk1CiphertextRoot?.computeCiphertextRoot, "function");
  const chunks = [bytes(33), bytes(173)];
  const actual = await context.RootarkZk1CiphertextRoot.computeCiphertextRoot(chunks);
  assert.deepEqual(Buffer.from(actual), computeZk1CiphertextRoot(chunks));
  assert.equal(context.Buffer, undefined);
});
