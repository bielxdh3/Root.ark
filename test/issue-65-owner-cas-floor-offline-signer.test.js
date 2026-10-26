"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const checkpoint = require("../src/crypto/rootark-zk1-owner-cas-floor-checkpoint");

const SCRIPT = path.resolve(__dirname, "../scripts/zk1-owner-cas-floor-sign-offline.js");
const { run: runSigner } = require(SCRIPT);
const now = () => Math.floor(Date.now() / 1000);
// Windows hosted runners may expose TEMP through a junction/alias. The signer
// deliberately rejects such ancestors, so fixtures must start at the resolved
// physical directory; the adversarial tests still introduce their own swaps.
const fixtureTempRoot = fs.realpathSync.native(os.tmpdir());

test("owner offline signer enforces independent inputs, signer separation, custody and exclusive output", (t) => {
  const dir = fs.mkdtempSync(path.join(fixtureTempRoot, "rootark-owner-sign-offline-"));
  const foreign = fs.mkdtempSync(path.join(fixtureTempRoot, "rootark-owner-sign-foreign-"));
  t.after(() => {
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    fs.rmSync(foreign, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const own = crypto.generateKeyPairSync("ed25519");
  const wit = crypto.generateKeyPairSync("ed25519");
  const sta = crypto.generateKeyPairSync("ed25519");
  const paths = Object.fromEntries(["input", "private", "public", "witness", "status", "output"]
    .map((name) => [name, path.join(dir, name + (name === "output" ? ".json" : ".pem"))]));
  paths.input = path.join(dir, "minimum.json");
  const write = (name, key, priv = false) => fs.writeFileSync(paths[name],
    key.export({ type: priv ? "pkcs8" : "spki", format: "pem" }));
  write("private", own.privateKey, true);
  write("public", own.publicKey);
  write("witness", wit.publicKey);
  write("status", sta.publicKey);
  const minimum = {
    source: "owner-retained-independent-floor/v1",
    witnessKeyId: crypto.randomBytes(16).toString("base64url"),
    statusKeyId: crypto.randomBytes(16).toString("base64url"),
    trustedMinimumHead: { sequence: 2, lastHash: "a".repeat(64) },
    issuedAt: now(), expiresAt: now() + 1200,
  };
  function invoke(input = minimum, overrides = {}) {
    fs.writeFileSync(paths.input, JSON.stringify(input));
    const choices = { ...paths, ...overrides };
    return spawnSync(process.execPath, [SCRIPT,
      "--owned-dir", dir, "--input", choices.input,
      "--owner-private-key", choices.private, "--owner-public-key", choices.public,
      "--witness-public-key", choices.witness, "--status-public-key", choices.status,
      "--output", choices.output, "--confirm-independent-minimum",
    ], { encoding: "utf8", windowsHide: true });
  }
  const valid = invoke();
  assert.equal(valid.status, 0, valid.stderr);
  assert.equal(valid.stdout, "OWNER_FLOOR_SIGNED\n");
  const artifact = JSON.parse(fs.readFileSync(paths.output, "utf8"));
  assert.equal(artifact.casAnchorFloor.owner.signature.length, 86);
  assert.match(artifact.envPins.ROOTARK_ZK1_CAS_FLOOR_OWNER_SPKI_SHA256, /^[a-f0-9]{64}$/);
  assert.match(artifact.envPins.ROOTARK_ZK1_CAS_FLOOR_OWNER_CHECKPOINT_SHA256, /^[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(artifact).includes("PRIVATE KEY"), false);
  const v2Statement = checkpoint.statement({
    witnessKeyId: minimum.witnessKeyId, statusKeyId: minimum.statusKeyId,
    witnessSpkiSha256: checkpoint.spkiFingerprint(wit.publicKey).toString("hex"),
    statusSpkiSha256: checkpoint.spkiFingerprint(sta.publicKey).toString("hex"),
    sequence: minimum.trustedMinimumHead.sequence,
    lastHash: minimum.trustedMinimumHead.lastHash,
    issuedAt: minimum.issuedAt, expiresAt: minimum.expiresAt,
  });
  assert.equal(v2Statement.type, "rootark-zk1-cas-owner-floor/v2");
  const signature = Buffer.from(artifact.casAnchorFloor.owner.signature, "base64url");
  assert.equal(crypto.verify(null, checkpoint.signingBytes(v2Statement), own.publicKey,
    signature), true, "owner CLI actually signs the exact v2 public-key identities");
  assert.equal(checkpoint.checkpointDigest(v2Statement, signature).toString("hex"),
    artifact.envPins.ROOTARK_ZK1_CAS_FLOOR_OWNER_CHECKPOINT_SHA256);
  const wrongAuthorityStatement = { ...v2Statement,
    statusSpkiSha256: checkpoint.spkiFingerprint(crypto.generateKeyPairSync("ed25519").publicKey).toString("hex") };
  assert.equal(crypto.verify(null, checkpoint.signingBytes(wrongAuthorityStatement),
    own.publicKey, signature), false);
  const original = fs.readFileSync(paths.output);
  function denied(input, changes) {
    const result = invoke(input, changes);
    assert.notEqual(result.status, 0);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr, "OWNER_FLOOR_SIGN_FAILED\n");
    assert.deepEqual(fs.readFileSync(paths.output), original);
  }
  denied(minimum); // no overwrite even for an otherwise identical checkpoint
  const unsafe = path.join(foreign, "outside.json");
  denied(minimum, { output: unsafe });
  denied(minimum, { private: path.join(foreign, "private.pem") });
  denied({ ...minimum, source: "server-reported-floor/v1" });
  denied({ ...minimum, trustedMinimumHead: { sequence: 1, lastHash: "0".repeat(64) } });
  denied({ ...minimum, trustedMinimumHead: { sequence: -1, lastHash: "0".repeat(64) } });
  denied({ ...minimum, witnessKeyId: "invalid" });
  denied({ ...minimum, arbitraryField: true });
  denied({ ...minimum, issuedAt: now() - 300, expiresAt: now() + 1200 });
  denied({ ...minimum, issuedAt: now() + 300, expiresAt: now() + 1200 });
  denied({ ...minimum, issuedAt: now(), expiresAt: now() - 1 });
  denied({ ...minimum, issuedAt: now(), expiresAt: now() + 86400 });
  denied(minimum, { witness: paths.public }); // exact owner key reuse forbidden
  denied(minimum, { status: paths.public });
  // Distinct owned paths can still contain the *same* witness/status signer.
  // Reject before signing or creating a checkpoint artifact.
  write("status", wit.publicKey);
  const duplicateSignerOutput = path.join(dir, "duplicate-authority-checkpoint.json");
  const duplicateSigner = invoke(minimum, { output: duplicateSignerOutput });
  assert.notEqual(duplicateSigner.status, 0);
  assert.equal(duplicateSigner.stdout, "");
  assert.equal(duplicateSigner.stderr, "OWNER_FLOOR_SIGN_FAILED\n");
  assert.equal(fs.existsSync(duplicateSignerOutput), false);
  write("status", sta.publicKey);
  const duplicateIdOutput = path.join(dir, "duplicate-authority-id-checkpoint.json");
  const duplicateId = invoke({ ...minimum, statusKeyId: minimum.witnessKeyId },
    { output: duplicateIdOutput });
  assert.notEqual(duplicateId.status, 0);
  assert.equal(duplicateId.stdout, "");
  assert.equal(duplicateId.stderr, "OWNER_FLOOR_SIGN_FAILED\n");
  assert.equal(fs.existsSync(duplicateIdOutput), false);
  const other = crypto.generateKeyPairSync("ed25519");
  write("public", other.publicKey);
  denied(minimum); // private key does not match pinned owner public key
});

test("offline signer refuses a directory swap before consuming the owner private key", (t) => {
  const fixture = nestedFixture(t);
  const foreignKey = crypto.generateKeyPairSync("ed25519").privateKey.export({
    type: "pkcs8", format: "pem",
  });
  const foreignPrivate = path.join(fixture.foreign, "private.pem");
  fs.writeFileSync(foreignPrivate, foreignKey);
  const ownedPrivate = path.join(fixture.nested, "private.pem");
  let swapped = false;
  let foreignReads = 0;
  const fakeFs = Object.create(fs);
  fakeFs.lstatSync = (name, ...rest) => {
    if (name === ownedPrivate && !swapped) {
      fixture.swapToForeign();
      swapped = true;
    }
    return fs.lstatSync(name, ...rest);
  };
  fakeFs.readFileSync = (fd, ...rest) => {
    if (typeof fd === "number") {
      const opened = fs.fstatSync(fd);
      const foreign = fs.statSync(foreignPrivate);
      if (opened.dev === foreign.dev && opened.ino === foreign.ino) foreignReads++;
    }
    return fs.readFileSync(fd, ...rest);
  };
  try {
    assert.throws(() => runSigner(fixture.args, now(), fakeFs));
    assert.equal(swapped, true);
    assert.equal(foreignReads, 0, "the signer read bytes through the foreign junction");
    assert.equal(fs.existsSync(fixture.output), false);
  } finally { fixture.restore(); }
});

test("offline signer does not write through an output-parent junction swapped at open", (t) => {
  const fixture = nestedFixture(t);
  const foreignOutput = path.join(fixture.foreign, "checkpoint.json");
  const sentinel = path.join(fixture.foreign, "untouched.txt");
  fs.writeFileSync(sentinel, "foreign contents stay untouched");
  let swapped = false;
  const fakeFs = Object.create(fs);
  fakeFs.openSync = (filename, ...rest) => {
    if (filename === fixture.output) {
      fixture.swapToForeign();
      swapped = true;
    }
    return fs.openSync(filename, ...rest);
  };
  try {
    assert.throws(() => runSigner(fixture.args, now(), fakeFs));
    assert.equal(swapped, true);
    assert.equal(fs.existsSync(foreignOutput), false, "foreign output must be rolled back");
    assert.equal(fs.readFileSync(sentinel, "utf8"), "foreign contents stay untouched");
  } finally { fixture.restore(); }
  assert.equal(fs.existsSync(fixture.output), false);
});

function nestedFixture(t) {
  const root = fs.mkdtempSync(path.join(fixtureTempRoot, "rootark-owner-swap-owned-"));
  const foreign = fs.mkdtempSync(path.join(fixtureTempRoot, "rootark-owner-swap-foreign-"));
  const nested = path.join(root, "keys");
  const saved = path.join(root, "keys-original");
  fs.mkdirSync(nested);
  const [owner, witness, status] = Array.from({ length: 3 }, () => crypto.generateKeyPairSync("ed25519"));
  const files = {
    input: "minimum.json", private: "private.pem", public: "public.pem",
    witness: "witness.pem", status: "status.pem", output: "checkpoint.json",
  };
  const loc = (file) => path.join(nested, files[file]);
  fs.writeFileSync(loc("input"), JSON.stringify({
    source: "owner-retained-independent-floor/v1",
    witnessKeyId: crypto.randomBytes(16).toString("base64url"),
    statusKeyId: crypto.randomBytes(16).toString("base64url"),
    trustedMinimumHead: { sequence: 2, lastHash: "a".repeat(64) },
    issuedAt: now(), expiresAt: now() + 1200,
  }));
  for (const [name, key, priv] of [
    ["private", owner.privateKey, true], ["public", owner.publicKey, false],
    ["witness", witness.publicKey, false], ["status", status.publicKey, false],
  ]) fs.writeFileSync(loc(name), key.export({ type: priv ? "pkcs8" : "spki", format: "pem" }));
  const args = ["--owned-dir", root,
    "--input", loc("input"), "--owner-private-key", loc("private"),
    "--owner-public-key", loc("public"), "--witness-public-key", loc("witness"),
    "--status-public-key", loc("status"), "--output", loc("output"),
    "--confirm-independent-minimum"];
  let isSwapped = false;
  function restore() {
    if (!isSwapped) return;
    fs.unlinkSync(nested);
    fs.renameSync(saved, nested);
    isSwapped = false;
  }
  t.after(() => {
    restore();
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(foreign, { recursive: true, force: true });
  });
  return {
    foreign, nested, output: loc("output"), args, restore,
    swapToForeign() {
      fs.renameSync(nested, saved);
      try {
        fs.symlinkSync(foreign, nested, process.platform === "win32" ? "junction" : "dir");
        isSwapped = true;
      } catch (error) {
        fs.renameSync(saved, nested);
        throw error;
      }
    },
  };
}
