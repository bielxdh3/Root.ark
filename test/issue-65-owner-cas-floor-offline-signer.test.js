"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");

const SCRIPT = path.resolve(__dirname, "../scripts/zk1-owner-cas-floor-sign-offline.js");
const now = () => Math.floor(Date.now() / 1000);

test("owner offline signer enforces independent inputs, signer separation, custody and exclusive output", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-owner-sign-offline-"));
  const foreign = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-owner-sign-foreign-"));
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
  const other = crypto.generateKeyPairSync("ed25519");
  write("public", other.publicKey);
  denied(minimum); // private key does not match pinned owner public key
});
