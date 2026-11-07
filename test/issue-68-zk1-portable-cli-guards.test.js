"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const cli = require("../scripts/zk1-recipient-offer-local");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

const entry = path.resolve(__dirname, "../scripts/zk1-recipient-offer-local.js");

test("#68: local portable offer CLI requires exact private context and never logs supplied input", () => {
  assert.equal(typeof cli.run, "function");
  for (const args of [
    [], ["export"], ["redeem"],
    ["export", "--owned-dir", "SECRET_PLAINTEXT_MARKER"],
    ["redeem", "--owned-dir", "SECRET_PLAINTEXT_MARKER",
      "--context-module", "foo.js", "--offer", "offer.json",
      "--output", "offer.json"],
    ["redeem", "--owned-dir", "SECRET_PLAINTEXT_MARKER",
      "--context-module", "foo.js", "--offer", "offer.json",
      "--output", "payload.bin", "--output", "other.bin"],
    ["export", "--owned-dir", "SECRET_PLAINTEXT_MARKER",
      "--context-module", "foo.js", "--grant", "grant.json",
      "--offer", "foo.js"],
  ]) {
    assert.throws(() => cli.parse(args), /ZK_RECIPIENT_OFFER_CLI_DENIED/);
    const child = spawnSync(process.execPath, [entry, ...args], {
      encoding: "utf8", timeout: 12000, env: process.env,
    });
    assert.equal(child.status, 1, child.error?.code);
    assert.equal(child.stdout, "");
    assert.equal(child.stderr.trim(), "ZK_RECIPIENT_OFFER_CLI_DENIED");
    assert.equal(child.stderr.includes("SECRET_PLAINTEXT_MARKER"), false);
  }
});

test("#68: trusted source must exist before any owner CEK release or recipient file write", async () => {
  await assert.rejects(cli.run([
    "redeem", "--owned-dir", "/an-absent-private-owner-directory-8b9e3d",
    "--context-module", "trusted.js", "--offer", "offer.json",
    "--output", "output.bin",
  ]), /ZK_RECIPIENT_OFFER_CLI_DENIED/);
});

test("#68: recipient private output rejects malformed and oversized data without creating a leaf", (t) => {
  const dir = createPrivateAuthorityFixture("rootark-recipient-out-bound-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  // Load the actual CLI source with a test-only export appended in-memory.
  // No production API or proof-verification behavior is changed by this test.
  const compiled = new Module(entry, module);
  compiled.filename = entry;
  compiled.paths = Module._nodeModulePaths(path.dirname(entry));
  compiled._compile(fs.readFileSync(entry, "utf8")
    + "\nmodule.exports.__privateOutputForTest = privateOutput;\n", entry);
  const output = compiled.exports.__privateOutputForTest;
  assert.throws(() => output(dir, "oversized.bin", Buffer.alloc(4 * 1024 * 1024 + 1)),
    /ZK_RECIPIENT_OFFER_CLI_DENIED/);
  assert.throws(() => output(dir, "wrong-type.bin", new Uint16Array([1])),
    /ZK_RECIPIENT_OFFER_CLI_DENIED/);
  assert.equal(fs.existsSync(path.join(dir, "oversized.bin")), false);
  assert.equal(fs.existsSync(path.join(dir, "wrong-type.bin")), false);
});
