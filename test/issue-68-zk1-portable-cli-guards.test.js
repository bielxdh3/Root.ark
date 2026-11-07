"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const cli = require("../scripts/zk1-recipient-offer-local");

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
    ["redeem-batch", "--owned-dir", "SECRET_PLAINTEXT_MARKER",
      "--context-module", "foo.js", "--manifest", "foo.js"],
    ["redeem-batch", "--owned-dir", "SECRET_PLAINTEXT_MARKER",
      "--context-module", "foo.js", "--manifest", "set.json",
      "--output", "unexpected.bin"],
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
