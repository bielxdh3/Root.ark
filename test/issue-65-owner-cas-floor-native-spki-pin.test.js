"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { spkiFingerprint } =
  require("../src/crypto/rootark-zk1-owner-cas-floor-checkpoint");

test("owner CAS/FLOOR retained minimum hashes the real Ed25519 signer, not forged export", () => {
  const trusted = crypto.generateKeyPairSync("ed25519").publicKey;
  const attacker = crypto.generateKeyPairSync("ed25519").publicKey;
  const retainedFingerprint = spkiFingerprint(trusted);
  attacker.export = () => trusted.export({ type: "spki", format: "der" });
  assert.notDeepEqual(spkiFingerprint(attacker), retainedFingerprint,
    "an untrusted exported DER must not impersonate the pinned CAS/FLOOR owner");
});
