"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { privateAuthorityDirectory } = require("./support/issue-65-private-authority-directory");
const { createWindowsSynchronousPrivateAclVerifier } =
  require("../src/services/zk1WindowsSynchronousPrivateAclVerifier");

test("resident native private ACL verifier fresh checks, denies unsafe paths and refuses use after close", {
  skip: process.platform !== "win32" }, () => {
  const directory = privateAuthorityDirectory("zk65-resident-cas-acl-");
  const verifier = createWindowsSynchronousPrivateAclVerifier();
  try {
    assert.doesNotThrow(() => verifier.verify(directory));
    assert.doesNotThrow(() => verifier.verify(directory));
    assert.throws(() => verifier.verify(path.join(directory, "nonexistent")));
    assert.doesNotThrow(() => verifier.verify(directory), "a denied request must not authorize a later request");
    execFileSync("C:\\Windows\\System32\\icacls.exe", [directory, "/grant",
      "*S-1-5-32-545:(OI)(CI)M"], { windowsHide: true, stdio: "ignore" });
    assert.throws(() => verifier.verify(directory),
      "every warm call must re-read the ACTUAL native Users Modify DACL");
    execFileSync("C:\\Windows\\System32\\icacls.exe", [directory,
      "/remove:g", "*S-1-5-32-545"], { windowsHide: true, stdio: "ignore" });
    assert.doesNotThrow(() => verifier.verify(directory),
      "trust is fresh, not a cached permanent rejection either");
    verifier.stop();
    assert.throws(() => verifier.verify(directory), "closed resident workers fail closed");
  } finally {
    verifier.stop();
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 5 });
  }
});
