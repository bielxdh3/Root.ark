"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { readEdgeDevToolsPort } = require("./support/issue-65-edge-devtools-port");

test("offline Edge E2E routes CDP port readiness through the race-safe shared reader", () => {
  // The real browser fixture must use the same helper that is exercised below
  // under a physical publication/read race. A second open-coded check reopens
  // the existence-to-read window and silently loses the shared regression.
  const source = fs.readFileSync(path.join(__dirname,
    "issue-65-browser-offline-persisted-restore.test.js"), "utf8");
  assert.match(source, /const \{ readEdgeDevToolsPort \} = require\("\.\/support\/issue-65-edge-devtools-port"\);/);
  assert.match(source, /await waitFor\(\(\) => readEdgeDevToolsPort\(profile\)\)/);
  assert.doesNotMatch(source, /if \(!fs\.existsSync\(file\)\) return null;/);
});

test("Edge CDP readiness retries a port file removed during its read", (t) => {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-edge-port-race-"));
  t.after(() => fs.rmSync(profile, { recursive: true, force: true }));
  const portFile = path.join(profile, "DevToolsActivePort");
  fs.writeFileSync(portFile, "12345\n/devtools/browser/fixture\n", { flag: "wx" });
  const concurrentDelete = {
    existsSync: fs.existsSync,
    readFileSync(filename, encoding) {
      assert.equal(filename, portFile);
      fs.unlinkSync(filename);
      return fs.readFileSync(filename, encoding);
    },
  };
  assert.equal(readEdgeDevToolsPort(profile, concurrentDelete), null);
});

test("Edge CDP readiness accepts only a complete numeric local port", () => {
  const read = (contents) => readEdgeDevToolsPort("profile", {
    existsSync: () => true,
    readFileSync: () => contents,
  });
  assert.equal(read("9222\n/devtools/browser/fixture"), 9222);
  for (const bad of ["", "0", "65536", "port=9222", "9222junk", "9222.5", "-1", "NaN"]) {
    assert.equal(read(bad), null);
  }
});

test("Edge CDP readiness retries transient read failures and exposes unexpected failures", () => {
  const interrupted = (code) => () => {
    const error = new Error("untrusted local file error");
    error.code = code;
    throw error;
  };
  for (const code of ["ENOENT", "EACCES", "EPERM", "EBUSY"]) {
    assert.equal(readEdgeDevToolsPort("profile", { readFileSync: interrupted(code) }), null);
  }
  assert.throws(() => readEdgeDevToolsPort("profile", {
    readFileSync: interrupted("EIO"),
  }), { code: "EIO" });
});
