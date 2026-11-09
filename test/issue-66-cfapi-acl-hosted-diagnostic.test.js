"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const { createHash } = require("node:crypto");
const { spawnSync } = require("node:child_process");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createAclFailureDiagnostic, parseAclFailureDiagnostic } = require("../scripts/acl-test-failure-diagnostic");
const { extractHostedAclFailureDiagnostics } = require("../scripts/release-gate-acl-diagnostics");
const { createTapProgressRecorder } = require("../scripts/run-windows-canonical-tests");

const title = String.raw`\#66 Windows SDK ACL preflight accepts a protected owner-only DACL and rejects broad access or reparse points`;
const sourceFile = "test/issue-66-cfapi-acl-preflight-native.test.js";
const hash = (value) => createHash("sha256").update(value).digest("hex").slice(0, 24);
const diagnostic = "# ROOTARK_ACL_V1 case=CFAPI_PREFLIGHT stage=OWNER_ACCEPT code=ASSERTION trust=UNKNOWN";
const location = String.raw`D:\a\Root.ark\Root.ark\test\issue-66-cfapi-acl-preflight-native.test.js:32:1`;

function failedTap(name = title, file = location, line = diagnostic) {
  return ["TAP version 13", `not ok 2009 - ${name}`, "  ---",
    `  location: '${file}'`, "  failureType: 'testCodeFailure'", "  code: 'ERR_ASSERTION'",
    "  ...", line, "# tests 2777", "# fail 1"].join("\n");
}

test("CFAPI hosted identity is exact hashed escaped TAP title and original source", () => {
  const identity = { nameHash: hash(title), pathHash: hash(sourceFile) };
  assert.equal(identity.nameHash, "647cac1545ad2aa0aba566f1");
  assert.equal(identity.pathHash, "671b6316a6c69136db400ccd");
  assert.deepEqual(parseAclFailureDiagnostic(diagnostic, identity), {
    stage: "OWNER_ACCEPT", code: "ASSERTION", trust: "UNKNOWN",
  });
  assert.deepEqual(parseAclFailureDiagnostic(diagnostic, { name: title, path: sourceFile }), {
    stage: "OWNER_ACCEPT", code: "ASSERTION", trust: "UNKNOWN",
  });
  for (const wrong of [
    { ...identity, nameHash: hash(title.slice(1)) },
    { ...identity, pathHash: hash("test/other.test.js") },
    { ...identity, name: title, path: sourceFile },
    { name: title.slice(1), path: sourceFile },
    { name: title, path: "test/other.test.js" },
  ]) assert.equal(parseAclFailureDiagnostic(diagnostic, wrong), null);
});

test("CFAPI hosted release extracts only strict bounded categories from matching failed TAP", () => {
  assert.deepEqual(extractHostedAclFailureDiagnostics(failedTap()), [diagnostic]);
  for (const [index, forged] of [
    failedTap(title.slice(1)),
    failedTap(title + " "),
    failedTap(title, location.replace("issue-66", "issue-65")),
    failedTap(title, location, diagnostic.replace("OWNER_ACCEPT", "USER_SID")),
    failedTap(title, location, `${diagnostic} path=C:\\secret`),
    failedTap().replace("not ok 2009", "ok 2009"),
    failedTap(title, location, "  ...") + "\n" + diagnostic,
  ].entries()) {
    assert.deepEqual(extractHostedAclFailureDiagnostics(forged), [], `forged or late diagnostic ${index} rejected`);
  }
});

test("CFAPI canonical Windows reporter keeps only hash and verified stage", () => {
  const printed = [];
  const tracker = createTapProgressRecorder((line) => printed.push(line));
  for (const line of failedTap().split("\n")) tracker.accept(line);
  tracker.finish();
  const joined = printed.join("\n");
  assert.match(joined, /aclStage=OWNER_ACCEPT aclError=ASSERTION aclTrust=UNKNOWN/);
  assert.match(joined, /nameSha256=647cac1545ad2aa0aba566f1/);
  assert.match(joined, /testPathSha256=671b6316a6c69136db400ccd/);
  assert.doesNotMatch(joined, /Windows SDK|Root\.ark|OWNER SID|C:\\|D:\\|secret/);
});

test("CFAPI producer reports fixed categories from an actual failure without disclosing error text", async () => {
  const printed = [];
  const producer = createAclFailureDiagnostic({ diagnostic: (value) => printed.push(value) }, "CFAPI_PREFLIGHT");
  producer.stage("OWNER_ACCEPT");
  const error = Object.assign(new Error("C:\\private\\S-1-5-11\\secret"), { code: "ERR_ASSERTION" });
  await assert.rejects(producer.run(() => { throw error; }), (actual) => actual === error);
  assert.throws(() => producer.stage("SID_AND_SECRET"), /INVALID_ACL_DIAGNOSTIC_STAGE/);
  if (process.platform === "win32") assert.deepEqual(printed, [diagnostic.slice(2)]);
  else assert.deepEqual(printed, []);
});

test("real Node TAP escapes the leading # and attributes the CFAPI diagnostic to its file", async (t) => {
  const scratch = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cfapi-tap-diagnostic-"));
  t.after(() => fs.rm(scratch, { recursive: true, force: true }));
  const dir = path.join(scratch, "test");
  await fs.mkdir(dir);
  const fixture = path.join(dir, "issue-66-cfapi-acl-preflight-native.test.js");
  const script = [
    "const test = require('node:test');",
    "const assert = require('node:assert/strict');",
    `test(${JSON.stringify(title.slice(1))}, (t) => { t.diagnostic(${JSON.stringify(diagnostic.slice(2))}); assert.equal(1, 2); });`,
  ].join("\n");
  await fs.writeFile(fixture, script);
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const child = spawnSync(process.execPath, ["--test", "--test-reporter=tap", fixture], {
    encoding: "utf8", timeout: 12000, env, windowsHide: true,
  });
  assert.equal(child.status, 1, "the isolated fixture must genuinely fail");
  assert.deepEqual(extractHostedAclFailureDiagnostics(child.stdout), [diagnostic]);
  const printed = [];
  const tracker = createTapProgressRecorder((message) => printed.push(message));
  for (const line of child.stdout.split(/\r?\n/)) tracker.accept(line);
  tracker.finish();
  assert.match(printed.join("\n"), /aclStage=OWNER_ACCEPT aclError=ASSERTION aclTrust=UNKNOWN/);
  assert.doesNotMatch(printed.join("\n"), /Windows SDK|C:\\|D:\\|secret/);
});
