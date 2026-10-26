"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { publishFixtureJson, awaitFixtureJson } =
  require("./support/issue-65-owner-revocation-fixture-ipc");

test("offline witness fixture publishes complete JSON after writing temporary bytes", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-revoke-ipc-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const dest = path.join(dir, "committed-receipt.json");
  let observed = false;
  publishFixtureJson(dir, "committed-receipt.json", { proof: "fixture" }, () => {
    observed = true;
    assert.equal(fs.existsSync(dest), false, "consumer must not see an incomplete receipt");
  });
  assert.equal(observed, true);
  assert.deepEqual(JSON.parse(fs.readFileSync(dest, "utf8")), { proof: "fixture" });
  assert.throws(() => publishFixtureJson(dir, "committed-receipt.json", {}),
    /FIXTURE_EXISTS/, "fixture must never overwrite a signed receipt");
});

test("owner CLI consumer ignores transient incomplete JSON until the other process finishes publication", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-revoke-ipc-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const filename = path.join(dir, "candidate.json");
  fs.writeFileSync(filename, '{"committed":');
  let ticks = 0;
  const result = await awaitFixtureJson(filename, {
    exited: () => false,
    sleep: async () => { ticks++; fs.writeFileSync(filename, '{"committed":false}'); },
  });
  assert.deepEqual(result, { committed: false });
  assert.equal(ticks, 1);
  await assert.rejects(awaitFixtureJson(path.join(dir, "absent.json"), {
    exited: () => true,
  }), /EARLY_CLI_EXIT/);
});
