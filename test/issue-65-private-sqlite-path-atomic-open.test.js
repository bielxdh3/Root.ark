"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { assertPrivateSqliteFile } =
  require("../src/services/zk1PrivateSqlitePath");

test("private SQLite checks validate opened descriptor and deny hard-linked files", (t) => {
  const dir = createPrivateAuthorityFixture("rootark-zk-private-sqlite-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const filename = path.join(dir, "store.sqlite");
  const alias = path.join(dir, "alias.sqlite");
  fs.writeFileSync(filename, "disposable", { mode: 0o600 });
  assert.doesNotThrow(() => assertPrivateSqliteFile(filename));
  fs.linkSync(filename, alias);
  assert.throws(() => assertPrivateSqliteFile(filename), /UNTRUSTED_SQLITE_PATH/);
  assert.throws(() => assertPrivateSqliteFile(alias), /UNTRUSTED_SQLITE_PATH/);
  fs.unlinkSync(alias);
  assert.doesNotThrow(() => assertPrivateSqliteFile(filename));
});
