"use strict";

// Fixed test preload: fixture paths are process data, never JavaScript source.
const fs = require("node:fs");
const path = require("node:path");

const dir = process.env.ROOTARK_TEST_DAV_FIXTURE;
// Inert under default test discovery; an explicitly supplied invalid root
// still fails before any monkeypatch or filesystem operation.
if (dir !== undefined) {
  if (!dir || !path.isAbsolute(dir)) throw Error("INVALID_DAV_TEST_FIXTURE");
  const bcrypt = require("bcryptjs");
  const { readPinnedFixtureFileSync, writeExistingFixtureFileSync } =
    require("./pinned-fixture-file");
  const mutate = path.join(dir, "mutate.json");
  const localUsers = path.join(dir, "data", "users.local.json");
  const originalCompare = bcrypt.compare;
  bcrypt.compare = async function injectedCompare(...args) {
    const result = await originalCompare.apply(this, args);
    if (fs.existsSync(mutate)) {
      // The fixture mutates only its own disposable local user snapshot.
      writeExistingFixtureFileSync(localUsers, readPinnedFixtureFileSync(mutate));
      fs.unlinkSync(mutate);
    }
    return result;
  };
}
