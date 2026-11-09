"use strict";

const assert = require("node:assert/strict");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { validateFixtureArgs } = require("./support/issue-66-cfapi-built-artifact");

test("#66 native CFAPI fixture helper accepts only fixed operation modes and owned test paths", () => {
  const acl = path.join(os.tmpdir(), "rootark-cfapi-acl-test-owned");
  const deny = path.join(os.tmpdir(), "rootark-cfapi-abi-owned");
  const positive = path.join(os.tmpdir(), "rootark-cfapi-positive-abi-owned");
  const inherit = path.join(os.tmpdir(), "rootark-cfapi-ace-native-owned");
  const accepted = [
    ["acl-preflight.exe", acl, ["--inspect", path.join(acl, "owner-only")]],
    ["acl-preflight.exe", acl, ["--inspect", path.join(acl, "junction")]],
    ["acl-preflight.exe", acl, ["--inspect", path.join(acl, "missing")]],
    ["acl-preflight.exe", acl, ["--register", path.join(acl, "owner-only")]],
    ["deny-fetch.exe", deny, ["--self-test"]],
    ["deny-fetch.exe", deny, ["--connect", deny]],
    ["positive-shape.exe", positive, []],
    ["positive-shape.exe", positive, ["--self-test"]],
    ["positive-shape.exe", positive, ["--connect", positive]],
    ["positive-shape.exe", positive, ["--register", positive]],
    ["positive-shape.exe", positive, ["--hydrate", positive]],
    ["inherit-only-fixture.exe", inherit, []],
  ];
  for (const [name, scratch, args] of accepted) {
    assert.deepEqual(validateFixtureArgs(name, scratch, args), args);
  }

  const rejected = [
    ["acl-preflight.exe", acl, ["--inspect", path.join(os.tmpdir(), "foreign")]],
    ["acl-preflight.exe", acl, ["--register", path.join(acl, "junction")]],
    ["acl-preflight.exe", acl, ["--inspect", path.join(acl, "..", "foreign")]],
    ["acl-preflight.exe", acl, ["--inspect", path.join(acl, "owner-only"), "--extra"]],
    ["deny-fetch.exe", deny, ["--connect", path.join(os.tmpdir(), "foreign")]],
    ["deny-fetch.exe", deny, ["--register", deny]],
    ["positive-shape.exe", positive, ["--hydrate", path.join(os.tmpdir(), "foreign")]],
    ["positive-shape.exe", positive, ["--self-test", "--connect"]],
    ["inherit-only-fixture.exe", inherit, ["--self-test"]],
    ["anything.exe", acl, []],
    ["acl-preflight.exe", acl, ["--inspect", "owner-only"]],
    ["acl-preflight.exe", acl, ["--inspect", path.join(acl, "owner-only") + "\n"]],
    ["acl-preflight.exe", acl, new Array(3).fill("--self-test")],
  ];
  for (const [name, scratch, args] of rejected) {
    assert.throws(() => validateFixtureArgs(name, scratch, args), /UNTRUSTED_EXECUTABLE/);
  }
});
