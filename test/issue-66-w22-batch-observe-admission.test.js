"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { SyncJournal } = require("../sync-client/rootark-sync-journal");

function observation(index, namespace = "batch") {
  return {
    operationId: `${namespace}-${index}`,
    digest: crypto.createHash("sha256").update(`${namespace}:${index}`).digest("hex"),
  };
}

async function fixture(t) {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-w22-batch-"));
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, ".rootark-sync-journal.json");
  const journal = await new SyncJournal(file).open();
  return { file, journal };
}

test("W22: 160/640 verified digest observations use one durable transaction per bounded batch", async (t) => {
  for (const count of [160, 640]) {
    const { file, journal } = await fixture(t);
    const input = Array.from({ length: count }, (_, i) => observation(i));
    let commits = 0;
    const originalRename = fsp.rename;
    fsp.rename = async (...args) => {
      if (args[1] === file) commits += 1;
      return originalRename(...args);
    };
    try {
      await journal.batchObserveAdmission(input);
    } finally {
      fsp.rename = originalRename;
    }
    assert.equal(commits, 1, `${count} observations require exactly one JSON commit`);
    const cold = await new SyncJournal(file).open();
    for (const { operationId, digest } of input) {
      assert.equal(cold.hasLocalAdmission(operationId, digest), true);
    }
    assert.equal(Object.keys(cold.state.observed).length, count);
  }
});

test("W22: late conflicting digest, duplicate ID and malformed digest reject the entire transaction", async (t) => {
  const { file, journal } = await fixture(t);
  await journal.observeAdmission("prior", observation(9).digest);
  const previous = await fsp.readFile(file, "utf8");
  for (const tail of [
    { operationId: "prior", digest: observation(12).digest },
    observation(0),
    { operationId: "invalid", digest: "not-a-sha256" },
  ]) {
    const input = [observation(0), observation(1), tail];
    await assert.rejects(journal.batchObserveAdmission(input));
    assert.equal(await fsp.readFile(file, "utf8"), previous);
    assert.equal(journal.hasLocalAdmission("batch-1", observation(1).digest), false);
  }
  const cold = await new SyncJournal(file).open();
  assert.equal(Object.keys(cold.state.observed).length, 1);
  assert.equal(cold.hasLocalAdmission("prior", observation(9).digest), true);
});

test("W22: EIO before atomic rename leaves no partial observation, including after cold reopen", async (t) => {
  const { file, journal } = await fixture(t);
  const previous = await fsp.readFile(file, "utf8");
  const originalRename = fsp.rename;
  fsp.rename = async (...args) => {
    if (args[1] === file) throw Object.assign(new Error("injected EIO"), { code: "EIO" });
    return originalRename(...args);
  };
  try {
    await assert.rejects(journal.batchObserveAdmission([observation(0), observation(1)]),
      { code: "EIO" });
  } finally {
    fsp.rename = originalRename;
  }
  assert.equal(await fsp.readFile(file, "utf8"), previous);
  assert.equal(journal.hasLocalAdmission("batch-0", observation(0).digest), false);
  const cold = await new SyncJournal(file).open();
  assert.equal(cold.hasLocalAdmission("batch-1", observation(1).digest), false);
});

test("W22: post-rename directory EIO reports an indeterminate ACK while preserving disk and memory pins", async (t) => {
  const { file, journal } = await fixture(t);
  const originalOpen = fsp.open;
  const directory = path.dirname(file);
  fsp.open = async (...args) => {
    if (args[0] === directory && args[1] === "r") {
      throw Object.assign(new Error("injected directory EIO"), { code: "EIO" });
    }
    return originalOpen(...args);
  };
  try {
    await assert.rejects(journal.batchObserveAdmission([observation(0), observation(1)]),
      (error) => error.code === "EIO" && error.journalCommitted === true);
  } finally {
    fsp.open = originalOpen;
  }
  for (const id of [0, 1]) {
    assert.equal(journal.hasLocalAdmission(`batch-${id}`, observation(id).digest), true);
  }
  const cold = await new SyncJournal(file).open();
  assert.equal(cold.hasLocalAdmission("batch-1", observation(1).digest), true);
});

test("W22: process exits after journal commit but before any stage; cold proof survives", async (t) => {
  const { file } = await fixture(t);
  const modulePath = require.resolve("../sync-client/rootark-sync-journal");
  const script = `const {SyncJournal}=require(${JSON.stringify(modulePath)});\n` +
    `new SyncJournal(${JSON.stringify(file)}).open().then(async j=>{` +
    `await j.batchObserveAdmission([${JSON.stringify(observation(42))}]);process.exit(73);` +
    `}).catch(()=>process.exit(90));`;
  const child = spawnSync(process.execPath, ["-e", script], {
    timeout: 15000, encoding: "utf8", windowsHide: true,
  });
  assert.equal(child.status, 73, child.stderr);
  const cold = await new SyncJournal(file).open();
  assert.equal(cold.hasLocalAdmission("batch-42", observation(42).digest), true);
});

test("W22: mutable input cannot switch authorization digests while an earlier transaction is pending", async (t) => {
  const { file, journal } = await fixture(t);
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const earlier = journal.commit(async () => gate);
  const original = observation(71);
  const input = [original];
  const admission = journal.batchObserveAdmission(input);
  input[0].operationId = "swapped-id";
  input[0].digest = observation(90).digest;
  input.push(observation(999));
  release();
  await earlier;
  await admission;
  const cold = await new SyncJournal(file).open();
  assert.equal(cold.hasLocalAdmission("batch-71", observation(71).digest), true);
  assert.equal(cold.hasLocalAdmission("swapped-id", observation(90).digest), false);
  assert.equal(cold.hasLocalAdmission("batch-999", observation(999).digest), false);
});

test("W22: special literal operation IDs keep their own keys across commits and cold reopen", async (t) => {
  const { file, journal } = await fixture(t);
  const input = [observation(1), { operationId: "__proto__", digest: observation(2).digest }];
  await journal.batchObserveAdmission(input);
  const cold = await new SyncJournal(file).open();
  assert.equal(Object.hasOwn(cold.state.observed, "__proto__"), true);
  assert.equal(cold.hasLocalAdmission("__proto__", observation(2).digest), true);
  assert.equal(cold.hasLocalAdmission("batch-1", observation(1).digest), true);
});
