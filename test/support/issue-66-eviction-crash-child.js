"use strict";

// Disposable fixture process: intentionally exits immediately after a real
// signed, guarded local cache file was staged but before an eviction COMMIT.
// Never use with a non-test root or real credentials.
const { SyncEngine } = require("../../sync-client/rootark-sync-engine");
const { SyncObjectStore } = require("../../src/routes/sync");

process.once("message", async (message) => {
  try {
    if (!message || message.fixture !== "issue66-eviction-crash-v1"
      || typeof message.root !== "string" || !message.root.includes("rootark-issue66-eviction-crash-")
      || typeof message.storePath !== "string" || !message.storePath.includes("rootark-issue66-eviction-crash-")) {
      process.exit(90);
    }
    const key = Buffer.from(message.fixtureKey, "base64");
    const store = await new SyncObjectStore(message.storePath).open();
    const adapter = {
      async list(objectId = "") { return store.list("alice", objectId || null); },
      async push() { throw new Error("remote write not permitted in crash fixture"); },
    };
    const sync = await new SyncEngine({
      rootDir: message.root, adapter, deviceId: "device-b", keyEpoch: "epoch-1",
      compartmentId: "private", excludedPaths: ["private"],
      fileKeyResolver: () => key,
    }).open();
    const stage = sync.stageExisting.bind(sync);
    sync.stageExisting = async (target) => {
      const staged = await stage(target);
      process.send({ type: "staged", staged }, () => process.exit(79));
      return new Promise(() => {});
    };
    await sync.syncOnce();
    process.exit(91); // The fixture must crash inside the staged state.
  } catch {
    process.exit(92);
  }
});
