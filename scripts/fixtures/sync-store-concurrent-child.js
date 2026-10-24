"use strict";

const { SyncObjectStore } = require("../../src/routes/sync");

(async () => {
  const store = await new SyncObjectStore(process.argv[2]).open();
  process.send?.({ type: "ready" });
  await new Promise((resolve) => process.on("message", (message) => {
    if (message?.type === "go") resolve();
  }));
  for (let index = 0; index < 8; index += 1) {
    await store.transact((next) => {
      const user = store.user(next, process.argv[3]);
      user.testIteration = index;
    });
  }
  process.send?.({ type: "done" });
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
