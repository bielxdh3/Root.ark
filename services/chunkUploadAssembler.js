"use strict";

const fs = require("node:fs");
const path = require("node:path");

// Opening 2,000 Windows files one after another magnifies per-open AV and
// filesystem latency at the last HTTP request. Prefetch only file descriptors:
// the corresponding read streams remain sequential and bounded in memory.
const MAX_PENDING_OPENS = 16;

async function assembleChunkedUpload(sessionDir, destinationPath, totalChunks,
  { openPart = fs.promises.open } = {}) {
  if (!Number.isSafeInteger(totalChunks) || totalChunks < 1 || totalChunks > 2000
    || typeof openPart !== "function") throw new TypeError("Invalid chunk assembly");
  await fs.promises.mkdir(path.dirname(destinationPath), { recursive: true });
  // Claim the destination before doing anything else. If `wx` fails because
  // another assembled payload exists, cleanup must NEVER delete that file.
  const outputHandle = await fs.promises.open(destinationPath, "wx");
  let output;
  try {
    output = outputHandle.createWriteStream({ autoClose: true });
  } catch (error) {
    await outputHandle.close();
    await fs.promises.rm(destinationPath, { force: true });
    throw error;
  }
  let outputError = null;
  let activeInput = null;
  output.on("error", (error) => {
    outputError = error;
    activeInput?.destroy(error);
  });
  const queued = [];
  let nextPart = 0;
  let succeeded = false;

  const queueOpens = () => {
    while (queued.length < MAX_PENDING_OPENS && nextPart < totalChunks) {
      const filename = path.join(sessionDir, `${nextPart++}.part`);
      // Convert rejections to results immediately: a prefetched descriptor can
      // fail before its turn, and must never become an unhandled rejection.
      queued.push(Promise.resolve().then(async () => {
        // A filename checked earlier by the HTTP handler is not a trustable
        // descriptor: a local actor could replace a part while opens queue.
        // Pin the exact regular inode and byte length across this open.
        const before = await fs.promises.lstat(filename, { bigint: true });
        if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) {
          throw new Error("Unsafe chunk assembly input");
        }
        const flags = process.platform === "win32" ? "r"
          : fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW;
        const handle = await openPart(filename, flags);
        try {
          const stat = await handle.stat({ bigint: true });
          if (!stat.isFile() || stat.nlink !== 1n || stat.dev !== before.dev
            || stat.ino !== before.ino || stat.size !== before.size) {
            throw new Error("Unsafe chunk assembly input");
          }
          return { handle };
        } catch (error) {
          await handle.close();
          throw error;
        }
      }).catch((error) => ({ error })));
    }
  };

  try {
    queueOpens();
    for (let index = 0; index < totalChunks; index += 1) {
      const result = await queued.shift();
      if (result.error) throw result.error;
      const handle = result.handle;
      try {
        if (outputError) throw outputError;
        queueOpens();
        const input = handle.createReadStream({ autoClose: true });
        activeInput = input;
        await new Promise((resolve, reject) => {
          let reachedEnd = false;
          input.once("end", () => { reachedEnd = true; });
          input.once("error", reject);
          input.once("close", () => reachedEnd ? resolve()
            : reject(new Error("Chunk assembly input closed prematurely")));
          input.pipe(output, { end: false });
        });
        if (outputError) throw outputError;
      } finally {
        activeInput = null;
        await handle.close();
      }
    }
    await new Promise((resolve, reject) => {
      if (outputError) return reject(outputError);
      output.once("finish", resolve);
      output.once("error", reject);
      output.end();
    });
    succeeded = true;
  } finally {
    if (!succeeded) {
      activeInput?.destroy();
      output.destroy();
    }
    // Every future open is settled and closed, including an early failed part.
    const leftovers = await Promise.all(queued);
    await Promise.all(leftovers.map((result) => result.handle?.close()));
    await outputHandle.close();
    if (!succeeded) {
      if (!output.closed) await new Promise((resolve) => output.once("close", resolve));
      await fs.promises.rm(destinationPath, { force: true });
    }
  }
}

module.exports = { assembleChunkedUpload };
