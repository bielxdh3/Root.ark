"use strict";

const { performance } = require("node:perf_hooks");
const { setTimeout: delay } = require("node:timers/promises");

async function waitForBrowserValue(read, ms = 23000) {
  const deadline = performance.now() + ms;
  let expired = false;
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      expired = true;
      reject(Error("EDGE_LOCAL_TIMEOUT"));
    }, ms);
  });
  const poll = async () => {
    while (!expired && performance.now() < deadline) {
      const value = await read();
      if (expired || performance.now() >= deadline) break;
      if (value) return value;
      await delay(Math.min(90, Math.max(0, deadline - performance.now())));
    }
    throw Error("EDGE_LOCAL_TIMEOUT");
  };
  try {
    return await Promise.race([poll(), timeout]);
  } finally {
    expired = true;
    clearTimeout(timer);
  }
}

module.exports = { waitForBrowserValue };
