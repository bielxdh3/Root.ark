"use strict";

// One absolute monotonic deadline for all opaque provider reads in a restore.
// There is deliberately NO Promise.race: an adapter which ignores AbortSignal
// holds its caller (and the signed witness admission) until it actually settles.
// A socket watchdog may terminate the HTTP response, but cannot claim STOP.
const { performance } = require("node:perf_hooks");

const DEFAULT_PROVIDER_DEADLINE_MS = 15000;
const issued = new WeakSet();
function unavailable() {
  const error = new Error("ZK_PROVIDER_DEADLINE_EXCEEDED");
  error.code = error.message;
  return error;
}
function validDeadlineMs(value) {
  if (!Number.isSafeInteger(value) || value < 50 || value > 120000) throw unavailable();
  return value;
}
function createZk1ProviderDeadline({ deadlineMs = DEFAULT_PROVIDER_DEADLINE_MS,
  parentSignal } = {}) {
  validDeadlineMs(deadlineMs);
  if (parentSignal !== undefined && !(parentSignal instanceof AbortSignal)) throw unavailable();
  const end = performance.now() + deadlineMs;
  const controller = new AbortController();
  const cancel = () => controller.abort();
  if (parentSignal) {
    if (parentSignal.aborted) cancel();
    else parentSignal.addEventListener("abort", cancel, { once: true });
  }
  const timer = setTimeout(cancel, deadlineMs);
  const deadline = Object.freeze({
    signal: controller.signal,
    assertActive() {
      if (controller.signal.aborted || performance.now() >= end) {
        cancel();
        throw unavailable();
      }
    },
    async run(operation) {
      if (typeof operation !== "function") throw unavailable();
      this.assertActive();
      // Await actual adapter completion even after the deadline. A noncooperative
      // adapter must never allow early witness finish or deletion of its staging.
      const result = await operation(controller.signal);
      this.assertActive();
      return result;
    },
    close() {
      clearTimeout(timer);
      if (parentSignal) parentSignal.removeEventListener("abort", cancel);
    },
  });
  issued.add(deadline);
  return deadline;
}

module.exports = { createZk1ProviderDeadline, validDeadlineMs,
  DEFAULT_PROVIDER_DEADLINE_MS,
  isZk1ProviderDeadline: (value) => issued.has(value) };
