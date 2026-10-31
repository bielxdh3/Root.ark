"use strict";

// DEV-OFF ZK10 transport boundary. A handler's Promise can resolve after
// writing headers but before a streamed HTTP body is finished. Releasing an
// external legacy lease at that point would permit a concurrent account
// cutover while bytes are still leaving the process.
const EGRESS_METHODS = Object.freeze(["write", "end", "writeHead", "flushHeaders",
  "writeContinue", "writeProcessing", "writeEarlyHints", "addTrailers", "uncork"]);

function createZk10HttpResponseLeaseGuard(res, signal, assertLeaseActive) {
  if (!res || typeof res.once !== "function" || typeof res.off !== "function"
    || typeof res.destroy !== "function" || !signal
    || typeof signal.addEventListener !== "function"
    || typeof signal.removeEventListener !== "function"
    || typeof assertLeaseActive !== "function") {
    throw new Error("ZK10_LEASE_UNAVAILABLE");
  }

  if (signal.aborted) {
    if (!res.writableFinished && !res.destroyed) {
      try { res.destroy(); } catch { /* still reject */ }
    }
    throw new Error("ZK10_LEASE_EXPIRED");
  }
  if (res.destroyed && !res.writableFinished) throw new Error("ZK10_RESPONSE_INTERRUPTED");

  if (res.writableFinished) return Object.freeze({
    waitForFinish: () => Promise.resolve(), disarm: () => {},
  });
  let settled = false;
  let resolveTerminal;
  let rejectTerminal;
  const terminal = new Promise((resolve, reject) => {
    resolveTerminal = resolve;
    rejectTerminal = reject;
  });
  // A stream may expire while its handler Promise is still pending and before
  // the owner callback starts awaiting terminal. Observe that early rejection
  // without swallowing it for the eventual caller.
  terminal.catch(() => {});
  const originals = [];
  const restoreEgress = () => {
    for (const [name, descriptor] of originals.reverse()) {
      if (descriptor) Object.defineProperty(res, name, descriptor);
      else delete res[name];
    }
    originals.length = 0;
  };
  const cleanup = () => {
    res.off("finish", onFinish);
    res.off("close", onClose);
    signal.removeEventListener("abort", onAbort);
    restoreEgress();
  };
  const settle = (error) => {
    if (settled) return;
    settled = true;
    cleanup();
    if (error) rejectTerminal(error);
    else resolveTerminal();
  };
  function onFinish() { settle(null); }
  function onClose() { settle(new Error("ZK10_RESPONSE_INTERRUPTED")); }
  function onAbort() {
    settle(new Error("ZK10_LEASE_EXPIRED"));
    // The stream guard MUST be armed BEFORE invoking the async handler. A
    // timed-out external lease destroys the data-plane while it is in flight.
    if (!res.writableFinished && !res.destroyed) {
      try { res.destroy(); } catch { /* reject even if destroy itself fails */ }
    }
  }

  // A timer is NOT a reliable time barrier if synchronous work delays the
  // event loop. Check the physical wall-clock deadline synchronously at each
  // normal ServerResponse egress method, including end() and flushHeaders().
  // This guards ordinary Express/stream.pipe(res) output, not arbitrary raw
  // socket writes or externally controlled host/storage infrastructure.
  try {
    for (const name of EGRESS_METHODS) {
      if (typeof res[name] !== "function") continue;
      const descriptor = Object.getOwnPropertyDescriptor(res, name);
      if (descriptor && descriptor.configurable === false)
        throw new Error("ZK10_UNGUARDABLE_HTTP_RESPONSE");
      const original = res[name];
      Object.defineProperty(res, name, { configurable: true, writable: true,
        value: function (...args) {
          try { assertLeaseActive(); }
          catch (error) {
            if (!res.destroyed) res.destroy();
            throw error;
          }
          return original.apply(this, args);
        },
      });
      originals.push([name, descriptor]);
    }
    assertLeaseActive();
  } catch (error) {
    restoreEgress();
    if (!res.destroyed && !res.writableFinished) res.destroy();
    throw error;
  }
  res.once("finish", onFinish);
  res.once("close", onClose);
  signal.addEventListener("abort", onAbort, { once: true });
  // Cover a finish, disconnect or abort racing listener registration.
  if (signal.aborted) onAbort();
  else if (res.writableFinished) onFinish();
  else if (res.destroyed) onClose();

  return Object.freeze({ waitForFinish: () => terminal, disarm: cleanup });
}

function waitForZk10HttpResponse(res, signal, assertLeaseActive) {
  let guard;
  try { guard = createZk10HttpResponseLeaseGuard(res, signal, assertLeaseActive); }
  catch (error) { return Promise.reject(error); }
  return guard.waitForFinish().finally(() => guard.disarm());
}

module.exports = { waitForZk10HttpResponse, createZk10HttpResponseLeaseGuard };
