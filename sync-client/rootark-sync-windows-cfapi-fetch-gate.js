"use strict";

// Deliberately non-hydrating bridge for an eventual CF_CALLBACK_TYPE_FETCH_DATA
// handler. Current signed sync inventory is advisory and SyncEngine._apply()
// writes ordinary paths: neither can authorize CF_OPERATION_TYPE_TRANSFER_DATA.
// An actual CFAPI provider must supply its own durable independent object/CAS
// proof, pinned placeholder identity, and handle-relative race protection.
// Until that design exists this gate always reports failure to its native
// boundary. It never opens contents, resolves a CEK, or creates a sync root.

const fs = require("node:fs/promises");
const path = require("node:path");
const { validatePortableRelativePath } = require("./rootark-sync-paths");

const ALLOWED = ["length", "offset", "placeholderId", "relativePath", "requestKey", "type"];
const ID = /^[A-Za-z0-9._:-]{1,160}$/;
const MAX_RANGE = 1024 * 1024;
const MAX_SEEN_REQUEST_KEYS = 4096;

function boundedOption(value, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw Object.assign(new Error("Invalid bounded CFAPI callback option"),
      { code: "invalid_cfapi_boundary" });
  }
  return value;
}

function trustedValue(value, props) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const desc = Object.getOwnPropertyDescriptors(value);
  return Object.keys(desc).sort().join(",") === props.slice().sort().join(",")
    && Object.values(desc).every((entry) => Object.hasOwn(entry, "value"));
}

function validateRequest(raw) {
  if (!trustedValue(raw, ALLOWED)) return null;
  const input = Object.fromEntries(ALLOWED.map((key) => [key, raw[key]]));
  if (input.type !== "FETCH_DATA"
    || typeof input.requestKey !== "string" || !ID.test(input.requestKey)
    || typeof input.placeholderId !== "string" || !ID.test(input.placeholderId)
    || !Number.isSafeInteger(input.offset) || input.offset < 0
    || !Number.isSafeInteger(input.length) || input.length < 1 || input.length > MAX_RANGE
    || input.offset > Number.MAX_SAFE_INTEGER - input.length
    || typeof input.relativePath !== "string") return null;
  try { validatePortableRelativePath(input.relativePath); }
  catch { return null; }
  return Object.freeze(input);
}

async function inspectNoLink(rootDir, relativePath) {
  const root = await fs.lstat(rootDir);
  if (!root.isDirectory() || root.isSymbolicLink()) return false;
  let current = rootDir;
  const segments = relativePath.split("/");
  for (let i = 0; i < segments.length; i++) {
    // Win32 can open case-folded names and short DOS aliases. A callback
    // identity must match the exact on-disk segment before any native query.
    let entries;
    try { entries = await fs.readdir(current); }
    catch { return false; }
    if (!entries.includes(segments[i])) return false;
    current = path.join(current, segments[i]);
    let stat;
    try { stat = await fs.lstat(current); }
    catch { return false; }
    if (stat.isSymbolicLink()) return false;
    if (i < segments.length - 1 && !stat.isDirectory()) return false;
    // POSIX directory nlink values naturally exceed one; only file hardlinks
    // are rejected as ambiguous physical identities.
    if (i === segments.length - 1 && (!stat.isFile() || stat.nlink > 1)) return false;
  }
  // This check is advisory; it is not a race-safe native HANDLE identity pin.
  return true;
}

function createCfapiFetchGate({ rootDir, native, inspectionTimeoutMs = 1500,
  ackTimeoutMs = 250, maxInFlight = 32,
  maxLifetimeRequests = MAX_SEEN_REQUEST_KEYS } = {}) {
  if (typeof rootDir !== "string" || !path.isAbsolute(rootDir) || !native
    || typeof native.inspectPlaceholder !== "function"
    || typeof native.failFetch !== "function") {
    throw Object.assign(new Error("CFAPI fail-closed callback boundary is required"),
      { code: "invalid_cfapi_boundary" });
  }
  boundedOption(inspectionTimeoutMs, 5, 30000);
  boundedOption(ackTimeoutMs, 5, 10000);
  boundedOption(maxInFlight, 1, 64);
  boundedOption(maxLifetimeRequests, 1, MAX_SEEN_REQUEST_KEYS);
  const root = path.resolve(rootDir);
  const inFlight = new Map();
  // An abandoned path scan OR native inspection may never settle. Keep its
  // promise in the inspection budget until it really settles, including after
  // the JS request has timed out or returned its failure ACK.
  const inspections = new Set();
  // A requestKey is connection-scoped. Do not replay an indeterminate failure
  // ACK after timeout; the finite receipt budget also bounds memory growth.
  const seenKeys = new Set();
  let stopping = false;

  function interrupt(context, reason) {
    if (context.reason) return false;
    context.reason = reason;
    context.controller.abort();
    context.resolveInterrupt(reason);
    return true;
  }

  function cancelFetch(key) {
    const active = inFlight.get(key);
    if (!active) return false;
    return interrupt(active, "cancelled");
  }

  async function inspect(context, raw) {
    try {
      const input = validateRequest(raw);
      if (!input) return "invalid_callback";
      if (context.reason) return context.reason;
      if (!await inspectNoLink(root, input.relativePath)) return "unsafe_path";
      if (context.reason) return context.reason;
      // The second argument is optional for legacy mocks, but a cooperating
      // native boundary can abort its work when the signal becomes aborted.
      const actual = await native.inspectPlaceholder(input.relativePath,
        { signal: context.controller.signal });
      if (context.reason) return context.reason;
      return trustedValue(actual, ["placeholder", "reparsePoint", "syncRootMatch"])
        && actual.placeholder === true && actual.syncRootMatch === true
        && actual.reparsePoint === true ? "authority_unavailable" : "placeholder_untrusted";
    } catch {
      return context.reason || "unsafe_path";
    }
  }

  function boundedInspect(context, raw) {
    if (inspections.size >= maxInFlight) return Promise.resolve("inspector_capacity_exceeded");
    const pending = inspect(context, raw);
    inspections.add(pending);
    // Late fulfillment/rejection only frees the occupied slot. It cannot
    // execute a second failure ACK or authorize the cancelled request.
    void pending.then(() => inspections.delete(pending),
      () => inspections.delete(pending));
    return pending;
  }

  async function failOnce(key, code) {
    // At most one native failure completion is attempted. If an adapter never
    // acknowledges it, abort the advisory signal, report indeterminate ACK,
    // and release the JS shutdown gate without retrying the request key.
    const controller = new AbortController();
    let timer;
    const timedOut = new Promise((resolve) => {
      timer = setTimeout(() => {
        controller.abort();
        resolve(true);
      }, ackTimeoutMs);
    });
    try {
      const ack = Promise.resolve().then(() => native.failFetch(key, code,
        { signal: controller.signal })).then(() => false);
      return await Promise.race([ack, timedOut])
        ? { status: "denied", code: "failure_ack_timeout" }
        : { status: "denied", code };
    } finally { clearTimeout(timer); }
  }

  async function fetchData(raw) {
    // Keep a bounded opaque callback key for reporting a failure. Never pass
    // an invalid path or untrusted raw request back into the native runtime.
    let key = null;
    try {
      const desc = raw && typeof raw === "object"
        ? Object.getOwnPropertyDescriptor(raw, "requestKey") : null;
      if (desc && Object.hasOwn(desc, "value")
        && typeof desc.value === "string" && ID.test(desc.value)) key = desc.value;
    } catch { /* A throwing Proxy cannot establish a callback identity. */ }
    if (!key) return { status: "denied", code: "invalid_callback" };
    if (stopping) return { status: "denied", code: "shutdown" };
    if (seenKeys.has(key)) return { status: "denied", code: "duplicate_request" };
    // Overflow requests are not admitted: the native dispatcher must reject
    // them on its own boundary, including their CFAPI failure completion.
    if (inFlight.size >= maxInFlight || seenKeys.size >= maxLifetimeRequests) {
      if (seenKeys.size >= maxLifetimeRequests) stopping = true;
      return { status: "denied", code: "capacity_exceeded" };
    }
    let resolveInterrupt;
    const interrupted = new Promise((resolve) => { resolveInterrupt = resolve; });
    const context = { reason: null, controller: new AbortController(),
      resolveInterrupt, interrupted, promise: null };
    seenKeys.add(key);
    inFlight.set(key, context);
    const work = (async () => {
      const timer = setTimeout(() => interrupt(context, "inspection_timeout"), inspectionTimeoutMs);
      let code;
      try {
        code = await Promise.race([boundedInspect(context, raw), interrupted]);
      } finally { clearTimeout(timer); }
      code = context.reason || code;
      // A local journal or the caller's claim of a signed receipt is not an
      // independently pinned authority. Never call native.transferData.
      return failOnce(key, code);
    })();
    context.promise = work;
    try { return await work; }
    finally { inFlight.delete(key); }
  }

  async function shutdown() {
    stopping = true;
    for (const active of inFlight.values()) interrupt(active, "shutdown");
    // Each admitted request has a bounded ACK. Do not await noncooperative
    // native inspections: those stay charged to the native inspection budget.
    await Promise.allSettled([...inFlight.values()].map((item) => item.promise));
  }

  return Object.freeze({ fetchData, cancelFetch, shutdown });
}

module.exports = { createCfapiFetchGate };
