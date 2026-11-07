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

function createCfapiFetchGate({ rootDir, native } = {}) {
  if (typeof rootDir !== "string" || !path.isAbsolute(rootDir) || !native
    || typeof native.inspectPlaceholder !== "function"
    || typeof native.failFetch !== "function") {
    throw Object.assign(new Error("CFAPI fail-closed callback boundary is required"),
      { code: "invalid_cfapi_boundary" });
  }
  const root = path.resolve(rootDir);
  const inFlight = new Map();
  let stopping = false;

  function cancelFetch(key) {
    const active = inFlight.get(key);
    if (!active) return false;
    active.cancelled = true;
    return true;
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
    if (inFlight.has(key)) return { status: "denied", code: "duplicate_request" };
    const context = { cancelled: false, promise: null };
    inFlight.set(key, context);
    const work = (async () => {
      let code = "authority_unavailable";
      try {
        const input = validateRequest(raw);
        if (!input) code = "invalid_callback";
        else if (stopping || context.cancelled) code = stopping ? "shutdown" : "cancelled";
        else if (!await inspectNoLink(root, input.relativePath)) code = "unsafe_path";
        else if (stopping || context.cancelled) code = stopping ? "shutdown" : "cancelled";
        else {
          const actual = await native.inspectPlaceholder(input.relativePath);
          if (stopping || context.cancelled) code = stopping ? "shutdown" : "cancelled";
          else if (!trustedValue(actual, ["placeholder", "reparsePoint", "syncRootMatch"])
            || actual.placeholder !== true || actual.syncRootMatch !== true
            || actual.reparsePoint !== true) code = "placeholder_untrusted";
        }
      } catch { code = "unsafe_path"; }
      // A local journal or the caller's claim of a signed receipt is not an
      // independently pinned authority. Never call native.transferData.
      await native.failFetch(key, code);
      return { status: "denied", code };
    })();
    context.promise = work;
    try { return await work; }
    finally { inFlight.delete(key); }
  }

  async function shutdown() {
    stopping = true;
    // No new callback may start while outstanding failure ACKs drain.
    await Promise.allSettled([...inFlight.values()].map((item) => item.promise));
  }

  return Object.freeze({ fetchData, cancelFetch, shutdown });
}

module.exports = { createCfapiFetchGate };
