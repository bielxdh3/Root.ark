"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

// Execute the actual production auditLog -> appendAuditLog -> archiveAuditLogs
// functions in a deterministic harness, without starting the full server or
// writing to a real account database.
const source = fs.readFileSync(path.join(__dirname, "../server.js"), "utf8");
const start = source.indexOf("function archiveAuditLogs(");
const end = source.indexOf("function addActionHistory(", start);
assert.ok(start >= 0 && end > start, "production audit functions must be present");

function fixture({ strictWriter = false, database = true, max = 2, now = Date.now(),
  seed = [], archiveFailure = false } = {}) {
  const events = seed.map((entry) => ({ ...entry }));
  const archived = [];
  const deferred = [];
  const legacyArchiveWrites = [];
  const writes = [];
  const repo = {
    withJsonAuditLock(callback) { return callback(); },
    deferIfStrictSyncWriter(log) {
      if (!strictWriter) return false;
      deferred.push(log);
      return true;
    },
    archiveAuditLogs(logs) {
      if (archiveFailure) throw Error("archive unavailable");
      archived.push(...logs);
    },
  };
  const context = vm.createContext({
    crypto: { randomUUID: () => "new-audit-id" },
    Date: class extends Date { constructor(value) { super(value === undefined ? now : value); }
      static now() { return now; } },
    AUDIT_EVENTS: {},
    AUDIT_RETENTION_MS: 1000,
    MAX_AUDIT_LOGS: max,
    AUDIT_LOGS_FILE: "audit.json",
    AUDIT_ARCHIVE_FILE: "archived.json",
    shouldUseDatabase: () => database,
    auditRepository: repo,
    broadcastDataChanged(source) { assert.equal(source, "audit"); },
    loadAuditLogs(file) {
      return file === "archived.json" ? { logs: legacyArchiveWrites.slice() }
        : { logs: events.slice() };
    },
    saveAuditLogs(value, file) {
      if (file) { legacyArchiveWrites.push(...value.logs); return; }
      if (strictWriter) throw Error("SYNC_ATOMIC_ACCOUNT_UNAVAILABLE: main account writer reserved");
      writes.push(value.logs.slice());
      events.splice(0, events.length, ...value.logs);
    },
    sanitizeAuditValue: (value) => value,
    console: { error() {} },
  });
  vm.runInContext(source.slice(start, end), context, { filename: "server.js/audit" });
  return { audit: context.auditLog, events, archived, deferred, legacyArchiveWrites, writes };
}

test("strict reserved sync writer defers failed login audit through durable repository without main DB write", () => {
  const state = fixture({ strictWriter: true });
  assert.equal(state.audit("auth.login.failed", { username: "anonymous" },
    { type: "auth", id: "login" }, "attempted", "failure", { reason: "invalid" }), "new-audit-id");
  assert.equal(state.deferred.length, 1);
  assert.equal(state.deferred[0].eventType, "auth.login.failed");
  assert.equal(state.writes.length, 0);
  assert.equal(state.legacyArchiveWrites.length, 0);
});

test("SQLite retention archives both aged and count-evicted events in durable sidecar", () => {
  const now = Date.parse("2026-11-02T00:00:00Z");
  const state = fixture({ now, seed: [
    { id: "old", timestamp: new Date(now - 3000).toISOString() },
    { id: "one", timestamp: new Date(now - 300).toISOString() },
    { id: "two", timestamp: new Date(now - 200).toISOString() },
  ] });
  state.audit("auth.login.failed", {}, null, "login", "failure");
  assert.deepEqual(state.archived.map((entry) => entry.id), ["old", "one"]);
  assert.deepEqual(state.writes[0].map((entry) => entry.id), ["two", "new-audit-id"]);
  assert.deepEqual(state.legacyArchiveWrites, [], "SQLite mode must not duplicate the JSON archive");
});

test("archive failure stops active-table retention before acknowledging a new audit", () => {
  const now = Date.parse("2026-11-02T00:00:00Z");
  const state = fixture({ now, archiveFailure: true, seed: [
    { id: "expired", timestamp: new Date(now - 3000).toISOString() },
  ] });
  assert.throws(() => state.audit("auth.login.failed", {}, null, "login", "failure"),
    /archive unavailable/);
  assert.equal(state.writes.length, 0);
});

test("legacy JSON mode retains its original count archive path", () => {
  const now = Date.parse("2026-11-02T00:00:00Z");
  const state = fixture({ now, database: false, max: 1, seed: [
    { id: "one", timestamp: new Date(now - 300).toISOString() },
  ] });
  state.audit("auth.login.failed", {}, null, "login", "failure");
  assert.equal(state.archived.length, 0);
  assert.deepEqual(state.legacyArchiveWrites.map((entry) => entry.id), ["one"]);
});
