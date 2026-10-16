const assert = require("node:assert/strict");
const test = require("node:test");
const registerAuditRoutes = require("../src/routes/audit");

test("audit export is a CSRF-protected POST and legacy GET cannot record an event", async () => {
  const getRoutes = new Map();
  const postRoutes = new Map();
  const events = [];
  const middlewareCalls = [];
  const actor = { username: "admin", role: "admin", ip: "198.51.100.9" };
  const app = {
    get(route, ...handlers) { getRoutes.set(route, handlers); },
    post(route, ...handlers) { postRoutes.set(route, handlers); },
  };
  registerAuditRoutes(app, {
    auditLog(...event) { events.push(event); },
    authenticate(_req, _res, next) { middlewareCalls.push("authenticate"); return next(); },
    convertAuditLogsToCSV(logs) { return `csv:${logs.length}`; },
    countBy: () => ({}),
    findSuspiciousIPs: () => [],
    getAuditActor: () => actor,
    getFilteredAuditLogs: () => [{ id: "fixture-event" }],
    loadAuditLogs: () => ({ logs: [] }),
    requireAuditAccess(_req, _res, next) { middlewareCalls.push("requireAuditAccess"); return next(); },
  });

  const run = async (handlers, req) => {
    const res = {
      headers: {},
      body: undefined,
      statusCode: 200,
      setHeader(name, value) { this.headers[name.toLowerCase()] = String(value); return this; },
      status(code) { this.statusCode = code; return this; },
      send(body) { this.body = body; return this; },
      json(body) { this.body = body; return this; },
    };
    let cursor = 0;
    const next = async () => {
      const handler = handlers[cursor++];
      if (handler) return handler(req, res, next);
    };
    await next();
    return res;
  };

  const legacyGet = await run(getRoutes.get("/audit/export"), {
    query: { format: "csv" }, user: actor, headers: {}, method: "GET", path: "/audit/export",
  });
  assert.equal(legacyGet.statusCode, 405);
  assert.equal(legacyGet.headers.allow, "POST");
  assert.deepEqual(events, [], "legacy GET cannot mutate the audit log");

  const response = await run(postRoutes.get("/audit/export"), {
    query: { format: "csv" }, user: actor, headers: {}, method: "POST", path: "/audit/export",
  });

  assert.deepEqual(middlewareCalls, ["authenticate", "requireAuditAccess", "authenticate", "requireAuditAccess"]);
  assert.deepEqual(events, [[
    "audit.exported",
    actor,
    { type: "audit", id: "export" },
    "exported",
    "success",
    { format: "csv", count: 1 },
  ]]);
  assert.equal(response.headers["content-type"], "text/csv; charset=utf-8");
  assert.equal(response.headers["content-disposition"], "attachment; filename=audit-logs.csv");
  assert.equal(response.body, "csv:1");
});
