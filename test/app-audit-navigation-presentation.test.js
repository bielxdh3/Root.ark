"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");

const source = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-management.js"), "utf8");

const flush = () => new Promise(setImmediate);
const page = (number, label, total = 120) => ({
  page: number, limit: 50, total,
  logs: label ? [{ eventType: label, severity: "info", result: "success" }] : [],
});

function element() {
  return {
    innerHTML: "", textContent: "", hidden: false, disabled: false,
    listeners: {},
    addEventListener(type, handler) { this.listeners[type] = handler; },
    setAttribute() {},
  };
}

async function fixture() {
  const nodes = Object.fromEntries([
    "audit-body", "audit-page-info", "audit-filter-form", "audit-filter-feedback",
    "audit-export", "audit-total", "audit-critical", "audit-failed-logins",
  ].map(id => [id, element()]));
  const previous = element(), next = element(), refresh = element();
  const target = element();
  target.querySelector = selector => {
    if (selector === '[data-action="audit-previous"]') return previous;
    if (selector === '[data-action="audit-next"]') return next;
    assert.fail("Unexpected fixture selector: " + selector);
  };
  const requests = [], summaries = [];
  let refreshSummary;
  const api = {
    query(route, values) { return { route, values }; },
    get(request) {
      if (request === "/audit/summary") {
        if (!summaries.length) {
          summaries.push({});
          return Promise.resolve({ totalLogs: 120, bySeverity: { critical: 0 }, failedLogins: 0 });
        }
        return new Promise((resolve, reject) => summaries.push({ resolve, reject }));
      }
      assert.equal(request.route, "/audit/logs");
      if (!requests.length) {
        requests.push({ values: request.values });
        return Promise.resolve(page(1, "Initial fixture"));
      }
      return new Promise((resolve, reject) => requests.push({ values: request.values, resolve, reject }));
    },
  };
  const window = {
    RootarkApi: api,
    RootarkUI: { escape: String, formatDate: () => "Fixture date" },
    setInterval: callback => { refreshSummary = callback; return 1; },
    addEventListener() {},
  };
  const document = {
    body: { dataset: { rootarkView: "audit" } },
    getElementById(id) {
      assert.ok(nodes[id], "Unexpected fixture element: " + id);
      return nodes[id];
    },
  };
  class FormData {
    constructor(form) { this.values = form.values; }
    get(name) { return this.values[name] || ""; }
  }
  const entry = source.lastIndexOf("  start().catch(");
  assert.ok(entry >= 0, "Expected startup entry");
  await vm.runInNewContext(source.slice(0, entry) + "  return initAudit(fixtureUser, fixtureTarget);\n})();", {
    window, document, FormData, fixtureUser: { role: "admin" }, fixtureTarget: target,
  });
  function click(action, button) {
    button.dataset = { action };
    target.listeners.click({ target: { closest: () => button } });
  }
  function filter(eventType) {
    nodes["audit-filter-form"].listeners.submit({
      preventDefault() {},
      currentTarget: { values: { eventType } },
    });
  }
  return {
    requests, summaries, previous, next, refresh, filter,
    refreshSummary: () => refreshSummary(),
    summaryTotal: nodes["audit-total"],
    summaryCritical: nodes["audit-critical"],
    summaryFailed: nodes["audit-failed-logins"],
    feedback: nodes["audit-filter-feedback"],
    goNext: () => click("audit-next", next),
    goPrevious: () => click("audit-previous", previous),
    reload: () => click("refresh-audit", refresh),
    body: nodes["audit-body"], info: nodes["audit-page-info"],
  };
}

test("pagination reflects the displayed page and disables navigation while loading", async () => {
  const f = await fixture();
  assert.equal(f.info.textContent, "Página 1 de 3");
  assert.equal(f.previous.disabled, true);
  assert.equal(f.next.disabled, false);
  f.goNext();
  assert.equal(f.info.textContent, "Carregando registros…");
  assert.equal(f.previous.disabled, true);
  assert.equal(f.next.disabled, true);
  f.goNext();
  assert.equal(f.requests.length, 2);
  assert.equal(f.requests[1].values.page, 2);
  f.requests[1].resolve(page(2, "Page two"));
  await flush();
  assert.equal(f.info.textContent, "Página 2 de 3");
  assert.match(f.body.innerHTML, /Page two/);
  assert.equal(f.previous.disabled, false);
  assert.equal(f.next.disabled, false);
});

test("switching filters resets pagination and displays only the latest selection", async () => {
  const f = await fixture();
  f.goNext();
  f.filter("fixture.new");
  assert.equal(f.requests[2].values.page, 1);
  assert.equal(f.requests[2].values.eventType, "fixture.new");
  f.requests[2].resolve(page(1, "New filter", 1));
  await flush();
  const displayed = f.body.innerHTML;
  assert.match(displayed, /New filter/);
  f.requests[1].resolve(page(2, "Previous page"));
  await flush();
  assert.equal(f.body.innerHTML, displayed);
  assert.equal(f.info.textContent, "Página 1 de 1");
  assert.equal(f.previous.disabled, true);
  assert.equal(f.next.disabled, true);
});

test("a completed filter result stays displayed after an earlier request fails", async () => {
  const f = await fixture();
  f.filter("fixture.old");
  f.filter("fixture.current");
  f.requests[2].resolve(page(1, "Current selection", 1));
  await flush();
  const displayed = f.body.innerHTML;
  f.requests[1].reject(Object.assign(new Error("Fixture failure"), { status: 500 }));
  await flush();
  assert.equal(f.body.innerHTML, displayed);
  assert.equal(f.info.textContent, "Página 1 de 1");
});

test("a failed page shows unavailable state and refresh retries the selected page", async () => {
  const f = await fixture();
  f.goNext();
  f.requests[1].reject(Object.assign(new Error("Fixture failure"), { status: 500 }));
  await flush();
  assert.equal(f.info.textContent, "Registros indisponíveis");
  assert.match(f.body.innerHTML, /Não foi possível carregar os registros de auditoria/);
  assert.equal(f.previous.disabled, true);
  assert.equal(f.next.disabled, true);
  f.reload();
  assert.equal(f.refresh.disabled, true);
  assert.equal(f.requests[2].values.page, 2);
  f.requests[2].resolve(page(2, "Retried page"));
  f.summaries[1].resolve({ totalLogs: 120, bySeverity: { critical: 0 }, failedLogins: 0 });
  await flush();
  assert.equal(f.refresh.disabled, false);
  assert.match(f.body.innerHTML, /Retried page/);
  assert.equal(f.info.textContent, "Página 2 de 3");
  assert.equal(f.previous.disabled, false);
});

test("an empty filtered result restores a consistent empty state", async () => {
  const f = await fixture();
  f.filter("fixture.empty");
  f.requests[1].resolve(page(1, "", 0));
  await flush();
  assert.match(f.body.innerHTML, /Nenhum registro encontrado/);
  assert.equal(f.info.textContent, "Página 1 de 1");
  assert.equal(f.previous.disabled, true);
  assert.equal(f.next.disabled, true);
});

test("audit summary retains the latest counts when an earlier refresh resolves later", async () => {
  const f = await fixture();
  const earlier = f.refreshSummary();
  const later = f.refreshSummary();
  f.summaries[2].resolve({ totalLogs: 21, bySeverity: { critical: 7 }, failedLogins: 3 });
  await later;
  const latest = [f.summaryTotal.textContent, f.summaryCritical.textContent, f.summaryFailed.textContent];
  assert.deepEqual(latest, ["21", "7", "3"]);
  f.summaries[1].resolve({ totalLogs: 11, bySeverity: { critical: 2 }, failedLogins: 1 });
  await earlier;
  assert.deepEqual([f.summaryTotal.textContent, f.summaryCritical.textContent, f.summaryFailed.textContent], latest);
});

test("an earlier summary failure does not replace feedback after a current refresh succeeds", async () => {
  const f = await fixture();
  const earlier = f.refreshSummary();
  const later = f.refreshSummary();
  f.summaries[2].resolve({ totalLogs: 21, bySeverity: { critical: 0 }, failedLogins: 0 });
  await later;
  const feedback = f.feedback.textContent;
  f.summaries[1].reject(Object.assign(new Error("Fixture failure"), { status: 500 }));
  await earlier;
  assert.equal(f.feedback.textContent, feedback);
  assert.equal(f.summaryTotal.textContent, "21");
});
