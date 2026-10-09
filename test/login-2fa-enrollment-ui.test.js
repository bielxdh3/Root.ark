"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");

function createElement(id, document) {
  return {
    id,
    hidden: false,
    textContent: "",
    value: "",
    dataset: {},
    listeners: {},
    attributes: {},
    addEventListener(type, listener) { this.listeners[type] = listener; },
    focus() { document.activeElement = this; },
    select() { this.selected = true; },
    removeAttribute(name) { delete this.attributes[name]; },
  };
}

test("2FA enrollment asks for a new login after the server revokes the setup session", async () => {
  const document = { activeElement: null, elements: new Map() };
  const formIds = ["login-form", "totp-form", "enroll-form"];
  const ids = [
    ...formIds,
    "auth-error", "login-title", "login-intro", "login-eyebrow", "login-submit",
    "username", "password", "totp-code", "enroll-code", "enroll-secret", "enroll-qr",
    "back-to-login", "cancel-enroll", "recovery-step", "recovery-step-title", "recovery-codes",
    "continue-after-enroll",
  ];
  ids.forEach((id) => document.elements.set(id, createElement(id, document)));
  document.elements.get("recovery-step").hidden = true;
  const submitButtons = new Map([
    ["login-form", document.elements.get("login-submit")],
    ["totp-form", createElement("totp-submit", document)],
    ["enroll-form", createElement("enroll-submit", document)],
  ]);
  for (const id of formIds) {
    const form = document.elements.get(id);
    form.values = {};
    form.querySelector = (selector) => selector === 'button[type="submit"]' ? submitButtons.get(id) : null;
    form.reset = () => { form.values = {}; };
  }
  document.getElementById = (id) => document.elements.get(id);

  const location = { search: "", origin: "http://localhost", assigned: [], assign(value) { this.assigned.push(value); } };
  let resolveEnrollmentStarted;
  let resolveEnrollmentResponse;
  const enrollmentStarted = new Promise((resolve) => { resolveEnrollmentStarted = resolve; });
  const window = {
    RootarkApi: {
      async get() { throw new Error("anonymous"); },
      async post(route) {
        if (route === "/auth/login") {
          throw Object.assign(new Error("Enrollment required"), {
            status: 403,
            payload: { enrollmentRequired: true, token: "disposable-enrollment-token" },
          });
        }
        if (route === "/auth/2fa/enroll") {
          return new Promise((resolve) => {
            resolveEnrollmentResponse = resolve;
            resolveEnrollmentStarted();
          });
        }
        if (route === "/auth/2fa/confirm") {
          return { enabled: true, loginRequired: true, recoveryCodes: ["fixture-code", "second-fixture-code"] };
        }
        throw new Error(`Unexpected route: ${route}`);
      },
    },
    location,
    localStorage: { getItem() { return null; } },
  };
  class FormDataFixture {
    constructor(form) { this.form = form; }
    get(name) { return this.form.values[name] ?? null; }
  }
  const source = fs.readFileSync(path.join(__dirname, "../public/client/rootark-login.js"), "utf8");
  vm.runInNewContext(source, { document, window, FormData: FormDataFixture, URL, URLSearchParams });
  await new Promise((resolve) => setImmediate(resolve));

  const loginForm = document.getElementById("login-form");
  loginForm.values = { username: "admin", password: "test-only" };
  document.getElementById("username").value = "admin";
  document.getElementById("password").value = "test-only";
  const loginSubmission = loginForm.listeners.submit({ preventDefault() {} });
  await enrollmentStarted;
  assert.equal(document.getElementById("username").value, "admin", "the username can remain available for the enrollment flow");
  assert.equal(document.getElementById("password").value, "", "the password must be cleared before enrollment setup finishes");
  resolveEnrollmentResponse({ secret: "JBSWY3DPEHPK3PXP", qrCode: "data:image/png;base64,fixture" });
  await loginSubmission;
  const enrollForm = document.getElementById("enroll-form");
  assert.equal(enrollForm.hidden, false, "the login flow should show the enrollment form");
  assert.equal(document.getElementById("username").value, "admin", "the username can remain available for the enrollment flow");
  assert.equal(document.getElementById("password").value, "", "the password must be cleared as soon as enrollment is required");
  enrollForm.values = { code: "123456" };

  await enrollForm.listeners.submit({ preventDefault() {} });

  const recoveryStep = document.getElementById("recovery-step");
  assert.equal(recoveryStep.hidden, false, "one-time recovery codes must be shown after enrollment");
  assert.equal(document.activeElement && document.activeElement.id, "recovery-step-title", "focus must move to the recovery-step heading");
  assert.match(document.getElementById("recovery-codes").value, /fixture-code[\s\S]*second-fixture-code/);
  assert.deepEqual(location.assigned, [], "the revoked setup session must not navigate to the app");
  assert.equal(enrollForm.hidden, true, "the setup secret should leave the active view");

  await document.getElementById("continue-after-enroll").listeners.click();

  assert.equal(recoveryStep.hidden, true, "recovery codes should leave the active view after acknowledgement");
  assert.equal(document.getElementById("recovery-codes").value, "", "recovery codes should be cleared after leaving the one-time view");
  assert.equal(loginForm.hidden, false, "the user must be returned to the login form");
  assert.match(document.getElementById("login-intro").textContent, /entre novamente/i);
  assert.equal(document.getElementById("username").value, "admin", "the non-secret username can remain available");
  assert.equal(document.getElementById("password").value, "", "the old password must be cleared before a fresh login");
  assert.equal(document.activeElement && document.activeElement.id, "password", "focus must move to the password field for the fresh login");
  assert.deepEqual(location.assigned, []);
});

test("failed 2FA enrollment keeps the setup error visible", async () => {
  const document = { activeElement: null, elements: new Map() };
  const formIds = ["login-form", "totp-form", "enroll-form"];
  const ids = [
    ...formIds,
    "auth-error", "login-title", "login-intro", "login-eyebrow", "login-submit",
    "username", "password", "totp-code", "enroll-code", "enroll-secret", "enroll-qr",
    "back-to-login", "cancel-enroll", "recovery-step", "recovery-step-title", "recovery-codes",
    "continue-after-enroll",
  ];
  ids.forEach((id) => document.elements.set(id, createElement(id, document)));
  const submitButtons = new Map([ ["login-form", document.elements.get("login-submit")] ]);
  for (const id of formIds) {
    const form = document.elements.get(id);
    form.values = {};
    form.querySelector = (selector) => selector === 'button[type="submit"]' ? submitButtons.get(id) : null;
    form.reset = () => { form.values = {}; };
  }
  document.getElementById = (id) => document.elements.get(id);
  const window = {
    RootarkApi: {
      async get() { throw new Error("anonymous"); },
      async post(route) {
        if (route === "/auth/login") {
          throw Object.assign(new Error("Enrollment required"), {
            status: 403,
            payload: { enrollmentRequired: true, token: "disposable-enrollment-token" },
          });
        }
        if (route === "/auth/2fa/enroll") throw Object.assign(new Error("TOTP unavailable"), { status: 503 });
        throw new Error(`Unexpected route: ${route}`);
      },
    },
    location: { search: "", origin: "http://localhost", assigned: [], assign(value) { this.assigned.push(value); } },
    localStorage: { getItem() { return null; } },
  };
  class FormDataFixture {
    constructor(form) { this.form = form; }
    get(name) { return this.form.values[name] ?? null; }
  }
  const source = fs.readFileSync(path.join(__dirname, "../public/client/rootark-login.js"), "utf8");
  vm.runInNewContext(source, { document, window, FormData: FormDataFixture, URL, URLSearchParams });
  await new Promise((resolve) => setImmediate(resolve));

  const loginForm = document.getElementById("login-form");
  loginForm.values = { username: "admin", password: "test-only" };
  document.getElementById("username").value = "admin";
  document.getElementById("password").value = "test-only";
  await loginForm.listeners.submit({ preventDefault() {} });

  assert.equal(loginForm.hidden, false);
  assert.equal(document.getElementById("password").value, "");
  assert.equal(document.getElementById("auth-error").textContent, "TOTP unavailable");
});
