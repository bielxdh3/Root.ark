"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const express = require("express");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");

const clientCrypto = require("../public/client/rootark-client-crypto");
const protectedIndex = require("../public/client/rootark-protected-index");
const protectedPreview = require("../public/client/rootark-protected-preview");
const protectedSession = require("../public/client/rootark-protected-session");
const syncAdapter = require("../public/client/rootark-sync-adapter");
const offlineQueue = require("../public/client/rootark-offline-queue");
const protocol = require("../sync-client/rootark-sync-protocol");
const { GroupKeySharing } = require("../src/services/groupKeySharing");
const { AtomicGroupsStore, isGroupMember, MAX_MEMBERS, registerGroupRoutes } = require("../src/routes/groups");

function request(port, requestPath, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, ...options }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
    });
    req.once("error", reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

function json(value) {
  return Buffer.from(JSON.stringify(value));
}

test("shared dialog close restores focus to its connected opener", async () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-ui.js"), "utf8");
  const listeners = new Map();
  const opener = { isConnected: true, focus() { document.activeElement = this; } };
  const cancelButton = { focus() { document.activeElement = this; }, addEventListener() {} };
  const form = { addEventListener() {} };
  const dialog = {
    returnValue: "",
    addEventListener(name, listener) { listeners.set(name, listener); },
    removeEventListener(name) { listeners.delete(name); },
    querySelector(selector) { return selector === "form" ? form : cancelButton; },
    querySelectorAll() { return [cancelButton]; },
    showModal() { document.activeElement = this; },
    close(value) {
      this.returnValue = value;
      document.activeElement = this;
      const listener = listeners.get("close");
      listeners.delete("close");
      listener();
    },
  };
  const document = {
    activeElement: opener,
    documentElement: { dataset: {} },
    addEventListener() {},
    removeEventListener() {},
    getElementById(id) { return id === "app-dialog" ? dialog : null; },
  };
  const context = {
    document,
    localStorage: { getItem() { return null; } },
    window: { addEventListener() {}, setTimeout },
    FormData: function FormData() {},
  };
  vm.runInNewContext(source, context);

  const pending = context.window.RootarkUI.dialog({ title: "Compartilhar arquivo" });
  dialog.close("cancel");
  assert.equal(await pending, null);
  assert.equal(document.activeElement, opener);
});

test("shared dialog close moves focus to the main region when its opener is removed", async () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-ui.js"), "utf8");
  const listeners = new Map();
  const opener = { isConnected: true, focus() { document.activeElement = this; } };
  const main = { isConnected: true, focus() { document.activeElement = this; } };
  const cancelButton = { focus() { document.activeElement = this; }, addEventListener() {} };
  const form = { addEventListener() {} };
  const dialog = {
    returnValue: "",
    addEventListener(name, listener) { listeners.set(name, listener); },
    removeEventListener(name) { listeners.delete(name); },
    querySelector(selector) { return selector === "form" ? form : cancelButton; },
    querySelectorAll() { return [cancelButton]; },
    showModal() { document.activeElement = this; },
    close(value) {
      this.returnValue = value;
      document.activeElement = this;
      const listener = listeners.get("close");
      listeners.delete("close");
      listener();
    },
  };
  const document = {
    activeElement: opener,
    documentElement: { dataset: {} },
    addEventListener() {},
    removeEventListener() {},
    getElementById(id) { return id === "app-dialog" ? dialog : id === "main" ? main : null; },
  };
  const context = {
    document,
    localStorage: { getItem() { return null; } },
    window: { addEventListener() {}, setTimeout },
    FormData: function FormData() {},
  };
  vm.runInNewContext(source, context);

  const pending = context.window.RootarkUI.dialog({ title: "Link criado" });
  opener.isConnected = false;
  dialog.close("cancel");
  assert.equal(await pending, null);
  assert.equal(document.activeElement, main);
});

test("shared dialog keeps keyboard focus inside while it is open", async () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-ui.js"), "utf8");
  const dialogListeners = new Map();
  const documentListeners = [];
  const opener = { isConnected: true, focus() { document.activeElement = this; } };
  const controls = ["link", "copy", "cancel", "confirm"].map((name) => ({
    name,
    disabled: false,
    hidden: false,
    getClientRects() { return [{}]; },
    focus() { document.activeElement = this; },
    addEventListener() {},
  }));
  const form = { addEventListener() {} };
  const dialog = {
    returnValue: "",
    open: false,
    addEventListener(name, listener) { dialogListeners.set(name, listener); },
    removeEventListener(name) { dialogListeners.delete(name); },
    querySelector(selector) { return selector === "form" ? form : selector.includes("input") ? controls[0] : controls[2]; },
    querySelectorAll() { return controls; },
    contains(element) { return element === this || controls.includes(element); },
    showModal() { this.open = true; document.activeElement = this; },
    close(value) {
      this.open = false;
      this.returnValue = value;
      const listener = dialogListeners.get("close");
      dialogListeners.delete("close");
      listener();
    },
  };
  const document = {
    activeElement: opener,
    documentElement: { dataset: {} },
    addEventListener(name, listener, options) { documentListeners.push({ name, listener, options }); },
    removeEventListener(name, listener, options) {
      const index = documentListeners.findIndex((entry) => entry.name === name && entry.listener === listener && entry.options === options);
      if (index !== -1) documentListeners.splice(index, 1);
    },
    getElementById(id) { return id === "app-dialog" ? dialog : null; },
  };
  const context = {
    document,
    localStorage: { getItem() { return null; } },
    window: { addEventListener() {}, setTimeout },
    FormData: function FormData() {},
  };
  vm.runInNewContext(source, context);

  const initialListenerCount = documentListeners.length;
  const pending = context.window.RootarkUI.dialog({ title: "Link criado" });
  assert.ok(dialog.open);
  assert.equal(document.activeElement, controls[0]);

  const dispatchTab = (shiftKey) => {
    const event = { key: "Tab", shiftKey, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; } };
    documentListeners.filter((entry) => entry.name === "keydown").forEach((entry) => entry.listener(event));
    if (!event.defaultPrevented) document.activeElement = {};
    return event;
  };

  document.activeElement = controls[3];
  assert.ok(dispatchTab(false).defaultPrevented);
  assert.equal(document.activeElement, controls[0]);
  document.activeElement = controls[0];
  assert.ok(dispatchTab(true).defaultPrevented);
  assert.equal(document.activeElement, controls[3]);
  document.activeElement = {};
  assert.ok(dispatchTab(false).defaultPrevented);
  assert.equal(document.activeElement, controls[0]);

  dialog.close("cancel");
  assert.equal(await pending, null);
  assert.equal(documentListeners.length, initialListenerCount);
});

test("mobile navigation backdrop close restores focus to the menu button", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-ui.js"), "utf8");
  const listeners = new Map();
  const body = {};
  const menuButton = {
    attributes: new Map(),
    setAttribute(name, value) { this.attributes.set(name, value); },
    focus() { document.activeElement = this; },
  };
  const sidebar = {
    inert: false,
    contains() { return false; },
    setAttribute() {},
    removeAttribute() {},
  };
  const root = {
    navOpen: true,
    classList: {
      contains(name) { return name === "nav-open" && root.navOpen; },
      toggle(name, value) { if (name === "nav-open") root.navOpen = Boolean(value); },
      remove(name) { if (name === "nav-open") root.navOpen = false; },
    },
    querySelector(selector) { return selector === ".sidebar" ? sidebar : selector === ".mobile-menu" ? menuButton : null; },
  };
  const document = {
    activeElement: body,
    documentElement: { dataset: {} },
    addEventListener(name, listener) { listeners.set(name, listener); },
    getElementById(id) { return id === "app-root" ? root : null; },
  };
  const context = {
    document,
    localStorage: { getItem() { return null; } },
    window: { addEventListener() {}, matchMedia() { return { matches: true }; }, setTimeout },
  };
  vm.runInNewContext(source, context);

  listeners.get("click")({ target: { closest() { return null; } } });

  assert.equal(root.classList.contains("nav-open"), false);
  assert.equal(menuButton.attributes.get("aria-expanded"), "false");
  assert.equal(document.activeElement, menuButton);
});

test("skip-link fragment keeps the route mounted while history and trash hashes still load", async () => {
  const workspaceSource = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-workspace.js"), "utf8");
  const hashListeners = new Map();
  const requests = [];
  const root = { addEventListener() {} };
  let mounts = 0;
  const window = {
    location: { hash: "", host: "127.0.0.1", protocol: "http:" },
    RootarkApi: {
      async get(requestPath) {
        requests.push(requestPath);
        if (requestPath === "/folders") return [{ id: "root", name: "Arquivos atuais", isRoot: true }];
        if (requestPath === "/trash") return { items: [], canManageTrash: false };
        return [];
      },
      query(requestPath) { return requestPath; },
    },
    RootarkUI: {
      async getSession() { return { username: "qa-admin", role: "admin", permissions: { listFiles: true } }; },
      escape(value) { return String(value == null ? "" : value); },
      formatBytes() { return "0 B"; },
      formatDate() { return ""; },
      mount() { mounts += 1; },
    },
    WebSocket: null,
    addEventListener(name, listener) { hashListeners.set(name, listener); },
    dispatchEvent() {},
    setTimeout,
    clearTimeout,
  };
  const document = { getElementById() { return root; }, addEventListener() {} };
  vm.runInNewContext(workspaceSource, { window, document, Event, setTimeout, clearTimeout, FormData });
  await new Promise((resolve) => setImmediate(resolve));

  const routeHandler = hashListeners.get("hashchange");
  assert.equal(typeof routeHandler, "function");
  const baselineRequests = requests.length;
  const baselineMounts = mounts;

  window.location.hash = "#main";
  await routeHandler();
  assert.equal(requests.length, baselineRequests);
  assert.equal(mounts, baselineMounts);

  window.location.hash = "#/history";
  await routeHandler();
  assert.ok(requests.includes("/history"));

  window.location.hash = "#/trash";
  await routeHandler();
  assert.ok(requests.includes("/trash"));

  assert.ok(mounts > baselineMounts);
});

test("mobile navigation keeps focus on an activated topbar action", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-ui.js"), "utf8");
  const listeners = new Map();
  const menuButton = { attributes: new Map(), setAttribute(name, value) { this.attributes.set(name, value); }, focus() { document.activeElement = this; } };
  const topbar = { className: "topbar" };
  const accountMenu = { className: "account-menu", parentElement: topbar };
  const accountSummary = { tagName: "SUMMARY", parentElement: accountMenu, focus() { document.activeElement = this; } };
  const avatar = { tagName: "SPAN", parentElement: accountSummary };
  const sidebarLink = { focus() { document.activeElement = this; } };
  const topbarActionSelector = '.topbar button, .topbar a[href], .topbar input:not([disabled]), .topbar select:not([disabled]), .topbar textarea:not([disabled]), .topbar summary, .topbar [role="button"], .topbar [tabindex]:not([tabindex="-1"])';
  const sidebar = {
    inert: false,
    contains(element) { return element === sidebarLink; },
    querySelector(selector) { return selector === ".nav-link" ? sidebarLink : null; },
    setAttribute() {},
    removeAttribute() {},
  };
  const root = {
    navOpen: true,
    classList: {
      contains(name) { return name === "nav-open" && root.navOpen; },
      toggle(name, value) { if (name === "nav-open") root.navOpen = Boolean(value); },
      remove(name) { if (name === "nav-open") root.navOpen = false; },
    },
    querySelector(selector) { return selector === ".sidebar" ? sidebar : selector === ".mobile-menu" ? menuButton : null; },
  };
  const document = {
    activeElement: sidebarLink,
    documentElement: { dataset: {} },
    addEventListener(name, listener) { listeners.set(name, listener); },
    getElementById(id) { return id === "app-root" ? root : null; },
  };
  const context = {
    document,
    localStorage: { getItem() { return null; } },
    window: { addEventListener() {}, matchMedia() { return { matches: true }; }, setTimeout },
  };
  vm.runInNewContext(source, context);

  let matchedTopbarActionSelector = false;
  listeners.get("click")({ target: { closest(selector) {
    if (selector === ".sidebar, .mobile-menu") return null;
    if (selector === topbarActionSelector && avatar.parentElement === accountSummary && accountSummary.parentElement.parentElement === topbar) {
      matchedTopbarActionSelector = true;
      return accountSummary;
    }
    return null;
  } } });

  assert.equal(root.classList.contains("nav-open"), false);
  assert.equal(menuButton.attributes.get("aria-expanded"), "false");
  assert.equal(source.includes(`closest('${topbarActionSelector}')`), true, "the handler asks for the exact selector that matches a summary inside the topbar");
  assert.equal(matchedTopbarActionSelector, true, "a clicked descendant resolves to its summary inside the topbar");
  assert.equal(document.activeElement, accountSummary, "closing the drawer moves focus from the sidebar to the activated topbar action");
});

test("opening compact navigation closes the account details popover and focuses the drawer", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-ui.js"), "utf8");
  const listeners = new Map();
  const firstLink = { focus() { document.activeElement = this; } };
  const sidebar = {
    inert: false,
    contains(element) { return element === firstLink; },
    querySelector(selector) { return selector === ".nav-link" ? firstLink : null; },
    setAttribute() {},
    removeAttribute() {},
  };
  const menuButton = { setAttribute() {}, addEventListener(name, listener) { listeners.set("menu:" + name, listener); }, focus() { document.activeElement = this; } };
  const accountMenu = { open: true };
  const root = {
    innerHTML: "",
    navOpen: false,
    classList: {
      contains(name) { return name === "nav-open" && root.navOpen; },
      toggle(name, value) { if (name === "nav-open") root.navOpen = Boolean(value); },
      remove(name) { if (name === "nav-open") root.navOpen = false; },
    },
    querySelector(selector) {
      if (selector === ".sidebar") return sidebar;
      if (selector === '[data-action="menu"]') return menuButton;
      if (selector === ".account-menu") return accountMenu;
      return null;
    },
  };
  const document = {
    activeElement: menuButton,
    documentElement: { dataset: {} },
    addEventListener(name, listener) { listeners.set("document:" + name, listener); },
    getElementById(id) { return id === "app-root" ? root : null; },
  };
  const context = {
    document,
    localStorage: { getItem() { return null; } },
    window: { addEventListener() {}, matchMedia() { return { matches: true }; }, setTimeout },
  };
  vm.runInNewContext(source, context);

  context.window.RootarkUI.mount({ user: { username: "admin", role: "admin", permissions: {} } });
  listeners.get("menu:click")();

  assert.equal(accountMenu.open, false, "opening the drawer closes the account details popover");
  assert.equal(root.classList.contains("nav-open"), true);
  assert.equal(document.activeElement, firstLink, "focus enters the open drawer");
});

test("compact drawer keeps geometry and stacking declarations stable while it animates", () => {
  const css = fs.readFileSync(path.join(__dirname, "..", "public", "styles", "app.css"), "utf8");
  const compactRules = css.match(/@media\s*\(max-width:\s*860px\)\s*\{([\s\S]*?)\n\}/);
  assert.ok(compactRules, "compact navigation styles are present");
  const sidebarRule = compactRules[1].match(/\.sidebar\s*\{([^}]*)\}/);
  const openRule = compactRules[1].match(/\.nav-open\s+\.sidebar\s*\{([^}]*)\}/);
  assert.ok(sidebarRule && openRule, "closed and open compact drawer rules are present");
  for (const property of ["top: 62px", "z-index: 15", "height: calc(100vh - 62px)"]) {
    assert.ok(sidebarRule[1].includes(property), `closed drawer geometry includes ${property}`);
  }
  assert.match(sidebarRule[1], /transition:\s*transform\s+180ms\s+ease/);
  assert.match(sidebarRule[1], /transform:\s*translateX\(-102%\)/);
  assert.match(openRule[1], /transform:\s*translateX\(0\)/);
  assert.doesNotMatch(openRule[1], /(?:top|height|z-index)\s*:/, "open and closed states share geometry and stacking");
});

test("mobile navigation traps keyboard focus at both sidebar boundaries", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-ui.js"), "utf8");
  const listeners = new Map();
  const brandLink = { focus() { document.activeElement = this; }, getAttribute() { return null; }, getClientRects() { return [1]; } };
  const navLink = { focus() { document.activeElement = this; }, getAttribute() { return null; }, getClientRects() { return [1]; } };
  const hiddenLink = { hidden: true, focus() { document.activeElement = this; }, getAttribute() { return null; }, getClientRects() { return []; } };
  const lastControl = { focus() { document.activeElement = this; }, getAttribute() { return null; }, getClientRects() { return [1]; } };
  const sidebar = {
    inert: false,
    contains(element) { return [brandLink, navLink, hiddenLink, lastControl].includes(element); },
    querySelectorAll() { return [brandLink, navLink, hiddenLink, lastControl]; },
    setAttribute() {},
    removeAttribute() {},
  };
  const menuButton = { setAttribute() {}, focus() { document.activeElement = this; } };
  const root = {
    navOpen: true,
    classList: {
      contains(name) { return name === "nav-open" && root.navOpen; },
      toggle(name, value) { if (name === "nav-open") root.navOpen = Boolean(value); },
      remove(name) { if (name === "nav-open") root.navOpen = false; },
    },
    querySelector(selector) { return selector === ".sidebar" ? sidebar : selector === ".mobile-menu" ? menuButton : null; },
  };
  const document = {
    activeElement: brandLink,
    documentElement: { dataset: {} },
    addEventListener(name, listener) { listeners.set(name, listener); },
    getElementById(id) { return id === "app-root" ? root : null; },
    querySelector() { return null; },
  };
  const context = {
    document,
    localStorage: { getItem() { return null; } },
    window: { addEventListener() {}, matchMedia() { return { matches: true }; }, setTimeout },
  };
  vm.runInNewContext(source, context);
  const keydown = listeners.get("keydown");

  let prevented = false;
  keydown({ key: "Tab", shiftKey: true, preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.equal(document.activeElement, lastControl);

  prevented = false;
  document.activeElement = lastControl;
  keydown({ key: "Tab", shiftKey: false, preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.equal(document.activeElement, brandLink);

  prevented = false;
  document.activeElement = navLink;
  keydown({ key: "Tab", shiftKey: true, preventDefault() { prevented = true; } });
  assert.equal(prevented, false, "focus can move naturally between visible links inside the sidebar");
  assert.equal(document.activeElement, navLink);
});

test("mobile navigation does not intercept Tab while a dialog is open", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-ui.js"), "utf8");
  const listeners = new Map();
  const firstLink = { focus() { document.activeElement = this; }, getAttribute() { return null; }, getClientRects() { return [1]; } };
  const sidebar = {
    contains() { return false; },
    querySelectorAll() { return [firstLink]; },
  };
  const dialogButton = { focus() { document.activeElement = this; } };
  const root = {
    classList: { contains(name) { return name === "nav-open"; } },
    querySelector(selector) { return selector === ".sidebar" ? sidebar : null; },
  };
  const document = {
    activeElement: dialogButton,
    documentElement: { dataset: {} },
    addEventListener(name, listener) { listeners.set(name, listener); },
    getElementById(id) { return id === "app-root" ? root : null; },
    querySelector(selector) { return selector === "dialog[open]" ? {} : null; },
  };
  const context = {
    document,
    localStorage: { getItem() { return null; } },
    window: { addEventListener() {}, matchMedia() { return { matches: true }; }, setTimeout },
  };
  vm.runInNewContext(source, context);

  let prevented = false;
  listeners.get("keydown")({ key: "Tab", shiftKey: false, preventDefault() { prevented = true; } });

  assert.equal(prevented, false, "the mobile navigation handler leaves Tab uncanceled");
  assert.equal(document.activeElement, dialogButton, "the handler does not redirect focus into the drawer");
});

test("Escape closes mobile navigation and restores focus unless a dialog is open", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-ui.js"), "utf8");
  const listeners = new Map();
  const menuButton = { setAttribute() {}, focus() { document.activeElement = this; } };
  const sidebar = {
    inert: false,
    contains() { return false; },
    setAttribute() {},
    removeAttribute() {},
  };
  const root = {
    navOpen: true,
    classList: {
      contains(name) { return name === "nav-open" && root.navOpen; },
      toggle(name, value) { if (name === "nav-open") root.navOpen = Boolean(value); },
      remove(name) { if (name === "nav-open") root.navOpen = false; },
    },
    querySelector(selector) { return selector === ".sidebar" ? sidebar : selector === ".mobile-menu" ? menuButton : null; },
  };
  let dialogOpen = false;
  const document = {
    activeElement: {},
    documentElement: { dataset: {} },
    addEventListener(name, listener) { listeners.set(name, listener); },
    getElementById(id) { return id === "app-root" ? root : null; },
    querySelector() { return dialogOpen ? {} : null; },
  };
  const context = {
    document,
    localStorage: { getItem() { return null; } },
    window: { addEventListener() {}, matchMedia() { return { matches: true }; }, setTimeout },
  };
  vm.runInNewContext(source, context);
  const keydown = listeners.get("keydown");

  let prevented = false;
  keydown({ key: "Escape", preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.equal(root.navOpen, false);
  assert.equal(document.activeElement, menuButton);

  root.navOpen = true;
  dialogOpen = true;
  prevented = false;
  keydown({ key: "Escape", preventDefault() { prevented = true; } });
  assert.equal(prevented, false);
  assert.equal(root.navOpen, true, "Escape remains available to the active dialog");
});

test("backup creation announces partial success and refreshes the backup list", async () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-management.js"), "utf8");
  const listeners = new Map();
  const createButton = { disabled: false, addEventListener(name, listener) { this.listener = listener; } };
  const body = { innerHTML: "" };
  const feedback = { hidden: false, textContent: "", className: "", setAttribute(name, value) { this[name] = value; } };
  const elements = new Map([["create-backup", createButton], ["backups-body", body], ["backup-feedback", feedback]]);
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, { hidden: false, textContent: "", className: "", setAttribute(name, value) { this[name] = value; }, addEventListener(name, listener) { this.listener = listener; } });
    return elements.get(id);
  };
  const target = {
    addEventListener(name, listener) { listeners.set(name, listener); },
    querySelectorAll() { return []; },
    scrollIntoView() {},
  };
  let mounted;
  const didMount = new Promise((resolve) => { mounted = resolve; });
  let initialBackupsLoaded;
  const didLoadBackups = new Promise((resolve) => { initialBackupsLoaded = resolve; });
  let backupListRequests = 0;
  let postedRoute = null;
  let successToasts = 0;
  const createdBackup = { id: "fixture-backup", filename: "fixture.zip", createdAt: "2026-10-10T10:00:00.000Z", type: "manual", status: "success", sizeBytes: 128 };
  const context = {
    console,
    window: {
      RootarkApi: {
        async get(route) {
          if (route === "/backups/latest-status") return { latest: null };
          if (route === "/backups") {
            backupListRequests += 1;
            if (backupListRequests === 1) { initialBackupsLoaded(); return { backups: [] }; }
            return { backups: [createdBackup] };
          }
          throw new Error("unexpected route: " + route);
        },
        async post(route) {
          postedRoute = route;
          return {
            backup: createdBackup,
            backupOperationState: "created-post-processing-failed",
            warning: "Backup criado, mas uma etapa de manutenção automática falhou. Confira a lista e a auditoria antes de repetir a operação.",
          };
        },
      },
      RootarkUI: {
        async getSession() { return { username: "fixture-admin", role: "admin", permissions: { manageBackups: true } }; },
        mount() { mounted(); return target; },
        escape: (value) => String(value),
        formatDate: (value) => String(value || ""),
        formatBytes: (value) => String(value || 0),
        toast(message, tone) { if (tone === "success") successToasts += 1; },
      },
      addEventListener() {},
    },
    document: {
      body: { dataset: { rootarkView: "backups" } },
      getElementById(id) { return id === "page-content" ? target : element(id); },
    },
  };
  vm.runInNewContext(source, context);
  await didMount;
  await didLoadBackups;
  await createButton.listener({ currentTarget: createButton });

  assert.equal(postedRoute, "/backups");
  assert.equal(backupListRequests, 2, "the history is reloaded after partial success");
  assert.match(body.innerHTML, /Concluído/, "the newly created backup appears in the refreshed list");
  assert.equal(feedback.hidden, false);
  assert.equal(feedback.className, "feedback feedback-warning");
  assert.equal(feedback.role, "status");
  assert.match(feedback.textContent, /Backup criado/);
  assert.equal(successToasts, 0, "partial success must not look like an unqualified success toast");
  assert.equal(createButton.disabled, false);
});

test("backup recovery stays blocked after an in-flight action returns a structured 503", async () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-management.js"), "utf8");
  for (const page of ["admin.html", "audit.html", "backups.html", "dashboard.html"]) {
    const html = fs.readFileSync(path.join(__dirname, "..", "public", page), "utf8");
    assert.match(html, new RegExp(`rootark-management\\.js\\?v=19`));
  }
  assert.match(fs.readFileSync(path.join(__dirname, "..", "public", "service-worker.js"), "utf8"), /rootark-public-shell-v22/);
  const listeners = new Map();
  const buttons = [{ disabled: false }, { disabled: false }, { disabled: false }];
  const target = {
    addEventListener: (name, listener) => listeners.set(name, listener),
    querySelectorAll: () => buttons,
    scrollIntoView() {},
  };
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, { hidden: false, textContent: "", setAttribute() {}, addEventListener(name, listener) { this.listener = listener; } });
    return elements.get(id);
  };
  const createButton = element("create-backup");
  const warning = element("backup-warning");
  let mounted;
  const didMount = new Promise((resolve) => { mounted = resolve; });
  let initialBackupsLoaded;
  const didLoadBackups = new Promise((resolve) => { initialBackupsLoaded = resolve; });
  const context = {
    console,
    window: {
      RootarkApi: {
        async get(route) {
          if (route === "/backups/latest-status") return { latest: null };
          if (route === "/backups") { initialBackupsLoaded(); return { backups: [{ id: "fixture-backup", status: "success" }] }; }
          throw new Error("unexpected route");
        },
        async post() {
          const error = new Error("recovery required");
          error.status = 503;
          error.payload = { recoveryRequired: true };
          throw error;
        },
      },
      RootarkUI: {
        async getSession() { return { username: "fixture-admin", role: "admin", permissions: { manageBackups: true } }; },
        mount() { mounted(); return target; },
        escape: (value) => String(value),
        formatDate: (value) => String(value || ""),
        formatBytes: (value) => String(value || 0),
        toast() {},
      },
    },
    document: {
      body: { dataset: { rootarkView: "backups" } },
      getElementById(id) { return id === "page-content" ? target : id === "app-root" ? element(id) : id === "backups-body" ? element(id) : id === "backup-warning" ? warning : element(id); },
    },
  };
  vm.runInNewContext(source, context);
  await didMount;
  await didLoadBackups;
  await createButton.listener({ currentTarget: createButton });
  assert.equal(warning.hidden, false);
  assert.match(warning.textContent, /Reinicie todas as instâncias/);
  assert.equal(createButton.disabled, true);
  assert.deepEqual(buttons.map((button) => button.disabled), [true, true, true]);
});

test("protected client index canonicalizes metadata and rejects tamper/wrong keys", async () => {
  const key = crypto.randomBytes(32);
  const wrongKey = crypto.randomBytes(32);
  const first = await protectedIndex.createEntry({ id: "file-1", versionId: "version-1", keyEpoch: "epoch-1", compartmentId: "private", metadata: { name: "secret.txt", size: 4, nested: { b: 2, a: 1 } } }, key);
  const second = await protectedIndex.createEntry({ id: "file-2", versionId: "version-1", keyEpoch: "epoch-1", compartmentId: "private", metadata: { name: "public.txt", size: 6 } }, key);
  assert.equal(JSON.stringify(first).includes("secret.txt"), false);
  assert.deepEqual((await protectedIndex.search([first, second], "secret", key)).map((item) => item.id), ["file-1"]);
  await assert.rejects(protectedIndex.decryptEntry(first, wrongKey));
  await assert.rejects(protectedIndex.decryptEntry({ ...first, envelope: { ...first.envelope, ciphertext: `${first.envelope.ciphertext}x` } }, key));
  assert.equal(clientCrypto.canonicalJson({ b: 2, a: 1 }), clientCrypto.canonicalJson({ a: 1, b: 2 }));
});

test("protected preview never exposes body in its envelope and decrypts locally", async () => {
  const key = crypto.randomBytes(32);
  const preview = await protectedPreview.seal({ fileId: "file-1", sourceVersionId: "version-1", keyEpoch: "epoch-1", compartmentId: "private", contentType: "text/plain", body: "private preview" }, key);
  assert.equal(JSON.stringify(preview).includes("private preview"), false);
  assert.deepEqual(await protectedPreview.open(preview, key), { fileId: "file-1", sourceVersionId: "version-1", keyEpoch: "epoch-1", compartmentId: "private", previewFormat: "rootark-protected-preview-v2", contentType: "text/plain", body: "private preview" });
  await assert.rejects(protectedPreview.open(preview, crypto.randomBytes(32)));
  await assert.rejects(protectedPreview.seal({ fileId: "file-1", sourceVersionId: "version-1", keyEpoch: "epoch-1", compartmentId: "private", contentType: "text/plain; charset=utf-8", body: "x" }, key));
  await assert.rejects(protectedPreview.open({ ...preview, fileId: "file-2" }, key));
  const jsonPreview = await protectedPreview.seal({ fileId: "file-1", sourceVersionId: "version-2", keyEpoch: "epoch-2", compartmentId: "private", contentType: "application/json", body: "{}" }, key);
  assert.equal(protectedPreview.invalidateOnEpoch([preview, jsonPreview], "file-1", "epoch-2").length, 1);
  assert.equal(protectedPreview.invalidateOnVersion([preview, jsonPreview], "file-1", "version-2").length, 1);
});

test("protected browser session keeps keys in memory and wires queue/sync/logout hooks", async () => {
  let queued = null;
  let cleared = 0;
  const store = {
    enqueue: async (operation, key) => { queued = { operation, key }; return true; },
    clear: async () => { cleared += 1; return true; },
  };
  const key = new Uint8Array(32);
  protectedSession.attachStore(store);
  protectedSession.configure({ getKey: () => key, syncOnce: () => "synced" });
  assert.equal(await protectedSession.enqueue({ operationId: "session-op" }), true);
  assert.equal(queued.key, key);
  assert.equal(protectedSession.syncOnce(), "synced");
  assert.equal(await protectedSession.logout(), true);
  assert.equal(cleared, 1);
  await assert.rejects(protectedSession.getKey());
});

test("chunked password uploads send the password only on the final chunk", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-workspace.js"), "utf8");
  assert.match(source, /if \(index === 0\) appendEncryption\(form, \{\s*\.\.\.settings,\s*password: totalChunks === 1 \? settings\.password : "",\s*\}\);/);
  assert.match(source, /if \(index === totalChunks - 1 && totalChunks > 1 && settings\.password\) form\.append\("password", settings\.password\);/);
  assert.match(source, /finally \{ form\.delete\("password"\); \}/);
});

test("offline queue and sync adapter reject plaintext, keys, and search terms", () => {
  const store = new Map();
  const local = { getItem: (key) => store.get(key) || null, setItem: (key, value) => store.set(key, value), removeItem: (key) => store.delete(key) };
  const queue = offlineQueue.createOfflineQueue(local);
  assert.throws(() => queue.enqueue({ ciphertext: "opaque", plaintext: "secret" }));
  const valid = protocol.createOperation({ operation: "create", objectId: "object-queue", fileId: "file-queue", versionId: "version-queue", operationId: "operation-queue", deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", revision: { counter: 1, deviceId: "device-a" }, metadata: { path: "queue.txt" }, plaintext: Buffer.from("opaque"), fileKey: crypto.randomBytes(32) });
  assert.equal(queue.enqueue(valid), 1);
  const normalized = syncAdapter.assertOpaqueEnvelope(valid);
  assert.notEqual(normalized, valid);
  assert.throws(() => syncAdapter.assertOpaqueEnvelope({ ...valid, nested: { plaintext: "secret" } }));
  assert.throws(() => syncAdapter.assertOpaqueEnvelope({ ...valid, metadata: { ...valid.metadata, preview: "secret" } }));
  assert.throws(() => syncAdapter.assertOpaqueEnvelope({ ...valid, metadata: { ...valid.metadata, path: "../escape" } }));
  store.set("rootark.offline.encrypted.v2", "not-json");
  assert.equal(queue.size(), 0);
  assert.equal(queue.clear(), true);
  assert.throws(() => syncAdapter.assertOpaqueEnvelope({ plaintext: "secret" }));
  assert.throws(() => syncAdapter.assertOpaqueEnvelope({ ciphertext: "x", fileKey: "key" }));
});

test("service worker caches only the public shell and bypasses protected paths", async () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "public", "service-worker.js"), "utf8");
  const handlers = {};
  const caches = new Map([["rootark-public-shell-v20", new Map()]]);
  const cacheValue = (asset) => ({ asset });
  caches.get("rootark-public-shell-v20").set("https://rootark.test/index.html", cacheValue("stale index html"));
  caches.get("rootark-public-shell-v20").set("https://rootark.test/client/rootark-workspace.js", cacheValue("stale workspace js"));
  caches.get("rootark-public-shell-v20").set("https://rootark.test/styles/app.css", cacheValue("stale css"));
  caches.get("rootark-public-shell-v20").set("https://rootark.test/client/rootark-management.js", cacheValue("stale management js"));
  const context = {
    URL,
    Promise,
    self: {
      location: { origin: "https://rootark.test" },
      addEventListener: (name, handler) => { handlers[name] = handler; },
      skipWaiting: () => Promise.resolve(),
      clients: { claim: () => Promise.resolve() },
    },
    caches: {
      open: async (name) => {
        if (!caches.has(name)) caches.set(name, new Map());
        const cache = caches.get(name);
        return {
          addAll: async (assets) => assets.forEach((asset) => cache.set(new URL(asset, "https://rootark.test").href, cacheValue(asset))),
          put: async (request, response) => cache.set(new URL(request.url).href, response),
        };
      },
      match: async (request, options) => {
        const url = new URL(request.url);
        if (options && options.ignoreSearch) url.search = "";
        for (const cache of caches.values()) {
          const hit = cache.get(url.href);
          if (hit) return hit;
        }
        return null;
      },
      keys: async () => [...caches.keys()],
      delete: async (name) => caches.delete(name),
    },
    fetch: async () => { throw new Error("offline cache miss"); },
  };
  assert.match(source, /const CACHE_NAME = "rootark-public-shell-v22";/, "workspace asset updates advance the public shell cache revision");
  const pageAssets = {
    "index.html": [["rootark-api.js", 17], ["rootark-workspace.js", 18], ["rootark-ui.js", 17]],
    "admin.html": [["rootark-api.js", 17], ["rootark-management.js", 19], ["rootark-ui.js", 17]],
    "audit.html": [["rootark-api.js", 17], ["rootark-management.js", 19], ["rootark-ui.js", 17]],
    "backups.html": [["rootark-api.js", 17], ["rootark-management.js", 19], ["rootark-ui.js", 17]],
    "dashboard.html": [["rootark-api.js", 17], ["rootark-management.js", 19], ["rootark-ui.js", 17]],
    "login.html": [["rootark-api.js", 17]],
  };
  for (const [page, scripts] of Object.entries(pageAssets)) {
    const html = fs.readFileSync(path.join(__dirname, "..", "public", page), "utf8");
    for (const [script, version] of scripts) assert.match(html, new RegExp(`/client/${script.replaceAll(".", "\\.")}\\?v=${version}`), `${page} refreshes ${script}`);
  }
  for (const page of Object.keys(pageAssets)) {
    const html = fs.readFileSync(path.join(__dirname, "..", "public", page), "utf8");
    assert.match(html, /\/styles\/app\.css\?v=19/, `${page} refreshes the updated stylesheet`);
  }
  vm.runInNewContext(source, context);
  let installWait;
  handlers.install({ waitUntil: (promise) => { installWait = promise; } });
  await installWait;
  assert.ok(caches.get("rootark-public-shell-v22").has("https://rootark.test/"));
  assert.ok(caches.get("rootark-public-shell-v22").has("https://rootark.test/client/rootark-api.js"));
  assert.ok(caches.get("rootark-public-shell-v22").has("https://rootark.test/client/rootark-workspace.js"));
  assert.ok(caches.get("rootark-public-shell-v22").has("https://rootark.test/client/rootark-bootstrap.js"));
  assert.ok(caches.get("rootark-public-shell-v22").has("https://rootark.test/client/rootark-protected-index.js"));
  assert.ok(caches.get("rootark-public-shell-v22").has("https://rootark.test/client/rootark-offline-queue.js"));
  assert.ok(caches.get("rootark-public-shell-v22").has("https://rootark.test/client/rootark-protected-session.js"));
  assert.ok(caches.get("rootark-public-shell-v22").has("https://rootark.test/client/rootark-ui.js"));
  assert.equal([...caches.get("rootark-public-shell-v22").keys()].some((asset) => /^https:\/\/rootark\.test\/(?:auth|api|files|preview|sync|encrypted|groups|folders)(?:\/|$)/i.test(new URL(asset).pathname)), false);
  let activateWait;
  handlers.activate({ waitUntil: (promise) => { activateWait = promise; } });
  await activateWait;
  assert.deepEqual([...caches.keys()], ["rootark-public-shell-v22"]);
  const shellPages = ["index.html", "login.html", "dashboard.html", "audit.html", "admin.html", "backups.html"];
  const versionedAssets = [...new Set(shellPages.flatMap((page) => {
    const html = fs.readFileSync(path.join(__dirname, "..", "public", page), "utf8");
    return [...html.matchAll(/<(?:script|link)\b[^>]*(?:src|href)="([^\"]+\?v=\d+)"[^>]*>/g)].map((match) => match[1]);
  }))];
  for (const asset of versionedAssets) {
    let response;
    handlers.fetch({ request: { method: "GET", url: "https://rootark.test" + asset }, respondWith: (promise) => { response = promise; } });
    assert.equal((await response).asset, new URL(asset, "https://rootark.test").pathname, `${asset} is served from the upgraded cache while offline`);
  }
  let fetchWait;
  handlers.fetch({ request: { method: "GET", url: "https://rootark.test/files/private.txt" }, respondWith: (promise) => { fetchWait = promise; } });
  assert.equal(fetchWait, undefined);
  for (const pathname of ["/auth/me", "/preview/file/public/private.txt", "/encrypted/private.txt/metadata", "/sync/operations", "/share/private-token", "/open-file/private-token/private.txt"]) {
    let intercepted = false;
    handlers.fetch({ request: { method: "GET", url: "https://rootark.test" + pathname }, respondWith: () => { intercepted = true; } });
    assert.equal(intercepted, false, pathname + " must bypass the public shell cache");
  }
  handlers.fetch({ request: { method: "GET", url: "https://rootark.test/" }, respondWith: (promise) => { fetchWait = promise; } });
  assert.ok(fetchWait);
  await fetchWait;
});

test("groups require manageUsers, persist atomically, and add folder membership access", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase13-groups-"));
  const events = [];
  const users = [{ username: "admin", role: "admin" }, { username: "alice", role: "user" }, { username: "bob", role: "user" }];
  const folders = [{ id: "folder-1", createdBy: "owner", users: { bob: { read: true } }, groupIds: [] }];
  const app = express();
  app.use(express.json());
  const authenticate = (req, _res, next) => { req.user = users.find((user) => user.username === req.headers["x-user"]) || users[1]; next(); };
  const requirePermission = (permission) => (req, res, next) => req.user.role === "admin" || req.user.permissions?.[permission] ? next() : res.status(403).json({ error: `Permissao negada: ${permission}` });
  const route = registerGroupRoutes({ app, authenticate, requirePermission, loadUsers: () => users, loadFolders: () => folders, saveFolders: (next) => folders.splice(0, folders.length, ...next), auditLog: (...args) => events.push(args), getAuditActor: () => ({ username: "admin" }), storagePath: path.join(dir, "groups.json") });
  const server = await new Promise((resolve) => { const value = app.listen(0, "127.0.0.1", () => resolve(value)); });
  t.after(async () => { await new Promise((resolve) => server.close(resolve)); await fsp.rm(dir, { recursive: true, force: true }); });
  const port = server.address().port;
  const denied = await request(port, "/groups", { headers: { "x-user": "alice" } });
  assert.equal(denied.status, 403);
  const createdBody = json({ name: "docs", members: ["alice"] });
  const created = await request(port, "/groups", { method: "POST", headers: { "x-user": "admin", "content-type": "application/json", "content-length": createdBody.length }, body: createdBody });
  assert.equal(created.status, 201);
  const group = JSON.parse(created.body).group;
  assert.equal(JSON.stringify(created.body).includes("password"), false);
  assert.equal(route.store.isMember("alice", [group.id]), true);
  assert.equal(isGroupMember(route.store, "alice", [group.id]), true);
  folders[0].groupIds = [group.id];
  assert.equal(route.store.isMember("alice", folders[0].groupIds), true);
  const persisted = new AtomicGroupsStore(path.join(dir, "groups.json"));
  assert.equal(persisted.get(group.id).name, "docs");
  const sharing = new GroupKeySharing({ groupId: group.id, members: ["alice"] });
  const cek = crypto.randomBytes(32);
  const cer = crypto.randomBytes(32);
  const wrap = await sharing.wrapFor({ compartmentId: "private", epoch: 1, objectId: "object-1", versionId: "version-1", keyRef: "file-1", recipientId: "alice", deviceId: "device-a", cek, cer });
  const manifestBody = json({ groupId: group.id, epoch: 1, wraps: [wrap] });
  const manifest = await request(port, `/groups/${group.id}/key-manifest`, { method: "POST", headers: { "x-user": "admin", "content-type": "application/json", "content-length": manifestBody.length }, body: manifestBody });
  assert.equal(manifest.status, 201);
  assert.equal(JSON.stringify(await fsp.readFile(path.join(dir, "groups.json"), "utf8")).includes(cek.toString("base64")), false);
  const changedMembers = json({ members: ["alice", "bob"] });
  assert.equal((await request(port, `/groups/${group.id}/members`, { method: "PUT", headers: { "x-user": "admin", "content-type": "application/json", "content-length": changedMembers.length }, body: changedMembers })).status, 200);
  assert.equal(JSON.parse((await request(port, `/groups/${group.id}/key-manifest`, { headers: { "x-user": "admin" } })).body).wraps.length, 0);
  assert.ok(events.some((entry) => entry[0] === "group.created"));
  route.store.state.groups[group.id].members = Array.from({ length: MAX_MEMBERS }, () => "alice");
  const overLimitBody = json({ username: "bob" });
  const overLimit = await request(port, `/groups/${group.id}/members`, { method: "POST", headers: { "x-user": "admin", "content-type": "application/json", "content-length": overLimitBody.length }, body: overLimitBody });
  assert.equal(overLimit.status, 400);
});
