"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

test("admin group member draft survives account creation refresh", async () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-management.js"), "utf8");
  const group = { id: "group-1", name: "Operações", members: ["member"] };
  const user = { username: "admin", role: "admin", permissions: { manageUsers: true } };
  const elements = new Map();
  const targetListeners = new Map();
  const firstGroupRead = deferred(), secondGroupRead = deferred();
  const firstGroupReadStarted = deferred(), secondGroupReadStarted = deferred();
  let groupReadCount = 0;
  let createdUser;
  let groupInput;
  let groupInputConnected = false;

  function element(id) {
    if (!elements.has(id)) {
      const listeners = new Map();
      const value = {
        id,
        hidden: false,
        disabled: false,
        textContent: "",
        className: "",
        innerHTML: "",
        value: id === "new-role" ? "user" : "",
        listeners,
        addEventListener(name, listener) { listeners.set(name, listener); },
        setAttribute(name, next) { this[name] = next; },
        querySelector(selector) { return selector === "button[type='submit']" ? element(`${id}-submit`) : null; },
        reset() { this.wasReset = true; },
      };
      if (id === "groups-body") {
        let html = "";
        Object.defineProperty(value, "innerHTML", {
          get() { return html; },
          set(next) {
            html = String(next);
            const renderedGroup = html.match(/<input[^>]*data-group-id="group-1"[^>]*value="([^"]*)"/);
            groupInputConnected = Boolean(renderedGroup);
            if (renderedGroup && groupInput) {
              groupInput.value = renderedGroup[1].replace(/&quot;/g, "\"").replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
            }
          },
        });
      }
      elements.set(id, value);
    }
    return elements.get(id);
  }

  const target = {
    addEventListener(name, listener) { targetListeners.set(name, listener); },
    querySelector() { return groupInput; },
    querySelectorAll() { return []; },
    scrollIntoView() {},
  };
  const root = { innerHTML: "" };
  const document = {
    body: { dataset: { rootarkView: "admin" } },
    getElementById(id) {
      if (id === "app-root") return root;
      if (id === "page-content") return target;
      return element(id);
    },
  };

  class FormDataFixture {
    constructor(form) { this.values = form.values || {}; }
    get(name) { return this.values[name] ?? null; }
  }

  const api = {
    async get(route) {
      if (route === "/users") return [user, ...(createdUser ? [createdUser] : [])];
      if (route === "/groups") {
        const index = groupReadCount++;
        if (index === 0) { firstGroupReadStarted.resolve(); return firstGroupRead.promise; }
        if (index === 1) { secondGroupReadStarted.resolve(); return secondGroupRead.promise; }
        return [{ id: group.id, name: group.name, members: [...group.members] }];
      }
      if (route === "/quarantine" || route === "/folders") return [];
      throw new Error(`Unexpected GET route: ${route}`);
    },
    async post(route, payload) {
      assert.equal(route, "/users");
      createdUser = { username: payload.username, role: payload.role, permissions: payload.permissions };
      return {};
    },
    async put(route, payload) {
      assert.equal(route, `/groups/${group.id}/members`);
      group.members = [...payload.members].sort();
      return {};
    },
    query(route) { return route; },
  };

  const context = {
    document,
    FormData: FormDataFixture,
    window: {
      RootarkApi: api,
      RootarkUI: {
        async getSession() { return user; },
        mount() { return target; },
        escape(value) { return String(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" })[character]); },
        roleLabel(role) { return role; },
        formatDate() { return ""; },
        formatBytes() { return "0 B"; },
        toast() {},
        redirectToLogin() {},
      },
    },
  };

  vm.runInNewContext(source, context);
  const groupsBody = element("groups-body");
  await firstGroupReadStarted.promise;

  const createUserForm = element("create-user-form");
  createUserForm.values = { username: "new-user", password: "fixture-only", role: "user", "permission-listFiles": "on" };
  const createUser = createUserForm.listeners.get("submit")({ currentTarget: createUserForm, preventDefault() {} });
  await secondGroupReadStarted.promise;
  secondGroupRead.resolve([{ id: group.id, name: group.name, members: [...group.members] }]);
  await createUser;
  assert.match(groupsBody.innerHTML, /value="member"/);

  groupInput = { dataset: { groupId: group.id }, value: "member, admin" };
  groupInputConnected = groupsBody.innerHTML.includes(`data-group-id="${group.id}"`);
  targetListeners.get("input")?.({ target: groupInput });
  firstGroupRead.resolve([]);
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(groupInputConnected, true, "a stale response must not replace the group input that is being edited");
  assert.equal(groupInput.value, "member, admin", "the live input keeps its current unsaved value");
  assert.match(groupsBody.innerHTML, /aria-label="Membros de Operações"/);

  const saveGroupButton = { dataset: { action: "save-group", groupIndex: "0" }, disabled: false, closest() { return this; } };
  await targetListeners.get("click")({ target: { closest() { return saveGroupButton; } } });
  assert.match(groupsBody.innerHTML, /value="admin, member"/, "a successful save clears the draft and displays refreshed server data");

  groupInput.value = 'admin, <img src=x onerror="alert(1)">';
  targetListeners.get("input")({ target: groupInput });
  createUserForm.values.username = "another-user";
  await createUserForm.listeners.get("submit")({ currentTarget: createUserForm, preventDefault() {} });
  assert.match(groupsBody.innerHTML, /value="admin, &lt;img src=x onerror=&quot;alert\(1\)&quot;&gt;"/, "draft text remains escaped when rerendered as an HTML attribute");
  assert.doesNotMatch(groupsBody.innerHTML, /<img src=x onerror=/, "a member draft cannot inject markup during refresh");
});
