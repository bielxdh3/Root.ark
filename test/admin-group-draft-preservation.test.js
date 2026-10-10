"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");

test("admin group member draft survives account creation refresh", async () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-management.js"), "utf8");
  const group = { id: "group-1", name: "Operações", members: ["member"] };
  const user = { username: "admin", role: "admin", permissions: { manageUsers: true } };
  const elements = new Map();
  const targetListeners = new Map();
  const groupsLoaded = new Promise((resolve) => { group.loadInitial = resolve; });
  let createdUser;
  let groupInput;

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
        group.loadInitial();
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
  await groupsLoaded;
  await new Promise((resolve) => setImmediate(resolve));

  const groupsBody = element("groups-body");
  assert.match(groupsBody.innerHTML, /value="member"/);

  groupInput = { dataset: { groupId: group.id }, value: "member, admin" };
  targetListeners.get("input")?.({ target: groupInput });
  const createUserForm = element("create-user-form");
  createUserForm.values = { username: "new-user", password: "fixture-only", role: "user", "permission-listFiles": "on" };
  await createUserForm.listeners.get("submit")({ currentTarget: createUserForm, preventDefault() {} });

  assert.match(groupsBody.innerHTML, /value="member, admin"/, "refreshing groups must preserve an unsaved member edit");
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
