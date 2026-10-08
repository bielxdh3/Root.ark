"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");

test("opening and closing the inline versions panel preserve keyboard focus", async () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-workspace.js"), "utf8");
  const rootListeners = new Map();
  const documentListeners = new Map();
  let activeElement = null;
  const body = {};
  let versionButton;
  let closeButton;
  let folderButton;
  let searchForm;
  let searchInput;
  let advancedDetails;
  let advancedSummary;
  let versionsHeading;
  let deferVersions = false;
  let resolveVersions;
  let versionCalls = 0;
  let versionsPanelScrollCount = 0;
  let uploadDelay = false;
  let resolveUpload;
  let uploadRequestCount = 0;
  let uploadForm;
  let uploadFileInput;
  let uploadProgress;
  let uploadSubmitButton;
  const makeButton = (action, name, folder, id) => ({
    isConnected: true,
    dataset: { action, name, folder, id },
    closest(selector) { return selector === "[data-action]" ? this : null; },
    focus() { activeElement = this; },
  });
  const makeSearchInput = (form) => ({
    isConnected: true,
    name: "q",
    tagName: "INPUT",
    type: "search",
    defaultValue: "",
    form,
    value: "",
    closest(selector) { return selector === "[data-action]" ? null : this; },
    focus() { activeElement = this; },
  });
  const makeAdvancedSummary = () => ({
    isConnected: true,
    tagName: "SUMMARY",
    textContent: "Filtros avançados",
    closest(selector) {
      if (selector === "[data-action]") return null;
      return selector === "details" ? advancedDetails : null;
    },
    focus() { activeElement = this; },
  });
  const makeUploadForm = () => {
    uploadSubmitButton = { disabled: false };
    uploadProgress = { hidden: true, textContent: "" };
    uploadFileInput = { isConnected: true, form: null, name: "files", tagName: "INPUT", type: "file", files: [] };
    const form = {
      id: "upload-form",
      tagName: "FORM",
      isConnected: true,
      elements: [uploadFileInput],
      reset() { uploadFileInput.files = []; },
      querySelector(selector) { return selector === 'button[type="submit"]' ? uploadSubmitButton : null; },
    };
    uploadFileInput.form = form;
    return form;
  };
  const root = {
    addEventListener(name, listener) { rootListeners.set(name, listener); },
    contains(button) { return button.isConnected; },
    querySelectorAll(selector) {
      if (selector === '[data-action="file-versions"]') return versionButton ? [versionButton] : [];
      if (selector === "[data-action]") return [versionButton, closeButton, folderButton].filter(Boolean);
      if (selector === "input, select, textarea") return [searchInput, uploadFileInput].filter(Boolean);
      return selector.startsWith("[data-action],") ? [versionButton, closeButton, folderButton, searchInput, advancedSummary, uploadFileInput].filter(Boolean) : [];
    },
    querySelector(selector) { return selector === "details.search-advanced" ? advancedDetails : null; },
  };
  const document = {
    get activeElement() { return activeElement; },
    set activeElement(value) { activeElement = value; },
    forms: [],
    addEventListener(name, listener) { documentListeners.set(name, listener); },
    getElementById(id) {
      if (id === "app-root") return root;
      if (id === "upload-files") return uploadFileInput;
      if (id === "upload-progress") return uploadProgress;
      return null;
    },
    querySelector(selector) {
      if (selector === ".versions-panel h2") return versionsHeading;
      return selector === ".versions-panel" ? { scrollIntoView() { versionsPanelScrollCount += 1; } } : null;
    },
  };
  const context = {
    document,
    Event: function Event() {},
    window: {
      addEventListener() {},
      dispatchEvent() {},
      setTimeout,
      clearTimeout,
      location: { hash: "", protocol: "http:", host: "rootark.test" },
    },
  };
  context.window.RootarkApi = {
    query: (pathname) => pathname,
    get: async (pathname) => pathname === "/folders" ? [{ id: "root", name: "Arquivos", isRoot: true }, { id: "archive", name: "Arquivo" }]
      : pathname === "/list" ? [{ name: "example.txt", folderId: "root", size: 1 }]
        : pathname.startsWith("/versions/") ? (versionCalls += 1, deferVersions ? new Promise((resolve) => { resolveVersions = resolve; }) : { fileName: "example.txt", versions: [] })
          : [],
    post: async () => ({}),
    postForm: async () => {
      uploadRequestCount += 1;
      return uploadDelay ? new Promise((resolve) => { resolveUpload = resolve; }) : {};
    },
  };
  context.FormData = class TestFormData {
    constructor() { this.values = new Map([["encryptionLevel", "none"], ["versionComment", ""], ["expiresInDays", ""]]); }
    append(key, value) { this.values.set(key, value); }
    get(key) { return this.values.get(key) || ""; }
    set(key, value) { this.values.set(key, value); }
    delete(key) { this.values.delete(key); }
  };
  context.window.RootarkUI = {
    escape: (value) => String(value || ""),
    formatBytes: () => "0 B",
    formatDate: () => "",
    getSession: async () => ({ username: "tester", role: "user", permissions: { listFiles: true, upload: true } }),
    mount({ content }) {
      if (activeElement === versionButton || activeElement === closeButton || activeElement === folderButton || activeElement === searchInput || activeElement === advancedSummary || activeElement === versionsHeading) activeElement = body;
      if (versionButton) versionButton.isConnected = false;
      if (closeButton) closeButton.isConnected = false;
      if (folderButton) folderButton.isConnected = false;
      if (searchInput) searchInput.isConnected = false;
      if (uploadFileInput) uploadFileInput.isConnected = false;
      if (advancedDetails) advancedDetails.isConnected = false;
      if (advancedSummary) advancedSummary.isConnected = false;
      if (versionsHeading) versionsHeading.isConnected = false;
      searchForm = content.includes('id="search-form"') ? { id: "search-form", elements: [] } : null;
      advancedDetails = content.includes('<details class="search-advanced">') ? { className: "search-advanced", open: false, isConnected: true } : null;
      versionButton = content.includes('data-action="file-versions"') ? makeButton("file-versions", "example.txt", "root") : null;
      closeButton = content.includes('data-action="close-versions"') ? makeButton("close-versions", "", "") : null;
      folderButton = content.includes('data-action="select-folder"') ? makeButton("select-folder", "", "", "archive") : null;
      searchInput = content.includes('name="q" type="search"') ? makeSearchInput(searchForm) : null;
      if (searchForm && searchInput) searchForm.elements.push(searchInput);
      advancedSummary = content.includes("<summary>Filtros avançados</summary>") ? makeAdvancedSummary() : null;
      versionsHeading = content.includes('<h2 tabindex="-1">') ? { isConnected: true, focus() { activeElement = this; } } : null;
      uploadForm = content.includes('id="upload-form"') ? makeUploadForm() : null;
    },
    toast() {},
    redirectToLogin() {},
  };
  vm.runInNewContext(source, context);
  await new Promise((resolve) => setImmediate(resolve));

  const click = async (button) => rootListeners.get("click")({ target: { closest: () => button } });
  versionButton.focus();
  await click(versionButton);
  assert.equal(activeElement, versionsHeading, "opening the panel moves focus to its heading");
  assert.equal(versionsPanelScrollCount, 1, "opening the panel while focus stays on its trigger may scroll it into view");
  await click(closeButton);
  assert.equal(activeElement, versionButton, "closing returns focus to the file action");

  searchInput.focus();
  deferVersions = true;
  const delayedPointerOpen = click(versionButton);
  await new Promise((resolve) => setImmediate(resolve));
  searchInput.focus();
  uploadFileInput.files = [{ name: "deferred-upload.txt", size: 10 }];
  const uploadCountBeforeVersionsFinish = uploadRequestCount;
  const submitDuringVersionRequest = rootListeners.get("submit")({ target: uploadForm, preventDefault() {} });
  await submitDuringVersionRequest;
  assert.equal(uploadRequestCount, uploadCountBeforeVersionsFinish, "a pending versions request blocks upload submission until its render completes");
  const scrollCountBeforeUserFocusChange = versionsPanelScrollCount;
  resolveVersions({ fileName: "example.txt", versions: [] });
  await delayedPointerOpen;
  assert.equal(activeElement, searchInput, "a delayed pointer action must not steal focus back to the versions heading after the user moves focus");
  assert.equal(versionsPanelScrollCount, scrollCountBeforeUserFocusChange, "a delayed response must not scroll the viewport away from a control focused during the request");

  versionButton.focus();
  const focusedFolderButton = folderButton;
  deferVersions = true;
  const delayedOpen = click(versionButton);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(typeof resolveVersions, "function", "the versions response is held for the focus-race case");
  focusedFolderButton.focus();
  resolveVersions({ fileName: "example.txt", versions: [] });
  await delayedOpen;
  assert.notEqual(folderButton, focusedFolderButton, "render replaces the focused workspace control");
  assert.equal(activeElement, folderButton, "a delayed response restores focus to the equivalent current control");
  assert.equal(focusedFolderButton.isConnected, false);
  assert.notEqual(activeElement, versionsHeading);

  versionButton.focus();
  const focusedSearchInput = searchInput;
  const delayedInputOpen = click(versionButton);
  await new Promise((resolve) => setImmediate(resolve));
  focusedSearchInput.value = "unsent search draft";
  documentListeners.get("input")({ target: focusedSearchInput });
  focusedSearchInput.focus();
  resolveVersions({ fileName: "example.txt", versions: [] });
  await delayedInputOpen;
  assert.notEqual(searchInput, focusedSearchInput, "render replaces the focused search input");
  assert.equal(activeElement, searchInput, "a delayed response restores focus to the equivalent form control");
  assert.equal(searchInput.value, "unsent search draft", "a delayed response preserves an unsent search draft");
  assert.equal(focusedSearchInput.isConnected, false);

  versionButton.focus();
  const focusedSummary = advancedSummary;
  const delayedSummaryOpen = click(versionButton);
  await new Promise((resolve) => setImmediate(resolve));
  advancedDetails.open = true;
  focusedSummary.focus();
  resolveVersions({ fileName: "example.txt", versions: [] });
  await delayedSummaryOpen;
  assert.notEqual(advancedSummary, focusedSummary, "render replaces the focused advanced-filter summary");
  assert.equal(activeElement, advancedSummary, "a delayed response restores focus to the equivalent summary control");
  assert.equal(advancedDetails.open, true, "a delayed response preserves the open advanced-filter disclosure");
  assert.equal(focusedSummary.isConnected, false);

  uploadDelay = true;
  uploadFileInput.files = [{ name: "synthetic-upload.txt", size: 10 }];
  const activeUploadForm = uploadForm;
  const activeUploadButton = uploadSubmitButton;
  const activeUploadProgress = uploadProgress;
  let submitPrevented = false;
  const uploadPromise = rootListeners.get("submit")({ target: activeUploadForm, preventDefault() { submitPrevented = true; } });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(submitPrevented, true);
  assert.equal(uploadRequestCount, 1);
  assert.equal(activeUploadButton.disabled, true);
  assert.equal(activeUploadProgress.hidden, false);
  const duplicateUpload = rootListeners.get("submit")({ target: activeUploadForm, preventDefault() {} });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(uploadRequestCount, 1, "a second submit cannot start while the first upload is pending");
  const versionsBeforeUploadClick = versionCalls;
  await click(versionButton);
  assert.equal(versionCalls, versionsBeforeUploadClick, "opening versions is deferred while an upload owns the form controls");
  assert.equal(uploadForm, activeUploadForm, "a pending upload is not replaced by the versions render");
  assert.equal(activeUploadButton.disabled, true, "the active upload remains protected against duplicate submission");
  assert.equal(activeUploadProgress.hidden, false, "the active upload keeps its visible progress state");
  resolveUpload({});
  await uploadPromise;
  await duplicateUpload;
});
