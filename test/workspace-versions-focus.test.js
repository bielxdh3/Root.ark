"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");

test("workspace version and upload flows preserve state and explain upload retries", async () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "public", "client", "rootark-workspace.js"), "utf8");
  const rootListeners = new Map();
  const documentListeners = new Map();
  const windowListeners = new Map();
  const location = { hash: "", protocol: "http:", host: "rootark.test", pathname: "/index.html", search: "" };
  let historyReplaceUrl = "";
  let activeElement = null;
  const body = { matches() { return false; }, isContentEditable: false };
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
  let uploadFailureMessage = "";
  let uploadFailureAfterAcceptance = false;
  let partialUploadSuccessesBeforeFailure = null;
  let delayPartialUploadFailure = false;
  let rejectPartialUploadFailure;
  let pendingFetchCount = 0;
  let pendingFetchFailureMessage = "";
  let pendingFiles = [];
  let pendingMarkup = "";
  let pendingPanel = null;
  let pendingActions = [];
  let pendingHeading = null;
  let uploadMarkup = "";
  let uploadForm;
  let uploadFileInput;
  let uploadVersionComment;
  let uploadEncryptionLevel;
  let uploadPassword;
  let uploadExpiration;
  let uploadProgress;
  let uploadSubmitButton;
  let uploadToolbarButton;
  let filePickerOpenCount = 0;
  let folderSelect;
  let dialogCount = 0;
  let realtimeSocket;
  let deferFolderLoad = false;
  let resolveFolderLoad;
  let availableFolders = [{ id: "root", name: "Arquivos", isRoot: true }, { id: "archive", name: "Arquivo" }];
  let deferListLoad = false;
  let resolveListLoad;
  let nextWindowTimerId = 0;
  const windowTimers = new Map();
  const folderQueries = [];
  const observedUploadSettings = [];
  class TestWebSocket {
    constructor(url) { this.url = url; this.listeners = new Map(); realtimeSocket = this; }
    addEventListener(name, listener) { this.listeners.set(name, listener); }
    emit(name, event) { this.listeners.get(name)?.(event); }
    close() {}
  }
  const makeButton = (action, name, folder, id) => ({
    isConnected: true,
    dataset: { action, name, folder, id },
    closest(selector) { return selector === "[data-action]" ? this : null; },
    focus() { activeElement = this; },
  });
  const makePendingPanel = (markup) => {
    pendingMarkup = markup;
    pendingActions = Array.from(markup.matchAll(/data-action="([^"]+)" data-name="([^"]*)" data-folder="([^"]*)"/g), (match) => makeButton(match[1], match[2], match[3]));
    pendingHeading = { tagName: "H2", focus() { activeElement = this; } };
    const panel = {
      get outerHTML() { return pendingMarkup; },
      set outerHTML(value) {
        const focusWasInside = this.contains(activeElement);
        const nextPanel = makePendingPanel(value);
        pendingPanel = nextPanel;
        if (focusWasInside) activeElement = body;
      },
      contains(node) { return pendingActions.includes(node) || node === pendingHeading; },
      querySelectorAll(selector) { return selector === "[data-action]" ? pendingActions : []; },
      querySelector(selector) { return selector === "h2" ? pendingHeading : null; },
    };
    pendingPanel = panel;
    return panel;
  };
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
    const submitButton = { disabled: /<button[^>]*type="submit"[^>]*disabled/.test(uploadMarkup) };
    uploadSubmitButton = submitButton;
    uploadProgress = { hidden: true, textContent: "" };
    let selectedFiles = [];
    uploadFileInput = {
      isConnected: true, form: null, name: "files", tagName: "INPUT", type: "file", disabled: /<input[^>]*id="upload-files"[^>]*disabled/.test(uploadMarkup),
      get files() { return selectedFiles; },
      set files(value) { selectedFiles = value; },
      set value(value) { if (value === "") selectedFiles = []; },
      click() { filePickerOpenCount += 1; },
    };
    uploadVersionComment = { name: "versionComment", value: "", disabled: /<input[^>]*name="versionComment"[^>]*disabled/.test(uploadMarkup) };
    uploadEncryptionLevel = { name: "encryptionLevel", value: "none", disabled: /<select[^>]*name="encryptionLevel"[^>]*disabled/.test(uploadMarkup) };
    uploadPassword = { name: "password", value: "", disabled: /<input[^>]*name="password"[^>]*disabled/.test(uploadMarkup) };
    uploadExpiration = { name: "expiresInDays", value: "", disabled: /<select[^>]*name="expiresInDays"[^>]*disabled/.test(uploadMarkup) };
    const passwordRow = { hidden: true };
    const form = {
      id: "upload-form",
      tagName: "FORM",
      isConnected: true,
      elements: [uploadFileInput, uploadVersionComment, uploadEncryptionLevel, uploadPassword, uploadExpiration, submitButton],
      reset() {
        uploadFileInput.files = [];
        uploadVersionComment.value = "";
        uploadEncryptionLevel.value = "none";
        uploadPassword.value = "";
        uploadExpiration.value = "";
      },
      querySelector(selector) {
        if (selector === 'button[type="submit"]') return submitButton;
        if (selector === '[name="files"]') return uploadFileInput;
        if (selector === '[name="versionComment"]') return uploadVersionComment;
        if (selector === '[name="encryptionLevel"]') return uploadEncryptionLevel;
        if (selector === '[name="password"]') return uploadPassword;
        if (selector === '[name="expiresInDays"]') return uploadExpiration;
        if (selector === "#upload-password-row") return passwordRow;
        return null;
      },
    };
    uploadFileInput.form = form;
    uploadVersionComment.form = form;
    uploadEncryptionLevel.form = form;
    uploadPassword.form = form;
    uploadExpiration.form = form;
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
    querySelector(selector) {
      if (selector === 'details.search-advanced') return advancedDetails;
      if (selector === '[data-action="focus-upload"]') return uploadToolbarButton;
      return null;
    },
  };
  const document = {
    get activeElement() { return activeElement; },
    set activeElement(value) { activeElement = value; },
    forms: [],
    addEventListener(name, listener) { documentListeners.set(name, listener); },
    getElementById(id) {
      if (id === "app-root") return root;
      if (id === "upload-form") return uploadForm;
      if (id === "upload-files") return uploadFileInput;
      if (id === "upload-progress") return uploadProgress;
      if (id === "folder-select") return folderSelect;
      if (id === "pending-section") return pendingPanel;
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
    WebSocket: TestWebSocket,
    window: {
      addEventListener(name, listener) { windowListeners.set(name, listener); },
      dispatchEvent() {},
      WebSocket: TestWebSocket,
      setTimeout(callback, delay) { const id = ++nextWindowTimerId; windowTimers.set(id, { callback, delay }); return id; },
      clearTimeout(id) { windowTimers.delete(id); },
      location,
      history: { state: null, replaceState(_state, _title, url) { historyReplaceUrl = url; location.hash = url.includes("#") ? url.slice(url.indexOf("#")) : ""; } },
    },
  };
  context.window.RootarkApi = {
    query: (pathname, params) => {
      if (params && Object.hasOwn(params, "folderId")) folderQueries.push({ pathname, folderId: params.folderId });
      return pathname;
    },
    get: async (pathname) => {
      if (pathname === "/folders") {
        if (deferFolderLoad) return new Promise((resolve) => { resolveFolderLoad = () => { deferFolderLoad = false; resolve(availableFolders); }; });
        return availableFolders;
      }
      if (pathname === "/list") {
        if (deferListLoad) return new Promise((resolve) => { resolveListLoad = () => { deferListLoad = false; resolve([{ name: "example.txt", folderId: "root", size: 1 }]); }; });
        return [{ name: "example.txt", folderId: "root", size: 1 }];
      }
      if (pathname === "/pending") return (pendingFetchCount += 1, pendingFetchFailureMessage ? (() => { const message = pendingFetchFailureMessage; pendingFetchFailureMessage = ""; throw new Error(message); })() : pendingFiles);
      if (pathname.startsWith("/versions/")) return (versionCalls += 1, deferVersions ? new Promise((resolve) => { resolveVersions = resolve; }) : { fileName: "example.txt", versions: [] });
      return [];
    },
    post: async () => ({}),
    postForm: async (_pathname, form) => {
      uploadRequestCount += 1;
      observedUploadSettings.push({ encryptionLevel: form.get("encryptionLevel"), versionComment: form.get("versionComment") });
      if (partialUploadSuccessesBeforeFailure !== null) {
        if (partialUploadSuccessesBeforeFailure > 0) {
          partialUploadSuccessesBeforeFailure -= 1;
          const file = form.values.get("file");
          pendingFiles = pendingFiles.concat({ name: file.name, folderId: "root", size: file.size });
          return {};
        }
        partialUploadSuccessesBeforeFailure = null;
        if (delayPartialUploadFailure) {
          delayPartialUploadFailure = false;
          return new Promise((_resolve, reject) => { rejectPartialUploadFailure = reject; });
        }
        throw new Error("Não foi possível concluir a solicitação.");
      }
      if (uploadFailureMessage) {
        const message = uploadFailureMessage;
        uploadFailureMessage = "";
        throw new Error(message);
      }
      if (uploadFailureAfterAcceptance) {
        uploadFailureAfterAcceptance = false;
        const file = form.values.get("file");
        if (file) pendingFiles = pendingFiles.concat({ name: file.name, folderId: "root", size: file.size });
        throw new Error("Não foi possível concluir a solicitação.");
      }
      if (uploadDelay) return new Promise((resolve) => { resolveUpload = resolve; });
      const file = form.values.get("file");
      if (file) pendingFiles = pendingFiles.concat({ name: file.name, folderId: "root", size: file.size });
      return {};
    },
  };
  context.FormData = class TestFormData {
    constructor(form) {
      const value = (name, fallback) => form && form.querySelector('[name="' + name + '"]') ? form.querySelector('[name="' + name + '"]').value : fallback;
      this.values = new Map([["encryptionLevel", value("encryptionLevel", "none")], ["versionComment", value("versionComment", "")], ["password", value("password", "")], ["expiresInDays", value("expiresInDays", "")]]);
    }
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
    mount({ content, toolbar }) {
      const pendingIdIndex = content.indexOf('id="pending-section"');
      const pendingStart = pendingIdIndex < 0 ? -1 : content.lastIndexOf("<section", pendingIdIndex);
      const pendingEnd = pendingStart < 0 ? -1 : content.indexOf("</section>", pendingStart) + "</section>".length;
      if (pendingStart >= 0 && pendingEnd > pendingStart) {
        makePendingPanel(content.slice(pendingStart, pendingEnd));
      }
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
      folderSelect = content.includes('id="folder-select"') ? { id: "folder-select", value: content.includes('<option value="archive" selected>') ? "archive" : "root", disabled: /<select[^>]*id="folder-select"[^>]*disabled/.test(content) } : null;
      searchInput = content.includes('name="q" type="search"') ? makeSearchInput(searchForm) : null;
      if (searchForm && searchInput) searchForm.elements.push(searchInput);
      advancedSummary = content.includes("<summary>Filtros avançados</summary>") ? makeAdvancedSummary() : null;
      versionsHeading = content.includes('<h2 tabindex="-1">') ? { isConnected: true, focus() { activeElement = this; } } : null;
      uploadMarkup = content;
      uploadForm = content.includes('id="upload-form"') ? makeUploadForm() : null;
      const toolbarAction = toolbar && toolbar.match(/<button[^>]*data-action="focus-upload"[^>]*>/);
      uploadToolbarButton = toolbarAction ? { disabled: /\sdisabled(?:\s|>)/.test(toolbarAction[0]) } : null;
    },
    dialog() { dialogCount += 1; return Promise.resolve(null); },
    toast() {},
    redirectToLogin() {},
  };
  vm.runInNewContext(source, context);
  await new Promise((resolve) => setImmediate(resolve));

  const click = async (button) => rootListeners.get("click")({ target: { closest: () => button } });
  assert.ok(realtimeSocket, "the workspace connects the realtime transport");
  folderSelect.value = "archive";
  rootListeners.get("change")({ target: folderSelect });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(folderSelect.value, "archive", "the current folder is selected before its refresh begins");
  availableFolders = [{ id: "root", name: "Arquivos", isRoot: true }];
  const folderRefreshQueriesBeforeUpload = folderQueries.length;
  deferFolderLoad = true;
  realtimeSocket.emit("message", { data: JSON.stringify({ event: "data:changed" }) });
  const realtimeTimer = Array.from(windowTimers.entries()).find(([, timer]) => timer.delay === 150);
  assert.ok(realtimeTimer, "a realtime data change schedules a refresh");
  windowTimers.delete(realtimeTimer[0]);
  realtimeTimer[1].callback();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(typeof resolveFolderLoad, "function", "the realtime refresh is held while fetching folders");
  uploadDelay = true;
  uploadFileInput.files = [{ name: "upload-during-realtime-refresh.txt", size: 10 }];
  const formDuringRealtimeRefresh = uploadForm;
  const uploadDuringRealtimeRefresh = rootListeners.get("submit")({ target: uploadForm, preventDefault() {} });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(typeof resolveUpload, "function", "the upload remains pending while the earlier folder refresh is in flight");
  resolveFolderLoad();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(uploadForm, formDuringRealtimeRefresh, "an earlier realtime refresh cannot rerender and discard a newly started upload");
  assert.ok(folderQueries.slice(folderRefreshQueriesBeforeUpload).some((query) => query.pathname === "/upload" && query.folderId === "archive"), "the upload stays targeted at the folder selected when the batch began");
  resolveUpload({});
  await uploadDuringRealtimeRefresh;
  uploadDelay = false;
  assert.ok(folderQueries.slice(folderRefreshQueriesBeforeUpload).some((query) => query.pathname === "/list" && query.folderId === "archive"), "success refreshes the same folder targeted by the active upload");
  assert.equal(uploadToolbarButton && uploadToolbarButton.disabled, false, "the toolbar upload action is available again after success");
  assert.equal(uploadSubmitButton.disabled, false, "the current form submit action is available again after the success refresh");
  const deferredFolderRetry = Array.from(windowTimers.entries()).find(([, timer]) => timer.delay === 300);
  assert.ok(deferredFolderRetry, "the realtime refresh remains pending until the upload completes");
  windowTimers.delete(deferredFolderRetry[0]);
  deferredFolderRetry[1].callback();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(folderSelect.value, "root", "a deferred folder refresh reconciles a removed current folder after the upload");

  availableFolders = [{ id: "root", name: "Arquivos", isRoot: true }, { id: "archive", name: "Arquivo" }];
  realtimeSocket.emit("message", { data: JSON.stringify({ event: "data:changed" }) });
  const restoredFolderTimer = Array.from(windowTimers.entries()).find(([, timer]) => timer.delay === 150);
  assert.ok(restoredFolderTimer, "restoring the fixture folder schedules a refresh");
  windowTimers.delete(restoredFolderTimer[0]);
  restoredFolderTimer[1].callback();
  await new Promise((resolve) => setImmediate(resolve));
  assert.ok(folderButton, "the folder focus fixture is available again after restoring the disposable folder");

  deferListLoad = true;
  realtimeSocket.emit("message", { data: JSON.stringify({ event: "data:changed" }) });
  const listRefreshTimer = Array.from(windowTimers.entries()).find(([, timer]) => timer.delay === 150);
  assert.ok(listRefreshTimer, "a second realtime update schedules a list refresh");
  windowTimers.delete(listRefreshTimer[0]);
  listRefreshTimer[1].callback();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(typeof resolveListLoad, "function", "the route refresh pauses while the file list is loading");
  assert.equal(uploadFileInput.disabled, true, "upload selection is disabled while a workspace list refresh is pending");
  assert.equal(uploadToolbarButton.disabled, true, "the toolbar action is disabled while a workspace list refresh is pending");
  const uploadsBeforeLoadingAttempt = uploadRequestCount;
  const fileInputDuringListLoad = uploadFileInput;
  await rootListeners.get("submit")({ target: uploadForm, preventDefault() {} });
  assert.equal(uploadRequestCount, uploadsBeforeLoadingAttempt, "an upload cannot begin while its workspace is loading");
  resolveListLoad();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(uploadFileInput.disabled, false, "upload selection is enabled again after the list refresh completes");
  assert.equal(fileInputDuringListLoad.isConnected, false, "the completed refresh replaces its temporary loading view");

  assert.ok(versionButton, `file actions should be restored after the list refresh; selected=${folderSelect && folderSelect.value}; search=${searchInput && searchInput.value}; files=${JSON.stringify(availableFolders)}`);
  versionButton.focus();
  deferVersions = false;
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

  const uploadRequestsBeforeHeldBatch = uploadRequestCount;
  const heldSettingsStart = observedUploadSettings.length;
  uploadVersionComment.value = "comentário enviado";
  uploadEncryptionLevel.value = "server-key";
  rootListeners.get("change")({ target: uploadEncryptionLevel });
  uploadDelay = true;
  uploadFileInput.files = [{ name: "synthetic-upload.txt", size: 10 }];
  const activeUploadForm = uploadForm;
  const activeUploadButton = uploadSubmitButton;
  const activeUploadProgress = uploadProgress;
  let submitPrevented = false;
  const uploadPromise = rootListeners.get("submit")({ target: activeUploadForm, preventDefault() { submitPrevented = true; } });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(submitPrevented, true);
  assert.equal(uploadRequestCount, uploadRequestsBeforeHeldBatch + 1);
  assert.equal(uploadVersionComment.disabled, true, "version comments cannot be changed after the upload starts");
  assert.equal(uploadEncryptionLevel.disabled, true, "encryption settings cannot be changed after the upload starts");
  assert.equal(uploadPassword.disabled, true, "encryption passwords cannot be changed after the upload starts");
  assert.equal(uploadExpiration.disabled, true, "expiration settings cannot be changed after the upload starts");
  assert.equal(activeUploadButton.disabled, true);
  assert.equal(activeUploadProgress.hidden, false);
  const duplicateUpload = rootListeners.get("submit")({ target: activeUploadForm, preventDefault() {} });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(uploadRequestCount, uploadRequestsBeforeHeldBatch + 1, "a second submit cannot start while the first upload is pending");
  const versionsBeforeUploadClick = versionCalls;
  await click(versionButton);
  assert.equal(versionCalls, versionsBeforeUploadClick, "opening versions is deferred while an upload owns the form controls");
  assert.equal(uploadForm, activeUploadForm, "a pending upload is not replaced by the versions render");
  assert.equal(activeUploadButton.disabled, true, "the active upload remains protected against duplicate submission");
  assert.equal(activeUploadProgress.hidden, false, "the active upload keeps its visible progress state");
  resolveUpload({});
  await uploadPromise;
  await duplicateUpload;
  assert.equal(observedUploadSettings[heldSettingsStart].versionComment, "comentário enviado", "the request uses the settings captured when the upload began");
  assert.equal(observedUploadSettings[heldSettingsStart].encryptionLevel, "server-key", "the request keeps its original encryption selection");
  assert.equal(uploadVersionComment.value, "", "settings reset only after the successful upload completes");
  assert.equal(uploadEncryptionLevel.value, "none", "the next upload begins with the default encryption selection");
  assert.equal(uploadVersionComment.disabled, false, "comment editing is available for the next upload");

  uploadDelay = false;
  const uploadRequestsBeforeRetry = uploadRequestCount;
  const selectedFile = { name: "retry-upload.txt", size: 10 };
  uploadFileInput.files = [selectedFile];
  uploadFailureMessage = "Não foi possível concluir a solicitação.";
  await rootListeners.get("submit")({ target: uploadForm, preventDefault() {} });
  assert.equal(uploadFileInput.files[0], selectedFile, "a failed file-input upload keeps the selected file available");
  assert.match(uploadProgress.textContent, /^Falha no envio\. A seleção foi mantida\./);
  assert.match(uploadProgress.textContent, /tente novamente apenas se o arquivo não aparecer na lista/);
  assert.equal(uploadSubmitButton.disabled, false, "the submit button is re-enabled after a failed upload");

  await rootListeners.get("submit")({ target: uploadForm, preventDefault() {} });
  assert.equal(uploadRequestCount, uploadRequestsBeforeRetry + 2, "retrying the retained file starts a new upload");
  assert.equal(uploadFileInput.files.length, 0, "the file selection is cleared only after the retry succeeds");
  assert.equal(uploadFileInput.disabled, false, "the upload file input is re-enabled after success");

  const responseLostFile = { name: "accepted-response-lost.txt", size: 10 };
  uploadFileInput.files = [responseLostFile];
  uploadFailureAfterAcceptance = true;
  await rootListeners.get("submit")({ target: uploadForm, preventDefault() {} });
  assert.match(pendingMarkup, /accepted-response-lost\.txt/, "an upload accepted before a lost response appears in refreshed pending files");
  assert.equal(uploadFileInput.files[0], responseLostFile, "an ambiguous single-file failure keeps the selection for inspection");
  assert.match(uploadProgress.textContent, /tente novamente apenas se o arquivo não aparecer na lista/);

  uploadFailureMessage = "Não foi possível concluir a solicitação.";
  const dropzone = { classList: { remove() {} } };
  let dropPrevented = false;
  rootListeners.get("drop")({
    target: { closest(selector) { return selector === "#upload-dropzone" ? dropzone : null; } },
    dataTransfer: { files: [{ name: "dropzone-retry.txt", size: 10 }] },
    preventDefault() { dropPrevented = true; },
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(dropPrevented, true);
  assert.match(uploadProgress.textContent, /Confira as pendências atualizadas e reenvie somente os arquivos que não aparecem na lista/);

  const independentPickerFile = { name: "independent-picker-selection.txt", size: 10 };
  const successfulDropFile = { name: "successful-drop.txt", size: 10 };
  uploadFileInput.files = [independentPickerFile];
  const uploadFormBeforeSuccessfulDrop = uploadForm;
  rootListeners.get("drop")({
    target: { closest(selector) { return selector === "#upload-dropzone" ? dropzone : null; } },
    dataTransfer: { files: [successfulDropFile] },
    preventDefault() {},
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(uploadForm, uploadFormBeforeSuccessfulDrop, "a successful drop refreshes pending files without replacing the separate picker selection");
  assert.equal(uploadFileInput.files[0], independentPickerFile, "a successful dropped batch preserves a separate picker selection");
  assert.match(pendingMarkup, /successful-drop\.txt/, "the successful dropped file appears in pending approvals");
  assert.match(uploadProgress.textContent, /A seleção do campo foi mantida; ela não fez parte deste envio/);

  const preselectedFile = { name: "already-selected-in-input.txt", size: 10 };
  uploadFileInput.files = [preselectedFile];
  partialUploadSuccessesBeforeFailure = 1;
  delayPartialUploadFailure = true;
  rootListeners.get("drop")({
    target: { closest(selector) { return selector === "#upload-dropzone" ? dropzone : null; } },
    dataTransfer: { files: [{ name: "accepted-drop.txt", size: 10 }, { name: "failed-drop.txt", size: 10 }] },
    preventDefault() {},
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(typeof rejectPartialUploadFailure, "function", "the later dropped file is held while the upload input already has a separate selection");
  rejectPartialUploadFailure(new Error("Não foi possível concluir a solicitação."));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(uploadFileInput.files[0], preselectedFile, "a partial drop failure preserves a separate file-input selection");
  assert.match(uploadProgress.textContent, /A seleção independente do campo foi mantida/);
  assert.match(uploadProgress.textContent, /Confira as pendências atualizadas e arraste somente os arquivos restantes que não aparecem na lista/);

  deferVersions = false;
  await click(versionButton);
  assert.ok(closeButton, "the active batch can begin while an already-open versions panel is visible");
  const pendingFetchesBeforePartialBatch = pendingFetchCount;
  const folderQueriesBeforePartialBatch = folderQueries.length;
  const uploadFormBeforePartialBatch = uploadForm;
  const focusedPendingActionBeforePartialBatch = pendingActions.find((action) => action.dataset.name === "accepted-response-lost.txt");
  assert.ok(focusedPendingActionBeforePartialBatch, "the pending panel has a keyboard action to focus before the next upload finishes");
  partialUploadSuccessesBeforeFailure = 1;
  delayPartialUploadFailure = true;
  const acceptedFile = { name: "accepted-before-failure.txt", size: 10 };
  const unacceptedFile = { name: "failed-after-first.txt", size: 10 };
  uploadFileInput.files = [acceptedFile, unacceptedFile];
  const partialUploadPromise = rootListeners.get("submit")({ target: uploadForm, preventDefault() {} });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(typeof rejectPartialUploadFailure, "function", "the later upload is held while focus moves to a pending action");
  assert.equal(uploadFileInput.disabled, true, "choosing another file is disabled during an upload batch");
  const pickerOpensBeforeActiveUploadClick = filePickerOpenCount;
  await click(makeButton("focus-upload", "", "", ""));
  assert.equal(filePickerOpenCount, pickerOpensBeforeActiveUploadClick, "the choose-files action cannot open a picker during an upload");
  assert.equal(folderSelect.disabled, true, "folder switching is disabled while an upload batch is active");
  folderSelect.value = "archive";
  rootListeners.get("change")({ target: folderSelect });
  assert.equal(folderSelect.value, "root", "an attempted dropdown switch is restored to the upload folder");
  const folderListRequestsBeforeNavigationAttempt = folderQueries.filter((query) => query.pathname === "/list").length;
  await click(folderButton);
  assert.equal(folderQueries.filter((query) => query.pathname === "/list").length, folderListRequestsBeforeNavigationAttempt, "folder-card navigation cannot replace the active upload view");
  const dialogsBeforeFolderMutation = dialogCount;
  await click(makeButton("create-folder", "", "", ""));
  assert.equal(dialogCount, dialogsBeforeFolderMutation, "folder creation cannot change the active upload destination");
  const uploadFormBeforeNavigation = uploadForm;
  const dialogCountBeforeWorkspaceActions = dialogCount;
  await click(closeButton);
  assert.equal(uploadForm, uploadFormBeforeNavigation, "closing version history cannot rerender and discard an active upload");
  await click(makeButton("approve-file", "pending.txt", "root", ""));
  await click(makeButton("reject-file", "pending.txt", "root", ""));
  assert.equal(dialogCount, dialogCountBeforeWorkspaceActions, "approve and reject actions are deferred until the active upload completes");
  location.hash = "#/unexpected-route";
  await windowListeners.get("hashchange")();
  assert.equal(historyReplaceUrl, "/index.html", "unknown hash routes are reverted instead of rerendering the active files workspace");
  assert.equal(uploadForm, uploadFormBeforeNavigation, "an unknown hash cannot discard an active upload selection");
  location.hash = "#/history";
  await windowListeners.get("hashchange")();
  assert.equal(historyReplaceUrl, "/index.html", "workspace route changes are reverted while an upload is active");
  assert.equal(location.hash, "", "the current files route stays selected during upload");
  assert.equal(uploadForm, uploadFormBeforeNavigation, "navigation cannot discard the upload form or its retry selection");
  let navigationClickPrevented = false;
  const sidebarLink = { isConnected: true };
  documentListeners.get("click")({
    target: { closest(selector) { return selector.includes(".sidebar a[href]") ? sidebarLink : null; } },
    preventDefault() { navigationClickPrevented = true; },
  });
  assert.equal(navigationClickPrevented, true, "sidebar links cannot unload the workspace during an upload");
  let logoutClickStopped = false;
  const logoutButton = { isConnected: true, dataset: { action: "logout" } };
  documentListeners.get("click")({
    target: { closest(selector) { return selector.includes('[data-action="logout"]') ? logoutButton : null; } },
    preventDefault() {},
    stopPropagation() { logoutClickStopped = true; },
  });
  assert.equal(logoutClickStopped, true, "the capture guard prevents the UI logout listener from running");
  const uploadFormBeforeSearch = uploadForm;
  await rootListeners.get("submit")({ target: searchForm, preventDefault() {} });
  assert.equal(uploadForm, uploadFormBeforeSearch, "search submission cannot rerender and discard the upload selection");
  await click(makeButton("clear-search", "", "", ""));
  assert.equal(uploadForm, uploadFormBeforeSearch, "clearing search cannot rerender and discard the upload selection");
  let unloadPrevented = false;
  const beforeUnloadEvent = { preventDefault() { unloadPrevented = true; } };
  windowListeners.get("beforeunload")(beforeUnloadEvent);
  assert.equal(unloadPrevented, true, "external page navigation warns before discarding an in-flight upload");
  focusedPendingActionBeforePartialBatch.focus();
  rejectPartialUploadFailure(new Error("Não foi possível concluir a solicitação."));
  await partialUploadPromise;
  const partialBatchFolderQueries = folderQueries.slice(folderQueriesBeforePartialBatch);
  assert.ok(partialBatchFolderQueries.some((query) => query.pathname === "/pending/repair" && query.folderId === "root"), "pending repair remains scoped to the folder where the batch started");
  assert.ok(partialBatchFolderQueries.some((query) => query.pathname === "/pending" && query.folderId === "root"), "pending refresh remains scoped to the folder where the batch started");
  assert.equal(partialBatchFolderQueries.some((query) => query.folderId === "archive"), false, "no request in the active batch switches to a different folder");
  assert.equal(pendingFetchCount, pendingFetchesBeforePartialBatch + 1, "a failed batch refreshes pending files after an earlier file succeeds");
  assert.match(pendingMarkup, /accepted-before-failure\.txt/, "the pending panel shows the file accepted before the later failure");
  const refreshedPendingAction = pendingActions.find((action) => action.dataset.name === "accepted-response-lost.txt");
  assert.notEqual(refreshedPendingAction, focusedPendingActionBeforePartialBatch, "the refreshed pending action is a replacement DOM node");
  assert.equal(activeElement, refreshedPendingAction, "keyboard focus returns to the equivalent pending action after refresh");
  assert.equal(uploadForm, uploadFormBeforePartialBatch, "refreshing pending files does not rerender or discard the upload form");
  assert.equal(uploadFileInput.files.length, 0, "a partially accepted batch is cleared to prevent duplicate retries");
  assert.equal(uploadFileInput.disabled, false, "the file input is re-enabled after a partial failure");
  assert.match(uploadProgress.textContent, /1 arquivo foi enviado para aprovação/);
  assert.match(uploadProgress.textContent, /Confira as pendências atualizadas e selecione somente os arquivos restantes que não aparecem na lista/);

  const disappearingPendingAction = pendingActions.find((action) => action.dataset.name === "accepted-before-failure.txt");
  assert.ok(disappearingPendingAction, "the refreshed panel includes the accepted file action before its concurrent removal");
  disappearingPendingAction.focus();
  pendingFiles = pendingFiles.filter((file) => file.name !== "accepted-before-failure.txt");
  uploadFailureMessage = "Falha temporária.";
  uploadFileInput.files = [{ name: "retry-after-pending-removal.txt", size: 10 }];
  await rootListeners.get("submit")({ target: uploadForm, preventDefault() {} });
  assert.equal(activeElement, pendingHeading, "when the focused pending row disappears, focus moves to the pending section heading");

  pendingFetchFailureMessage = "Lista indisponível.";
  uploadFailureMessage = "Falha temporária.";
  uploadFileInput.files = [{ name: "retry-after-pending-refresh-fails.txt", size: 10 }];
  await rootListeners.get("submit")({ target: uploadForm, preventDefault() {} });
  assert.match(uploadProgress.textContent, /atualize a tela e confira a lista antes de reenviar/);
});
