"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

let chromium;
try { ({ chromium } = require("playwright")); } catch {}
const browserAvailable = Boolean(chromium && fs.existsSync(chromium.executablePath()));

const WORKSPACE = path.join(__dirname, "..", "public", "client", "rootark-workspace.js");

test("closing an unfinished image or PDF preview does not leak a late object URL", { skip: !browserAvailable, timeout: 30_000 }, async (t) => {
  const browser = await chromium.launch({ headless: true, executablePath: chromium.executablePath() });
  t.after(() => browser.close());
  const page = await browser.newPage();
  await page.setContent('<!doctype html><html lang="pt-BR"><body><div id="app-root"></div></body></html>');
  await page.evaluate(() => {
    window.WebSocket = undefined;
    window.__previewRequests = [];
    window.__createdUrls = [];
    window.__revokedUrls = [];
    const create = URL.createObjectURL.bind(URL);
    const revoke = URL.revokeObjectURL.bind(URL);
    URL.createObjectURL = (blob) => {
      const url = create(blob);
      window.__createdUrls.push(url);
      return url;
    };
    URL.revokeObjectURL = (url) => {
      window.__revokedUrls.push(url);
      return revoke(url);
    };
    window.RootarkUI = {
      getSession: async () => ({ username: "preview-fixture", role: "user", permissions: { listFiles: true } }),
      escape: (value) => String(value ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;").replace(/>/g, "&gt;"),
      formatBytes: (value) => String(value) + " B",
      formatDate: (value) => String(value),
      mount: (options) => { document.getElementById("app-root").innerHTML = options.content; },
      toast() {},
    };
    window.RootarkApi = {
      query: (route, params) => route + "?" + new URLSearchParams(params).toString(),
      async get(route) {
        if (route === "/folders") return [{ id: "root", name: "Root", isRoot: true }];
        if (route.startsWith("/list")) return [
          { name: "preview.png", folderId: "root", size: 10 },
          { name: "preview.pdf", folderId: "root", size: 10 },
        ];
        if (route.startsWith("/pending")) return [];
        if (route.startsWith("/preview/file/")) {
          return new Promise((resolve) => { window.__previewRequests.push({ route, resolve }); });
        }
        throw new Error("unexpected read");
      },
      async post() { return {}; },
    };
  });
  await page.addScriptTag({ path: WORKSPACE });
  for (const filename of ["preview.png", "preview.pdf"]) {
    await page.locator(`[data-action="preview-file"][data-name="${filename}"]`).click();
    await page.waitForFunction(() => window.__previewRequests.length > 0);
    await page.locator("dialog.preview-dialog").evaluate((element) => element.close());
    await page.locator("dialog.preview-dialog").waitFor({ state: "detached" });
    await page.evaluate(() => {
      const pending = window.__previewRequests.shift();
      pending.resolve(new Blob(["disposable"], { type: pending.route.includes(".pdf") ? "application/pdf" : "image/png" }));
    });
    await page.waitForTimeout(70);
  }
  const count = await page.evaluate(() => ({
    created: window.__createdUrls.length,
    revoked: window.__revokedUrls.length,
  }));
  assert.deepEqual(count, { created: 0, revoked: 0 }, "late preview completion must not allocate a Blob URL after close");

  await page.locator('[data-action="preview-file"][data-name="preview.png"]').click();
  await page.waitForFunction(() => window.__previewRequests.length > 0);
  await page.evaluate(() => {
    window.__previewRequests.shift().resolve(new Blob(["disposable"], { type: "image/png" }));
  });
  await page.locator("dialog.preview-dialog img").waitFor({ state: "attached" });
  await page.locator("dialog.preview-dialog button").click();
  await page.locator("dialog.preview-dialog").waitFor({ state: "detached" });
  const finalized = await page.evaluate(() => ({
    created: window.__createdUrls.length,
    revoked: window.__revokedUrls.length,
    sameUrl: window.__createdUrls[0] === window.__revokedUrls[0],
  }));
  assert.deepEqual(finalized, { created: 1, revoked: 1, sameUrl: true }, "a completed preview must release its object URL exactly once");
});
