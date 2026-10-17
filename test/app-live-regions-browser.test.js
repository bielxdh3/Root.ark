"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

let chromium;
try { ({ chromium } = require("playwright")); } catch {}
const browserAvailable = Boolean(chromium && fs.existsSync(chromium.executablePath()));

const PUBLIC = path.join(__dirname, "..", "public");
const APP_PAGES = ["index.html", "dashboard.html", "admin.html", "audit.html", "backups.html"];

test("route remounts stay outside live regions while toast announcements remain accessible", { skip: !browserAvailable, timeout: 20_000 }, async (t) => {
  const browser = await chromium.launch({ headless: true, executablePath: chromium.executablePath() });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const documents = Object.fromEntries(APP_PAGES.map((filename) => [filename, fs.readFileSync(path.join(PUBLIC, filename), "utf8")]));
  const announcements = await page.evaluate((sources) => {
    return Object.entries(sources).map(([name, source]) => {
      const doc = new DOMParser().parseFromString(source, "text/html");
      const appRoot = doc.querySelector("#app-root");
      return { name, live: appRoot && appRoot.getAttribute("aria-live") };
    });
  }, documents);
  assert.deepEqual(announcements.map((entry) => entry.live), APP_PAGES.map(() => null), "full-page rerenders must not be announced as updates");

  await page.setContent('<!doctype html><html lang="pt-BR"><body><div id="app-root"></div></body></html>');
  await page.addScriptTag({ path: path.join(PUBLIC, "client", "rootark-ui.js") });
  await page.evaluate(() => {
    window.RootarkUI.mount({
      user: { username: "fixture", role: "user", permissions: { listFiles: true } },
      content: '<p id="focused-status" role="status">Carregando…</p>',
    });
  });
  assert.equal(await page.locator("#toast-region").getAttribute("aria-live"), "polite");
  assert.equal(await page.locator("#focused-status").getAttribute("role"), "status");
});
