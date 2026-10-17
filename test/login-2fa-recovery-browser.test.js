"use strict";

const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const { once } = require("node:events");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");
const { encryptSecret, generateRecoveryCodes, generateSecret, hotp } = require("../src/services/totp");

let chromium;
try { ({ chromium } = require("playwright")); } catch {}
const browserAvailable = Boolean(chromium && fs.existsSync(chromium.executablePath()));

const ROOT = path.resolve(__dirname, "..");

async function waitForServer(child, output) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error("Disposable Root.ark server stopped before startup");
    const match = output().match(/Servidor rodando em http:\/\/(?:\[[^\]]+\]|[^:\s]+):(\d+)/);
    if (match) return Number(match[1]);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("Disposable Root.ark server startup timed out");
}

test("browser login accepts single-use recovery proof and retains six-digit TOTP mode", { skip: !browserAvailable, timeout: 80_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-recovery-browser-"));
  const key = crypto.randomBytes(32);
  const secret = generateSecret();
  const recovery = generateRecoveryCodes(2);
  const user = {
    username: "recovery-fixture",
    password: bcrypt.hashSync("disposable-password", 4),
    role: "user",
    permissions: { listFiles: true },
    sessionVersion: 0,
    totpEnabled: true,
    totpSecret: encryptSecret(secret, key, "Root.ark/TOTP/recovery-fixture"),
    totpRecoveryHashes: recovery.hashes,
    totpLastUsedStep: Math.floor(Date.now() / 1000 / 30) - 1,
  };
  fs.mkdirSync(path.join(directory, "data"), { recursive: true });
  fs.writeFileSync(path.join(directory, "data", "users.local.json"), JSON.stringify([user]));
  fs.symlinkSync(path.join(ROOT, "public"), path.join(directory, "public"), "junction");

  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], {
    cwd: directory,
    env: {
      ...process.env,
      PORT: "0",
      JWT_SECRET: crypto.randomBytes(32).toString("hex"),
      SERVER_MASTER_KEY: key.toString("hex"),
      DB_ENABLED: "false",
      DB_WRITE_LEGACY_JSON: "true",
      UPLOAD_SCAN_ENABLED: "false",
      LOGIN_DELAY_BASE: "0",
      NODE_ENV: "test",
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout = (stdout + chunk.toString()).slice(-4096); });
  child.stderr.on("data", (chunk) => { stderr = (stderr + chunk.toString()).slice(-1024); });
  let browser;
  t.after(async () => {
    if (browser) await browser.close();
    if (child.exitCode === null) {
      child.kill();
      await Promise.race([once(child, "exit"), new Promise((resolve) => setTimeout(resolve, 2_000))]);
    }
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });

  let port;
  try { port = await waitForServer(child, () => stdout); }
  catch (error) { throw new Error(`${error.message}: ${stderr.replace(/\r?\n/g, " ").slice(0, 300)}`); }
  browser = await chromium.launch({ headless: true, executablePath: chromium.executablePath() });
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const page = await context.newPage();
  const baseUrl = `http://127.0.0.1:${port}`;

  async function enterChallenge() {
    await page.goto(baseUrl + "/login.html");
    await page.locator("#username").fill("recovery-fixture");
    await page.locator("#password").fill("disposable-password");
    await page.locator("#login-submit").click();
    await page.locator("#totp-form").waitFor({ state: "visible" });
    assert.equal(await page.locator("#totp-code").getAttribute("maxlength"), "6");
    assert.equal(await page.locator("#totp-code").getAttribute("pattern"), "[0-9]{6}");
    assert.equal(await page.locator("#totp-code").getAttribute("inputmode"), "numeric");
  }

  await enterChallenge();
  assert.equal(await page.locator("#use-recovery-code").count(), 1, "a separate accessible recovery action must exist");
  await page.locator("#use-recovery-code").click();
  assert.equal(await page.locator("#totp-code").getAttribute("inputmode"), "text");
  assert.equal(await page.locator("#totp-code").getAttribute("pattern"), null);
  assert.match(await page.locator("#totp-code-label").innerText(), /recupera/i);
  assert.equal(await page.evaluate(() => document.activeElement?.id), "totp-code");

  const challengeField = page.locator("#totp-code");
  await challengeField.fill(recovery.codes[0]);
  assert.equal(await challengeField.evaluate((field) => field.checkValidity()), true);
  const proofAccepted = page.waitForResponse((res) => res.url().endsWith("/auth/login/2fa"));
  await page.locator("#totp-form button[type=submit]").click();
  assert.equal((await proofAccepted).status(), 200);
  await page.waitForURL("**/index.html");
  assert.equal((await page.request.get(baseUrl + "/auth/me")).status(), 200);

  await context.clearCookies();
  await enterChallenge();
  await page.locator("#use-recovery-code").click();
  await challengeField.fill(recovery.codes[0]);
  const replayDenied = page.waitForResponse((res) => res.url().endsWith("/auth/login/2fa"));
  await page.locator("#totp-form button[type=submit]").click();
  assert.equal((await replayDenied).status(), 401, "used recovery code must be rejected");
  await page.locator("#auth-error").waitFor({ state: "visible" });
  assert.equal(await page.locator("#totp-form").isVisible(), true);

  await challengeField.fill("invalid-recovery");
  const invalidDenied = page.waitForResponse((res) => res.url().endsWith("/auth/login/2fa"));
  await page.locator("#totp-form button[type=submit]").click();
  assert.equal((await invalidDenied).status(), 401, "invalid recovery code reaches server generic rejection");

  await page.locator("#use-recovery-code").click();
  assert.equal(await page.locator("#totp-code").getAttribute("pattern"), "[0-9]{6}");
  assert.equal(await page.locator("#totp-code").getAttribute("maxlength"), "6");
  assert.equal(await page.locator("#totp-code").getAttribute("inputmode"), "numeric");
  assert.equal(await page.evaluate(() => document.activeElement?.id), "totp-code");
  await challengeField.fill(hotp(secret, Math.floor(Date.now() / 1000 / 30)));
  const totpAccepted = page.waitForResponse((res) => res.url().endsWith("/auth/login/2fa"));
  await page.locator("#totp-form button[type=submit]").click();
  assert.equal((await totpAccepted).status(), 200, "standard TOTP proof still authenticates");
  await page.waitForURL("**/index.html");
});
