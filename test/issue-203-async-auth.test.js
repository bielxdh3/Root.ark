"use strict";

const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const test = require("node:test");
const registerAuthRoutes = require("../src/routes/auth");
const { encryptSecret, generateRecoveryCodes, generateRecoveryCodesAsync, generateSecret, verifyRecoveryCode, verifyRecoveryCodeAsync } = require("../src/services/totp");

let counter = 0;

function response() {
  return {
    code: 200, body: undefined, cookies: {}, headers: {},
    status(code) { this.code = code; return this; },
    json(body) { this.body = body; return this; },
    end() { return this; },
    cookie(name, value) { this.cookies[name] = value; return this; },
    clearCookie() { return this; },
    setHeader(name, value) { this.headers[name.toLowerCase()] = String(value); return this; },
  };
}

function createHarness(users, { onCompare } = {}) {
  const routes = new Map();
  const app = { post(path, ...h) { routes.set(`POST ${path}`, h); }, get(path, ...h) { routes.set(`GET ${path}`, h); } };
  const key = Buffer.alloc(32, 7);
  const stats = { compareCalls: 0, compareSyncCalls: 0 };
  const countingBcrypt = {
    compare: async (...args) => { stats.compareCalls += 1; const result = await bcrypt.compare(...args); if (onCompare) onCompare(); return result; },
    compareSync: (...args) => { stats.compareSyncCalls += 1; return bcrypt.compareSync(...args); },
  };
  registerAuthRoutes(app, {
    authenticate(req, res, next) { next(); },
    auditLog() {},
    bcrypt: countingBcrypt,
    checkAnomalies() {},
    getAuditActor: (req, fallback = "system") => ({ username: fallback, ip: req?.ip || "unknown" }),
    getTotpKey: () => key,
    jwt,
    jwtSecret: "s".repeat(48),
    loadUsers: () => users,
    saveUsers: (next) => { users.splice(0, users.length, ...JSON.parse(JSON.stringify(next))); },
    logAnalyticsEvent() {},
    normalizeUserPermissions: (u) => u.permissions || {},
    qrcode: { toDataURL: async (uri) => `qr:${uri}` },
    requirePermission: () => (_req, _res, next) => next(),
    sessionCookieOptions: { httpOnly: true },
  });
  async function call(path, body, ip, extra = {}) {
    const req = { body, headers: {}, method: "POST", path, ip, params: {}, ...extra };
    const res = response();
    for (const handler of routes.get(`POST ${path}`)) await handler(req, res, () => {});
    return res;
  }
  return { call, key, stats, users };
}

function withEnv(values, fn) {
  const previous = {};
  for (const [name, value] of Object.entries(values)) { previous[name] = process.env[name]; process.env[name] = value; }
  const restore = () => { for (const [name, value] of Object.entries(previous)) { if (value === undefined) delete process.env[name]; else process.env[name] = value; } };
  return Promise.resolve().then(fn).finally(restore);
}

test("async recovery verification matches the sync implementation", async () => {
  const { codes, hashes } = generateRecoveryCodes(2);
  assert.equal(await verifyRecoveryCodeAsync(codes[0], hashes[0]), verifyRecoveryCode(codes[0], hashes[0]));
  assert.equal(await verifyRecoveryCodeAsync(codes[0], hashes[0]), true);
  assert.equal(await verifyRecoveryCodeAsync(codes[0], hashes[1]), false);
  assert.equal(await verifyRecoveryCodeAsync("nonsense", hashes[0]), false);
  assert.equal(await verifyRecoveryCodeAsync(codes[0], "bad"), false);
});

test("async recovery-code generation preserves legacy encoding and scrypt hash bytes", async () => {
  const makeDeterministicRandom = () => {
    let nextByte = 0;
    return (size) => {
      const bytes = Buffer.alloc(size);
      for (let index = 0; index < size; index += 1) bytes[index] = nextByte++ & 0xff;
      return bytes;
    };
  };
  const synchronous = generateRecoveryCodes(2, makeDeterministicRandom());
  const asynchronous = await generateRecoveryCodesAsync(2, makeDeterministicRandom());
  assert.deepEqual(asynchronous, synchronous);
});

test("concurrent wrong-password logins from one IP cannot exceed the rate limit before blocking", async () => {
  await withEnv({ LOGIN_RATE_LIMIT_MAX: "5", LOGIN_BLOCK_THRESHOLD: "10", LOGIN_DELAY_BASE: "0", LOGIN_RATE_LIMIT_WINDOW: "60" }, async () => {
    const name = `c203a${++counter}`;
    const harness = createHarness([{ username: name, password: bcrypt.hashSync("right-password", 4), role: "user", permissions: {}, sessionVersion: 0 }]);
    const ip = `10.203.0.${counter}`;
    const results = await Promise.all(Array.from({ length: 40 }, () => harness.call("/auth/login", { username: name, password: "wrong" }, ip)));
    assert.equal(harness.stats.compareSyncCalls, 0);
    assert.ok(harness.stats.compareCalls <= 5, `password checks started: ${harness.stats.compareCalls}`);
    assert.equal(results.filter((r) => r.code === 401).length, harness.stats.compareCalls);
    assert.equal(results.filter((r) => r.code === 429).length, 40 - harness.stats.compareCalls);
    // Reservations are fully released: the IP stays limited by recorded failures (not stuck by leaked pending counters).
    const after = await harness.call("/auth/login", { username: name, password: "right-password" }, ip);
    assert.equal(after.code, 429);
  });
});

test("concurrent wrong-password logins across many IPs cannot exceed the per-username block threshold", async () => {
  await withEnv({ LOGIN_RATE_LIMIT_MAX: "5", LOGIN_BLOCK_THRESHOLD: "10", LOGIN_DELAY_BASE: "0", LOGIN_RATE_LIMIT_WINDOW: "60" }, async () => {
    const name = `c203b${++counter}`;
    const harness = createHarness([{ username: name, password: bcrypt.hashSync("right-password", 4), role: "user", permissions: {}, sessionVersion: 0 }]);
    const results = await Promise.all(Array.from({ length: 40 }, (_, i) => harness.call("/auth/login", { username: name, password: "wrong" }, `10.204.${counter}.${i + 1}`)));
    assert.ok(harness.stats.compareCalls <= 10, `password checks started: ${harness.stats.compareCalls}`);
    assert.ok(results.every((r) => r.code === 401 || r.code === 429));
    const correct = await harness.call("/auth/login", { username: name, password: "right-password" }, `10.205.${counter}.1`);
    assert.equal(correct.code, 429);
  });
});

test("a successful async login releases its reservation and still logs in", async () => {
  await withEnv({ LOGIN_RATE_LIMIT_MAX: "5", LOGIN_BLOCK_THRESHOLD: "10", LOGIN_DELAY_BASE: "0", TOTP_POLICY: "optional" }, async () => {
    const name = `c203c${++counter}`;
    const harness = createHarness([{ username: name, password: bcrypt.hashSync("right-password", 4), role: "user", permissions: {}, sessionVersion: 0 }]);
    const ip = `10.206.0.${counter}`;
    for (let i = 0; i < 12; i += 1) {
      const res = await harness.call("/auth/login", { username: name, password: "right-password" }, ip);
      assert.equal(res.code, 200, `attempt ${i}`);
      assert.ok(res.body.token);
    }
  });
});

test("two concurrent 2FA logins with the same recovery code cannot both succeed", async () => {
  await withEnv({ LOGIN_DELAY_BASE: "0", TOTP_POLICY: "optional" }, async () => {
    const name = `c203d${++counter}`;
    const users = [];
    const harness = createHarness(users);
    const secret = generateSecret();
    const recovery = generateRecoveryCodes();
    users.push({
      username: name, password: bcrypt.hashSync("right-password", 4), role: "user", permissions: {}, sessionVersion: 0,
      totpEnabled: true, totpSecret: encryptSecret(secret, harness.key, `Root.ark/TOTP/${name}`), totpRecoveryHashes: recovery.hashes, totpLastUsedStep: null,
    });
    const ip = `10.207.0.${counter}`;
    const c1 = await harness.call("/auth/login", { username: name, password: "right-password" }, ip);
    const c2 = await harness.call("/auth/login", { username: name, password: "right-password" }, ip);
    assert.ok(c1.body.challengeId && c2.body.challengeId);
    const code = recovery.codes[3];
    const [r1, r2] = await Promise.all([
      harness.call("/auth/login/2fa", { challengeId: c1.body.challengeId, code }, ip),
      harness.call("/auth/login/2fa", { challengeId: c2.body.challengeId, code }, ip),
    ]);
    assert.deepEqual([r1.code, r2.code].sort(), [200, 401]);
    assert.equal(users[0].totpRecoveryHashes.length, 9);
    assert.equal(harness.stats.compareSyncCalls, 0);
  });
});

// ---- WebDAV verified-credential cache / coalescing (real server process) ----
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const crypto = require("node:crypto");
const ROOT = path.resolve(__dirname, "..");

function freePort() {
  return new Promise((resolve, reject) => {
    const l = net.createServer();
    l.once("error", reject);
    l.listen(0, "127.0.0.1", () => { const p = l.address().port; l.close(() => resolve(p)); });
  });
}
function dav(port, authorization) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: "/dav", method: "PROPFIND", headers: { authorization, depth: "0" }, agent: false }, (res) => {
      res.resume(); res.on("end", () => resolve(res.statusCode));
    });
    req.once("error", reject);
    req.end();
  });
}
const basic = (u, p) => `Basic ${Buffer.from(`${u}:${p}`).toString("base64")}`;

async function withDavServer(fn) {
  const base = process.platform === "win32" ? process.env.USERPROFILE : os.tmpdir();
  const dir = fs.mkdtempSync(path.join(base, "rootark-203-dav-"));
  fs.mkdirSync(path.join(dir, "data")); fs.mkdirSync(path.join(dir, "uploads"));
  const usersFile = path.join(dir, "data", "users.json");
  const writeUsers = (patch = {}, password = "password", file = usersFile) => fs.writeFileSync(file, JSON.stringify([{ username: "agent", password: bcrypt.hashSync(password, 10), role: "admin", permissions: { upload: true }, sessionVersion: 0, ...patch }]));
  writeUsers();
  try { fs.symlinkSync(path.join(ROOT, "public"), path.join(dir, "public"), "junction"); } catch {}
  const port = await freePort();
  const env = { ...process.env, NODE_ENV: "test", PORT: String(port), DB_ENABLED: "false", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", WEBDAV_ENABLED: "true", LOGIN_DELAY_BASE: "0", UPLOAD_SCAN_ENABLED: "false", CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume", JWT_SECRET: crypto.randomBytes(48).toString("base64url") };
  const hook = path.join(dir, "hook.js");
  fs.writeFileSync(hook, `const fs=require("fs");const b=require(${JSON.stringify(path.join(ROOT, "node_modules", "bcryptjs"))});const c=b.compare;b.compare=async function(...a){const r=await c.apply(this,a);const t=${JSON.stringify(path.join(dir, "mutate.json"))};if(fs.existsSync(t)){fs.writeFileSync(${JSON.stringify(path.join(dir, "data", "users.local.json"))},fs.readFileSync(t));fs.unlinkSync(t);}return r;};`);
  const child = spawn(process.execPath, ["-r", hook, path.join(ROOT, "server.js")], { cwd: dir, env, stdio: "ignore", windowsHide: true });
  try {
    for (let i = 0; i < 150; i += 1) {
      try { await new Promise((res, rej) => { http.get({ host: "127.0.0.1", port, path: "/login.html", agent: false }, (r) => { r.resume(); r.on("end", res); }).once("error", rej); }); break; } catch { await new Promise((r) => setTimeout(r, 40)); }
    }
    await fn({ port, writeUsers, localUsers: path.join(dir, "data", "users.local.json"), dir });
  } finally {
    await new Promise((resolve) => { if (child.exitCode !== null) return resolve(); child.once("exit", resolve); child.kill(); });
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test("20 concurrent WebDAV requests with the correct password all succeed; wrong passwords stay limited", { timeout: 60_000 }, async () => {
  await withDavServer(async ({ port }) => {
    const ok = await Promise.all(Array.from({ length: 20 }, () => dav(port, basic("agent", "password"))));
    assert.deepEqual(ok, Array(20).fill(207));
    // Cached now: still fine in parallel again.
    assert.deepEqual(await Promise.all(Array.from({ length: 20 }, () => dav(port, basic("agent", "password")))), Array(20).fill(207));
    // Distinct wrong passwords cannot all be checked: at most 5 get 401, the rest 429.
    const bad = await Promise.all(Array.from({ length: 20 }, (_, i) => dav(port, basic("agent", `wrong-${i}`))));
    assert.ok(bad.filter((c) => c === 401).length <= 5, JSON.stringify(bad));
    assert.ok(bad.includes(429));
  });
});

test("WebDAV credential cache is invalidated immediately by password change and by disabling the user", { timeout: 60_000 }, async () => {
  await withDavServer(async ({ port, writeUsers, localUsers }) => {
    assert.equal(await dav(port, basic("agent", "password")), 207);
    writeUsers({}, "new-password-value", localUsers);
    assert.equal(await dav(port, basic("agent", "password")), 401);
    assert.equal(await dav(port, basic("agent", "new-password-value")), 207);
    writeUsers({ disabled: true }, "new-password-value", localUsers);
    assert.equal(await dav(port, basic("agent", "new-password-value")), 401);
  });
});

// ---- Post-await revalidation regressions ----
test("login: account disabled or password changed while bcrypt.compare is in flight is rejected", async () => {
  await withEnv({ LOGIN_DELAY_BASE: "0", TOTP_POLICY: "optional" }, async () => {
    for (const mutate of [(u) => { u.disabled = true; }, (u) => { u.password = bcrypt.hashSync("another-password", 4); }]) {
      const name = `c203e${++counter}`;
      const users = [{ username: name, password: bcrypt.hashSync("right-password", 4), role: "user", permissions: {}, sessionVersion: 0 }];
      const harness = createHarness(users, { onCompare: () => mutate(users[0]) });
      const res = await harness.call("/auth/login", { username: name, password: "right-password" }, `10.208.0.${counter}`);
      assert.equal(res.code, 401);
      assert.equal(res.body?.token, undefined);
    }
  });
});

function adminHarness(users, onCompare) {
  const harness = createHarness(users, { onCompare });
  const reset = (actorName, targetName) => harness.call("/users/:username/2fa/reset", { password: "password" }, `10.209.0.${++counter}`, {
    user: { username: actorName, role: users.find((u) => u.username === actorName).role, sessionVersion: 0 },
    params: { username: targetName },
  });
  return { harness, reset };
}
const mkUser = (username, role, permissions = {}) => ({ username, password: bcrypt.hashSync("password", 4), role, permissions, sessionVersion: 0 });

test("2FA reset: actor losing manageUsers during reauthentication gets 403 and target is untouched", async () => {
  await withEnv({ TOTP_POLICY: "optional" }, async () => {
    const users = [mkUser("mgr203", "user", { manageUsers: true }), mkUser("target203", "user")];
    users[1].totpEnabled = true; users[1].totpRecoveryHashes = ["x"];
    const { reset } = adminHarness(users, () => { users[0].permissions = { manageUsers: false }; });
    const res = await reset("mgr203", "target203");
    assert.equal(res.code, 403);
    assert.equal(users[1].totpEnabled, true);
  });
});

test("2FA reset: target promoted to admin during reauthentication by a non-admin gets 403", async () => {
  await withEnv({ TOTP_POLICY: "optional" }, async () => {
    const users = [mkUser("mgr203b", "user", { manageUsers: true }), mkUser("target203b", "user")];
    users[1].totpEnabled = true; users[1].totpRecoveryHashes = ["x"];
    const { reset } = adminHarness(users, () => { users[1].role = "admin"; });
    const res = await reset("mgr203b", "target203b");
    assert.equal(res.code, 403);
    assert.equal(users[1].totpEnabled, true);
  });
});

test("2FA reset still succeeds when nothing changes during reauthentication", async () => {
  await withEnv({ TOTP_POLICY: "optional" }, async () => {
    const users = [mkUser("mgr203c", "user", { manageUsers: true }), mkUser("target203c", "user")];
    users[1].totpEnabled = true; users[1].totpRecoveryHashes = ["x"];
    const { reset } = adminHarness(users);
    assert.equal((await reset("mgr203c", "target203c")).code, 200);
    assert.equal(users[1].totpEnabled, false);
  });
});

test("WebDAV: user disabled or password changed while bcrypt.compare is in flight is rejected and not cached", { timeout: 60_000 }, async () => {
  await withDavServer(async ({ port, writeUsers, localUsers, dir }) => {
    const trigger = path.join(dir, "mutate.json");
    for (const mutated of [{ disabled: true }, { password: bcrypt.hashSync("changed-password", 4) }]) {
      writeUsers({}, "password", localUsers);
      fs.writeFileSync(trigger, JSON.stringify([{ username: "agent", role: "admin", permissions: { upload: true }, sessionVersion: 0, password: bcrypt.hashSync("password", 4), ...mutated }]));
      assert.equal(await dav(port, basic("agent", "password")), 401);
      assert.equal(fs.existsSync(trigger), false, "mutation hook must have fired");
      // Not cached: with the original account restored the next request still needs (and passes) a fresh compare.
      writeUsers({}, "password", localUsers);
      assert.equal(await dav(port, basic("agent", "password")), 207);
    }
  });
});
