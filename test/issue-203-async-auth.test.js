"use strict";

const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const test = require("node:test");
const registerAuthRoutes = require("../src/routes/auth");
const { encryptSecret, generateRecoveryCodes, generateSecret, verifyRecoveryCode, verifyRecoveryCodeAsync } = require("../src/services/totp");

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

function createHarness(users) {
  const routes = new Map();
  const app = { post(path, ...h) { routes.set(`POST ${path}`, h); }, get(path, ...h) { routes.set(`GET ${path}`, h); } };
  const key = Buffer.alloc(32, 7);
  const stats = { compareCalls: 0, compareSyncCalls: 0 };
  const countingBcrypt = {
    compare: (...args) => { stats.compareCalls += 1; return bcrypt.compare(...args); },
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
  async function call(path, body, ip) {
    const req = { body, headers: {}, method: "POST", path, ip, params: {} };
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
