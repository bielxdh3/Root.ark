const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const jwt = require("jsonwebtoken");
const test = require("node:test");
const registerAuthRoutes = require("../src/routes/auth");
const { decryptSecret, encryptSecret, generateRecoveryCodes, generateSecret, hotp, verifyRecoveryCodeAsync, verifyTotp } = require("../src/services/totp");

function response() {
  return {
    code: 200,
    body: undefined,
    cookies: {},
    clearedCookies: [],
    headers: {},
    status(code) { this.code = code; return this; },
    json(body) { this.body = body; return this; },
    end() { return this; },
    cookie(name, value) { this.cookies[name] = value; return this; },
    clearCookie(name) { this.clearedCookies.push(name); delete this.cookies[name]; return this; },
    setHeader(name, value) { this.headers[name.toLowerCase()] = String(value); return this; },
  };
}

function assertNoStore(res) {
  assert.equal(res.headers["cache-control"], "no-store");
  assert.equal(res.headers.pragma, "no-cache");
}

let harnessCounter = 0;

function createHarness(users, options = {}) {
  const routes = new Map();
  const app = {
    post(path, ...handlers) { routes.set(`POST ${path}`, handlers); },
    get(path, ...handlers) { routes.set(`GET ${path}`, handlers); },
  };
  const events = [];
  const key = Buffer.alloc(32, 3);
  const ip = options.ip || `127.0.0.${++harnessCounter}`;
  const context = {
    authenticate(req, res, next) {
      const user = users.find((entry) => entry.username === req.user?.username) || users[0];
      req.user = { username: user.username, role: user.role, permissions: user.permissions || {}, sessionVersion: user.sessionVersion || 0, totpEnabled: Boolean(user.totpEnabled) };
      next();
    },
    auditLog(...args) { events.push(args); },
    bcrypt,
    checkAnomalies() {},
    getAuditActor: (req, fallbackUsername = "system") => ({
      username: req?.user?.username || fallbackUsername || "system",
      role: req?.user?.role || null,
      ip: req?.ip || "unknown",
    }),
    getTotpKey: options.getTotpKey || (() => key),
    jwt,
    jwtSecret: "s".repeat(48),
    loadUsers: options.loadUsers || (() => users),
    saveUsers: (nextUsers) => { users.splice(0, users.length, ...JSON.parse(JSON.stringify(nextUsers))); },
    logAnalyticsEvent() {},
    normalizeUserPermissions: (user) => user.permissions || {},
    qrcode: { toDataURL: async (uri) => `qr:${uri}` },
    requirePermission: (_permission) => (_req, _res, next) => next(),
    sessionCookieOptions: { httpOnly: true, sameSite: "lax" },
  };
  registerAuthRoutes(app, context);
  async function call(method, path, body = {}, username = "alice") {
    const req = { body, user: path.startsWith("/auth/login") ? undefined : { username }, headers: {}, method, path, ip, params: path.includes(":username") ? { username: "alice" } : {} };
    const res = response();
    for (const handler of routes.get(`${method} ${path}`) || []) {
      let continued = false;
      await handler(req, res, () => { continued = true; });
      if (!continued && handler.length >= 3) break;
    }
    return res;
  }
  return { call, events, ip, key, users };
}

function user(username, role = "user") {
  return { username, password: bcrypt.hashSync("password", 4), role, permissions: role === "admin" ? { manageUsers: true } : {}, sessionVersion: 0 };
}

test("issue 203 2FA confirmation hashes recovery codes without synchronous scrypt", async () => {
  const harness = createHarness([user("async-confirm")]);
  await harness.call("POST", "/auth/2fa/enroll", {}, "async-confirm");
  const account = harness.users.find((entry) => entry.username === "async-confirm");
  const pendingSecret = decryptSecret(account.totpPendingSecret, harness.key, "Root.ark/TOTP/async-confirm");
  const code = hotp(pendingSecret, Math.floor(Date.now() / 1000 / 30));
  const originalScryptSync = crypto.scryptSync;
  crypto.scryptSync = () => { throw new Error("synchronous recovery-code scrypt is forbidden on the request path"); };
  let confirmations;
  try {
    confirmations = await Promise.all([
      harness.call("POST", "/auth/2fa/confirm", { code }, "async-confirm"),
      harness.call("POST", "/auth/2fa/confirm", { code }, "async-confirm"),
    ]);
  } finally {
    crypto.scryptSync = originalScryptSync;
  }
  assert.equal(confirmations.filter((result) => result.code === 200).length, 1);
  assert.equal(confirmations.filter((result) => result.code === 429).length, 1);
  const confirmed = confirmations.find((result) => result.code === 200);
  assert.equal(confirmed.code, 200);
  assert.equal(confirmed.body.recoveryCodes.length, 10);
  const enrolled = harness.users.find((entry) => entry.username === "async-confirm");
  assert.equal(await verifyRecoveryCodeAsync(confirmed.body.recoveryCodes[0], enrolled.totpRecoveryHashes[0]), true);
});

test("logout fails closed when the auth store is unavailable after authentication", async () => {
  const alice = user("alice");
  const harness = createHarness([alice], {
    loadUsers: ({ failOnDatabaseError = false } = {}) => {
      if (failOnDatabaseError) throw Object.assign(new Error("Authorization store unavailable"), { code: "AUTHORIZATION_STORE_UNAVAILABLE" });
      return [];
    },
  });

  const result = await harness.call("POST", "/auth/logout", {}, "alice");

  assert.equal(result.code, 503);
  assert.deepEqual(result.body, { error: "Sessao nao pode ser revogada agora." });
  assertNoStore(result);
  assert.deepEqual(result.clearedCookies, []);
  assert.equal(alice.sessionVersion, 0);
});

test("logout persists session revocation before clearing cookies", async () => {
  const alice = user("alice");
  const harness = createHarness([alice]);

  const result = await harness.call("POST", "/auth/logout", {}, "alice");

  assert.equal(result.code, 204);
  assert.equal(alice.sessionVersion, 1);
  assert.deepEqual(result.clearedCookies, ["rootark_session", "rootark_csrf"]);
});

test("logout does not trust an empty JSON fallback after an authoritative SQLite read failure", async () => {
  const alice = user("alice");
  const harness = createHarness([alice], {
    loadUsers: ({ allowJsonFallback = true } = {}) => {
      if (!allowJsonFallback) throw Object.assign(new Error("Authorization store unavailable"), { code: "AUTHORIZATION_STORE_UNAVAILABLE" });
      return [];
    },
  });

  const result = await harness.call("POST", "/auth/logout", {}, "alice");

  assert.equal(result.code, 503);
  assert.deepEqual(result.body, { error: "Sessao nao pode ser revogada agora." });
  assert.deepEqual(result.clearedCookies, []);
  assert.equal(alice.sessionVersion, 0);
});

test("TOTP enrollment, challenge, recovery single-use, disable, and admin reset preserve revocation", async () => {
  const originalPolicy = process.env.TOTP_POLICY;
  process.env.TOTP_POLICY = "optional";
  const alice = user("alice");
  const admin = user("admin", "admin");
  const harness = createHarness([alice, admin]);
  try {
    const enrolled = await harness.call("POST", "/auth/2fa/enroll", {}, "alice");
    assert.equal(enrolled.code, 200);
    assertNoStore(enrolled);
    assert.match(enrolled.body.otpauthUri, /^otpauth:\/\/totp\//);
    assert.match(enrolled.body.qrCode, /^qr:otpauth:\/\/totp\//);
    assert.equal(Boolean(harness.users.find((entry) => entry.username === "alice").totpEnabled), false);
    assert.ok(harness.users.find((entry) => entry.username === "alice").totpPendingSecret);
    assert.equal(JSON.stringify(harness.events).includes(enrolled.body.secret), false);

    const pendingSecret = decryptSecret(harness.users.find((entry) => entry.username === "alice").totpPendingSecret, harness.key, "Root.ark/TOTP/alice");
    const confirmationCode = verifyTotp(pendingSecret, "000000", { now: Date.now(), window: 0 }) === null
      ? require("../src/services/totp").hotp(pendingSecret, Math.floor(Date.now() / 1000 / 30))
      : "000000";
    const confirmed = await harness.call("POST", "/auth/2fa/confirm", { code: confirmationCode }, "alice");
    assert.equal(confirmed.code, 200);
    assertNoStore(confirmed);
    assert.equal(confirmed.body.recoveryCodes.length, 10);
    let currentAlice = harness.users.find((entry) => entry.username === "alice");
    assert.equal(currentAlice.totpEnabled, true);
    assert.equal(currentAlice.totpPendingSecret, null);
    assert.equal(currentAlice.sessionVersion, 1);
    assert.equal(JSON.stringify(harness.events).includes(confirmed.body.recoveryCodes[0]), false);
    assert.equal(JSON.stringify(harness.users).includes(confirmed.body.recoveryCodes[0]), false);
    assert.equal(JSON.stringify(harness.users).includes(pendingSecret), false);

    const challenged = await harness.call("POST", "/auth/login", { username: "alice", password: "password" }, "alice");
    assertNoStore(challenged);
    assert.equal(challenged.body.challengeRequired, true);
    const bad = await harness.call("POST", "/auth/login/2fa", { challengeId: challenged.body.challengeId, code: "000000" }, "alice");
    assert.equal(bad.code, 401);
    assertNoStore(bad);
    const recovered = await harness.call("POST", "/auth/login/2fa", { challengeId: challenged.body.challengeId, code: confirmed.body.recoveryCodes[0] }, "alice");
    assert.equal(recovered.code, 200);
    assertNoStore(recovered);
    assert.ok(recovered.body.token);
    const replayChallenge = await harness.call("POST", "/auth/login", { username: "alice", password: "password" }, "alice");
    const replay = await harness.call("POST", "/auth/login/2fa", { challengeId: replayChallenge.body.challengeId, code: confirmed.body.recoveryCodes[0] }, "alice");
    assert.equal(replay.code, 401);

    const disable = await harness.call("POST", "/auth/2fa/disable", { password: "password", code: confirmed.body.recoveryCodes[1] }, "alice");
    assert.equal(disable.code, 200);
    assertNoStore(disable);
    currentAlice = harness.users.find((entry) => entry.username === "alice");
    assert.equal(currentAlice.totpEnabled, false);
    assert.equal(currentAlice.sessionVersion, 2);
    assert.equal(currentAlice.totpRecoveryHashes.length, 0);

    await harness.call("POST", "/auth/2fa/enroll", {}, "alice");
    const unenrolledReset = await harness.call("POST", "/users/:username/2fa/reset", { password: "password" }, "admin");
    assert.equal(unenrolledReset.code, 200);
    currentAlice = harness.users.find((entry) => entry.username === "alice");
    assert.equal(currentAlice.totpPendingSecret, null);
    assert.equal(currentAlice.sessionVersion, 3);

    await harness.call("POST", "/auth/2fa/enroll", {}, "alice");
    const admin = harness.users.find((entry) => entry.username === "admin");
    const adminRecovery = generateRecoveryCodes(1);
    admin.totpEnabled = true;
    admin.totpSecret = encryptSecret(generateSecret(), harness.key, "Root.ark/TOTP/admin");
    admin.totpRecoveryHashes = adminRecovery.hashes;
    admin.totpLastUsedStep = Math.floor(Date.now() / 1000 / 30) - 1;
    const badReset = await harness.call("POST", "/users/:username/2fa/reset", { password: "wrong", code: adminRecovery.codes[0] }, "admin");
    assert.equal(badReset.code, 401);
    const reset = await harness.call("POST", "/users/:username/2fa/reset", { password: "password", code: adminRecovery.codes[0] }, "admin");
    assert.equal(reset.code, 200);
    currentAlice = harness.users.find((entry) => entry.username === "alice");
    assert.equal(currentAlice.totpSecret, null);
    assert.equal(currentAlice.totpPendingSecret, null);
    assert.equal(currentAlice.sessionVersion, 4);
    assert.equal(JSON.stringify(harness.events).includes(pendingSecret), false);
  } finally {
    if (originalPolicy === undefined) delete process.env.TOTP_POLICY;
    else process.env.TOTP_POLICY = originalPolicy;
  }
});

test("global required policy returns a bounded enrollment session without activating all users", async () => {
  const originalPolicy = process.env.TOTP_POLICY;
  process.env.TOTP_POLICY = "global-required";
  const bob = user("bob");
  const harness = createHarness([bob]);
  try {
    const result = await harness.call("POST", "/auth/login", { username: "bob", password: "password" }, "bob");
    assert.equal(result.code, 403);
    assertNoStore(result);
    assert.equal(result.body.enrollmentRequired, true);
    assert.ok(result.body.token);
    assert.equal(harness.users.find((entry) => entry.username === "bob").totpEnabled, undefined);
  } finally {
    if (originalPolicy === undefined) delete process.env.TOTP_POLICY;
    else process.env.TOTP_POLICY = originalPolicy;
  }
});

test("invalid runtime TOTP policy blocks login with a sanitized configuration error", async () => {
  const originalPolicy = process.env.TOTP_POLICY;
  const originalRoles = process.env.TOTP_REQUIRED_ROLES;
  try {
    const harness = createHarness([user("invalid-policy")]);
    process.env.TOTP_POLICY = "not-a-policy";
    let result = await harness.call("POST", "/auth/login", { username: "invalid-policy", password: "password" }, "invalid-policy");
    assert.equal(result.code, 503);
    assert.deepEqual(result.body, { error: "Configuracao TOTP invalida." });
    assert.equal(JSON.stringify(result.body).includes("not-a-policy"), false);

    process.env.TOTP_POLICY = "role-required";
    process.env.TOTP_REQUIRED_ROLES = " \t ";
    result = await harness.call("POST", "/auth/login", { username: "invalid-policy", password: "password" }, "invalid-policy");
    assert.equal(result.code, 503);
    assert.deepEqual(result.body, { error: "Configuracao TOTP invalida." });
  } finally {
    if (originalPolicy === undefined) delete process.env.TOTP_POLICY;
    else process.env.TOTP_POLICY = originalPolicy;
    if (originalRoles === undefined) delete process.env.TOTP_REQUIRED_ROLES;
    else process.env.TOTP_REQUIRED_ROLES = originalRoles;
  }
});

test("bad confirmation and missing application key fail closed without activating or exposing material", async () => {
  const missingHarness = createHarness([user("carol")], { getTotpKey: () => { throw new Error("missing"); } });
  const missing = await missingHarness.call("POST", "/auth/2fa/enroll", {}, "carol");
  assert.equal(missing.code, 503);
  assertNoStore(missing);
  assert.equal(missingHarness.users[0].totpPendingSecret, undefined);

  const working = createHarness([user("dave")]);
  const started = await working.call("POST", "/auth/2fa/enroll", {}, "dave");
  const bad = await working.call("POST", "/auth/2fa/confirm", { code: "000000" }, "dave");
  assert.equal(bad.code, 400);
  assertNoStore(bad);
  assert.equal(Boolean(working.users[0].totpEnabled), false);
  assert.equal(JSON.stringify(working.events).includes(started.body.secret), false);
  assert.equal(JSON.stringify(working.events).includes(started.body.otpauthUri), false);
});

test("expired pending enrollment and expired login challenges fail generically", async () => {
  const originalTtl = process.env.TOTP_CHALLENGE_TTL_MS;
  const originalNow = Date.now;
  process.env.TOTP_CHALLENGE_TTL_MS = "60000";
  const harness = createHarness([user("expiry")]);
  try {
    await harness.call("POST", "/auth/2fa/enroll", {}, "expiry");
    harness.users[0].totpPendingSecret.createdAt = Date.now() - (10 * 60 * 1000 + 1);
    const pending = await harness.call("POST", "/auth/2fa/confirm", { code: "000000" }, "expiry");
    assert.equal(pending.code, 400);
    harness.users[0].totpEnabled = true;
    harness.users[0].totpSecret = encryptSecret(generateSecret(), harness.key, "Root.ark/TOTP/expiry");
    harness.users[0].totpLastUsedStep = Math.floor(Date.now() / 1000 / 30) - 1;

    const now = originalNow;
    const challenge = await harness.call("POST", "/auth/login", { username: "expiry", password: "password" }, "expiry");
    Date.now = () => now() + 61 * 1000;
    const expired = await harness.call("POST", "/auth/login/2fa", { challengeId: challenge.body.challengeId, code: "000000" }, "expiry");
    assert.equal(expired.code, 401);
    assert.equal(harness.events.some(([eventType, , , , , details]) => eventType === "auth.login.challenge.failed" && details.reason === "invalid_challenge"), true);
    assert.doesNotMatch(JSON.stringify(harness.events), new RegExp(challenge.body.challengeId));
  } finally {
    Date.now = originalNow;
    if (originalTtl === undefined) delete process.env.TOTP_CHALLENGE_TTL_MS;
    else process.env.TOTP_CHALLENGE_TTL_MS = originalTtl;
  }
});

test("confirmation, disable, and admin-reset verification paths share bounded throttles", async () => {
  const originalMax = process.env.TOTP_CHALLENGE_MAX_ATTEMPTS;
  process.env.TOTP_CHALLENGE_MAX_ATTEMPTS = "5";
  try {
    const confirmHarness = createHarness([user("confirm-throttle")]);
    await confirmHarness.call("POST", "/auth/2fa/enroll", {}, "confirm-throttle");
    for (let index = 0; index < 5; index += 1) assert.equal((await confirmHarness.call("POST", "/auth/2fa/confirm", { code: "000000" }, "confirm-throttle")).code, 400);
    assert.equal((await confirmHarness.call("POST", "/auth/2fa/confirm", { code: "000000" }, "confirm-throttle")).code, 429);

    const disableHarness = createHarness([user("disable-throttle")]);
    const disableUser = disableHarness.users[0];
    disableUser.totpEnabled = true;
    disableUser.totpSecret = encryptSecret(generateSecret(), disableHarness.key, "Root.ark/TOTP/disable-throttle");
    disableUser.totpRecoveryHashes = [];
    disableUser.totpLastUsedStep = Math.floor(Date.now() / 1000 / 30) - 1;
    for (let index = 0; index < 5; index += 1) assert.equal((await disableHarness.call("POST", "/auth/2fa/disable", { password: "password", code: "000000" }, "disable-throttle")).code, 401);
    assert.equal((await disableHarness.call("POST", "/auth/2fa/disable", { password: "password", code: "000000" }, "disable-throttle")).code, 429);

    const resetHarness = createHarness([user("alice"), user("admin-throttle", "admin")]);
    const resetAdmin = resetHarness.users.find((entry) => entry.username === "admin-throttle");
    resetAdmin.totpEnabled = true;
    resetAdmin.totpSecret = encryptSecret(generateSecret(), resetHarness.key, "Root.ark/TOTP/admin-throttle");
    resetAdmin.totpRecoveryHashes = [];
    resetAdmin.totpLastUsedStep = Math.floor(Date.now() / 1000 / 30) - 1;
    for (let index = 0; index < 5; index += 1) assert.equal((await resetHarness.call("POST", "/users/:username/2fa/reset", { password: "password", code: "000000" }, "admin-throttle")).code, 401);
    assert.equal((await resetHarness.call("POST", "/users/:username/2fa/reset", { password: "password", code: "000000" }, "admin-throttle")).code, 429);
  } finally {
    if (originalMax === undefined) delete process.env.TOTP_CHALLENGE_MAX_ATTEMPTS;
    else process.env.TOTP_CHALLENGE_MAX_ATTEMPTS = originalMax;
  }
});

test("fresh challenges share bounded IP and account throttles", async () => {
  const account = user("throttled");
  const harness = createHarness([account]);
  account.totpEnabled = true;
  account.totpSecret = encryptSecret(generateSecret(), harness.key, "Root.ark/TOTP/throttled");
  account.totpLastUsedStep = Math.floor(Date.now() / 1000 / 30) - 1;
  let last;
  for (let index = 0; index < 10; index += 1) {
    const challenge = await harness.call("POST", "/auth/login", { username: "throttled", password: "password" }, "throttled");
    last = await harness.call("POST", "/auth/login/2fa", { challengeId: challenge.body.challengeId, code: "000000" }, "throttled");
    assert.equal(last.code, 401);
  }
  const fresh = await harness.call("POST", "/auth/login", { username: "throttled", password: "password" }, "throttled");
  last = await harness.call("POST", "/auth/login/2fa", { challengeId: fresh.body.challengeId, code: "000000" }, "throttled");
  assert.equal(last.code, 429);
  assert.match(last.body.error, /dois fatores/);
});

test("failed login audit identifies an anonymous actor and keeps attempted username separate", async () => {
  const password = "synthetic-password-that-must-not-be-audited";
  const username = "synthetic-missing-user";
  const harness = createHarness([]);
  const result = await harness.call("POST", "/auth/login", { username, password }, username);

  assert.equal(result.code, 401);
  const [eventType, actor, target, , , details] = harness.events.find(([name]) => name === "auth.login.failed");
  assert.equal(eventType, "auth.login.failed");
  assert.deepEqual(actor, { username: "anonymous", role: null, ip: harness.ip });
  assert.deepEqual(target, { type: "auth", id: username });
  assert.equal(details.attemptedUsername, username);
  assert.equal(details.ip, harness.ip);
  assert.doesNotMatch(JSON.stringify(harness.events), /synthetic-password-that-must-not-be-audited/);
});

test("invalid login 2FA audit identifies an anonymous actor and omits credential material", async () => {
  const account = user("synthetic-totp-user");
  const harness = createHarness([account]);
  const secret = generateSecret();
  const secretCode = "synthetic-totp-code-that-must-not-be-audited";
  account.totpEnabled = true;
  account.totpSecret = encryptSecret(secret, harness.key, `Root.ark/TOTP/${account.username}`);
  account.totpRecoveryHashes = [];
  account.totpLastUsedStep = Math.floor(Date.now() / 1000 / 30) - 1;

  const primary = await harness.call("POST", "/auth/login", { username: account.username, password: "password" }, account.username);
  const result = await harness.call("POST", "/auth/login/2fa", { challengeId: primary.body.challengeId, code: secretCode }, account.username);

  assert.equal(result.code, 401);
  const [eventType, actor, target, , , details] = harness.events.find(([name]) => name === "auth.login.challenge.failed");
  assert.equal(eventType, "auth.login.challenge.failed");
  assert.deepEqual(actor, { username: "anonymous", role: null, ip: harness.ip });
  assert.deepEqual(target, { type: "user", id: account.username });
  assert.equal(details.reason, "invalid_proof");
  assert.doesNotMatch(JSON.stringify(harness.events), new RegExp(secret));
  assert.doesNotMatch(JSON.stringify(harness.events), new RegExp(secretCode));
});

test("invalid and rate-limited challenge submissions are audited once per IP window without logging challenge IDs", async () => {
  const originalMax = process.env.TOTP_CHALLENGE_MAX_ATTEMPTS;
  process.env.TOTP_CHALLENGE_MAX_ATTEMPTS = "5";
  try {
    const harness = createHarness([]);
    const challengeId = "synthetic-bearer-challenge-id";
    const results = [];
    for (let attempt = 0; attempt < 7; attempt += 1) {
      results.push(await harness.call("POST", "/auth/login/2fa", { challengeId, code: "synthetic-secret-code" }));
    }

    assert.deepEqual(results.slice(0, 5).map((result) => result.code), [401, 401, 401, 401, 401]);
    assert.deepEqual(results.slice(5).map((result) => result.code), [429, 429]);
    assert.ok(results.every((result) => result.body.error === "Autenticacao de dois fatores invalida."));
    const failures = harness.events.filter(([eventType]) => eventType === "auth.login.challenge.failed");
    assert.deepEqual(failures.map(([, , , , , details]) => details.reason), ["invalid_challenge", "rate_limited"]);
    for (const [, actor, target, , , details] of failures) {
      assert.equal(actor.username, "anonymous");
      assert.equal(actor.ip, harness.ip);
      assert.deepEqual(target, { type: "auth", id: "login/2fa" });
      assert.equal(details.ip, harness.ip);
    }
    assert.doesNotMatch(JSON.stringify(harness.events), /synthetic-bearer-challenge-id|synthetic-secret-code/);
  } finally {
    if (originalMax === undefined) delete process.env.TOTP_CHALLENGE_MAX_ATTEMPTS;
    else process.env.TOTP_CHALLENGE_MAX_ATTEMPTS = originalMax;
  }
});

test("a challenge for a stale account is audited without exposing its bearer ID", async () => {
  const account = user("synthetic-stale-account");
  const harness = createHarness([account]);
  account.totpEnabled = true;
  account.totpSecret = encryptSecret(generateSecret(), harness.key, `Root.ark/TOTP/${account.username}`);
  account.totpRecoveryHashes = [];
  account.totpLastUsedStep = Math.floor(Date.now() / 1000 / 30) - 1;
  const primary = await harness.call("POST", "/auth/login", { username: account.username, password: "password" }, account.username);
  account.disabled = true;

  const result = await harness.call("POST", "/auth/login/2fa", { challengeId: primary.body.challengeId, code: "synthetic-secret-code" }, account.username);

  assert.equal(result.code, 401);
  assert.equal(result.body.error, "Autenticacao de dois fatores invalida.");
  const failure = harness.events.find(([eventType, , , , , details]) => eventType === "auth.login.challenge.failed" && details.reason === "account_unavailable");
  assert.ok(failure);
  assert.deepEqual(failure[1], { username: "anonymous", role: null, ip: harness.ip });
  assert.deepEqual(failure[2], { type: "user", id: account.username });
  assert.doesNotMatch(JSON.stringify(harness.events), new RegExp(primary.body.challengeId));
  assert.doesNotMatch(JSON.stringify(harness.events), /synthetic-secret-code/);
});

test("an exhausted challenge is audited on reuse without logging its bearer ID", async () => {
  const account = user("synthetic-exhausted-account");
  const harness = createHarness([account]);
  account.totpEnabled = true;
  account.totpSecret = encryptSecret(generateSecret(), harness.key, `Root.ark/TOTP/${account.username}`);
  account.totpRecoveryHashes = [];
  account.totpLastUsedStep = Math.floor(Date.now() / 1000 / 30) - 1;
  const primary = await harness.call("POST", "/auth/login", { username: account.username, password: "password" }, account.username);
  const invalidProofs = [];
  for (let attempt = 0; attempt < 5; attempt += 1) {
    invalidProofs.push(await harness.call("POST", "/auth/login/2fa", { challengeId: primary.body.challengeId, code: "synthetic-secret-code" }, account.username));
  }
  const reused = await harness.call("POST", "/auth/login/2fa", { challengeId: primary.body.challengeId, code: "synthetic-secret-code" }, account.username);

  assert.ok(invalidProofs.every((result) => result.code === 401));
  assert.equal(reused.code, 401);
  assert.equal(reused.body.error, "Autenticacao de dois fatores invalida.");
  const invalidChallenge = harness.events.find(([eventType, , , , , details]) => eventType === "auth.login.challenge.failed" && details.reason === "invalid_challenge");
  assert.ok(invalidChallenge);
  assert.equal(invalidChallenge[1].username, "anonymous");
  assert.equal(invalidChallenge[1].ip, harness.ip);
  assert.doesNotMatch(JSON.stringify(harness.events), new RegExp(primary.body.challengeId));
  assert.doesNotMatch(JSON.stringify(harness.events), /synthetic-secret-code/);
});
