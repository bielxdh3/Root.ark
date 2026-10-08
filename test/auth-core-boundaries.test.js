const assert = require("node:assert/strict");
const jwt = require("jsonwebtoken");
const test = require("node:test");
const { createAuthenticate, parseCookies, verifyClaims } = require("../src/middlewares/auth");

const SECRET = "a".repeat(48);
const valid = (claims = {}, options = {}) => jwt.sign({ username: "alice", sessionVersion: 2, ...claims }, SECRET, { algorithm: "HS256", ...options });
function auth(headers = {}, claims = { username: "alice", sessionVersion: 2 }) {
  let result;
  createAuthenticate({ jwt: { verify: () => claims }, jwtSecret: SECRET, loadUser: () => ({ username: "alice", sessionVersion: 2, permissions: {} }), normalizeUserPermissions: (user) => user.permissions })({ headers, method: "GET", protocol: "http", get: () => "localhost" }, { status: (code) => ({ json: (body) => { result = { code, body }; } }) }, () => { result = { ok: true }; });
  return result;
}

test("JWT claim boundary accepts only current HS256 session identities", async (t) => {
  await t.test("explicit HS256 allowlist", () => assert.equal(verifyClaims(jwt, valid(), SECRET).username, "alice"));
  for (const [name, token] of [
    ["none", `${Buffer.from('{"alg":"none","typ":"JWT"}').toString("base64url")}.${Buffer.from('{"username":"alice","sessionVersion":2}').toString("base64url")}.`],
    ["unexpected symmetric algorithm", jwt.sign({ username: "alice", sessionVersion: 2 }, SECRET, { algorithm: "HS384" })],
    ["malformed header", "not-a-token"],
    ["malformed payload", `${Buffer.from('{"alg":"HS256"}').toString("base64url")}.not-json.signature`],
    ["invalid signature", `${valid()}.tampered`],
    ["expired token", valid({}, { expiresIn: -1 })],
    ["future nbf", valid({}, { notBefore: "1h" })],
    ["future iat", valid({ iat: Math.floor(Date.now() / 1000) + 600 })],
    ["missing identity", jwt.sign({ sessionVersion: 2 }, SECRET, { algorithm: "HS256" })],
    ["missing session version", jwt.sign({ username: "alice" }, SECRET, { algorithm: "HS256" })],
    ["noninteger session version", jwt.sign({ username: "alice", sessionVersion: 2.5 }, SECRET, { algorithm: "HS256" })],
    ["oversized token", "x".repeat(4097)],
  ]) await t.test(name, () => assert.throws(() => verifyClaims(jwt, token, SECRET)));
});

test("cookie parsing fails closed on duplicates and bearer remains deliberate precedence", () => {
  assert.equal(parseCookies("rootark_session=a; rootark_session=b").get("rootark_session"), undefined);
  const unusual = parseCookies("__proto__=hostile; constructor=hostile; rootark_session=valid");
  assert.equal(unusual.get("rootark_session"), "valid");
  assert.equal(unusual.get("__proto__"), "hostile");
  assert.equal(unusual.get("constructor"), "hostile");
  assert.equal(unusual instanceof Map, true);
  assert.equal(auth({ authorization: "Bearer token", cookie: "rootark_session=other" }).ok, true);
  assert.equal(auth({ cookie: "rootark_session=a; rootark_session=b" }).code, 401);
});

test("middleware suppresses token parsing detail", () => {
  const denied = auth({ authorization: "Bearer token" }, { username: "alice", sessionVersion: "bad" });
  assert.deepEqual(denied, { code: 401, body: { error: "Token invalido ou expirado" } });
});

test("enrollment-only sessions cannot reach application routes or realtime", () => {
  const middleware = createAuthenticate({
    jwt: { verify: () => ({ username: "alice", sessionVersion: 2, totpEnrollment: true }) },
    jwtSecret: SECRET,
    loadUser: () => ({ username: "alice", sessionVersion: 2, permissions: {} }),
    normalizeUserPermissions: (user) => user.permissions,
  });
  let result;
  const deniedReq = { headers: { authorization: "Bearer token" }, method: "GET", path: "/files", protocol: "http", get: () => "localhost" };
  middleware(deniedReq, { status: (code) => ({ json: (body) => { result = { code, body }; } }) }, () => { result = { ok: true }; });
  assert.equal(result.code, 403);
  const allowedReq = { ...deniedReq, path: "/auth/2fa/enroll" };
  middleware(allowedReq, { status: (code) => ({ json: (body) => { result = { code, body }; } }) }, () => { result = { ok: true, user: allowedReq.user }; });
  assert.equal(result.ok, true);
  const realtime = require("../src/middlewares/auth").createRealtimeAuthenticator({
    jwt: { verify: () => ({ username: "alice", sessionVersion: 2, totpEnrollment: true }) },
    jwtSecret: SECRET,
    loadUser: () => ({ username: "alice", sessionVersion: 2, permissions: {} }),
    normalizeUserPermissions: (user) => user.permissions,
  });
  assert.equal(realtime("token"), null);
});

function runPolicyHttp(user, path) {
  let result;
  const middleware = createAuthenticate({
    jwt: { verify: () => ({ username: user.username, sessionVersion: user.sessionVersion || 0 }) },
    jwtSecret: SECRET,
    loadUser: () => user,
    normalizeUserPermissions: (entry) => entry.permissions || {},
  });
  const req = { headers: { authorization: "Bearer token" }, method: "GET", path, protocol: "http", get: () => "localhost" };
  middleware(req, { status: (code) => ({ json: (body) => { result = { code, body }; } }) }, () => { result = { ok: true, user: req.user }; });
  return result;
}

function runPolicyRealtime(user) {
  const realtime = require("../src/middlewares/auth").createRealtimeAuthenticator({
    jwt: { verify: () => ({ username: user.username, sessionVersion: user.sessionVersion || 0 }) },
    jwtSecret: SECRET,
    loadUser: () => user,
    normalizeUserPermissions: (entry) => entry.permissions || {},
  });
  return realtime("token");
}

test("HTTP and realtime authentication re-evaluate optional, role, and global TOTP policy", () => {
  const originalPolicy = process.env.TOTP_POLICY;
  const originalRoles = process.env.TOTP_REQUIRED_ROLES;
  const admin = { username: "policy-admin", role: "admin", permissions: {}, sessionVersion: 4, totpEnabled: false };
  const user = { username: "policy-user", role: "user", permissions: {}, sessionVersion: 4, totpEnabled: false };
  try {
    process.env.TOTP_POLICY = "optional";
    assert.equal(runPolicyHttp(admin, "/files").ok, true);
    assert.ok(runPolicyRealtime(admin));

    process.env.TOTP_POLICY = "role-required";
    process.env.TOTP_REQUIRED_ROLES = "admin";
    assert.equal(runPolicyHttp(admin, "/files").code, 403);
    for (const path of ["/auth/2fa/enroll", "/auth/2fa/confirm", "/auth/2fa/status", "/auth/2fa/policy", "/auth/logout"]) {
      assert.equal(runPolicyHttp(admin, path).ok, true);
    }
    assert.equal(runPolicyRealtime(admin), null);
    admin.totpEnabled = true;
    assert.equal(runPolicyHttp(admin, "/files").ok, true);
    assert.ok(runPolicyRealtime(admin));
    assert.equal(runPolicyHttp(user, "/files").ok, true);
    assert.ok(runPolicyRealtime(user));

    process.env.TOTP_POLICY = "global-required";
    admin.totpEnabled = false;
    assert.equal(runPolicyHttp(admin, "/files").code, 403);
    assert.equal(runPolicyRealtime(admin), null);
  } finally {
    if (originalPolicy === undefined) delete process.env.TOTP_POLICY;
    else process.env.TOTP_POLICY = originalPolicy;
    if (originalRoles === undefined) delete process.env.TOTP_REQUIRED_ROLES;
    else process.env.TOTP_REQUIRED_ROLES = originalRoles;
  }
});

test("a policy change binds an existing full HTTP and realtime session", () => {
  const originalPolicy = process.env.TOTP_POLICY;
  const account = { username: "existing-session", role: "admin", permissions: {}, sessionVersion: 7, totpEnabled: false };
  try {
    process.env.TOTP_POLICY = "optional";
    assert.equal(runPolicyHttp(account, "/files").ok, true);
    assert.ok(runPolicyRealtime(account));
    process.env.TOTP_POLICY = "global-required";
    assert.equal(runPolicyHttp(account, "/files").code, 403);
    assert.equal(runPolicyRealtime(account), null);
    assert.equal(runPolicyHttp(account, "/auth/2fa/status").ok, true);
  } finally {
    if (originalPolicy === undefined) delete process.env.TOTP_POLICY;
    else process.env.TOTP_POLICY = originalPolicy;
  }
});

test("invalid dynamic TOTP policy blocks HTTP and realtime authentication without disclosure", () => {
  const originalPolicy = process.env.TOTP_POLICY;
  const originalRoles = process.env.TOTP_REQUIRED_ROLES;
  const account = { username: "invalid-policy", role: "admin", permissions: {}, sessionVersion: 8, totpEnabled: false };
  try {
    process.env.TOTP_POLICY = "typo-mode";
    const httpDenied = runPolicyHttp(account, "/files");
    assert.deepEqual(httpDenied, { code: 503, body: { error: "Configuracao TOTP invalida." } });
    assert.equal(runPolicyRealtime(account), null);

    process.env.TOTP_POLICY = "role-required";
    process.env.TOTP_REQUIRED_ROLES = "   ";
    assert.deepEqual(runPolicyHttp(account, "/files"), { code: 503, body: { error: "Configuracao TOTP invalida." } });
    assert.equal(runPolicyRealtime(account), null);
  } finally {
    if (originalPolicy === undefined) delete process.env.TOTP_POLICY;
    else process.env.TOTP_POLICY = originalPolicy;
    if (originalRoles === undefined) delete process.env.TOTP_REQUIRED_ROLES;
    else process.env.TOTP_REQUIRED_ROLES = originalRoles;
  }
});
