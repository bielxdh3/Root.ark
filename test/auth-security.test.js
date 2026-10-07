const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");
const test = require("node:test");
const fs = require("node:fs");
const http = require("node:http");
const jwt = require("jsonwebtoken");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const WebSocket = require("ws");
const { createAuthenticate, getClientIp, getExpectedOrigin } = require("../src/middlewares/auth");

const ROOT = path.resolve(__dirname, "..");
const SERVER = path.join(ROOT, "server.js");
const PUBLIC = path.join(ROOT, "public");

function getUnusedPort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

function request(port, requestPath, { method = "GET", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, method, headers }, (res) => {
      let responseBody = "";
      res.on("data", (chunk) => { responseBody += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: responseBody }));
    });
    req.once("error", reject);
    if (body) req.end(body);
    else req.end();
  });
}

async function waitForServer(port) {
  const deadline = Date.now() + 10_000;
  let lastError;
  while (Date.now() < deadline) {
    try {
      return await request(port, "/login.html");
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  throw lastError;
}

async function login(port, username, password) {
  const body = JSON.stringify({ username, password });
  const response = await request(port, "/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) },
    body,
  });
  assert.equal(response.status, 200);
  const cookies = response.headers["set-cookie"].map((cookie) => cookie.split(";", 1)[0]);
  const sessionCookie = cookies.find((cookie) => cookie.startsWith("rootark_session="));
  return {
    cookie: cookies.join("; "),
    csrf: cookies.find((cookie) => cookie.startsWith("rootark_csrf=")).split("=", 2)[1],
    sessionVersion: jwt.decode(sessionCookie.split("=", 2)[1]).sessionVersion,
  };
}

function waitForWebSocketEvent(socket, event, timeout = 2_000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Timed out waiting for ${event}`)), timeout);
    socket.on("message", (rawMessage) => {
      const message = JSON.parse(rawMessage.toString());
      if (message.event !== event) return;
      clearTimeout(timer);
      resolve(message);
    });
    socket.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

function waitForWebSocketClose(socket, timeout = 2_000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Timed out waiting for WebSocket close")), timeout);
    socket.once("close", (code, reason) => {
      clearTimeout(timer);
      resolve({ code, reason: reason.toString() });
    });
    socket.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

function createSandbox(users) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-permission-removal-"));
  fs.mkdirSync(path.join(dir, "data"));
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify(users));
  fs.symlinkSync(PUBLIC, path.join(dir, "public"), "junction");
  return dir;
}

function authenticateRequest({ headers = {}, method = "GET", user = { username: "alice", role: "user", permissions: {}, sessionVersion: 2 } } = {}) {
  const middleware = createAuthenticate({
    jwt: { verify: () => ({ username: "alice", sessionVersion: 2 }) },
    jwtSecret: "test",
    loadUser: () => user,
    normalizeUserPermissions: (current) => current.permissions,
  });
  const req = { headers, method, protocol: "http", get: () => "localhost" };
  let result;
  const res = { status: (code) => ({ json: (body) => { result = { code, body }; } }) };
  middleware(req, res, () => { result = { user: req.user, authType: req.authType }; });
  return result;
}

test("cookie session requires CSRF for state changes", () => {
  assert.equal(authenticateRequest({ method: "POST", headers: { cookie: "rootark_session=t; rootark_csrf=c" } }).code, 403);
  assert.equal(authenticateRequest({ method: "POST", headers: { cookie: "rootark_session=t; rootark_csrf=c", "x-csrf-token": "c", origin: "http://localhost" } }).authType, "cookie");
  assert.equal(authenticateRequest({ method: "POST", headers: { cookie: "rootark_session=t; rootark_csrf=c", "x-csrf-token": "c", origin: "https://localhost", "x-forwarded-proto": "https" } }).code, 403);
});

test("origin and client IP use the Express trusted-proxy decision, never raw forwarded headers", () => {
  assert.equal(getExpectedOrigin({ protocol: "https", headers: { host: "rootark.test", "x-forwarded-proto": "http" }, socket: { encrypted: false } }), "https://rootark.test");
  assert.equal(getExpectedOrigin({ protocol: "http", headers: { host: "rootark.test", "x-forwarded-proto": "https" }, socket: { encrypted: false } }), "http://rootark.test");
  assert.equal(getExpectedOrigin({ headers: { host: "rootark.test", "x-forwarded-proto": "https" }, socket: { encrypted: false, remoteAddress: "198.51.100.20" } }), "http://rootark.test");
  assert.equal(getExpectedOrigin({ headers: { host: "rootark.test", "x-forwarded-proto": "https, http" }, socket: { encrypted: false, remoteAddress: "127.0.0.1" } }, (address) => address === "127.0.0.1"), "https://rootark.test");
  assert.equal(getClientIp({ ip: "198.51.100.7", socket: { remoteAddress: "127.0.0.1" }, headers: { "x-forwarded-for": "192.0.2.2" } }), "198.51.100.7");
  assert.equal(getClientIp({ socket: { remoteAddress: "::ffff:127.0.0.1" }, headers: { "cf-connecting-ip": "192.0.2.2" } }), "127.0.0.1");
});

test("WebDAV uses the Express 5 named wildcard syntax", () => {
  const contents = fs.readFileSync("server.js", "utf8");
  assert.match(contents, /app\.all\(`\$\{WEBDAV_PATH\}\/\*splat`, handler\)/);
});

test("revoked and disabled users cannot use old tokens", () => {
  assert.equal(authenticateRequest({ user: { username: "alice", disabled: true, sessionVersion: 2 } }).code, 401);
  assert.equal(authenticateRequest({ user: { username: "alice", sessionVersion: 3 } }).code, 401);
});

test("deleted usernames cannot resurrect old HTTP or WebSocket sessions", { timeout: 30_000 }, async (t) => {
  const password = crypto.randomBytes(24).toString("base64url");
  const recreatedPassword = crypto.randomBytes(24).toString("base64url");
  const users = ["admin", "agent"].map((username) => ({
    username,
    password: bcrypt.hashSync(password, 10),
    role: "user",
    permissions: { manageUsers: true },
    sessionVersion: 0,
  }));
  const cwd = createSandbox(users);
  const port = await getUnusedPort();
  const child = spawn(process.execPath, [SERVER], {
    cwd,
    env: { ...process.env, PORT: String(port), DB_ENABLED: "false", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    stdio: "ignore",
    windowsHide: true,
  });
  let socket;
  t.after(async () => {
    socket?.terminate();
    if (child.exitCode === null) {
      await new Promise((resolve) => {
        child.once("exit", resolve);
        child.kill();
      });
    }
    fs.rmSync(cwd, { recursive: true, force: true });
  });

  assert.equal((await waitForServer(port)).status, 200);
  const origin = `http://127.0.0.1:${port}`;
  const agent = await login(port, "agent", password);
  assert.equal((await request(port, "/storage/status", { headers: { cookie: agent.cookie } })).status, 200);
  socket = new WebSocket(`ws://127.0.0.1:${port}/ws`, { headers: { cookie: agent.cookie }, origin });
  await waitForWebSocketEvent(socket, "connected");
  socket.send(JSON.stringify({ event: "ping" }));
  await waitForWebSocketEvent(socket, "pong");

  const admin = await login(port, "admin", password);
  const headers = { cookie: admin.cookie, origin, "x-csrf-token": admin.csrf };
  assert.equal((await request(port, "/users/agent", { method: "DELETE", headers })).status, 200);
  const close = waitForWebSocketClose(socket);

  const createBody = JSON.stringify({ username: "agent", password: recreatedPassword, role: "user", permissions: { manageUsers: true } });
  assert.equal((await request(port, "/users", {
    method: "POST",
    headers: { ...headers, "content-type": "application/json", "content-length": Buffer.byteLength(createBody) },
    body: createBody,
  })).status, 201);

  assert.equal((await request(port, "/storage/status", { headers: { cookie: agent.cookie } })).status, 401);
  if (socket.readyState === WebSocket.OPEN) {
    const stalePong = waitForWebSocketEvent(socket, "pong", 500).then(() => {
      throw new Error("Resurrected WebSocket received pong");
    }, (error) => {
      if (!/Timed out/.test(error.message)) throw error;
    });
    socket.send(JSON.stringify({ event: "ping" }));
    await stalePong;
  }
  const closed = await close;
  assert.equal(closed.code, 1008);
  assert.equal(closed.reason, "Sessao revogada");

  const recreated = await login(port, "agent", recreatedPassword);
  assert.ok(recreated.sessionVersion > agent.sessionVersion);
  assert.equal((await request(port, "/storage/status", { headers: { cookie: recreated.cookie } })).status, 200);
  const newSocket = new WebSocket(`ws://127.0.0.1:${port}/ws`, { headers: { cookie: recreated.cookie }, origin });
  t.after(() => newSocket.terminate());
  await waitForWebSocketEvent(newSocket, "connected");
  newSocket.send(JSON.stringify({ event: "ping" }));
  await waitForWebSocketEvent(newSocket, "pong");
});

test("JSON user generations survive restart before same-username recreation", { timeout: 30_000 }, async (t) => {
  const password = crypto.randomBytes(24).toString("base64url");
  const recreatedPassword = crypto.randomBytes(24).toString("base64url");
  const users = ["admin", "agent"].map((username) => ({
    username,
    password: bcrypt.hashSync(password, 10),
    role: "user",
    permissions: { manageUsers: true },
    sessionVersion: 0,
  }));
  const cwd = createSandbox(users);
  const jwtSecret = crypto.randomBytes(48).toString("base64url");
  let port = await getUnusedPort();
  let child = spawn(process.execPath, [SERVER], {
    cwd,
    env: { ...process.env, PORT: String(port), DB_ENABLED: "false", JWT_SECRET: jwtSecret },
    stdio: "ignore",
    windowsHide: true,
  });
  t.after(async () => {
    if (child.exitCode === null) {
      await new Promise((resolve) => {
        child.once("exit", resolve);
        child.kill();
      });
    }
    fs.rmSync(cwd, { recursive: true, force: true });
  });

  assert.equal((await waitForServer(port)).status, 200);
  const agent = await login(port, "agent", password);
  const admin = await login(port, "admin", password);
  const origin = `http://127.0.0.1:${port}`;
  assert.equal((await request(port, "/users/agent", {
    method: "DELETE",
    headers: { cookie: admin.cookie, origin, "x-csrf-token": admin.csrf },
  })).status, 200);
  await new Promise((resolve) => {
    child.once("exit", resolve);
    child.kill();
  });

  port = await getUnusedPort();
  child = spawn(process.execPath, [SERVER], {
    cwd,
    env: { ...process.env, PORT: String(port), DB_ENABLED: "false", JWT_SECRET: jwtSecret },
    stdio: "ignore",
    windowsHide: true,
  });
  assert.equal((await waitForServer(port)).status, 200);
  const createBody = JSON.stringify({ username: "agent", password: recreatedPassword, role: "user", permissions: { manageUsers: true } });
  assert.equal((await request(port, "/users", {
    method: "POST",
    headers: {
      cookie: admin.cookie,
      origin: `http://127.0.0.1:${port}`,
      "x-csrf-token": admin.csrf,
      "content-type": "application/json",
      "content-length": Buffer.byteLength(createBody),
    },
    body: createBody,
  })).status, 201);

  const specialUsernameBody = JSON.stringify({ username: "constructor", password: crypto.randomBytes(24).toString("base64url"), role: "user", permissions: { manageUsers: true } });
  assert.equal((await request(port, "/users", {
    method: "POST",
    headers: {
      cookie: admin.cookie,
      origin: `http://127.0.0.1:${port}`,
      "x-csrf-token": admin.csrf,
      "content-type": "application/json",
      "content-length": Buffer.byteLength(specialUsernameBody),
    },
    body: specialUsernameBody,
  })).status, 201);
  const generations = JSON.parse(fs.readFileSync(path.join(cwd, "data", "user-generations.local.json"), "utf-8"));
  assert.equal(generations.constructor, 0, "special property names must persist as ordinary username keys");

  assert.equal((await request(port, "/storage/status", { headers: { cookie: agent.cookie } })).status, 401);
  const recreated = await login(port, "agent", recreatedPassword);
  assert.ok(recreated.sessionVersion > agent.sessionVersion);
});

test("permission removal revokes an existing browser session before a protected HTTP handler", { timeout: 30_000 }, async (t) => {
  const password = crypto.randomBytes(24).toString("base64url");
  const users = ["admin", "agent"].map((username) => ({
    username,
    password: bcrypt.hashSync(password, 10),
    role: "user",
    permissions: { manageUsers: true },
    sessionVersion: 0,
  }));
  const cwd = createSandbox(users);
  const port = await getUnusedPort();
  const child = spawn(process.execPath, [SERVER], {
    cwd,
    env: { ...process.env, PORT: String(port), DB_ENABLED: "false", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    stdio: "ignore",
    windowsHide: true,
  });
  t.after(async () => {
    if (child.exitCode === null) {
      await new Promise((resolve) => {
        child.once("exit", resolve);
        child.kill();
      });
    }
    fs.rmSync(cwd, { recursive: true, force: true });
  });

  assert.equal((await waitForServer(port)).status, 200);
  const agent = await login(port, "agent", password);
  assert.equal((await request(port, "/storage/status", { headers: { cookie: agent.cookie } })).status, 200);

  const admin = await login(port, "admin", password);
  const body = JSON.stringify({ permissions: { manageUsers: false } });
  assert.equal((await request(port, "/users/agent", {
    method: "PUT",
    headers: {
      cookie: admin.cookie,
      origin: `http://127.0.0.1:${port}`,
      "x-csrf-token": admin.csrf,
      "content-type": "application/json",
      "content-length": Buffer.byteLength(body),
    },
    body,
  })).status, 200);

  const denied = await request(port, "/storage/status", { headers: { cookie: agent.cookie } });
  assert.equal(denied.status, 401);
  assert.match(denied.body, /Token invalido ou expirado/);
});

test("permission removal closes an active WebSocket before its next authenticated message", { timeout: 30_000 }, async (t) => {
  const password = crypto.randomBytes(24).toString("base64url");
  const users = ["admin", "agent"].map((username) => ({
    username,
    password: bcrypt.hashSync(password, 10),
    role: "user",
    permissions: { manageUsers: true },
    sessionVersion: 0,
  }));
  const cwd = createSandbox(users);
  const port = await getUnusedPort();
  const child = spawn(process.execPath, [SERVER], {
    cwd,
    env: { ...process.env, PORT: String(port), DB_ENABLED: "false", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    stdio: "ignore",
    windowsHide: true,
  });
  let socket;
  t.after(async () => {
    socket?.terminate();
    if (child.exitCode === null) {
      await new Promise((resolve) => {
        child.once("exit", resolve);
        child.kill();
      });
    }
    fs.rmSync(cwd, { recursive: true, force: true });
  });

  assert.equal((await waitForServer(port)).status, 200);
  const agent = await login(port, "agent", password);
  const origin = `http://127.0.0.1:${port}`;
  socket = new WebSocket(`ws://127.0.0.1:${port}/ws`, { headers: { cookie: agent.cookie }, origin });
  await waitForWebSocketEvent(socket, "connected");
  socket.send(JSON.stringify({ event: "ping" }));
  await waitForWebSocketEvent(socket, "pong");

  const admin = await login(port, "admin", password);
  const body = JSON.stringify({ permissions: { manageUsers: false } });
  assert.equal((await request(port, "/users/agent", {
    method: "PUT",
    headers: {
      cookie: admin.cookie,
      origin,
      "x-csrf-token": admin.csrf,
      "content-type": "application/json",
      "content-length": Buffer.byteLength(body),
    },
    body,
  })).status, 200);

  const close = waitForWebSocketClose(socket);
  const stalePong = waitForWebSocketEvent(socket, "pong", 500).then(() => {
    throw new Error("Stale WebSocket received pong after permission removal");
  }, (error) => {
    if (!/Timed out/.test(error.message)) throw error;
  });
  socket.send(JSON.stringify({ event: "ping" }));
  await stalePong;
  const closed = await close;
  assert.equal(closed.code, 1008);
  assert.equal(closed.reason, "Sessao revogada");
});

test("expired browser session cookie is rejected before a protected HTTP handler", { timeout: 30_000 }, async (t) => {
  const password = crypto.randomBytes(24).toString("base64url");
  const users = [{
    username: "agent",
    password: bcrypt.hashSync(password, 10),
    role: "user",
    permissions: { manageUsers: true },
    sessionVersion: 0,
  }];
  const cwd = createSandbox(users);
  const port = await getUnusedPort();
  const jwtSecret = crypto.randomBytes(48).toString("base64url");
  const child = spawn(process.execPath, [SERVER], {
    cwd,
    env: { ...process.env, PORT: String(port), DB_ENABLED: "false", JWT_SECRET: jwtSecret },
    stdio: "ignore",
    windowsHide: true,
  });
  t.after(async () => {
    if (child.exitCode === null) {
      await new Promise((resolve) => {
        child.once("exit", resolve);
        child.kill();
      });
    }
    fs.rmSync(cwd, { recursive: true, force: true });
  });

  assert.equal((await waitForServer(port)).status, 200);
  const session = await login(port, "agent", password);
  assert.equal((await request(port, "/storage/status", { headers: { cookie: session.cookie } })).status, 200);

  const expired = jwt.sign({ username: "agent", sessionVersion: 0 }, jwtSecret, { expiresIn: -1 });
  const denied = await request(port, "/storage/status", { headers: { cookie: `rootark_session=${expired}` } });
  assert.equal(denied.status, 401);
  assert.match(denied.body, /Token invalido ou expirado/);
});

test("an expired active WebSocket closes before processing its next message", { timeout: 30_000 }, async (t) => {
  const password = crypto.randomBytes(24).toString("base64url");
  const users = [{
    username: "agent",
    password: bcrypt.hashSync(password, 10),
    role: "user",
    permissions: { manageUsers: true },
    sessionVersion: 0,
  }];
  const cwd = createSandbox(users);
  const port = await getUnusedPort();
  const jwtSecret = crypto.randomBytes(48).toString("base64url");
  const child = spawn(process.execPath, [SERVER], {
    cwd,
    env: { ...process.env, PORT: String(port), DB_ENABLED: "false", JWT_SECRET: jwtSecret },
    stdio: "ignore",
    windowsHide: true,
  });
  let socket;
  t.after(async () => {
    socket?.terminate();
    if (child.exitCode === null) {
      await new Promise((resolve) => {
        child.once("exit", resolve);
        child.kill();
      });
    }
    fs.rmSync(cwd, { recursive: true, force: true });
  });

  assert.equal((await waitForServer(port)).status, 200);
  const token = jwt.sign({ username: "agent", sessionVersion: 0 }, jwtSecret, { expiresIn: 2 });
  const { exp } = jwt.decode(token);
  assert.equal(typeof exp, "number");
  const origin = `http://127.0.0.1:${port}`;
  socket = new WebSocket(`ws://127.0.0.1:${port}/ws`, { headers: { cookie: `rootark_session=${token}` }, origin });
  await waitForWebSocketEvent(socket, "connected");
  socket.send(JSON.stringify({ event: "ping" }));
  await waitForWebSocketEvent(socket, "pong");

  await new Promise((resolve) => setTimeout(resolve, Math.max(0, exp * 1000 - Date.now()) + 150));
  const close = waitForWebSocketClose(socket);
  const stalePong = waitForWebSocketEvent(socket, "pong", 500).then(() => {
    throw new Error("Expired WebSocket received pong");
  }, (error) => {
    if (!/Timed out/.test(error.message)) throw error;
  });
  socket.send(JSON.stringify({ event: "ping" }));
  await stalePong;
  const closed = await close;
  assert.equal(closed.code, 1008);
  assert.equal(closed.reason, "Sessao expirada");
});

test("browser pages contain no persisted auth keys or WebSocket token URLs", () => {
  for (const file of ["login.html", "index.html", "dashboard.html", "admin.html", "audit.html", "backups.html"]) {
    const contents = fs.readFileSync(`public/${file}`, "utf8");
    assert.doesNotMatch(contents, /localStorage\.(getItem|setItem|clear)\([^)]*(token|permissions|username|role)/);
    assert.doesNotMatch(contents, /\/ws\?token/);
  }
});

test("dashboard activity escapes dynamic values before rendering", () => {
  const contents = fs.readFileSync("public/client/rootark-management.js", "utf8");
  const renderer = contents.match(/activity\.innerHTML = events\.length \? events\.map\(\(item\) => `([^`]+)`\)\.join\(""\)/);
  assert.ok(renderer, "the recent-activity renderer must remain discoverable");
  assert.match(renderer[1], /<span>\$\{esc\(eventDescription\(item\)\)\}<\/span>/);
  assert.match(renderer[1], /datetime="\$\{esc\(item\.timestamp \|\| ""\)\}"/);
  assert.match(renderer[1], />\$\{esc\(ui\.formatDate\(item\.timestamp\)\)\}<\/time>/);
});

test("session bootstrap escapes identity data before embedding JavaScript", () => {
  const contents = fs.readFileSync("server.js", "utf8");
  assert.match(contents, /JSON\.stringify\([^\n]+\.replace\(\/</);
});
