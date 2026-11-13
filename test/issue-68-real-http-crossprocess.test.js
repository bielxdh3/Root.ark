"use strict";

// Both remote participants are REAL independent Node processes with separate
// SQLite handles and actual HTTP.ServerResponse instances. They intentionally
// share ONE disposable physical WAL database; this proves no multi-host ledger.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const http = require("node:http");
const { fork } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Database = require("better-sqlite3");
const { Zk1ProtectedCiphertextSharing } =
  require("../src/services/zk1ProtectedCiphertextSharing");

const childFile = path.join(__dirname, "support", "issue-68-real-http-crossprocess-child.js");
const domain = Buffer.from("Root.ark/issue-68/two-process-http-fixture/v1\0");
const sleep = (duration) => new Promise((resolve) => setTimeout(resolve, duration));

function fixture(t) {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "zk68-real-two-process-"));
  const filename = path.join(folder, "wal.sqlite");
  const db = new Database(filename);
  db.pragma("journal_mode = WAL");
  new Zk1ProtectedCiphertextSharing({
    db, signedHistoryRequired: true, admissionRequired: true,
    nowSeconds: () => 1400,
    runWithAdmission() { throw Error("transport fixture only"); },
  });
  const scope = {
    account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(8),
    keyring_id: crypto.randomBytes(16),
  };
  const scopeId = Object.values(scope).map((part) => part.toString("hex")).join(":");
  const grantId = crypto.randomBytes(32).toString("base64url");
  db.prepare("INSERT INTO zk_content_share " +
    "(grant_id,scope,statement,signature,owner_username,recipient_username,expires_at) " +
    "VALUES(?,?,?,?,?,?,?)")
    .run(grantId, scopeId, Buffer.from("fixture-only; not a signed owner grant"),
      Buffer.alloc(64), "owner", "recipient", 2000);
  t.after(() => {
    if (db.inTransaction) db.exec("ROLLBACK");
    if (db.open) db.close();
    fs.rmSync(folder, { recursive: true, force: true });
  });
  return { db, filename, scope, grantId, scopeId };
}

function peer(t, role, setup) {
  const child = fork(childFile, [role], {
    execArgv: [], stdio: ["ignore", "ignore", "pipe", "ipc"],
    env: { ...process.env, W3_DB: setup.filename, W3_GRANT: setup.grantId,
      W3_SCOPE: JSON.stringify(Object.fromEntries(Object.entries(setup.scope)
        .map(([field, bytes]) => [field, bytes.toString("hex")]))),
      W3_GUEST_PUBLIC: setup.keys.guest.publicKey.export({ format: "der", type: "spki" }).toString("base64"),
      W3_OWNER_PUBLIC: setup.keys.owner.publicKey.export({ format: "der", type: "spki" }).toString("base64") },
  });
  let stderr = "";
  child.stderr.on("data", (part) => { stderr = (stderr + String(part)).slice(-800); });
  const messages = [];
  const listeners = [];
  child.on("message", (message) => {
    const index = listeners.findIndex((entry) => entry.kind === message.kind);
    if (index === -1) messages.push(message);
    else {
      const entry = listeners.splice(index, 1)[0];
      clearTimeout(entry.timer);
      entry.resolve(message);
    }
  });
  const exited = new Promise((resolve) => child.once("exit", resolve));
  const next = (kind, timeoutMs = 12000) => {
    const index = messages.findIndex((entry) => entry.kind === kind);
    if (index >= 0) return Promise.resolve(messages.splice(index, 1)[0]);
    return new Promise((resolve, reject) => {
      const entry = { kind, resolve, reject, timer: null };
      entry.timer = setTimeout(() => {
        const position = listeners.indexOf(entry);
        if (position >= 0) listeners.splice(position, 1);
        reject(new Error(`${role} did not emit ${kind}: ${stderr}`));
      }, timeoutMs);
      listeners.push(entry);
    });
  };
  const stop = async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await Promise.race([exited, sleep(4000)]);
  };
  t.after(stop);
  return { child, next, stop, send: (message) => child.send(message) };
}

function signedRequest(role, key, port) {
  const nonce = crypto.randomBytes(16).toString("hex");
  const signature = crypto.sign(null, Buffer.concat([domain,
    Buffer.from(`${role}:${nonce}`, "ascii")]), key.privateKey).toString("base64url");
  return new Promise((resolve, reject) => {
    const request = http.request({ hostname: "127.0.0.1", port,
      path: role === "guest" ? "/ciphertext" : "/revoke",
      method: role === "guest" ? "GET" : "POST",
      headers: { "x-fixture-account": role, "x-fixture-nonce": nonce,
        "x-fixture-signature": signature },
    }, (response) => {
      const chunks = [];
      response.on("data", (part) => chunks.push(part));
      response.once("end", () => resolve({ status: response.statusCode,
        body: Buffer.concat(chunks).toString("utf8") }));
      response.once("error", reject);
      response.once("aborted", () => reject(Error("HTTP peer aborted")));
    });
    request.once("error", reject);
    request.end();
  });
}

async function until(predicate, timeoutMs = 6000) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) throw Error("timed out waiting for durable SQLite state");
    await sleep(25);
  }
}

async function startTwo(t, f) {
  const keys = { guest: crypto.generateKeyPairSync("ed25519"),
    owner: crypto.generateKeyPairSync("ed25519") };
  const setup = { ...f, keys };
  const guest = peer(t, "guest", setup);
  const owner = peer(t, "owner", setup);
  const [guestInfo, ownerInfo] = await Promise.all([guest.next("ready"), owner.next("ready")]);
  assert.notEqual(guestInfo.pid, ownerInfo.pid);
  assert.notEqual(guestInfo.pid, process.pid);
  assert.notEqual(ownerInfo.pid, process.pid);
  return { guest, owner, keys, guestPort: guestInfo.port, ownerPort: ownerInfo.port };
}

test("real cross-process HTTP: remote guest finish precedes durable owner revoke ACK",
  { timeout: 22000 }, async (t) => {
    const f = fixture(t);
    const { guest, owner, keys, guestPort, ownerPort } = await startTwo(t, f);
    try {
      assert.deepEqual(await signedRequest("guest", keys.owner, guestPort),
        { status: 403, body: "" }, "wrong fixture device cannot start ciphertext egress");
      assert.equal(f.db.prepare("SELECT count(*) n FROM zk_content_share_egress WHERE grant_id=?")
        .get(f.grantId).n, 0, "failed signed guest authentication cannot create a lease");
      const receiving = signedRequest("guest", keys.guest, guestPort);
      await guest.next("admitted");
      assert.equal(f.db.prepare("SELECT count(*) n FROM zk_content_share_egress WHERE grant_id=?")
        .get(f.grantId).n, 1);
      let acknowledged = false;
      const revoking = signedRequest("owner", keys.owner, ownerPort)
        .then((reply) => { acknowledged = true; return reply; });
      await until(() => f.db.prepare("SELECT revoked FROM zk_content_share WHERE grant_id=?")
        .get(f.grantId).revoked === 1);
      assert.equal(acknowledged, false, "a different Node process cannot ACK before HTTP finish");
      assert.deepEqual(await signedRequest("guest", keys.guest, guestPort),
        { status: 403, body: "" }, "new signed guest read denied after tombstone");
      assert.equal(f.db.prepare("SELECT count(*) n FROM zk_content_share_egress WHERE grant_id=?")
        .get(f.grantId).n, 1, "in-flight lease stays physically durable until finish");
      guest.send({ kind: "release" });
      const [settled, sent, revoked] = await Promise.all([
        guest.next("settled"), receiving, revoking,
      ]);
      assert.equal(settled.ok, true);
      assert.deepEqual(sent, { status: 200, body: "ciphertext-only" });
      assert.deepEqual(revoked, { status: 200, body: "revoked" });
      assert.equal(f.db.prepare("SELECT count(*) n FROM zk_content_share_egress WHERE grant_id=?")
        .get(f.grantId).n, 0);
    } finally { await Promise.all([guest.stop(), owner.stop()]); }
  });

test("real cross-process HTTP: live guest reconciles terminal lease after transient WAL writer lock",
  { timeout: 23000 }, async (t) => {
    const f = fixture(t);
    const { guest, owner, keys, guestPort, ownerPort } = await startTwo(t, f);
    try {
      const receiving = signedRequest("guest", keys.guest, guestPort);
      await guest.next("admitted");
      f.db.exec("BEGIN IMMEDIATE");
      try {
        guest.send({ kind: "release" });
        const settled = await guest.next("settled", 4000);
        assert.equal(settled.ok, false,
          "terminal release fails while independent WAL writer holds the lock");
        assert.equal(settled.code, "ZK_SHARE_UNAVAILABLE");
        assert.deepEqual(await receiving, { status: 200, body: "ciphertext-only" });
        assert.equal(f.db.prepare("SELECT count(*) n FROM zk_content_share_egress WHERE grant_id=?")
          .get(f.grantId).n, 1);
      } finally { f.db.exec("ROLLBACK"); }
      // The guest process remains alive but receives no further request or IPC.
      // Only its observed terminal HTTP event can authorize removing this row.
      const revoked = await signedRequest("owner", keys.owner, ownerPort);
      assert.deepEqual(revoked, { status: 200, body: "revoked" },
        "healthy remote owner must ACK after guest's durable terminal reconciliation");
      assert.equal(f.db.prepare("SELECT count(*) n FROM zk_content_share_egress WHERE grant_id=?")
        .get(f.grantId).n, 0);
    } finally {
      if (f.db.inTransaction) f.db.exec("ROLLBACK");
      await Promise.all([guest.stop(), owner.stop()]);
    }
  });

test("real cross-process HTTP: SQLITE_BUSY then crashed guest leaves remote orphan 503 even after expiry",
  { timeout: 32000 }, async (t) => {
    const f = fixture(t);
    const { guest, owner, keys, guestPort, ownerPort } = await startTwo(t, f);
    try {
      const receiving = signedRequest("guest", keys.guest, guestPort);
      await guest.next("admitted");
      f.db.exec("BEGIN IMMEDIATE");
      try {
        guest.send({ kind: "release" });
        const settled = await guest.next("settled", 4000);
        assert.equal(settled.ok, false, "terminal DELETE must fail under a real WAL writer lock");
        assert.equal(settled.code, "ZK_SHARE_UNAVAILABLE");
        assert.equal(settled.busyTimeout, 50, "failed delete must restore the guest SQLite policy");
        assert.deepEqual(await receiving, { status: 200, body: "ciphertext-only" });
        assert.equal(f.db.prepare("SELECT count(*) n FROM zk_content_share_egress WHERE grant_id=?")
          .get(f.grantId).n, 1, "SQLITE_BUSY cannot silently delete a terminal lease");
      } finally { f.db.exec("ROLLBACK"); }
      await guest.stop(); // Simulate loss of the only process with observed terminal proof.
      owner.send({ kind: "clock", now: 2001 });
      assert.equal((await owner.next("clockSet")).now, 2001);
      const revoked = await signedRequest("owner", keys.owner, ownerPort);
      assert.equal(revoked.status, 503,
        "remote orphan remains fail-closed after 10s drain and 1s grace");
      assert.equal(f.db.prepare("SELECT revoked FROM zk_content_share WHERE grant_id=?")
        .get(f.grantId).revoked, 1, "owner tombstone persists despite denied ACK");
      assert.equal(f.db.prepare("SELECT count(*) n FROM zk_content_share_egress WHERE grant_id=?")
        .get(f.grantId).n, 1, "expiry never TTL-prunes an unproven cross-process orphan");
    } finally {
      if (f.db.inTransaction) f.db.exec("ROLLBACK");
      await Promise.all([guest.stop(), owner.stop()]);
    }
  });

test("real cross-process HTTP: an expired grant cannot admit another response or stale lease",
  { timeout: 22000 }, async (t) => {
    const f = fixture(t);
    const { guest, owner, keys, guestPort, ownerPort } = await startTwo(t, f);
    try {
      const receiving = signedRequest("guest", keys.guest, guestPort);
      await guest.next("admitted");
      guest.send({ kind: "clock", now: 2000 });
      assert.equal((await guest.next("clockSet")).now, 2000);
      assert.deepEqual(await signedRequest("guest", keys.guest, guestPort),
        { status: 403, body: "" }, "signed request at expiry cannot acquire a new lease");
      assert.equal(f.db.prepare("SELECT count(*) n FROM zk_content_share_egress WHERE grant_id=?")
        .get(f.grantId).n, 1, "already-admitted response is not retroactively revoked");
      guest.send({ kind: "release" });
      const [settled, sent] = await Promise.all([guest.next("settled"), receiving]);
      assert.equal(settled.ok, true, "proven finish can safely settle a pre-expiry lease");
      assert.deepEqual(sent, { status: 200, body: "ciphertext-only" });
      assert.equal(f.db.prepare("SELECT count(*) n FROM zk_content_share_egress WHERE grant_id=?")
        .get(f.grantId).n, 0);
      assert.deepEqual(await signedRequest("owner", keys.owner, ownerPort),
        { status: 200, body: "revoked" }, "no stale lease blocks later owner ACK");
    } finally { await Promise.all([guest.stop(), owner.stop()]); }
  });

test("helper refuses missing IPC configuration instead of starting an unauthenticated HTTP peer",
  { timeout: 18000 }, async (t) => {
    const f = fixture(t);
    const keys = { guest: crypto.generateKeyPairSync("ed25519"),
      owner: crypto.generateKeyPairSync("ed25519") };
    const validEnv = {
      ...process.env, W3_DB: f.filename, W3_GRANT: f.grantId,
      W3_SCOPE: JSON.stringify(Object.fromEntries(Object.entries(f.scope)
        .map(([field, value]) => [field, value.toString("hex")]))),
      W3_GUEST_PUBLIC: keys.guest.publicKey.export({ format: "der", type: "spki" }).toString("base64"),
      W3_OWNER_PUBLIC: keys.owner.publicKey.export({ format: "der", type: "spki" }).toString("base64"),
    };
    for (const missing of ["W3_DB", "W3_SCOPE", "W3_GRANT", "W3_GUEST_PUBLIC", "W3_OWNER_PUBLIC"]) {
      const env = { ...validEnv };
      delete env[missing];
      const child = fork(childFile, ["guest"], {
        execArgv: [], stdio: ["ignore", "ignore", "pipe", "ipc"], env,
      });
      let stderr = "";
      let announcedReady = false;
      child.stderr.on("data", (bytes) => { stderr = (stderr + bytes.toString()).slice(-1500); });
      child.on("message", (message) => {
        if (message?.kind === "ready") announcedReady = true;
      });
      const exit = new Promise((resolve) => child.once("exit", resolve));
      const timer = setTimeout(() => child.kill(), 2500);
      const code = await exit;
      clearTimeout(timer);
      assert.notEqual(code, 0, `${missing} omitted: helper must fail closed`);
      assert.equal(announcedReady, false, `${missing} omitted: no listener may be exposed`);
      assert.match(stderr, /ZK_SHARE_HTTP_FIXTURE_INVALID_IPC_ENV/,
        `${missing} omitted: reject at the IPC configuration gate`);
    }
  });
