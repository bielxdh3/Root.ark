"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const http = require("node:http");
const crypto = require("node:crypto");
const os = require("node:os");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
// Build independent AES-GCM catalog fixtures without loading server secrets,
// DB or the optional HPKE dependencies used by the production app.
function cborHead(type, value) {
  const t = type << 5;
  if (value < 24) return Buffer.from([t + value]);
  if (value < 256) return Buffer.from([t + 24, value]);
  if (value < 65536) return Buffer.from([t + 25, value >> 8, value & 255]);
  throw Error("FIXTURE_CBOR_RANGE");
}
function fixtureCbor(value) {
  if (typeof value === "number") return cborHead(0, value);
  if (typeof value === "string") {
    const bytes = Buffer.from(value); return Buffer.concat([cborHead(3, bytes.length), bytes]);
  }
  if (Buffer.isBuffer(value)) return Buffer.concat([cborHead(2, value.length), value]);
  const pairs = Object.entries(value).map(([key, inner]) =>
    [fixtureCbor(key), fixtureCbor(inner)]);
  pairs.sort(([a], [b]) => a.length - b.length || Buffer.compare(a, b));
  return Buffer.concat([cborHead(5, pairs.length), ...pairs.flat()]);
}
async function sealZk1CatalogMetadataV1({ scope, objectId, revision, epoch,
  metadataKey, name }) {
  const aad = Buffer.concat([
    Buffer.from("Root.ark/zk-1/opaque-catalog-metadata/v1\0"),
    fixtureCbor({ ...scope, object_id: objectId, revision, epoch }),
  ]);
  const iv = crypto.randomBytes(12);
  const clear = crypto.randomBytes(256), filename = Buffer.from(name);
  clear.writeUInt16BE(filename.length, 0);
  filename.copy(clear, 2);
  const cipher = crypto.createCipheriv("aes-256-gcm", metadataKey, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(clear), cipher.final()]);
  clear.fill(0);
  return Buffer.concat([iv, ciphertext, cipher.getAuthTag()]);
}

const clientRoot = path.join(__dirname, "../public/client");
const load = (name) => fs.readFileSync(path.join(clientRoot, name + ".js"), "utf8");
const probe = fs.readFileSync(path.join(__dirname,
  "support/issue-65-opaque-restore-probe.js"), "utf8");
const clientSource = load("rootark-zk1-opaque-device-delta-sync");
const cases = ["valid", "forgedSignature", "tamperedSource", "wrongCek",
  "wrongAncestry", "staleOwner", "revoked", "rollback", "logout",
  "epochRollover", "lostReadback", "rekeyValid", "rekeyForgedGrant",
  "rekeyWrongOwner", "rekeyStaleDeviceGrant",
  "rekeyStaleGrant", "rekeyRevokedGrant", "rekeyWrongEpoch",
  "rekeyWrongMetadataKey", "rekeySameCek", "rekeyNoGrant",
  "rekeyExpiredGrant", "rekeySameMetadataKey",
  "rekeySameTombstoneKey", "rekeyExpiredDuringRead",
  "rekeySignerSubstitute", "rekeyRollback",
  "rekeyLostReadback"];

test("normal browser restores signed logical trash with real HTTP readback, AAD and fail-closed journals", {
  timeout: 120_000,
}, async (t) => {
  const stored = new Map(), requests = [];
  const server = http.createServer(async (request, response) => {
    if (request.method !== "POST" || !["/fixture", "/protected-get",
      "/protected-put"].includes(request.url)) {
      response.writeHead(404); response.end(); return;
    }
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString("utf8");
    requests.push({ path: request.url, body: raw });
    let body;
    try { body = JSON.parse(raw); } catch (_) {
      response.writeHead(400); response.end(); return;
    }
    const key = body.objectId + ":" + body.revision;
    let result, status = 200;
    if (request.url === "/protected-get") {
      const ciphertextBase64 = stored.get(key);
      if (!ciphertextBase64) status = 404;
      result = { ciphertextBase64 };
    } else {
      if (!/^[A-Za-z0-9_-]{22}$/.test(body.objectId)
        || !Number.isSafeInteger(body.revision)
        || body.revision < 1 || typeof body.ciphertextBase64 !== "string"
        || (request.url === "/protected-put" && stored.has(key))) {
        status = 409;
      } else stored.set(key, body.ciphertextBase64);
      result = { accepted: status === 200 };
    }
    response.writeHead(status, { "content-type": "application/json" });
    response.end(JSON.stringify(result));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const origin = "http://127.0.0.1:" + server.address().port;
  for (const caseName of cases) {
    const scopeRaw = { account_id: crypto.randomBytes(16),
      compartment_id: crypto.randomBytes(16), keyring_id: crypto.randomBytes(16) };
    const scope = Object.fromEntries(Object.entries(scopeRaw)
      .map(([key, raw]) => [key, raw.toString("base64url")]));
    const objectId = crypto.randomBytes(16).toString("base64url");
    const sourceMetadata = { ...scope, object_id: objectId,
      version_id: crypto.randomBytes(16).toString("base64url"),
      parent_version_id: null, epoch: 1, kind: "file" };
    const metadataKey = crypto.randomBytes(32);
    const tombstoneMetadataKey = caseName.startsWith("rekey")
      && caseName !== "rekeySameTombstoneKey"
      ? crypto.randomBytes(32) : metadataKey;
    const sourceMetadataCiphertext = await sealZk1CatalogMetadataV1({
      scope: scopeRaw, objectId, revision: 1, epoch: 1,
      metadataKey, name: "restored-private-name.txt" });
    const tombstoneMetadataCiphertext = await sealZk1CatalogMetadataV1({
      scope: scopeRaw, objectId, revision: 2,
      epoch: caseName === "epochRollover" || caseName.startsWith("rekey") ? 2 : 1,
      metadataKey: tombstoneMetadataKey, name: "\uE000rootark-zk1-logical-trash/v1" });
    const fixture = { caseName, origin, scope, objectId, sourceMetadata,
      sourceMetadataCiphertextBase64: sourceMetadataCiphertext.toString("base64url"),
      tombstoneMetadataCiphertextBase64: tombstoneMetadataCiphertext.toString("base64url"),
      metadataKeyBase64: metadataKey.toString("base64url"),
      tombstoneMetadataKeyBase64: tombstoneMetadataKey.toString("base64url"),
      cekBase64: crypto.randomBytes(32).toString("base64url") };
    const context = vm.createContext({ crypto: crypto.webcrypto,
      TextEncoder, TextDecoder, atob, btoa, fetch });
    for (const script of ["rootark-zk1-browser-opaque-catalog-commit",
      "rootark-zk1-file-content", "rootark-zk1-ciphertext-chunk-root"]) {
      vm.runInContext(load(script), context, { filename: script + ".js" });
    }
    context.installOpaqueRestoreClient = () => vm.runInContext(
      clientSource, context, { filename: "rootark-zk1-opaque-device-delta-sync.js" });
    vm.runInContext(probe, context, { filename: "issue-65-opaque-restore-probe.js" });
    context.restoreFixture = fixture;
    const before = requests.length;
    const result = await vm.runInContext("runOpaqueRestoreProbe(restoreFixture)", context);
    assert.equal(result.result, "PASS", caseName);
    assert.equal(result.caseName, caseName);
    assert.equal(result.puts, ["valid", "lostReadback", "rekeyValid",
      "rekeyLostReadback"].includes(caseName) ? 1 : 0,
      caseName + ": prohibited PUT");
    const wire = requests.slice(before);
    assert.equal(wire.filter((entry) => entry.path === "/protected-get").length,
      result.gets + (result.puts && ["valid", "rekeyValid", "lostReadback",
        "rekeyLostReadback"].includes(caseName) ? 1 : 0),
      caseName + ": protected GET count");
    assert.equal(wire.filter((entry) => entry.path === "/protected-put").length,
      result.puts, caseName);
    assert.ok(wire.every((entry) =>
      !entry.body.includes("restored-private-name.txt")
      && !entry.body.includes("private-file-content")
      && !entry.body.includes(fixture.cekBase64)), caseName + ": cleartext disclosure");
    assert.equal(wire.some((entry) => /delete/i.test(entry.path)), false,
      caseName + ": no physical delete");
  }
});

test("real Edge WebCrypto restores via HTTP loopback under restrictive CSP", {
  timeout: 45_000,
}, async (t) => {
  const edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
  if (process.platform !== "win32" || !fs.existsSync(edge)) {
    t.skip("real Edge Windows unavailable");
    return;
  }
  const stored = new Map(), wire = [];
  const scopeRaw = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(16), keyring_id: crypto.randomBytes(16) };
  const scope = Object.fromEntries(Object.entries(scopeRaw)
    .map(([key, value]) => [key, value.toString("base64url")]));
  const objectId = crypto.randomBytes(16).toString("base64url");
  const metadataKey = crypto.randomBytes(32);
  const tombstoneMetadataKey = crypto.randomBytes(32);
  const sourceMetadata = { ...scope, object_id: objectId,
    version_id: crypto.randomBytes(16).toString("base64url"),
    parent_version_id: null, epoch: 1, kind: "file" };
  const original = await sealZk1CatalogMetadataV1({
    scope: scopeRaw, objectId, revision: 1, epoch: 1,
    metadataKey, name: "restored-private-name.txt" });
  const tombstone = await sealZk1CatalogMetadataV1({
    scope: scopeRaw, objectId, revision: 2, epoch: 2,
    metadataKey: tombstoneMetadataKey,
    name: "\uE000rootark-zk1-logical-trash/v1" });
  const fixture = { caseName: "rekeyValid", origin: "", scope, objectId, sourceMetadata,
    sourceMetadataCiphertextBase64: original.toString("base64url"),
    tombstoneMetadataCiphertextBase64: tombstone.toString("base64url"),
    metadataKeyBase64: metadataKey.toString("base64url"),
    tombstoneMetadataKeyBase64: tombstoneMetadataKey.toString("base64url"),
    cekBase64: crypto.randomBytes(32).toString("base64url") };
  const bootstrap = "window.__restoreFixture=" + JSON.stringify(fixture) + ";"
    + "window.__restoreFixture.origin=location.origin;"
    + "window.installOpaqueRestoreClient=()=>new Promise((resolve,reject)=>{"
    + "const script=document.createElement('script');script.src='/delta.js';"
    + "script.onload=resolve;script.onerror=reject;document.head.appendChild(script);});";
  const html = "<!doctype html><meta charset='utf-8'>"
    + "<output id='restore-result'>PENDING</output>"
    + "<script src='/bootstrap.js'></script><script src='/catalog.js'></script>"
    + "<script src='/content.js'></script><script src='/root.js'></script>"
    + "<script src='/probe.js'></script><script src='/runner.js'></script>";
  const runner = "window.addEventListener('load',async()=>{"
    + "const out=document.getElementById('restore-result');"
    + "try{for(const caseName of ['rekeyValid','rekeyForgedGrant',"
    + "'rekeyRevokedGrant','rekeySignerSubstitute','rekeyWrongEpoch']){"
    + "const fixture={...window.__restoreFixture,caseName};"
    + "const result=await window.runOpaqueRestoreProbe(fixture);"
    + "if(result.result!=='PASS')throw Error(caseName+':FAILED');}"
    + "out.textContent='EDGE_REKEY_HTTP_PASS';}"
    + "catch(error){out.textContent='EDGE_REKEY_HTTP_FAIL:'+error.message;}});";
  const server = http.createServer(async (request, response) => {
    response.setHeader("Content-Security-Policy",
      "default-src 'none'; script-src 'self'; connect-src 'self'");
    const scripts = { "/": html, "/bootstrap.js": bootstrap,
      "/catalog.js": load("rootark-zk1-browser-opaque-catalog-commit"),
      "/content.js": load("rootark-zk1-file-content"),
      "/root.js": load("rootark-zk1-ciphertext-chunk-root"),
      "/delta.js": clientSource, "/probe.js": probe, "/runner.js": runner };
    if (Object.hasOwn(scripts, request.url)) {
      response.writeHead(200, { "content-type": request.url === "/"
        ? "text/html; charset=utf-8" : "text/javascript; charset=utf-8" });
      response.end(scripts[request.url]);
      return;
    }
    if (request.method !== "POST" || !["/fixture", "/protected-get",
      "/protected-put"].includes(request.url)) {
      response.writeHead(404); response.end(); return;
    }
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const text = Buffer.concat(chunks).toString("utf8");
    wire.push({ path: request.url, body: text });
    let body;
    try { body = JSON.parse(text); } catch (_) {
      response.writeHead(400); response.end(); return;
    }
    const key = body.objectId + ":" + body.revision;
    let status = 200, result;
    if (request.url === "/protected-get") {
      result = { ciphertextBase64: stored.get(key) };
      if (!result.ciphertextBase64) status = 404;
    } else {
      if (stored.has(key) && request.url === "/protected-put") status = 409;
      else stored.set(key, body.ciphertextBase64);
      result = { accepted: status === 200 };
    }
    response.writeHead(status, { "content-type": "application/json" });
    response.end(JSON.stringify(result));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-opaque-restore-edge-"));
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(folder, { recursive: true, force: true, maxRetries: 5 });
  });
  const origin = "http://127.0.0.1:" + server.address().port;
  const result = await promisify(execFile)(edge, [
    "--headless=new", "--disable-gpu", "--no-first-run", "--disable-extensions",
    "--no-default-browser-check", "--virtual-time-budget=12000",
    "--user-data-dir=" + path.join(folder, "edge-profile"), "--dump-dom", origin,
  ], { timeout: 35_000, windowsHide: true, maxBuffer: 1024 * 1024 });
  assert.match(result.stdout, /EDGE_REKEY_HTTP_PASS/);
  assert.doesNotMatch(result.stdout, /EDGE_REKEY_HTTP_FAIL/);
  assert.equal(wire.filter((request) => request.path === "/protected-put").length, 1);
  assert.ok(wire.filter((request) => request.path === "/protected-get").length >= 4);
  assert.ok(wire.every((request) =>
    !request.body.includes("restored-private-name.txt")
    && !request.body.includes("private-file-content")
    && !request.body.includes(fixture.cekBase64)));
});
