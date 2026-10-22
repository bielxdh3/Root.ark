"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const express = require("express");
const z = require("../src/crypto/rootark-zk-1");
const v2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const normal = require("../public/client/rootark-zk1-normal-browser-content");
const { Zk1ProtectedObjectStore } = require("../src/services/zk1ProtectedObjectStore");
const { registerZk1ProtectedObjectRoutes } = require("../src/routes/zk1ProtectedObjectRoutes");

const EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const id = () => crypto.randomBytes(16).toString("base64url");
const b64 = (value) => Buffer.from(value).toString("base64url");
const grantFields = ["schema", "account_id", "compartment_id", "keyring_id",
  "device_id", "authorization_key_id", "authorization_public_key",
  "manifest_revision", "manifest_digest", "current_epoch",
  "enrolled_epoch", "revoked_at_epoch"];
const grantDomain = Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0");
const witnessDomain = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0");
const scriptNames = ["rootark-zk1-file-content", "rootark-zk1-ciphertext-chunk-root",
  "rootark-zk1-ciphertext-download-integrity", "rootark-zk1-owner-signed-checkpoint",
  "rootark-zk1-owner-ciphertext-root-checkpoint", "rootark-zk1-protected-http-client",
  "rootark-zk1-uncertain-put-reconciliation", "rootark-zk1-normal-browser-content",
  "rootark-zk1-normal-browser-lab-ui"];

async function setup(t) {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-normal-browser-"));
  const clock = Math.floor(Date.now() / 1000);
  const state = await fixtures.createInitialState(2);
  let head = state.headManifest;
  const baseDigest = await v2.recoveryManifestDigestV2(state.baseManifest);
  const witness = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const owner = crypto.generateKeyPairSync("ed25519");
  const ownerRaw = owner.publicKey.export({ type: "spki", format: "der" }).subarray(12);
  const device = head.devices[0];
  // State actor map is keyed by the hex identity, not its wire encoding.
  const devicePair = state.actors.get(Buffer.from(device.authorization_key_id).toString("hex"));
  assert.ok(devicePair);
  const privateDer = devicePair.export({ type: "pkcs8", format: "der" });
  const subtle = crypto.webcrypto.subtle;
  const devicePrivateKey = await subtle.importKey("pkcs8", privateDer, "Ed25519", false, ["sign"]);
  const devicePublicKey = await subtle.importKey("raw", device.authorization_public_key,
    "Ed25519", true, ["verify"]);
  const ownerPublicKey = await subtle.importKey("raw", ownerRaw,
    "Ed25519", true, ["verify"]);
  const scopeWire = Object.fromEntries(Object.entries(state.scope).map(([k, v]) => [k, b64(v)]));
  const makeGrant = async (overrides = {}) => {
    const digest = await v2.recoveryManifestDigestV2(head);
    const body = {
      schema: "rootark-zk1-browser-owner-device-grant/v1",
      ...scopeWire, device_id: device.device_id,
      authorization_key_id: b64(device.authorization_key_id),
      authorization_public_key: b64(device.authorization_public_key),
      manifest_revision: head.revision, manifest_digest: b64(digest),
      current_epoch: head.current_epoch, enrolled_epoch: device.enrolled_epoch,
      revoked_at_epoch: device.revoked_at_epoch, ...overrides,
    };
    const canonical = Object.fromEntries(grantFields.map((key) => [key, body[key]]));
    const signature = crypto.sign(null, Buffer.concat([
      grantDomain, Buffer.from(JSON.stringify(canonical)),
    ]), owner.privateKey);
    return { ...canonical, signature: b64(signature) };
  };
  const currentHead = async () => ({
    revision: head.revision, digest: await v2.recoveryManifestDigestV2(head),
    epoch: head.current_epoch,
  });
  const app = express();
  let putCount = 0;
  app.use((req, _res, next) => {
    if (req.path === "/zk-1/v1/content/put") putCount++;
    next();
  });
  const store = new Zk1ProtectedObjectStore(path.join(folder, "store.sqlite"), {
    trustedScope: state.scope, bootstrapNew: true, admissionRequired: true,
    minimumHead: { revision: 1, witnessSequence: 1, digest: baseDigest },
    witnessProvider: {
      async freshHead({ nonce }) {
        const unsigned = {
          type: "rootark-recovery-witness-head/v1",
          witness_key_id: witnessKeyId, ...state.scope, nonce,
          current_revision: head.revision,
          current_manifest_digest: await v2.recoveryManifestDigestV2(head),
          witness_sequence: head.revision,
          observed_at: clock, status: "committed", pending_reservation_id: null,
        };
        return z.encodeDeterministic({ ...unsigned, signature: crypto.sign(null,
          Buffer.concat([witnessDomain, Buffer.from(await z.encodeDeterministic(unsigned))]),
          witness.privateKey) });
      },
      async beginIoAdmission() { return { admissionId: crypto.randomBytes(16), proceed: true }; },
      async finishIoAdmission() { return { status: "FINISHED" }; },
    },
    witnessPinned: { keyId: witnessKeyId, publicKey: witness.publicKey },
    manifestProvider: () => z.encodeDeterministic(head),
    nowSeconds: () => clock,
  });
  registerZk1ProtectedObjectRoutes({
    app, store,
    authenticate: (req, _res, next) => { req.user = { username: "synthetic" }; next(); },
    requirePermission: () => (_req, _res, next) => next(),
    resolveTrustedScope: () => state.scope,
  });
  const html = fs.readFileSync(path.join(__dirname, "../public/zk1-protected-file-lab.html"), "utf8");
  app.get("/zk1-protected-file-lab.html", (_req, res) =>
    res.type("html").set("Content-Security-Policy", "default-src 'self'; script-src 'self'; connect-src 'self'").send(
      html.replace("</body>", '<script defer src="/__probe.js"></script></body>')));
  for (const script of scriptNames) {
    app.get("/client/" + script + ".js", (_req, res) => res.type("application/javascript")
      .sendFile(path.join(__dirname, "../public/client", script + ".js")));
  }
  let probe = "";
  app.get("/__probe.js", (_req, res) => res.type("application/javascript").send(probe));
  const server = await new Promise((resolve) => {
    const value = app.listen(0, "127.0.0.1", () => resolve(value));
  });
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    store.close();
    fs.rmSync(folder, { recursive: true, force: true });
  });
  const origin = "http://127.0.0.1:" + server.address().port;
  const fetchImpl = async (url, opts) => fetch(url, opts);
  const options = async () => ({
    ownerPublicKey, pinnedOwnerKeyHash: crypto.createHash("sha256").update(ownerRaw).digest(),
    pinnedCurrentHead: await currentHead(), signedDeviceGrant: await makeGrant(),
    devicePublicKey, devicePrivateKey,
    metadata: { ...scopeWire, object_id: id(), version_id: id(),
      parent_version_id: null, epoch: head.current_epoch, kind: "file" },
    fileName: "local-secret.txt", mediaType: "text/plain",
    data: Buffer.from("Unique browser owner plaintext is never stored on server."),
    origin, fetchImpl, nowSeconds: clock,
  });
  return { options, makeGrant, currentHead, store, ownerRaw, privateDer, device,
    origin, state, setHead: (next) => { head = next; },
    get putCount() { return putCount; },
    setProbe(value) { probe = value; } };
}

test("normal browser uploads ciphertext and confirms real localhost HTTP protected GET", async (t) => {
  const f = await setup(t);
  const args = await f.options();
  const result = await normal.uploadAndVerify(args);
  assert.equal(result.protectedHttpReadbackVerified, true);
  assert.equal(result.ownerAndDeviceCheckedLocally, true);
  assert.equal(result.independentDurableWriteProven, false);
  assert.equal(result.persistentKeyRecoveryAvailable, false);
  assert.equal(f.putCount, 1);
  const stored = f.store.db.prepare("SELECT ciphertext FROM zk_content_object WHERE id=?")
    .get(args.metadata.object_id).ciphertext;
  assert.ok(!stored.includes(args.data));
  assert.ok(!stored.toString().includes(args.fileName));
});

test("negative owner, head, grant, active device, epoch and mutation fail before HTTP", async (t) => {
  const f = await setup(t);
  const base = await f.options();
  let calls = 0;
  const blocked = (overrides) => assert.rejects(normal.uploadAndVerify({
    ...base, ...overrides, metadata: overrides.metadata ?? { ...base.metadata },
    fetchImpl: async (...args) => { calls++; return base.fetchImpl(...args); },
  }), /ZK_NORMAL_BROWSER_AUTHORITY_UNVERIFIED/);
  await blocked({ pinnedOwnerKeyHash: crypto.randomBytes(32) });
  await blocked({ pinnedCurrentHead: { ...base.pinnedCurrentHead, revision: 1 } });
  await blocked({ pinnedCurrentHead: { ...base.pinnedCurrentHead, digest: crypto.randomBytes(32) } });
  await blocked({ pinnedCurrentHead: null });
  await blocked({ signedDeviceGrant: { ...base.signedDeviceGrant,
    revoked_at_epoch: undefined } });
  await blocked({ signedDeviceGrant: { ...base.signedDeviceGrant, signature: b64(crypto.randomBytes(64)) } });
  await blocked({ signedDeviceGrant: await f.makeGrant({ revoked_at_epoch: 2 }) });
  await blocked({ signedDeviceGrant: await f.makeGrant({ authorization_public_key: b64(crypto.randomBytes(32)) }) });
  await blocked({ metadata: { ...base.metadata, epoch: base.metadata.epoch + 1 } });
  await blocked({ metadata: { ...base.metadata, keyring_id: id() } });
  const other = crypto.generateKeyPairSync("ed25519");
  const otherPrivate = await crypto.webcrypto.subtle.importKey("pkcs8",
    other.privateKey.export({ format: "der", type: "pkcs8" }),
    "Ed25519", false, ["sign"]);
  await blocked({ devicePrivateKey: otherPrivate });
  assert.equal(calls, 0);
  assert.equal(f.putCount, 0);
});

test("server advances to revoked signed head after local pin: protected request fails closed", async (t) => {
  const f = await setup(t);
  const opts = await f.options();
  const revoked = await fixtures.appendDeviceRevocation(f.state, f.device.device_id);
  f.setHead(revoked);
  await assert.rejects(normal.uploadAndVerify(opts), /ZK_NORMAL_BROWSER_AUTHORITY_UNVERIFIED/);
  assert.equal(f.store.db.prepare("SELECT COUNT(*) AS n FROM zk_content_object").get().n, 0);
});

test("lost PUT HTTP ACK reconciles by single historical GET without retrying PUT", async (t) => {
  const f = await setup(t);
  const opts = await f.options();
  let lost = false;
  opts.fetchImpl = async (url, options) => {
    const response = await fetch(url, options);
    if (url.endsWith("/content/put")) {
      lost = true;
      throw new Error("synthetic socket drop after commit");
    }
    return response;
  };
  const result = await normal.uploadAndVerify(opts);
  assert.equal(lost, true);
  assert.equal(result.lostPutAckReconciled, true);
  assert.equal(result.protectedHttpReadbackVerified, true);
  assert.equal(f.putCount, 1);
});

test("unexpected ciphertext and metadata in GET response never pass local readback", async (t) => {
  for (const attack of ["ciphertext", "epoch", "other-object"]) {
    const f = await setup(t);
    const opts = await f.options();
    opts.fetchImpl = async (url, options) => {
      const response = await fetch(url, options);
      if (!url.endsWith("/content/read") || response.status !== 200) return response;
      const body = await response.json();
      if (attack === "ciphertext") body.ciphertextBase64 = b64(crypto.randomBytes(64));
      if (attack === "epoch") body.epoch += 1;
      if (attack === "other-object") body.id = id();
      return new Response(JSON.stringify(body), { status: 200,
        headers: { "content-type": "application/json" } });
    };
    await assert.rejects(normal.uploadAndVerify(opts),
      /ZK_NORMAL_BROWSER_AUTHORITY_UNVERIFIED/, attack);
    assert.equal(f.putCount, 1);
  }
});

test("Edge WebCrypto executes normal file PUT/GET using actual localhost Express, under CSP", {
  timeout: 65_000,
}, async (t) => {
  if (process.platform !== "win32" || !fs.existsSync(EDGE)) {
    t.skip("Edge Windows browser unavailable");
    return;
  }
  const f = await setup(t);
  const opts = await f.options();
  const values = {
    ownerRaw: b64(f.ownerRaw), ownerHash: b64(opts.pinnedOwnerKeyHash),
    deviceRaw: b64(f.device.authorization_public_key), privateDer: b64(f.privateDer),
    pin: { revision: opts.pinnedCurrentHead.revision,
      epoch: opts.pinnedCurrentHead.epoch, digest: b64(opts.pinnedCurrentHead.digest) },
    grant: opts.signedDeviceGrant, scope: Object.fromEntries(
      ["account_id", "compartment_id", "keyring_id"].map((field) =>
        [field, opts.metadata[field]])),
    now: opts.nowSeconds, objectId: opts.metadata.object_id, versionId: opts.metadata.version_id,
  };
  // Synthetic key material is served only by this disposable browser test.
  f.setProbe(`window.addEventListener("load",async()=>{const output=document.createElement("output");
output.id="edge-normal-result";document.body.append(output);
const v=${JSON.stringify(values)};
function decode(s){return Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-s.length%4)%4)),x=>x.charCodeAt(0));}
function inputFile(id,data,name){const dt=new DataTransfer();dt.items.add(new File([data],name));
document.getElementById(id).files=dt.files;}
try {inputFile("owner-key",decode(v.ownerRaw),"owner.raw");
inputFile("device-public",decode(v.deviceRaw),"device.raw");
inputFile("device-private",decode(v.privateDer),"device.pkcs8");
inputFile("device-grant",new TextEncoder().encode(JSON.stringify(v.grant)),"grant.json");
inputFile("file",new TextEncoder().encode("WebCrypto Edge real HTTP protected content"),"edge-normal.txt");
document.getElementById("owner-hash").value=v.ownerHash;
document.getElementById("head-revision").value=String(v.pin.revision);
document.getElementById("head-digest").value=v.pin.digest;
document.getElementById("head-epoch").value=String(v.pin.epoch);
document.getElementById("upload").click();
for(let i=0;i<80;i++){await new Promise(resolve=>setTimeout(resolve,100));
const status=document.getElementById("status").textContent;
if(status.includes("Ciphertext conferido")){output.textContent="EDGE_NORMAL_HTTP_PASS";break;}
if(status.includes("Operação recusada")){output.textContent="EDGE_NORMAL_HTTP_FAIL";break;}}
if(!output.textContent)output.textContent="EDGE_NORMAL_HTTP_TIMEOUT";
}catch(e){output.textContent="EDGE_NORMAL_HTTP_FAIL";}});`);
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-edge-normal-"));
  const args = ["--headless=new", "--disable-gpu", "--no-first-run", "--disable-extensions",
    "--user-data-dir=" + path.join(folder, "profile"), "--virtual-time-budget=10000",
    "--dump-dom", f.origin + "/zk1-protected-file-lab.html"];
  let edge;
  try {
    const html = await new Promise((resolve, reject) => {
      edge = spawn(EDGE, args, { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
      const chunks = []; let size = 0;
      edge.stdout.on("data", (chunk) => {
        size += chunk.byteLength;
        if (size <= 256 * 1024) chunks.push(chunk);
        else edge.kill();
      });
      edge.stderr.resume();
      edge.once("error", reject);
      edge.once("exit", (code) => code === 0 && size <= 256 * 1024
        ? resolve(Buffer.concat(chunks).toString("utf8"))
        : reject(new Error("Edge headless did not complete")));
    });
    assert.match(html, /EDGE_NORMAL_HTTP_PASS/);
    assert.equal(f.putCount, 1);
  } finally {
    if (edge && edge.exitCode === null) edge.kill();
    fs.rmSync(folder, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 });
  }
});
