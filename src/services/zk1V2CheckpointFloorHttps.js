"use strict";

const https = require("node:https");
const tls = require("node:tls");
const net = require("node:net");
const crypto = require("node:crypto");
const { verifySignedHead, fullRetainedMinimum } =
  require("./zk1V2CheckpointRemoteFloor");

const CERT = /^(?:[0-9a-f]{2}:){31}[0-9a-f]{2}$/i;
const B64 = /^[A-Za-z0-9_-]+$/;
function deny() { throw new Error("ZK_V2_REMOTE_FLOOR_UNAVAILABLE"); }
function exact(v, fields) {
  if (!v || typeof v !== "object" || Array.isArray(v)
    || Reflect.ownKeys(v).length !== fields.length
    || fields.some((f) => !Object.hasOwn(v, f))) deny();
}
function raw(v, limit) {
  if (typeof v !== "string" || !v.length || !B64.test(v)
    || v.length > Math.ceil(limit * 4 / 3) + 4) deny();
  const result = Buffer.from(v, "base64url");
  if (!result.length || result.length > limit
    || result.toString("base64url") !== v) deny();
  return result;
}
const to64 = (v) => Buffer.from(v).toString("base64url");
function createZk1V2CheckpointFloorHttpsServer({ key, cert, clientCa,
  allowedClientFingerprint256, floor } = {}) {
  if (!key || !cert || !clientCa || !CERT.test(allowedClientFingerprint256)
    || typeof floor?.freshHead !== "function"
    || typeof floor?.advance !== "function") deny();
  const pinned = allowedClientFingerprint256.toUpperCase();
  const server = https.createServer({ key, cert, ca: clientCa, minVersion: "TLSv1.3",
    requestCert: true, rejectUnauthorized: true }, async (req, res) => {
    const respond = (code, object) => {
      const payload = Buffer.from(JSON.stringify(object));
      res.writeHead(code, { "content-type": "application/json", "cache-control": "no-store",
        "content-length": String(payload.length) });
      res.end(payload);
    };
    try {
      if (req.method !== "POST" || !["/v1/floor/head", "/v1/floor/advance"].includes(req.url))
        return respond(404, { error: "NOT_FOUND" });
      if (!req.socket.authorized
        || req.socket.getPeerCertificate()?.fingerprint256?.toUpperCase() !== pinned)
        return respond(403, { error: "FORBIDDEN" });
      const limit = req.url.endsWith("/advance") ? 14000 : 200;
      const parts = [];
      let received = 0;
      for await (const chunk of req) {
        received += chunk.length;
        if (received > limit) deny();
        parts.push(chunk);
      }
      if (req.headers["content-type"] !== "application/json") deny();
      const body = JSON.parse(Buffer.concat(parts).toString("utf8"));
      if (req.url.endsWith("/head")) {
        exact(body, ["nonce", "minimum"]);
        exact(body.minimum, ["sequence", "chainHash"]);
        if (!Number.isSafeInteger(body.minimum.sequence)
          || body.minimum.sequence < 128) deny();
        return respond(200, { proof: to64(await floor.freshHead(raw(body.nonce, 32), {
          sequence: body.minimum.sequence,
          chainHash: raw(body.minimum.chainHash, 32) })) });
      }
      exact(body, ["sequence", "epoch", "headDigest", "checkpointDigest",
        "previousHeadDigest", "previousCheckpointDigest",
        "operationId", "casReceipt", "floorReceipt", "ownerSignature"]);
      // The floor derives scope from independently configured trusted identity.
      await floor.advance({ sequence: body.sequence, epoch: body.epoch,
        headDigest: raw(body.headDigest, 32), checkpointDigest: raw(body.checkpointDigest, 32),
        previousHeadDigest: raw(body.previousHeadDigest, 32),
        previousCheckpointDigest: raw(body.previousCheckpointDigest, 32),
        operationId: raw(body.operationId, 32), casReceipt: raw(body.casReceipt, 4096),
        floorReceipt: raw(body.floorReceipt, 4096),
        ownerSignature: raw(body.ownerSignature, 64) });
      // Never accept this unsigned ACK as a trusted readback. Client must
      // fetch a fresh nonce-bound signed head after any advance.
      return respond(200, { accepted: true });
    } catch (_) { return respond(409, { error: "DENIED" }); }
  });
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
  server.timeout = 5000;
  return server;
}

class Zk1V2CheckpointFloorHttpsClient {
  #url;
  #tls;
  #serverPin;
  #floorPin;
  #ownerPin;
  #scope;
  #minimum;
  constructor({ endpoint, ca, clientKey, clientCert, serverFingerprint256,
    pinnedFloorPublicKey, pinnedOwnerPublicKey, scope, minimum,
    timeoutMs = 3000 } = {}) {
    try { this.#url = new URL(endpoint); }
    catch (_) { deny(); }
    if (this.#url.protocol !== "https:" || !this.#url.port || this.#url.username
      || this.#url.password || this.#url.search || this.#url.hash
      || !["", "/"].includes(this.#url.pathname) || !ca || !clientKey || !clientCert
      || !CERT.test(serverFingerprint256) || !Number.isSafeInteger(timeoutMs)
      || timeoutMs < 100 || timeoutMs > 10000
      || !(pinnedFloorPublicKey instanceof crypto.KeyObject)
      || pinnedFloorPublicKey.type !== "public"
      || pinnedFloorPublicKey.asymmetricKeyType !== "ed25519"
      || !(pinnedOwnerPublicKey instanceof crypto.KeyObject)
      || pinnedOwnerPublicKey.type !== "public"
      || pinnedOwnerPublicKey.asymmetricKeyType !== "ed25519") deny();
    this.#tls = { ca, key: clientKey, cert: clientCert, timeoutMs };
    this.#serverPin = serverFingerprint256.toUpperCase();
    this.#floorPin = pinnedFloorPublicKey;
    this.#ownerPin = pinnedOwnerPublicKey;
    if (!scope || !["account_id", "compartment_id", "keyring_id"].every((k) =>
      Buffer.isBuffer(scope[k]) || scope[k] instanceof Uint8Array)
      || scope.account_id.length !== 16 || scope.keyring_id.length !== 16
      || scope.compartment_id.length < 1 || scope.compartment_id.length > 128) deny();
    this.#scope = Object.freeze(Object.fromEntries(Object.entries(scope)
      .map(([k, v]) => [k, Buffer.from(v)])));
    try { this.#minimum = fullRetainedMinimum(minimum); }
    catch (_) { deny(); }
  }
  #send(urlPath, body) {
    const payload = Buffer.from(JSON.stringify(body));
    if (payload.length > (urlPath.endsWith("/advance") ? 14000 : 200)) deny();
    return new Promise((resolve, reject) => {
      let settled = false;
      const done = (error, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        if (error) reject(new Error("ZK_V2_REMOTE_FLOOR_UNAVAILABLE"));
        else resolve(value);
      };
      const request = https.request({ hostname: this.#url.hostname, port: this.#url.port,
        path: urlPath, method: "POST", agent: false, ca: this.#tls.ca,
        key: this.#tls.key, cert: this.#tls.cert, minVersion: "TLSv1.3",
        rejectUnauthorized: true,
        servername: net.isIP(this.#url.hostname) ? "" : this.#url.hostname,
        checkServerIdentity: (host, peer) => {
          const error = tls.checkServerIdentity(host, peer);
          return error || (peer.fingerprint256?.toUpperCase() === this.#serverPin
            ? undefined : new Error("ZK_V2_REMOTE_FLOOR_UNAVAILABLE"));
        },
        headers: { "content-type": "application/json", "content-length": String(payload.length) },
      }, (response) => {
        if (response.statusCode !== 200) {
          response.resume();
          return done(new Error("denied"));
        }
        const chunks = [];
        let count = 0;
        response.on("data", (chunk) => {
          count += chunk.length;
          if (count > 8192) { request.destroy(); done(new Error("too large")); }
          else chunks.push(chunk);
        });
        response.on("end", () => {
          try { done(null, JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
          catch (error) { done(error); }
        });
      });
      const deadline = setTimeout(() => request.destroy(
        new Error("ZK_V2_REMOTE_FLOOR_UNAVAILABLE")), this.#tls.timeoutMs);
      request.on("error", done);
      request.end(payload);
    });
  }
  async freshHead() {
    const nonce = crypto.randomBytes(32);
    try {
      const answer = await this.#send("/v1/floor/head", { nonce: to64(nonce),
        minimum: { sequence: this.#minimum.sequence,
          chainHash: to64(this.#minimum.chainHash) } });
      exact(answer, ["proof"]);
      const head = await verifySignedHead(raw(answer.proof, 4096), {
        scope: this.#scope, pinnedFloorPublicKey: this.#floorPin,
        pinnedOwnerPublicKey: this.#ownerPin, nonce, minimum: this.#minimum });
      this.#minimum = { sequence: head.sequence, chainHash: Buffer.from(head.chainHash),
        headDigest: Buffer.from(head.headDigest),
        checkpointDigest: Buffer.from(head.checkpointDigest), epoch: head.epoch,
        operationId: Buffer.from(head.operationId),
        casReceiptHash: Buffer.from(head.casReceiptHash),
        floorReceiptHash: Buffer.from(head.floorReceiptHash),
        casReceiptIdentityHash: Buffer.from(head.casReceiptIdentityHash),
        floorReceiptIdentityHash: Buffer.from(head.floorReceiptIdentityHash) };
      return head;
    } catch (_) { deny(); }
  }
  async advance(v) {
    try {
      exact(v, ["sequence", "epoch", "headDigest", "checkpointDigest",
        "previousHeadDigest", "previousCheckpointDigest",
        "operationId", "casReceipt", "floorReceipt", "ownerSignature"]);
      const answer = await this.#send("/v1/floor/advance", {
        sequence: v.sequence, epoch: v.epoch, headDigest: to64(v.headDigest),
        checkpointDigest: to64(v.checkpointDigest), operationId: to64(v.operationId),
        previousHeadDigest: to64(v.previousHeadDigest),
        previousCheckpointDigest: to64(v.previousCheckpointDigest),
        casReceipt: to64(v.casReceipt), floorReceipt: to64(v.floorReceipt),
        ownerSignature: to64(v.ownerSignature) });
      exact(answer, ["accepted"]);
      if (answer.accepted !== true) deny();
      return this.freshHead();
    } catch (_) { deny(); }
  }
}
module.exports = { createZk1V2CheckpointFloorHttpsServer,
  Zk1V2CheckpointFloorHttpsClient };
