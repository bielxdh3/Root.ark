"use strict";

// Non-authorizing transport adapter for strict Sync v2 historical reads.
// The embedding operator supplies a trusted, independent inventory source and
// signer pins. Never source those from mutable Sync JSON or witness replies.
// rootark-sync-v2.js still calls verifySyncV2HistoricalWitnessAdmission,
// including independent PG, witness, device and pinned-floor verification.
const crypto = require("node:crypto");
const https = require("node:https");
const net = require("node:net");
const tls = require("node:tls");
const z = require("../src/crypto/rootark-zk-1");
const inventory = require("../src/crypto/rootark-zk-content-inventory-v1");
const { envelopeBinding } = require("./rootark-sync-zk1-physical-binding");

const FINGERPRINT = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/i;
const RESPONSE_LIMIT = 16 * 1024;
const REQUEST_LIMIT = 12 * 1024 * 1024;
const MAX_NONCES = 4096;
const FLOOR = ["type", "witnessKeyId", "statusKeyId", "sequence",
  "lastHash", "physicalFenceDigest", "nonce", "signature"];
const ADMISSION = ["type", "envelopeSha256", "operationId", "deviceId",
  "deviceSpkiSha256", "epoch", "checkpointSequence", "checkpointRoot",
  "inventoryReceiptSha256", "admittedAtMs", "witnessSequence", "witnessLastHash",
  "witnessPhysicalFenceDigest", "signature"];
const HEX = /^[0-9a-f]{64}$/;

function fail() {
  const error = new Error("SYNC_V2_HISTORICAL_EVIDENCE_UNAVAILABLE");
  error.code = error.message;
  throw error;
}
function exact(input, fields) {
  if (!input || typeof input !== "object" || Array.isArray(input)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(input))
    || Reflect.ownKeys(input).length !== fields.length
    || fields.some((key) => !Object.hasOwn(input, key))) fail();
  const result = {};
  for (const key of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) fail();
    result[key] = descriptor.value;
  }
  return result;
}
function bytes(input, min, max = min) {
  if ((!Buffer.isBuffer(input) && !(input instanceof Uint8Array))
    || input.byteLength < min || input.byteLength > max
    || (typeof SharedArrayBuffer !== "undefined"
      && input.buffer instanceof SharedArrayBuffer)) fail();
  return Buffer.from(input);
}
function base64url(input, min, max = min) {
  if (typeof input !== "string" || !/^[A-Za-z0-9_-]+$/.test(input)
    || input.length > Math.ceil(max * 4 / 3) + 4) fail();
  const decoded = Buffer.from(input, "base64url");
  if (decoded.length < min || decoded.length > max
    || decoded.toString("base64url") !== input) fail();
  return decoded;
}
function digest(input) {
  return crypto.createHash("sha256").update(input).digest("base64url");
}
function createSyncV2HistoricalEvidenceProvider({
  endpoint, ca, clientKey, clientCert, serverFingerprint256,
  trustedInventoryEvidenceProvider, pinnedInventoryPublicKey,
  pinnedInventorySignerKeyId, timeoutMs = 5000,
} = {}) {
  let url, transport;
  try {
    url = new URL(endpoint);
    if (url.protocol !== "https:" || !url.hostname || !url.port
      || url.username || url.password || url.search || url.hash
      || (url.pathname !== "/" && url.pathname !== "")
      || !FINGERPRINT.test(serverFingerprint256)
      || typeof trustedInventoryEvidenceProvider !== "function"
      || !(pinnedInventoryPublicKey instanceof crypto.KeyObject)
      || pinnedInventoryPublicKey.type !== "public"
      || pinnedInventoryPublicKey.asymmetricKeyType !== "ed25519"
      || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10000) fail();
    const id = bytes(pinnedInventorySignerKeyId, 16);
    const tlsOptions = { ca: bytesOrPem(ca), key: bytesOrPem(clientKey),
      cert: bytesOrPem(clientCert) };
    tls.createSecureContext({ ...tlsOptions, minVersion: "TLSv1.3" });
    transport = { ...tlsOptions, id, host: url.hostname, port: url.port,
      fingerprint: serverFingerprint256.toUpperCase(), timeoutMs };
  } catch (_) { fail(); }

  // One client challenge may authorize no more than one attempt. The finite
  // cache fails closed instead of discarding old nonces and accepting replays.
  const issuedNonces = new Set();
  return async function historicalEvidenceProvider(operation, { nonce } = {}) {
    try {
      const challenge = bytes(nonce, 32);
      const nonceText = challenge.toString("base64url");
      if (issuedNonces.size >= MAX_NONCES || issuedNonces.has(nonceText)) fail();
      issuedNonces.add(nonceText);
      // TRUST BOUNDARY: this callback is operator-injected. The server cannot
      // provide a checkpoint, receipt, root or scope for its own admission.
      const source = exact(await trustedInventoryEvidenceProvider(operation),
        ["scope", "expectedSequence", "expectedRoot", "receipt"]);
      const scope = inventory.normalizeScope(source.scope);
      const root = bytes(source.expectedRoot, 32);
      const receipt = bytes(source.receipt, 1, inventory.MAX_COMMITTED_PROOF_BYTES);
      const bound = envelopeBinding(operation, scope, source.expectedSequence, root);
      // Verify the independent inventory signature and exact encrypted
      // envelope BEFORE contacting the witness. This also prevents a config-
      // supplied signed receipt for a different object/root from being used.
      await inventory.verifyCommittedEntryProof({
        serialized: receipt, pinnedPublicKey: pinnedInventoryPublicKey,
        pinnedSignerKeyId: transport.id, expectedScope: scope,
        operation: bound.operation,
      });
      const body = {
        envelope: bound.envelope,
        scope: Object.fromEntries(Object.entries(scope)
          .map(([key, value]) => [key, value.toString("base64url")])),
        expectedSequence: source.expectedSequence,
        expectedRoot: root.toString("base64url"),
        inventoryReceipt: receipt.toString("base64url"),
        nonce: nonceText,
      };
      const payload = Buffer.from(JSON.stringify(body), "utf8");
      if (payload.length < 2 || payload.length > REQUEST_LIMIT) fail();
      const result = await postHistoricalAdmission(transport, payload);
      const answer = exact(result, ["admission", "freshFloor",
        "physicalAttestation", "authority"]);
      const floor = exact(answer.freshFloor, FLOOR);
      const admission = exact(answer.admission, ADMISSION);
      if (answer.authority !== "WITNESS_SYNC_HISTORICAL_ADMISSION_V1"
        || floor.type !== "rootark-zk1-witness-cas-physical-floor/v2"
        || floor.nonce !== nonceText
        || !Number.isSafeInteger(floor.sequence) || floor.sequence < 1
        || !HEX.test(floor.lastHash) || !HEX.test(floor.physicalFenceDigest)
        || admission.type !== "rootark-sync-v2-historical-witness-admission/v1"
        || admission.envelopeSha256 !== digest(bound.canonicalEnvelope)
        || admission.operationId !== bound.operation.operation_id.toString("base64url")
        || admission.deviceId !== bound.envelope.deviceId
        || admission.deviceSpkiSha256 !== digest(base64url(bound.envelope.authorization.publicKey, 44))
        || admission.epoch !== bound.operation.epoch
        || admission.checkpointSequence !== bound.operation.expected_sequence
        || admission.checkpointRoot !== root.toString("base64url")
        || admission.inventoryReceiptSha256 !== digest(receipt)
        || admission.witnessSequence !== floor.sequence
        || admission.witnessLastHash !== floor.lastHash
        || admission.witnessPhysicalFenceDigest !== floor.physicalFenceDigest
        || !Number.isSafeInteger(admission.admittedAtMs)
        || admission.admittedAtMs < 1
        || admission.admittedAtMs >= bound.envelope.authorization.expiresAt
        || admission.admittedAtMs > Date.now()) fail();
      // This parsing and nonce check are only transport checks. A claimed PG
      // status, cryptographic signature or witness head never grants access
      // until the separate independently pinned strict verifier succeeds.
      const physicalAttestation = base64url(answer.physicalAttestation, 1, 2048);
      const physical = await z.decodeDeterministic(physicalAttestation);
      if (physical?.type !== "rootark-zk1-physical-pg-readback-attestation/v1"
        || (!Buffer.isBuffer(physical.nonce) && !(physical.nonce instanceof Uint8Array))
        || physical.nonce.length !== 32
        || !crypto.timingSafeEqual(Buffer.from(physical.nonce), challenge)) fail();
      return {
        scope, expectedSequence: source.expectedSequence, expectedRoot: root,
        receipt, physicalAttestation, admission, freshFloor: floor,
      };
    } catch (_) { fail(); }
  };
}
function bytesOrPem(input) {
  if (!Buffer.isBuffer(input) && !(input instanceof Uint8Array)
    && (typeof input !== "string" || !input.length)) fail();
  if (typeof input === "string") {
    if (input.length > 8192) fail();
    return input;
  }
  return bytes(input, 1, 8192);
}
async function postHistoricalAdmission(options, payload) {
  return new Promise((resolve, reject) => {
    let settled = false, request;
    const done = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      if (error) reject(error);
      else resolve(result);
    };
    request = https.request({
      hostname: options.host, port: options.port,
      path: "/v1/cas-anchor/historical-admit", method: "POST", agent: false,
      ca: options.ca, key: options.key, cert: options.cert,
      minVersion: "TLSv1.3", maxVersion: "TLSv1.3",
      rejectUnauthorized: true,
      servername: net.isIP(options.host) ? undefined : options.host,
      checkServerIdentity: (hostname, certificate) => {
        const problem = tls.checkServerIdentity(hostname, certificate);
        if (problem) return problem;
        return certificate.fingerprint256?.toUpperCase() === options.fingerprint
          ? undefined : new Error("WITNESS_TLS_IDENTITY_DENIED");
      },
      headers: { "content-type": "application/json", accept: "application/json",
        "content-length": String(payload.length) },
    }, (res) => {
      if (res.statusCode !== 200
        || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(res.headers["content-type"] || "")
        || res.headers["content-encoding"]
        || (res.headers["content-length"] !== undefined
          && (!/^\d+$/.test(res.headers["content-length"])
            || Number(res.headers["content-length"]) > RESPONSE_LIMIT))) {
        res.resume(); done(new Error("HISTORICAL_RESPONSE_INVALID")); return;
      }
      const parts = [];
      let count = 0;
      res.on("data", (chunk) => {
        count += chunk.length;
        if (count > RESPONSE_LIMIT) {
          request.destroy(new Error("HISTORICAL_RESPONSE_TOO_LARGE"));
        } else parts.push(chunk);
      });
      res.on("error", (error) => done(error));
      res.on("end", () => {
        try {
          if (!count || settled) fail();
          done(null, JSON.parse(Buffer.concat(parts).toString("utf8")));
        } catch (error) { done(error); }
      });
    });
    const deadline = setTimeout(() =>
      request.destroy(new Error("HISTORICAL_RESPONSE_TIMEOUT")), options.timeoutMs);
    request.once("error", (error) => done(error));
    request.end(payload);
  });
}

module.exports = { createSyncV2HistoricalEvidenceProvider };
