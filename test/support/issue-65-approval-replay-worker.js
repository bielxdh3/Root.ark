"use strict";

// Disposable test-only IPC child, not an HTTP/server worker. Secrets and
// candidate bytes are delivered by its own verified parent through IPC after
// spawn, never via inherited environment or process argv.
const { Pool } = require("pg");
const { Zk1ExperimentalPgApprovalReplayLedger } =
  require("../../src/services/zk1ExperimentalPgApprovalReplayLedger");

let used = false;
const decode = (value, len) => {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw Error("denied");
  const result = Buffer.from(value, "base64url");
  if (result.length !== len || result.toString("base64url") !== value) throw Error("denied");
  return result;
};
process.once("message", async (msg) => {
  let pool;
  try {
    if (used || msg?.kind !== "consume" || typeof msg.url !== "string"
      || msg.url.length > 512 || !Array.isArray(msg.scope) || msg.scope.length !== 3) {
      throw Error("denied");
    }
    used = true;
    const url = new URL(msg.url);
    if (url.protocol !== "postgresql:" || url.hostname !== "127.0.0.1"
      || url.pathname !== "/gatefixture" || !url.port || url.search || url.hash
      || !/^zkreplayfixture_[a-f0-9]{12}$/.test(decodeURIComponent(url.username))) {
      throw Error("denied");
    }
    const input = { scope: {
      account_id: decode(msg.scope[0], 16),
      compartment_id: decode(msg.scope[1], msg.scope[1].length ?
        Buffer.from(msg.scope[1], "base64url").length : -1),
      keyring_id: decode(msg.scope[2], 16) },
    nonce: decode(msg.nonce, 32), rawSignedApproval: decode(msg.approval,
      Buffer.from(msg.approval, "base64url").length),
    deviceKeyId: decode(msg.deviceKeyId, 16),
    manifestRevision: msg.manifestRevision,
    manifestDigest: decode(msg.manifestDigest, 32),
    witnessSequence: msg.witnessSequence, expiresAt: msg.expiresAt };
    pool = new Pool({ connectionString: msg.url, max: 1, connectionTimeoutMillis: 3000 });
    const result = await new Zk1ExperimentalPgApprovalReplayLedger({ pool }).consumeCandidate(input);
    process.send({ status: result.replayRecordCommitted === true ? "inserted" : "denied" });
  } catch (_) {
    if (process.connected) process.send({ status: "denied" });
  } finally {
    if (pool) try { await pool.end(); } catch (_) { /* fixture */ }
    process.disconnect();
  }
});
