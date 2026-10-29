"use strict";
// Separate OS process running W62's exact DEV-OFF client, over real pinned mTLS.
const crypto = require("node:crypto");
const https = require("node:https");
const { createPinnedLabClientTls } = require("./pinned-mtls-client");
const { createZk10ExternalOwnerCutoverCasClient } =
  require("../../src/services/zk10ExternalOwnerCutoverCasClient");
let client;
if (process.send) process.send({ type: "client-ready" });
function exchange(config, route, body) {
  return new Promise((resolve, reject) => {
    const bytes = Buffer.from(JSON.stringify(body));
    const req = https.request({
      hostname: "127.0.0.1", port: config.port, path: route, method: "POST",
      ...createPinnedLabClientTls(config.certDir, "client", config.serverPin),
      headers: { "content-type": "application/json", "content-length": bytes.length },
      timeout: 4000,
    }, (res) => {
      const parts = [];
      let size = 0;
      res.on("data", (v) => {
        size += v.length;
        if (size > 256 * 1024) {
          req.destroy(Error("ZK10_REMOTE_RESPONSE_TOO_LARGE"));
          return;
        }
        parts.push(v);
      });
      res.on("end", () => {
        if (res.statusCode !== 200) { reject(Error("ZK10_REMOTE_REJECTED")); return; }
        try { resolve(JSON.parse(Buffer.concat(parts).toString("utf8"))); }
        catch (_) { reject(Error("ZK10_REMOTE_MALFORMED")); }
      });
      res.on("error", reject);
    });
    req.on("timeout", () => req.destroy(Error("ZK10_REMOTE_TIMEOUT")));
    req.on("error", reject);
    req.end(bytes);
  });
}
process.on("message", async (m) => {
  if (m?.type !== "call" || !process.send) return;
  try {
    if (m.method === "init") {
      const c = m.payload;
      client = createZk10ExternalOwnerCutoverCasClient({
        immutableAccountId: c.accountId, identityDigest: c.identityDigest,
        pinnedOperator: { operatorId: c.operatorId, tlsServerFingerprint256: c.serverPin,
          signingPublicKey: crypto.createPublicKey(c.operatorPublicPem) },
        pinnedOwner: { canonicalZkAccountId: c.zkAccountId,
          signingPublicKey: crypto.createPublicKey(c.ownerPublicPem) },
        independentlyRetainedMinimum: c.minimum,
        transport: { operatorHostId: c.operatorId,
          tlsServerFingerprint256: c.serverPin,
          exchange: (route, body) => exchange(c, route, body) },
      });
      process.send({ type: "reply", requestId: m.requestId, ok: true,
        state: client.state });
      return;
    }
    if (!client || !["readCurrent", "submitCutover", "reconcile"].includes(m.method))
      throw Error("ZK10_CLIENT_INVALID");
    const result = await client[m.method](...(m.method === "submitCutover"
      ? [m.payload] : []));
    process.send({ type: "reply", requestId: m.requestId, ok: true,
      result, state: client.state });
  } catch (e) {
    process.send({ type: "reply", requestId: m.requestId, ok: false,
      code: String(e.code || e.message || "").slice(0, 80),
      state: client?.state || "absent" });
  }
});
