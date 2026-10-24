"use strict";

// Deliberately separate OS process, TLS endpoint, SQLite file and Ed25519 key.
// Only disposable lab materials; NEVER a daemon suitable for production.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { Zk1V2CheckpointRemoteFloor } =
  require("../../src/services/zk1V2CheckpointRemoteFloor");
const { createZk1V2CheckpointFloorHttpsServer } =
  require("../../src/services/zk1V2CheckpointFloorHttps");

let service;
let floor;
const send = (message) => { if (process.connected) process.send(message); };
const bytes = (s) => Buffer.from(s, "base64url");
async function stop() {
  if (service) await new Promise((resolve) => service.close(resolve));
  floor?.close();
  process.exit(0);
}
process.once("disconnect", () => { stop(); });
process.on("message", async (msg) => {
  try {
    if (msg.kind === "stop") return stop();
    if (msg.kind !== "init" || service || !path.isAbsolute(msg.dir)) throw Error();
    const file = (name) => path.join(msg.dir, name);
    const keyPath = file("private-floor.key");
    let privateKey;
    if (fs.existsSync(keyPath)) privateKey = crypto.createPrivateKey(fs.readFileSync(keyPath));
    else {
      privateKey = crypto.generateKeyPairSync("ed25519").privateKey;
      fs.writeFileSync(keyPath, privateKey.export({ type: "pkcs8", format: "pem" }),
        { flag: "wx", mode: 0o600 });
    }
    const scope = Object.fromEntries(Object.entries(msg.scope)
      .map(([name, value]) => [name, bytes(value)]));
    floor = new Zk1V2CheckpointRemoteFloor(file("independent-v2-floor.sqlite"), {
      bootstrapNew: msg.bootstrapNew, scope,
      casPublicKey: crypto.createPublicKey({ key: bytes(msg.casKey),
        type: "spki", format: "der" }),
      floorPublicKey: crypto.createPublicKey({ key: bytes(msg.floorKey),
        type: "spki", format: "der" }),
      ownerPublicKey: crypto.createPublicKey({ key: bytes(msg.ownerKey),
        type: "spki", format: "der" }),
      witnessPrivateKey: privateKey, baseHeadDigest: bytes(msg.baseHead),
      baseCheckpointDigest: bytes(msg.baseCheckpoint),
      ...(msg.minimum ? { minimum: { sequence: msg.minimum.sequence,
        chainHash: bytes(msg.minimum.chainHash) } } : {}),
    });
    service = createZk1V2CheckpointFloorHttpsServer({
      key: fs.readFileSync(file("v2floorremote.key")),
      cert: fs.readFileSync(file("v2floorremote.pem")),
      clientCa: fs.readFileSync(file("ca.pem")),
      allowedClientFingerprint256: new crypto.X509Certificate(
        fs.readFileSync(file("client.pem"))).fingerprint256,
      floor,
    });
    await new Promise((resolve) => service.listen(msg.port || 0, "127.0.0.1", resolve));
    send({ kind: "ready", port: service.address().port,
      floorKey: crypto.createPublicKey(privateKey).export({ type: "spki",
        format: "der" }).toString("base64url") });
  } catch (error) {
    send({ kind: "failed", code: error?.code || error?.message || "FAILED" });
    process.exitCode = 2;
  }
});
