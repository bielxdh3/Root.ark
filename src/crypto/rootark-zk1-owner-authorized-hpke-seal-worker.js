"use strict";

// A separate V8 realm is required here: an independent authority callback
// can mutate the calling realm's JS prototypes after the owner CEK is loaded.
// @hpke/core awaits a mutex and dynamically dispatches AES-GCM operations,
// so capturing individual methods in the calling realm cannot protect CEKs.
const { parentPort } = require("node:worker_threads");
const crypto = require("node:crypto");
const z = require("./rootark-zk-1");
const ACK_DOMAIN = Buffer.from("Root.ark/zk-1/owner-hpke-worker-ack/v1\0");

if (!parentPort) throw new Error("ZK_OWNER_HPKE_WORKER_REQUIRED");

parentPort.once("message", async (request) => {
  let plaintext, ackSecret;
  try {
    if (!request || request.type !== "seal"
      || !(request.cek instanceof ArrayBuffer) || request.cek.byteLength !== 32
      || !(request.ackKey instanceof ArrayBuffer) || request.ackKey.byteLength !== 32
      || !ArrayBuffer.isView(request.recipientPublicKey)
      || request.recipientPublicKey.byteLength !== 32
      || !ArrayBuffer.isView(request.info) || !ArrayBuffer.isView(request.aad)) {
      throw new Error("INVALID_HPKE_WORKER_INPUT");
    }
    // The 32-byte CEK ArrayBuffer was transferred, not cloned. This worker's
    // global prototypes were never exposed to the caller's authority callback.
    plaintext = new Uint8Array(request.cek);
    ackSecret = new Uint8Array(request.ackKey);
    const recipientPublicKey = await z.hpkeSuite().kem.deserializePublicKey(
      Buffer.from(request.recipientPublicKey));
    const sealed = await z.hpkeSeal({
      recipientPublicKey, plaintext,
      info: Buffer.from(request.info), aad: Buffer.from(request.aad),
    });
    if (sealed.enc.length !== 32 || sealed.ciphertext.length !== 48) {
      throw new Error("INVALID_HPKE_WORKER_OUTPUT");
    }
    const ackMac = crypto.createHmac("sha256", ackSecret).update(ACK_DOMAIN)
      .update(sealed.enc).update(sealed.ciphertext).digest();
    // Erase the worker's raw CEK *before* acknowledging success. Otherwise
    // the parent might terminate the worker while its finally still contains
    // a live copy of the plaintext secret.
    plaintext.fill(0);
    plaintext = null;
    ackSecret.fill(0);
    ackSecret = null;
    parentPort.postMessage({ ok: true, enc: sealed.enc,
      ciphertext: sealed.ciphertext, ackMac });
  } catch (_) {
    parentPort.postMessage({ ok: false });
  } finally {
    if (plaintext) plaintext.fill(0);
    if (ackSecret) ackSecret.fill(0);
    parentPort.close();
  }
});
