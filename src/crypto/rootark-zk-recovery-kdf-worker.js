"use strict";

const { parentPort, workerData } = require("node:worker_threads");
const { deriveRecoveryKey, clearSecret } = require("./rootark-zk-1");

const PROFILE = Object.freeze({
  id: "argon2id13",
  opslimit: 3,
  memlimit: 268435456,
  outputLength: 32,
});

function matchesProfile(value) {
  return value && value.id === PROFILE.id
    && value.opslimit === PROFILE.opslimit
    && value.memlimit === PROFILE.memlimit
    && value.outputLength === PROFILE.outputLength
    && Object.keys(value).length === 4;
}

async function run() {
  if (!workerData || !matchesProfile(workerData.profile)
    || !(workerData.password instanceof Uint8Array)
    || workerData.password.byteLength < 1 || workerData.password.byteLength > 1024
    || !(workerData.salt instanceof Uint8Array) || workerData.salt.byteLength !== 16) {
    throw new Error("invalid worker input");
  }

  const password = Buffer.from(workerData.password);
  const salt = Buffer.from(workerData.salt);
  let key;
  try {
    key = await deriveRecoveryKey({
      password,
      salt,
      opslimit: PROFILE.opslimit,
      memlimit: PROFILE.memlimit,
    });
    if (key.length !== PROFILE.outputLength) throw new Error("invalid key length");
    const transferredKey = Uint8Array.from(key);
    parentPort.postMessage({ ok: true, key: transferredKey }, [transferredKey.buffer]);
  } finally {
    clearSecret(password);
    clearSecret(salt);
    if (key) clearSecret(key);
    clearSecret(workerData.password);
    clearSecret(workerData.salt);
  }
}

run().catch(() => {
  try {
    parentPort.postMessage({ ok: false });
  } catch (_) {
    // Worker exit is mapped to the same fail-closed KDF error in the parent.
  }
});
