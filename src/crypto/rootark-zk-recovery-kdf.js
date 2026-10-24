"use strict";

const path = require("node:path");
const workerThreads = require("node:worker_threads");
const { RootarkZkError, clearSecret } = require("./rootark-zk-1");

const KDF_PROFILE = Object.freeze({
  id: "argon2id13",
  opslimit: 3,
  memlimit: 268435456,
  outputLength: 32,
});
const KDF_TIMEOUT_MS = 120000;
const WORKER_PATH = path.join(__dirname, "rootark-zk-recovery-kdf-worker.js");

let active = false;

function recoveryError(code) {
  return new RootarkZkError(code);
}

function clearTransferredSecret(value) {
  try {
    clearSecret(value);
  } catch (_) {
    // A transferred ArrayBuffer is detached and already unavailable here.
  }
}

function validateInput(input) {
  if (!input || typeof input !== "object" || typeof input.password !== "string") {
    throw recoveryError("INVALID_RECOVERY_PACKAGE");
  }
  const passwordLength = Buffer.byteLength(input.password, "utf8");
  if (passwordLength < 1 || passwordLength > 1024) throw recoveryError("INVALID_RECOVERY_PACKAGE");
  const passwordBytes = new TextEncoder().encode(input.password);
  if (!Buffer.isBuffer(input.salt) && !(input.salt instanceof Uint8Array)) {
    clearSecret(passwordBytes);
    throw recoveryError("INVALID_RECOVERY_PACKAGE");
  }
  if (input.salt.byteLength !== 16) {
    clearSecret(passwordBytes);
    throw recoveryError("INVALID_RECOVERY_PACKAGE");
  }
  return { passwordBytes, saltBytes: Uint8Array.from(input.salt) };
}

async function deriveRecoveryKeyBounded(input) {
  const { passwordBytes, saltBytes } = validateInput(input);
  if (active) {
    clearSecret(passwordBytes);
    clearSecret(saltBytes);
    throw recoveryError("KDF_BUSY");
  }
  active = true;

  let worker;
  let timer;
  let settled = false;
  const workerData = { password: passwordBytes, salt: saltBytes, profile: KDF_PROFILE };

  return new Promise((resolve, reject) => {
    const finish = async (error, key) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      let result;
      if (!error) {
        if (!(Buffer.isBuffer(key) || key instanceof Uint8Array) || key.byteLength !== KDF_PROFILE.outputLength) {
          error = true;
        } else {
          result = Buffer.from(key);
          clearSecret(key);
        }
      }
      try {
        if (worker) await worker.terminate();
      } catch (_) {
        // The KDF result or failure remains authoritative if termination raced exit.
      }
      clearTransferredSecret(passwordBytes);
      clearTransferredSecret(saltBytes);
      active = false;
      if (error) reject(recoveryError("RECOVERY_KDF_FAILED"));
      else resolve(result);
    };

    try {
      worker = new workerThreads.Worker(WORKER_PATH, {
        workerData,
        transferList: [passwordBytes.buffer, saltBytes.buffer],
      });
    } catch (_) {
      clearTransferredSecret(passwordBytes);
      clearTransferredSecret(saltBytes);
      active = false;
      reject(recoveryError("RECOVERY_KDF_FAILED"));
      return;
    }

    timer = setTimeout(() => { void finish(true); }, KDF_TIMEOUT_MS);
    timer.unref?.();
    worker.once("message", (message) => {
      if (!message || message.ok !== true) {
        void finish(true);
        return;
      }
      void finish(null, message.key);
    });
    worker.once("error", () => { void finish(true); });
    worker.once("exit", (code) => {
      if (!settled) void finish(code === 0);
    });
  });
}

module.exports = { deriveRecoveryKeyBounded };
