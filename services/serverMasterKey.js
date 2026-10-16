"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const syncedDirectories = new Set();

function readPersistedKey(filePath) {
  const fileKey = fs.readFileSync(filePath, "utf8").trim();
  if (!/^[a-f0-9]{64}$/i.test(fileKey)) throw new Error("SERVER_MASTER_KEY invalida");
  return Buffer.from(fileKey, "hex");
}

function syncParentDirectory(filePath) {
  if (process.platform === "win32") return;
  const directory = path.dirname(path.resolve(filePath));
  if (syncedDirectories.has(directory)) return;
  const descriptor = fs.openSync(directory, "r");
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  syncedDirectories.add(directory);
}

function getServerMasterKey(options = {}) {
  const filePath = options.filePath;
  const createIfMissing = options.createIfMissing !== false;
  const envKey = (options.env || process.env).SERVER_MASTER_KEY;
  if (envKey) {
    const cleanKey = envKey.trim();
    if (/^[a-f0-9]{64}$/i.test(cleanKey)) return Buffer.from(cleanKey, "hex");
    const decoded = Buffer.from(cleanKey, "base64");
    if (decoded.length === 32) return decoded;
    throw new Error("SERVER_MASTER_KEY precisa ter 32 bytes em hex ou base64");
  }

  if (!filePath) throw new Error("SERVER_MASTER_KEY ausente");
  if (!fs.existsSync(filePath)) {
    if (!createIfMissing) throw new Error("SERVER_MASTER_KEY ausente");

    const masterKey = crypto.randomBytes(32);
    const tempPath = `${filePath}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.key`;
    let descriptor = null;
    let created = false;
    try {
      descriptor = fs.openSync(tempPath, "wx", 0o600);
      fs.writeFileSync(descriptor, masterKey.toString("hex"), "utf8");
      fs.fsyncSync(descriptor);
      fs.closeSync(descriptor);
      descriptor = null;
      try {
        fs.linkSync(tempPath, filePath);
        created = true;
      } catch (error) {
        if (error.code !== "EEXIST") throw error;
      }
    } finally {
      if (descriptor !== null) {
        try { fs.closeSync(descriptor); } catch {}
      }
      // Clean only this attempt's unique temp; a directory sweep can race a live initializer.
      try { fs.unlinkSync(tempPath); } catch {}
    }

    if (created) console.warn("[security] Nova chave mestra gerada em data/server-master.key. Faca backup seguro imediatamente.");
  }

  syncParentDirectory(filePath);
  return readPersistedKey(filePath);
}

module.exports = { getServerMasterKey };
