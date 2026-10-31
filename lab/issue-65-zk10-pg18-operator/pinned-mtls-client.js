"use strict";

// DEV-only mTLS identity: import fixture credentials into OpenSSL once, then
// hand HTTPS an opaque TLS SecureContext instead of file contents.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const tls = require("node:tls");

function createPinnedLabClientTls(certDir, identity, serverPin) {
  if (typeof certDir !== "string" || !path.isAbsolute(certDir)
    || !["client", "foreign"].includes(identity)
    || typeof serverPin !== "string"
    || !/^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(serverPin)) {
    throw Error("ZK10_CLIENT_TLS_CONFIG_INVALID");
  }
  const read = (name) => fs.readFileSync(path.join(certDir, name));
  let ca;
  let cert;
  let key;
  let secureContext;
  try {
    ca = read("ca.pem");
    cert = read(identity + ".pem");
    key = read(identity + ".key");
    secureContext = tls.createSecureContext({
      ca, cert, key, minVersion: "TLSv1.3", maxVersion: "TLSv1.3",
    });
  } finally {
    // OpenSSL owns the imported key. Do not retain readable PEM in JS memory.
    ca?.fill(0);
    cert?.fill(0);
    key?.fill(0);
  }
  return Object.freeze({
    secureContext,
    // A pooled connection could reuse a prior request's client certificate
    // even if this request selects a different pinned mTLS identity.
    agent: false,
    minVersion: "TLSv1.3", maxVersion: "TLSv1.3",
    rejectUnauthorized: true,
    checkServerIdentity: (hostname, peer) => {
      const failure = tls.checkServerIdentity(hostname, peer);
      if (failure) return failure;
      if (new crypto.X509Certificate(peer.raw).fingerprint256 !== serverPin)
        return Error("ZK10_PEER_PIN_MISMATCH");
    },
  });
}

module.exports = { createPinnedLabClientTls };
