"use strict";

// Disposable synthetic ciphertext EGRESS child. Owns the loopback TCP listener
// and response socket; has no storage adapters, SQL role, keys or descendants.
// The fixture request token is only a local test-client selector. The parent
// separately enforces the complete trusted SQL GET admission before each grant.
const crypto = require("node:crypto");
const http = require("node:http");

const CHUNK = 16384;
let server;
let token;
let state = "new";
let activeResponse;
const send = (message) => {
  if (process.connected) process.send(message);
};
function matchToken(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
  const a = Buffer.from(value, "base64url");
  const b = Buffer.from(token, "base64url");
  return a.length === 32 && b.length === 32 && crypto.timingSafeEqual(a, b);
}
function denied(response, status) {
  response.writeHead(status, { "content-length": "0", "cache-control": "no-store" });
  response.end();
}
function ciphertext(message) {
  if (typeof message?.ciphertextBase64 !== "string"
    || !/^[A-Za-z0-9_-]+$/.test(message.ciphertextBase64)) process.exit(2);
  const bytes = Buffer.from(message.ciphertextBase64, "base64url");
  if (bytes.length !== CHUNK || bytes.toString("base64url") !== message.ciphertextBase64) process.exit(2);
  return bytes;
}

function listen() {
  server = http.createServer((request, response) => {
    if (request.method !== "GET" || request.url !== "/fixture-ciphertext") {
      denied(response, 404);
      return;
    }
    if (!matchToken(request.headers["x-lab-request-token"])) {
      denied(response, 403);
      return;
    }
    if (state !== "listening") {
      denied(response, 503);
      return;
    }
    state = "admitting";
    activeResponse = response;
    response.once("close", () => {
      activeResponse = null;
      if (state !== "finished") state = "closed";
    });
    send({ kind: "get-admit" });
  });
  server.maxHeadersCount = 12;
  server.listen(0, "127.0.0.1", () => {
    const address = server.address();
    if (!address || address.address !== "127.0.0.1") process.exit(2);
    state = "listening";
    send({ kind: "listening", address: address.address, port: address.port });
  });
}

process.on("message", (message) => {
  if (state === "new" && message?.kind === "init"
    && typeof message.token === "string"
    && /^[A-Za-z0-9_-]{43}$/.test(message.token)
    && Buffer.from(message.token, "base64url").length === 32) {
    token = message.token;
    state = "starting";
    listen();
    return;
  }
  if (state === "admitting" && message?.kind === "deny-get") {
    denied(activeResponse, 503);
    state = "closed";
    return;
  }
  if (state === "admitting" && message?.kind === "grant-get") {
    const payload = ciphertext(message);
    state = "partial";
    activeResponse.writeHead(200, {
      "content-type": "application/octet-stream",
      "cache-control": "no-store", "x-content-type-options": "nosniff",
    });
    // Real HTTP/socket write. The peer may consume some bytes and pause;
    // remaining bytes can be buffered in Node, OS and TCP after child exit.
    const buffered = !activeResponse.write(payload);
    send({ kind: "partial", bytes: CHUNK, buffered });
    return;
  }
  if (state === "partial" && message?.kind === "continue") {
    const payload = ciphertext(message);
    state = "finished";
    activeResponse.end(payload);
    return;
  }
  // Incorrect or unsolicited IPC never conveys an admission grant.
  process.exit(2);
});

process.on("disconnect", () => process.exit(2));
