"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const https = require("node:https");
const net = require("node:net");
const tls = require("node:tls");
const vm = require("node:vm");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");
const { generateNativeFixtureCertificates } = require("./support/issue-65-native-openssl-fixture");

// Exercise the *real* private transport helper, without exporting it as a
// production API or bypassing any independent historical authorization gate.
// The separate TLS 1.3/mTLS fixture only tests rejection/socket teardown.
function transportUnderTest() {
  const file = process.env.ROOTARK_HISTORICAL_PROVIDER_IMPL
    || path.resolve(__dirname, "../sync-client/rootark-sync-v2-historical-evidence-provider.js");
  const source = fs.readFileSync(file, "utf8");
  const begin = source.indexOf("async function postHistoricalAdmission(");
  const end = source.indexOf("\nmodule.exports", begin);
  assert.ok(begin > 0 && end > begin, "transport helper must remain present");
  const context = vm.createContext({ https, net, tls, Buffer, Promise,
    setTimeout, clearTimeout, Error, JSON });
  vm.runInContext(source.slice(begin, end), context);
  return vm.runInContext("postHistoricalAdmission", context);
}

test("rejected streaming 503 closes pinned TLS 1.3/mTLS socket immediately", async (t) => {
  const dir = createPrivateAuthorityFixture("zk65-history-rejected-");
  generateNativeFixtureCertificates(dir, {
    caSubject: "Rootark History Socket Test CA",
    servers: ["history-server"], clients: ["history-reader"],
  });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  let closed;
  const responseClosed = new Promise((resolve) => { closed = resolve; });
  const server = https.createServer({ key: read("history-server.key"),
    cert: read("history-server.pem"), ca: read("ca.pem"),
    requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
    maxVersion: "TLSv1.3" }, (_req, res) => {
    res.writeHead(503, { "content-type": "application/json",
      "transfer-encoding": "chunked" });
    const interval = setInterval(() => res.write("x"), 15);
    res.once("close", () => { clearInterval(interval); closed(true); });
    res.write("x");
  });
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const post = transportUnderTest();
  const options = {
    host: "127.0.0.1", port: server.address().port,
    ca: read("ca.pem"), key: read("history-reader.key"),
    cert: read("history-reader.pem"),
    fingerprint: new crypto.X509Certificate(read("history-server.pem"))
      .fingerprint256.toUpperCase(), timeoutMs: 750,
  };
  await assert.rejects(post(options, Buffer.from("{}"), "/v1/cas-anchor/historical-admit"),
    /HISTORICAL_RESPONSE_INVALID/);
  assert.equal(await Promise.race([responseClosed,
    new Promise((resolve) => setTimeout(() => resolve(false), 1100))]),
  true, "a rejected streaming response must physically close before three wall deadlines");
});
