"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");

test("read-only client list is backed by canonical authenticated server route and real captured wire fixture", () => {
  const server = read("src/routes/sync.js");
  assert.match(server, /app\.get\("\/sync\/v1\/objects", authenticate, requirePermission\("listFiles"\)/);
  const capture = JSON.parse(read("android/core/src/test/resources/server-responses.json"));
  assert.equal(capture.responses["sync.list.200"].status, 200);
  const { protocolVersion, objects } = capture.responses["sync.list.200"].body;
  assert.equal(protocolVersion, 2);
  assert.ok(Array.isArray(objects) && objects.length > 0);
  assert.equal(typeof objects[0].metadata.name, "string");
  assert.equal(typeof objects[0].ciphertext, "string", "the server currently transfers ciphertext: client must not display it");
});

test("native list limits responses, checks listFiles, handles denied sessions and renders a metadata-only projection", () => {
  const transport = read("android/app/src/main/java/dev/rootark/android/AuthHttpTransport.kt");
  const activity = read("android/app/src/main/java/dev/rootark/android/MainActivity.kt");
  const policy = read("android/core/src/main/kotlin/dev/rootark/core/sync/ReadOnlyFileListPolicy.kt");
  const origin = read("android/core/src/main/kotlin/dev/rootark/core/auth/ServerOrigin.kt");
  assert.match(origin, /\/sync\/v1\/objects/);
  assert.match(transport, /Authorization/);
  assert.match(transport, /Bearer /);
  assert.match(transport, /instanceFollowRedirects\s*=\s*false/);
  assert.match(transport, /MAX_RESPONSE_BYTES/);
  assert.match(transport, /ReadOnlyFileListPolicy\.checkEnvelope/);
  assert.match(transport, /ReadOnlyFileListPolicy\.project/);
  assert.match(policy, /listFiles/);
  assert.match(activity, /ReadOnlyFileListPolicy\.canList/);
  assert.match(activity, /401/);
  assert.match(activity, /403/);
  assert.match(activity, /onStop\(/);
  assert.match(activity, /row\.name/);
  assert.doesNotMatch(activity, /\.ciphertext|\.nonce|\.tag|\.aad|\.authorization/);
  assert.doesNotMatch(transport, /Log\.|printStackTrace|SharedPreferences|CookieManager/);
});
