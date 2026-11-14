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

test("real signed server listing with protocol-accepted 300 name and 512 contentType has two visible records", () => {
  const capture = JSON.parse(read("android/core/src/test/resources/server-responses.json"));
  const signedList = capture.responses["sync.list.long-metadata.200"];
  assert.equal(signedList.status, 200);
  assert.equal(signedList.body.protocolVersion, 2);
  assert.equal(signedList.body.objects.length, 2, "valid long metadata must not hide sibling files");
  const long = signedList.body.objects.find((record) => record.metadata.name.length === 300);
  assert.ok(long && long.metadata.contentType.length === 512);
  assert.equal(long.protocolVersion, 2);
  assert.equal(typeof long.authorization.signature, "string", "record is from signed write, not a synthetic response");
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
  assert.match(transport, /PagedInventoryPolicy\.checkEnvelope/);
  assert.match(transport, /ReadOnlyFileListPolicy\.project/);
  assert.match(policy, /listFiles/);
  assert.match(policy, /validText\(name, 512\)/, "name must obey server metadata limit");
  assert.match(policy, /validText\(contentType, 512\)/, "contentType must obey server metadata limit");
  assert.match(activity, /ReadOnlyFileListPolicy\.canList/);
  assert.match(activity, /401/);
  assert.match(activity, /403/);
  assert.match(activity, /onStop\(/);
  assert.match(activity, /row\.name/);
  assert.doesNotMatch(activity, /\.ciphertext|\.nonce|\.tag|\.aad|\.authorization/);
  assert.doesNotMatch(transport, /Log\.|printStackTrace|SharedPreferences|CookieManager/);
  assert.match(transport, /JSONException/, "malformed JSON parsing must catch JSONException");
  assert.match(transport, /SyncListingLimitException/, "size limit failures must be distinct");
  assert.match(transport, /SyncListingValidationException/, "validation failures must be distinct");
  assert.match(activity, /SyncListingLimitException/);
  assert.match(activity, /SyncListingValidationException/);
  assert.match(policy, /Character\.FORMAT|Character\.CONTROL|Character\.LINE_SEPARATOR|Character\.PARAGRAPH_SEPARATOR/);
});
