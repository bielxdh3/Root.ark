"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const read = (p) => fs.readFileSync(path.join(__dirname, "..", p), "utf8");

test("Android requests metadata-only cursor pages, bounded by 64 entries and 128KiB", () => {
  const origin = read("android/core/src/main/kotlin/dev/rootark/core/auth/ServerOrigin.kt");
  const transport = read("android/app/src/main/java/dev/rootark/android/AuthHttpTransport.kt");
  const policy = read("android/core/src/main/kotlin/dev/rootark/core/sync/PagedInventoryPolicy.kt");
  assert.match(origin, /view=metadata&limit=64/);
  assert.match(transport, /listInventoryPage/);
  assert.match(transport, /Authorization.*Bearer/);
  assert.match(transport, /instanceFollowRedirects\s*=\s*false/);
  assert.match(transport, /PagedInventoryPolicy\.MAX_RESPONSE_BYTES/);
  assert.match(transport, /PagedInventoryPolicy\.checkEnvelope/);
  assert.match(policy, /MAX_ENTRIES\s*=\s*64/);
  assert.doesNotMatch(transport, /SharedPreferences|CookieManager|Log\.|printStackTrace/);
});

test("Android pages remain memory only and restart on revoked or changed cursor", () => {
  const activity = read("android/app/src/main/java/dev/rootark/android/MainActivity.kt");
  assert.match(activity, /loadInventoryPage/);
  assert.match(activity, /showInventoryPage/);
  assert.match(activity, /401\s*->\s*showLogin/);
  assert.match(activity, /403\s*->\s*showLogin/);
  assert.match(activity, /409\s*->\s*\{\s*offlineInventory\?\.clear\(\)/);
  assert.match(activity, /409\s*->\s*\{[\s\S]{0,300}ciphertextCache\?\.clear\(\)/);
  assert.match(activity, /onStop\(/);
  assert.doesNotMatch(activity, /\.ciphertext|\.nonce|\.aad|\.tag|\.authorization/);
});
