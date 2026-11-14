"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const src = (p) => fs.readFileSync(path.join(__dirname, "..", p), "utf8");

test("#275 viewer is reachable from each #273 metadata-only page without an unbounded fallback", () => {
  const screen = src("android/app/src/main/java/dev/rootark/android/MainActivity.kt");
  const transport = src("android/app/src/main/java/dev/rootark/android/AuthHttpTransport.kt");
  const origin = src("android/core/src/main/kotlin/dev/rootark/core/auth/ServerOrigin.kt");
  assert.match(screen, /loadInventoryPage/);
  assert.match(screen, /showInventoryPage/);
  assert.match(screen, /showProtectedObject\(row\.objectId\)/);
  assert.match(screen, /independentlyProvisionedGrantProvider\(\).*null/);
  assert.match(screen, /409\s*->\s*\{\s*offlineInventory\?\.clear\(\)/);
  assert.match(screen, /409\s*->\s*\{[\s\S]{0,300}ciphertextCache\?\.clear\(\)/);
  assert.match(screen, /401\s*->\s*showLogin/);
  assert.match(screen, /403\s*->\s*showLogin/);
  assert.match(screen, /private fun clearSensitiveState\(\)/);
  assert.match(screen, /offlineInventory\?\.clear\(\)/);
  assert.match(screen, /LocalCipherCacheKey\.erase\(\)/);
  assert.match(screen, /onStop\(\)/);
  assert.match(transport, /listInventoryPage/);
  assert.doesNotMatch(transport, /fun listSyncObjects\(/);
  assert.match(origin, /syncInventoryUrl/);
  assert.match(origin, /syncObjectUrl/);
});

test("strict signed-content parser stays in the combined flow and page limits remain bounded", () => {
  const fetch = src("android/app/src/main/java/dev/rootark/android/ProtectedSyncFetch.kt");
  const policy = src("android/core/src/main/kotlin/dev/rootark/core/sync/PagedInventoryPolicy.kt");
  const view = src("android/app/src/main/java/dev/rootark/android/VerifiedTextPreview.kt");
  assert.match(fetch, /StrictSyncRecordJson\.parse/);
  assert.match(fetch, /ProtectedSyncContent\.verifyAndDecrypt/);
  assert.match(view, /withVerifiedContent/);
  assert.match(policy, /MAX_ENTRIES\s*=\s*64/);
  assert.match(policy, /MAX_RESPONSE_BYTES\s*=\s*128 \* 1024/);
});
