"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const read = (p) => fs.readFileSync(path.join(__dirname, "..", p), "utf8");

test("selected sync metadata retains opaque object id and never carries protected record bytes", () => {
  const policy = read("android/core/src/main/kotlin/dev/rootark/core/sync/ReadOnlyFileListPolicy.kt");
  const transport = read("android/app/src/main/java/dev/rootark/android/AuthHttpTransport.kt");
  assert.match(policy, /val objectId: String/);
  assert.match(policy, /objectId = objectId/);
  assert.match(transport, /ReadOnlyFileListPolicy\.project/);
  assert.doesNotMatch(policy, /val (ciphertext|nonce|tag|aad|authorization):/);
});

test("native protected text view requires provisioned trust, authenticated fetch and clears on lifecycle", () => {
  const viewer = read("android/app/src/main/java/dev/rootark/android/VerifiedTextPreview.kt");
  const activity = read("android/app/src/main/java/dev/rootark/android/MainActivity.kt");
  assert.match(viewer, /withVerifiedContent/);
  assert.match(viewer, /TrustedContentGrantProvider/);
  assert.match(viewer, /decodeVerifiedText/);
  assert.match(activity, /showProtectedObject/);
  assert.match(activity, /onStop\(/);
  assert.match(activity, /securePreviewText/);
  assert.match(activity, /setFlags\(WindowManager\.LayoutParams\.FLAG_SECURE,\s*WindowManager\.LayoutParams\.FLAG_SECURE\)/, "must set FLAG_SECURE via setFlags");
  assert.match(activity, /isForeground = true/, "onStart must set isForeground = true");
  assert.match(activity, /isForeground = false/, "onStop must set isForeground = false");
  assert.match(activity, /stillActive = \{ isForeground && generation == startedGeneration/, "stillActive must verify isForeground and atomic startedGeneration");
  assert.match(activity, /setText\(characters,\s*0,\s*characters\.size\)/, "must use CharArray setText without immutable String heap copy");
  assert.doesNotMatch(activity, /text\(view,\s*String\(characters\)\)/, "must not wrap characters in String");
  assert.doesNotMatch(activity, /\.ciphertext|\.nonce|\.tag|\.aad|\.authorization|SharedPreferences|ClipboardManager|WebView/);
});
