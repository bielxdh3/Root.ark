"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const base = path.join(__dirname, "../android/app/src/main");

test("Android declares a launched non-exported-by-default auth boundary with internet and no backup/cleartext", () => {
  const manifest = fs.readFileSync(path.join(base, "AndroidManifest.xml"), "utf8");
  assert.match(manifest, /android\.permission\.INTERNET/);
  assert.match(manifest, /android:allowBackup="false"/);
  assert.match(manifest, /android:usesCleartextTraffic="false"/);
  assert.match(manifest, /android:name="\.MainActivity"/);
  assert.match(manifest, /android:exported="true"/);
  assert.match(manifest, /android\.intent\.action\.MAIN/);
  assert.match(manifest, /android\.intent\.category\.LAUNCHER/);
  assert.doesNotMatch(manifest, /WRITE_EXTERNAL_STORAGE|READ_EXTERNAL_STORAGE|MANAGE_EXTERNAL_STORAGE/);
});

test("Android auth flow uses real auth routes and pins HTTPS requests without following redirects", () => {
  const activity = fs.readFileSync(path.join(base, "java/dev/rootark/android/MainActivity.kt"), "utf8");
  const transport = fs.readFileSync(path.join(base, "java/dev/rootark/android/AuthHttpTransport.kt"), "utf8");
  const origin = fs.readFileSync(path.join(__dirname, "../android/core/src/main/kotlin/dev/rootark/core/auth/ServerOrigin.kt"), "utf8");
  assert.match(activity, /FLAG_SECURE/);
  assert.match(activity, /onStop\(/);
  assert.match(activity, /challengeId/);
  assert.match(origin, /\/auth\/login/);
  assert.match(origin, /\/auth\/login\/2fa/);
  assert.match(transport, /origin\.loginUrl\(/);
  assert.match(transport, /origin\.twoFactorUrl\(/);
  assert.match(transport, /instanceFollowRedirects\s*=\s*false/);
  assert.match(activity, /ServerOrigin\.parse/);
  assert.doesNotMatch(transport, /Log\.|printStackTrace|SharedPreferences|CookieManager/);
});

test("ciphertext capture UI delegates duplicate handling before clearing cached state and Keystore", () => {
  const activity = fs.readFileSync(path.join(base, "java/dev/rootark/android/MainActivity.kt"), "utf8");
  const capture = activity.slice(activity.indexOf('button(layout, "Capturar ciphertext criptografado")'),
    activity.indexOf('button(layout, "Voltar")', activity.indexOf('button(layout, "Capturar ciphertext criptografado")')));
  assert.match(capture, /CiphertextCaptureFailurePolicy\.handle\(failure\)\s*\{\s*runCatching\s*\{\s*stored\.clear\(\)/);
  assert.match(capture, /LocalCipherCacheKey\.erase\(\)/);
  assert.match(capture, /CiphertextCaptureUiResult\.ALREADY_CAPTURED/);
});
