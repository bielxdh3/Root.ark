"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawnSync } = require("node:child_process");
const read = (p) => fs.readFileSync(path.join(__dirname, "..", p), "utf8");

test("Android owner vector resource is not executed by default Node test discovery", () => {
  const resourcePath = path.join("android", "core", "src", "test", "resources");
  const source = path.join(__dirname, "..", resourcePath);
  const resources = fs.readdirSync(source).filter((name) => name.startsWith("owner-enrollment-vector."));
  assert.equal(resources.length, 1, "the Kotlin fixture must remain available");
  assert.equal(resources[0], "owner-enrollment-vector.js.fixture", "the stdin-driven generator must not be a discoverable test script");
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-node-discovery-"));
  try {
    const target = path.join(scratch, resourcePath);
    fs.mkdirSync(target, { recursive: true });
    fs.copyFileSync(path.join(source, resources[0]), path.join(target, resources[0]));
    fs.writeFileSync(path.join(scratch, "sentinel.test.js"), 'require("node:test")("sentinel", () => {});\n');
    const env = { ...process.env };
    delete env.NODE_TEST_CONTEXT;
    const result = spawnSync(process.execPath, ["--test", "--test-reporter=tap"], {
      cwd: scratch, env, encoding: "utf8", timeout: 10_000, windowsHide: true,
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /^# tests 1\r?$/m);
    assert.match(result.stdout, /^# pass 1\r?$/m);
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
});

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
  const buffer = read("android/app/src/main/java/dev/rootark/android/SecurePreviewBuffer.kt");
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
  // SecurePreviewBuffer intentionally retains the caller-owned mutable
  // CharArray under the lambda name `retained` until the view is cleared.
  // Require that exact buffer (not a String copy or a new CharArray) to reach
  // TextView.setText and that the lifecycle still wipes/clears its owner.
  assert.match(activity, /securePreviewText\.show\(characters,\s*\{\s*retained\s*->/,
    "the secured view must retain the verified CharArray through SecurePreviewBuffer");
  assert.match(activity, /previewText\.setText\(retained,\s*0,\s*retained\.size\)/,
    "must use retained CharArray setText without an immutable String heap copy");
  assert.match(activity, /securePreviewText\.clear\(\)/, "protected preview must clear on close and lifecycle");
  assert.match(activity, /previewText\.text\s*=\s*""/,
    "clear must remove the TextView's reference to the old backing buffer");
  assert.match(buffer, /previous\?\.fill\('\\u0000'\)/,
    "clear must wipe the actual retained CharArray before the TextView is replaced");
  assert.doesNotMatch(activity, /text\(view,\s*String\(characters\)\)/, "must not wrap characters in String");
  const protectedView = activity.slice(
    activity.indexOf("private fun showProtectedObject"), activity.indexOf("private fun showDeviceEnrollment"),
  );
  assert.doesNotMatch(protectedView, /ClipboardManager|setPrimaryClip|WebView/,
    "the protected-content view must not copy content or use a WebView");
  assert.match(activity, /ClipData\.newPlainText\("Root\.ark Android device", "\$\{identity\.readerDeviceId\}\\n\$publicKeyText"\)/,
    "clipboard access is limited to the public device identity for out-of-band owner pinning");
  assert.doesNotMatch(activity, /\.ciphertext|\.nonce|\.tag|\.aad|\.authorization|SharedPreferences|WebView/);
});

test("owner fingerprint survives an out-of-band background check only via exact fresh reauthentication", () => {
  const activity = read("android/app/src/main/java/dev/rootark/android/MainActivity.kt");
  const policy = read("android/app/src/main/java/dev/rootark/android/AndroidKeySecurityPolicy.kt");
  assert.match(activity, /private var pendingOwnerFingerprintStartedAtElapsedMs: Long/);
  assert.match(activity, /SystemClock\.elapsedRealtime\(\)/);
  assert.match(activity, /OwnerFingerprintResumePolicy\.canResume\(/);
  assert.match(activity, /private fun resumeOwnerFingerprintAfterLogin\(/);
  assert.match(activity, /AndroidInstallationKey\(this\)\.publicIdentity\(allowCreate = false\)/);
  assert.match(activity, /MessageDigest\.isEqual\(/);
  assert.match(activity, /if \(resumeOwnerFingerprintAfterLogin\(result, origin\)\) return/);
  assert.match(activity, /pendingOwnerImportBytes\?\.fill\(0\)/);
  assert.match(policy, /object OwnerFingerprintResumePolicy/);
});

test("credential action never retains the authenticated bearer token after background logout", () => {
  const activity = read("android/app/src/main/java/dev/rootark/android/MainActivity.kt");
  const section = activity.slice(activity.indexOf("private fun showProtectedObject"), activity.indexOf("private fun <T> runCheckedRequest"));
  assert.doesNotMatch(section, /val session = authenticatedSession/,
    "credential launcher must never capture an authenticated session object");
  assert.ok(/authenticatedSession\s*\?: return/.test(section),
    "the callback must recheck current login rather than holding a stale token");
  assert.match(activity, /pendingDeviceCredentialAction = null/);
});

test("V2 runtime gate reflects Android Ed25519 provider support on API 33+", () => {
  const activity = read("android/app/src/main/java/dev/rootark/android/MainActivity.kt");
  const provider = read("android/app/src/main/java/dev/rootark/android/OwnerPinnedGrantProvider.kt");
  assert.match(activity, /Build\.VERSION\.SDK_INT < Build\.VERSION_CODES\.TIRAMISU/);
  assert.match(provider, /Build\.VERSION\.SDK_INT < Build\.VERSION_CODES\.TIRAMISU/);
  assert.doesNotMatch(activity, /Enrollment protegido exige Android 12/);
});

test("owner document picker requires a fresh exact-account login before processing its returned package", () => {
  const activity = read("android/app/src/main/java/dev/rootark/android/MainActivity.kt");
  const documentResult = activity.slice(activity.indexOf("REQUEST_OWNER_PACKAGE -> {"),
    activity.indexOf("REQUEST_DEVICE_CREDENTIAL -> {"));
  assert.match(documentResult, /pendingOwnerDocumentAwaitingLogin\s*=\s*true/);
  assert.match(activity, /resumeOwnerDocumentAfterLogin\(/);
  assert.match(activity, /OwnerFingerprintResumePolicy\.canResume\(/);
  assert.match(activity, /if \(resumeOwnerDocumentAfterLogin\(result, origin\)\) return/);
  assert.doesNotMatch(documentResult, /showOwnerFingerprintConfirmation\(|importOwnerPackage\(|requestDeviceCredentialThen\(/,
    "picker result must never authorize or persist a grant using the pre-background login");
});

test("protected viewer resumes only with a fresh matching login after Keyguard, without retaining bearer", () => {
  const activity = read("android/app/src/main/java/dev/rootark/android/MainActivity.kt");
  assert.match(activity, /pendingProtectedRead/);
  assert.match(activity, /OwnerCredentialResumePolicy\.canResume\(/);
  assert.match(activity, /if \(resumeProtectedReadAfterLogin\(result, origin\)\) return/);
  assert.match(activity, /deferProtectedReadAfterCredential\(/);
  assert.match(activity, /confirmedCredential/);
  assert.doesNotMatch(activity, /pendingProtectedRead\s*=\s*.*(?:token|Authenticated)/,
    "pending viewer intent must contain metadata only, never a server bearer");
});

test("owner hardware-floor import runs on worker, not on the login callback UI thread", () => {
  const activity = read("android/app/src/main/java/dev/rootark/android/MainActivity.kt");
  const resumption = activity.slice(activity.indexOf("private fun resumeOwnerCredentialAfterLogin("),
    activity.indexOf("private fun deferProtectedReadAfterCredential("));
  assert.match(resumption, /runCheckedRequest\(\{\s*stillActive\s*->/);
  assert.match(resumption, /importOwnerPackage\(/);
  assert.match(resumption, /OwnerCredentialResumePolicy\.canResume\(/);
  assert.doesNotMatch(resumption, /\n\s*importOwnerPackage\(bytes, pin, publicKey, initial\)\s*\n/,
    "blocking floor acquisition must not be called directly by the UI login callback");
  const importBody = activity.slice(activity.indexOf("private fun importOwnerPackage("),
    activity.indexOf("private fun readOwnerPackage("));
  assert.match(importBody, /stillActive\(\)/,
    "worker import must abort when foreground/login generation changes");
  assert.match(importBody, /OwnerCredentialResumePolicy\.isWithinWindow\(/,
    "worker import must recheck authenticated hardware window after waiting for the index lock");
  assert.doesNotMatch(importBody, /showLogin\(/,
    "worker import must not touch Activity UI after background thread execution");
});

test("owner floor enrollment commit fences reads and retires aliases only after persisted package", () => {
  const activity = read("android/app/src/main/java/dev/rootark/android/MainActivity.kt");
  const floor = read("android/app/src/main/java/dev/rootark/android/OwnerOfflineHardwareFloor.kt");
  const provider = read("android/app/src/main/java/dev/rootark/android/OwnerPinnedGrantProvider.kt");
  const store = read("android/app/src/main/java/dev/rootark/android/OwnerEnrollmentStore.kt");
  const importer = activity.slice(activity.indexOf("private fun importOwnerPackage("),
    activity.indexOf("private fun readOwnerPackage("));
  assert.match(importer, /prepareEnrollment\s*=\s*\{[\s\S]*?enrollmentStore\.stage\(/);
  assert.match(floor, /indexLock\s*=\s*acquireIndexLock\(noBackupRoot\)[\s\S]*?prepareEnrollment\(\)[\s\S]*?createdAlias = alias/,
    "candidate must be durable under the index lock before allocating a high-water alias");
  assert.match(importer, /enrollmentStore\.save\([\s\S]*?enrollmentSaved\s*=\s*true/);
  assert.match(importer, /retireOlder\([\s\S]*?enrollmentSaved\s*=\s*enrollmentSaved/);
  assert.doesNotMatch(importer.slice(importer.indexOf("observeHead("), importer.indexOf("enrollmentStore.save(")),
    /stillActive\(\)|isWithinWindow\(/, "after a durable seal, Activity cancellation cannot skip signed-package persistence");
  assert.match(floor, /PRESERVE_PRIOR_FOR_RECOVERY\s*->\s*return/);
  assert.match(floor, /clearPreparedOnCommit\?\.invoke\(\)/);
  assert.match(provider, /enrollmentStore\.hasPending\(\)/);
  assert.match(store, /fun stage\(/);
  assert.doesNotMatch(store.slice(store.indexOf("fun load("), store.indexOf("fun save(")),
    /pending\b/, "untrusted staged state must never become active enrollment during load()");
});
