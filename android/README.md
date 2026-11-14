# Root.ark Android client (authentication + read-only metadata prototype)

Status: **native launcher with online login, 2FA and bounded, authenticated read-only paginated sync metadata browsing.** Android depends on PR #258 (login), PR #261 (list projection) and separately on PR #255 (server metadata pagination, issue #66). PR #255 is not an ancestor of PR #261: deploy the approved server capability before expecting pagination on Android. No device runtime validation has been performed. This is a bounded step toward issue #64, not a protected-file or decrypting sync client. It implements no Keystore, device enrollment, recovery or sync engine, and is not an approved release. The design gates in `docs/architecture/android-client-architecture.md` remain open.

## Layout

| Path | Purpose |
|---|---|
| `core/` | Pure Kotlin/JVM module (no Android dependencies). Portable path validator, sync data classes, and the `RootArkApi` interface for the existing login and sync endpoints. |
| `core/src/test/resources/portable-paths.json` | Shared path-validator fixture. Used by the Kotlin JUnit test and by `test/issue-64-android-contract.test.js` (Node). |
| `app/` | Native Activity, HTTPS auth and read-only listing adapter. Internet permission only, `allowBackup=false`, `usesCleartextTraffic=false`, screenshot/task-switcher `FLAG_SECURE`. No file/storage permissions. |
| `core/src/main/kotlin/dev/rootark/core/auth/ServerOrigin.kt` | Pure Kotlin strict HTTPS origin parser with independent JUnit rejection tests. |
| `core/src/main/kotlin/dev/rootark/core/sync/ReadOnlyFileListPolicy.kt` | Explicit `listFiles` gate, protocol/version and metadata bounds; produces display-only rows with no ciphertext, nonce, key material or signatures. |

Targets: minSdk 29 (proposed in the architecture doc, owner to confirm), compileSdk/targetSdk 35, Kotlin 2.0.21, AGP 8.7.3, JDK 17.

## Build requirements

- JDK 17
- Android SDK with platform 35 and build-tools (Android Studio's SDK Manager, or `sdkmanager`)
- A Gradle 8.x distribution, or Android Studio, to generate the wrapper

The Gradle wrapper (`gradlew`, `gradle/wrapper/`) is not checked in. Generate it once with a local Gradle 8.10+ install:

```
cd android
gradle wrapper --gradle-version 8.10.2
```

Then:

```
./gradlew :core:test          # pure JVM path-validator and contract tests
./gradlew :app:assembleDebug  # Android launcher build (requires the Android SDK)
```

Set `ANDROID_HOME` or create `android/local.properties` with `sdk.dir=...` (not committed).

## Contract tests (run in Node, no JDK needed)

```
node --test --test-reporter=tap test/issue-64-android-contract.test.js test/issue-64-android-entry.test.js test/issue-64-android-filelist.test.js test/issue-64-android-pagination.test.js
```

- Path validator: the JS validator (`sync-client/rootark-sync-paths.js`) and the Kotlin validator must agree on every case in `portable-paths.json`.
- Wire models: every field of the Kotlin data classes in `core/src/main/kotlin/dev/rootark/core/sync/` must match a real server response in `core/src/test/resources/server-responses.json` (names, nullability, JSON types).
- The fixture is captured by calling the real route handlers in-process. Refresh it with `node scripts/issue-64-android-fixtures.js --write`. The contract test fails if the committed fixture drifts from a fresh capture.

## Verification and remaining gaps

- The `ZK65 Provider and Android Focused Regression` workflow runs `gradle --no-daemon :core:test` with pinned Gradle 8.10.2 and Temurin JDK 17 on hosted Ubuntu. The initial real run exposed a stale signed-DELETE tombstone assertion; after correction, the hosted core build and **51 JVM tests** passed. These actually compile the Kotlin core and deserialize the committed HTTP response fixture, rather than merely scanning source text.
- The Node route/fixture contracts are additionally exercised on hosted Ubuntu and Windows. Neither these checks nor the Kotlin core tests compile, exercise or certify the Android application module.
- No secure key storage, cryptographic envelope, or metadata protocol is implemented. The protected-metadata protocol gap is documented in the architecture doc and is a blocker for protected Android content.
- The native screen sends `POST /auth/login` and `POST /auth/login/2fa` to a strictly validated HTTPS origin and handles authenticated, TOTP challenge, mandatory 2FA-enrollment and generic error states. It disables redirects and caching, bounds responses, clears sensitive UI fields, drops sessions on backgrounding, disables view-state saving, and retains session data only in process memory. Enrollment itself still requires the web client.
- The Android adapter calls **only** `GET /sync/v1/objects?view=metadata&limit=64[&cursor=...]` for listing after login with explicit `listFiles: true`; the server independently enforces `listFiles` on each page. Response must declare `view:"metadata"`, protocol v2, at most 64 objects, body at most 128 KiB, and a valid optional cursor. The client never requests the ciphertext-bearing legacy inventory endpoint for browsing. Only name/path/size/content-type and tombstone state reach native TextViews. A 401 discards the local session; a 403 displays denial; 409 (changed inventory snapshot) drops stale navigation and offers a new start.
- The UI keeps only one page of metadata in memory at a time, and follows the server's opaque cursor for later pages, including libraries with more than 128 objects. "Atualizar desde o início" restarts from page one; a repeated/invalid cursor or malformed response aborts navigation rather than mixing snapshots. The new endpoint is supplied by separate draft PR #255 and must be explicitly included in the server release before this Android client can browse.
- The hosted focused workflow additionally checks out the **exact PR #255 HEAD `3ccf9558` outside the source tree** and runs `test/issue-64-android-pagination-real-http.test.js` against the real authenticated inventory route, including signed >128-object data, 401/403, cross-account and cursor invalidation. This test is skipped when the pinned server checkout is unavailable, but is required and unskipped by hosted CI. No Android emulator/device HTTP execution is claimed.
- This step is only a metadata viewer; no decryption, key enrollment/revocation, offline copies, protected metadata protocol, recovery or sync writes. Metadata names and paths are **currently server visible**, so this must not be presented as a fully zero-knowledge native client. No physical-device/emulator HTTP behavior has been validated.
- The focused CI workflow now requests Android SDK 35 and builds `:app:assembleDebug` as well as running core JVM tests; its result is required before treating the module as compiled.
