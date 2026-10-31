# Root.ark Android client (scaffold)

Status: **scaffold only; the pure Kotlin/JVM core has been compiled and tested in hosted Ubuntu CI.** This directory is step 1 of the native Android client tracked in issue #64. It implements no UI, no key storage, no networking, and no sync engine. The Android application module has not been built. It is not an approved release, and the design gates in `docs/architecture/android-client-architecture.md` remain open.

## Layout

| Path | Purpose |
|---|---|
| `core/` | Pure Kotlin/JVM module (no Android dependencies). Portable path validator, sync data classes, and the `RootArkApi` interface for the existing login and sync endpoints. |
| `core/src/test/resources/portable-paths.json` | Shared path-validator fixture. Used by the Kotlin JUnit test and by `test/issue-64-android-contract.test.js` (Node). |
| `app/` | Android application module. Manifest only: `allowBackup=false`, `usesCleartextTraffic=false`, no permissions. |

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
./gradlew :app:assembleDebug  # Android build (requires the Android SDK)
```

Set `ANDROID_HOME` or create `android/local.properties` with `sdk.dir=...` (not committed).

## Contract tests (run in Node, no JDK needed)

```
node --test --test-reporter=tap test/issue-64-android-contract.test.js
```

- Path validator: the JS validator (`sync-client/rootark-sync-paths.js`) and the Kotlin validator must agree on every case in `portable-paths.json`.
- Wire models: every field of the Kotlin data classes in `core/src/main/kotlin/dev/rootark/core/sync/` must match a real server response in `core/src/test/resources/server-responses.json` (names, nullability, JSON types).
- The fixture is captured by calling the real route handlers in-process. Refresh it with `node scripts/issue-64-android-fixtures.js --write`. The contract test fails if the committed fixture drifts from a fresh capture.

## Verification and remaining gaps

- The `ZK65 Provider and Android Focused Regression` workflow runs `gradle --no-daemon :core:test` with pinned Gradle 8.10.2 and Temurin JDK 17 on hosted Ubuntu. The initial real run exposed a stale signed-DELETE tombstone assertion; after correction, the hosted core build and **51 JVM tests** passed. These actually compile the Kotlin core and deserialize the committed HTTP response fixture, rather than merely scanning source text.
- The Node route/fixture contracts are additionally exercised on hosted Ubuntu and Windows. Neither these checks nor the Kotlin core tests compile, exercise or certify the Android application module.
- No secure key storage, cryptographic envelope, or metadata protocol is implemented. The protected-metadata protocol gap is documented in the architecture doc and is a blocker for protected Android content.
- The HTTP client (`RootArkApi` implementation) and the 2FA UI flow are not implemented; only the wire models and interface exist.
