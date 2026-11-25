# Root.ark Android client (authentication prototype)

Status: **native launcher with online login and 2FA implementation; Android build/device behavior pending hosted and device validation.** This is a bounded step toward the client in issue #64, not a protected-file or sync client. It implements no Keystore, device enrollment, recovery or sync engine, and is not an approved release. The design gates in `docs/architecture/android-client-architecture.md` remain open.

The original Kotlin/JVM scaffold was compiled and tested in hosted Ubuntu CI before the native login screen was added. Those results do not validate the newer Android application or an installed APK. The app now includes an HTTPS authentication screen, but no protected-file access or synchronization implementation.

## Layout

| Path | Purpose |
|---|---|
| `core/` | Pure Kotlin/JVM module (no Android dependencies). Portable path validator, sync data classes, and the `RootArkApi` interface for the existing login and sync endpoints. |
| `core/src/test/resources/portable-paths.json` | Shared path-validator fixture. Used by the Kotlin JUnit test and by `test/issue-64-android-contract.test.js` (Node). |
| `app/` | Native Activity and small HTTPS auth adapter. Declares internet permission with `allowBackup=false`, `usesCleartextTraffic=false` and screenshot/task-switcher `FLAG_SECURE`. No file/storage permissions. |
| `core/src/main/kotlin/dev/rootark/core/auth/ServerOrigin.kt` | Pure Kotlin strict HTTPS origin parser with independent JUnit rejection tests. |

Targets: minSdk 29 (proposed in the architecture doc, owner to confirm), compileSdk/targetSdk 35, Kotlin 2.0.21, AGP 8.7.3, JDK 17.

## Build requirements

- JDK 17
- Android SDK with `platforms;android-35`, `build-tools;34.0.0` and `build-tools;35.0.0` (Android Studio's SDK Manager, or `sdkmanager`). AGP 8.7.3 can require 34.0.0 even when 35.0.0 is installed.
- A Gradle 8.10.2 distribution (the version used by CI), or Android Studio configured to use that version.

The Gradle wrapper (`gradlew`, `gradle/wrapper/`) is not checked in. Generate it once with a local Gradle 8.10+ install:

```
cd android
gradle wrapper --gradle-version 8.10.2
```

Then:

```
./gradlew :core:test          # pure JVM path-validator and contract tests
./gradlew :app:testDebugUnitTest # application JVM tests, including screen-inset calculations
./gradlew :app:assembleDebug  # Android launcher build (requires the Android SDK)
```

On Windows PowerShell, run the same build after generating the wrapper:

```powershell
.\gradlew.bat :core:test :app:assembleDebug
```

Alternatively, with Gradle 8.10.2 already installed, run the same task pair as CI directly from `android/` without generating a wrapper:

```
gradle --no-daemon :core:test :app:assembleDebug
```

These JVM tests and the debug APK build do not replace the separate JavaScript contract or physical-device validation gates.

Set `ANDROID_HOME` or create `android/local.properties` with `sdk.dir=...` (not committed).

## Contract tests (run in Node, no JDK needed)

```
node --test --test-reporter=tap test/issue-64-android-contract.test.js test/issue-64-android-entry.test.js
```

- Path validator: the JS validator (`sync-client/rootark-sync-paths.js`) and the Kotlin validator must agree on every case in `portable-paths.json`.
- Wire models: every field of the Kotlin data classes in `core/src/main/kotlin/dev/rootark/core/sync/` must match a real server response in `core/src/test/resources/server-responses.json` (names, nullability, JSON types).
- The fixture is captured by calling the real route handlers in-process. Refresh it with `node scripts/issue-64-android-fixtures.js --write`. The contract test fails if the committed fixture drifts from a fresh capture.

## Verification and remaining gaps

- The first hosted run, before Android app tasks were added, executed `gradle --no-daemon :core:test` with pinned Gradle 8.10.2 and Temurin JDK 17 on hosted Ubuntu. It exposed a stale signed-DELETE tombstone assertion; after correction, the core build and **51 JVM tests** passed. This is historical core-only evidence, not the current workflow scope.
- The Node route/fixture contracts are additionally exercised on hosted Ubuntu and Windows; these Node checks do not compile or exercise the Android application module.
- No secure key storage, cryptographic envelope, or metadata protocol is implemented. The protected-metadata protocol gap is documented in the architecture doc and is a blocker for protected Android content.
- The native screen sends `POST /auth/login` and `POST /auth/login/2fa` to a strictly validated HTTPS origin and handles authenticated, TOTP challenge, mandatory 2FA-enrollment and generic error states. It disables redirects and caching, bounds responses, clears sensitive UI fields, drops sessions on backgrounding, disables view-state saving, and retains session data only in process memory. Enrollment itself still requires the web client.
- The Android adapter intentionally implements only authentication; `RootArkApi` sync methods, ZK keys, registration, device revocation, recovery and protected data access remain unavailable. No on-device runtime, network integration, or emulator/physical-device validation has been completed for this step yet.
- The focused CI workflow requests Android SDK 35 and runs `gradle --no-daemon :core:test :app:testDebugUnitTest :app:assembleDebug`. The application JVM tests include screen-inset calculations; these and the debug build do not establish device or visual validation.
