> **Source scope — PR #273 standalone checkout:** This commit implements
> metadata pagination, not protected-content fetch. `ProtectedSyncContent.kt`,
> `ProtectedSyncFetch.kt`, `withVerifiedContent` and their app-JVM tests are
> **ABSENT from this PR HEAD**; they exist only in its separately integrated
> configured parent branch `cdx/rootark-issue64-filelist-20261106` (`83b0e147`).
> References to those APIs, build targets, security checks and capabilities
> below describe **the intended combined parent + child tree**, not features
> or tests delivered by the standalone #273 checkout. No forward merge,
> trusted-grant provisioner, device validation or deployment is claimed.

# Root.ark Android client (authentication + read-only metadata prototype)

Status: **native launcher with online login, 2FA and bounded, authenticated read-only sync metadata listing with pagination.** Protected-content fetch and verification are upstream dependencies, absent from this standalone checkout. No Android device runtime validation has been performed. This is a bounded step toward issue #64; it implements no Keystore, device enrollment, recovery or sync engine, and is not an approved release. The design gates in `docs/architecture/android-client-architecture.md` remain open.

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
./gradlew :app:testDebugUnitTest # app JVM tests present in this checkout
./gradlew :app:assembleDebug  # Android launcher build (requires the Android SDK)
```

Set `ANDROID_HOME` or create `android/local.properties` with `sdk.dir=...` (not committed).

## Issue #64 — paginated metadata browsing (stacked PR #273)

This child replaces the **native browsing UI's** former full-record list request with authenticated metadata-only pages at `GET /sync/v1/objects?view=metadata&limit=64[&cursor=...]`. The server independently checks `listFiles` on every page. Each response must declare `view:"metadata"`, protocol v2, at most 64 entries and at most 128 KiB; the client accepts only a valid bounded cursor and never requests the ciphertext-bearing legacy list endpoint while browsing. The older unpaginated list limitations described above apply to the legacy API, **not** this new native paged UI.

The UI retains one page in memory and follows an opaque cursor without merging inventory snapshots. Unauthorized 401 drops the session; 403 displays denial; 409 invalidates the page and requires a fresh start. "Atualizar desde o início" restarts at page one. Malformed/repeated cursors, changed snapshots and invalid metadata are rejected instead of silently showing partial results.

The pagination code depends on PR #255's server endpoint and the separately delivered login and metadata-listing branches. A merged server PR is **not** proof the endpoint is deployed: verify its presence in the approved server release before using this Android screen. The child also adds `test/issue-64-android-pagination.test.js` to the Node contract list and `test/issue-64-android-pagination-real-http.test.js` against a pinned disposable server checkout in hosted focused CI. The latter is required without skip in the focused workflow. These contract and hosted JVM checks do not establish physical-device/emulator HTTP behavior.

The upstream `ProtectedSyncFetch`/`ProtectedSyncContent` implementations are **not present in this checkout** and are not connected to this UI. Metadata names/paths remain server-visible; this is not a Zero-Knowledge release. No merge, deployment or Ready status is claimed for this stacked feature.

## Contract tests (run in Node, no JDK needed)

```
node --test --test-reporter=tap test/issue-64-android-contract.test.js test/issue-64-android-entry.test.js test/issue-64-android-filelist.test.js test/issue-64-android-pagination.test.js
```

- Path validator: the JS validator (`sync-client/rootark-sync-paths.js`) and the Kotlin validator must agree on every case in `portable-paths.json`.
- Wire models: every field of the Kotlin data classes in `core/src/main/kotlin/dev/rootark/core/sync/` must match a real server response in `core/src/test/resources/server-responses.json` (names, nullability, JSON types).
- The fixture is captured by calling the real route handlers in-process. Refresh it with `node scripts/issue-64-android-fixtures.js --write`. The contract test fails if the committed fixture drifts from a fresh capture.

## Verification and remaining gaps

- The `ZK65 Provider and Android Focused Regression` workflow runs `gradle --no-daemon :core:test :app:testDebugUnitTest :app:assembleDebug` with pinned Gradle 8.10.2, Temurin JDK 17 and Android SDK 35 on hosted Ubuntu. Exact draft PR #268 head `1f5793aa` passed the Kotlin core tests, app transport/ephemeral cryptography JVM tests, and native app compilation. The Node server/fixture contracts passed on hosted Ubuntu and Windows-2022, **3/3 jobs green**. This is compile/JVM evidence, not an emulator, physical Android, or live TLS handshake test.
- **Upstream dependency:** the protected-content verifier, ciphertext-fetch adapter, `withVerifiedContent` and associated JVM tests must be integrated separately. The historical #268 results above are not evidence that these APIs or tests exist in #273.
- **Integration gate:** native login/list grants no signing trust or CEK. The server cannot provision its own signing key pin, current epoch or revocation state to make data trusted. Missing authenticated device enrollment, owner-approved key transfer, current trusted registry/epoch snapshots, and protected-metadata contract block actual UI access and usable protected content. There is no plaintext download/export flow.
- **Platform gate:** the JVM test environment provides Ed25519 through JDK 17. Android API 29 provider availability/behavior remains unverified; missing Ed25519 or AES/GCM is rejected by the core. Instrumented minimum-API and physical-device tests are required before app integration, with no fallback to server-supplied public keys.
- The native screen sends `POST /auth/login` and `POST /auth/login/2fa` to a strictly validated HTTPS origin and handles authenticated, TOTP challenge, mandatory 2FA-enrollment and generic error states. It disables redirects and caching, bounds responses, clears sensitive UI fields, drops sessions on backgrounding, disables view-state saving, and retains session data only in process memory. Enrollment itself still requires the web client.
- The Android adapter also supports authenticated read-only `GET /sync/v1/objects` after a login with explicit `listFiles: true`; the server independently enforces `listFiles` on this endpoint. Only name/path/size/content-type and tombstone state reach native TextViews. A 401 discards the local session; a 403 is displayed as a denial. Android revocation and privilege changes are enforced by the server on each request.
- The legacy list endpoint returns **complete records including ciphertext**, even though the Android UI never displays protected bytes. It has no pagination. The Android transport refuses a body over **1 MiB** or over **128 objects**, validates protocol v2 and display metadata, and reports an explicit error without showing a partial inventory. Large remote inventories therefore cannot be listed until a server-approved paginated metadata-only protocol exists.
- The native UI remains only a metadata viewer. This standalone checkout has **no protected-content fetch and verification implementation, trusted key provisioning, key enrollment/revocation delivery, offline copies, protected metadata protocol, recovery or sync writes**. Metadata names and paths are **currently server visible**, so this must not be presented as a fully zero-knowledge native client. No physical-device/emulator HTTP behavior has been validated.
