# Root.ark Android client (authentication + read-only metadata prototype)

Status: **native launcher with online login, 2FA and bounded, authenticated read-only sync metadata listing, plus an internal gated HTTPS ciphertext fetch/verification adapter.** The app-internal adapter calls the pure-JVM cryptographic core only when an external source supplies current independently pinned trust and a one-shot file CEK. No such trusted provider is installed; the native UI remains metadata-only. No Android device runtime validation has been performed. This is a bounded step toward issue #64; it implements no Keystore, device enrollment, recovery or sync engine, and is not an approved release. The design gates in `docs/architecture/android-client-architecture.md` remain open.

## Layout

| Path | Purpose |
|---|---|
| `core/` | Pure Kotlin/JVM module (no Android dependencies). Portable path validator, sync data classes, and the `RootArkApi` interface for the existing login and sync endpoints. |
| `core/src/test/resources/portable-paths.json` | Shared path-validator fixture. Used by the Kotlin JUnit test and by `test/issue-64-android-contract.test.js` (Node). |
| `app/` | Native Activity, HTTPS auth and read-only listing adapter. Internet permission only, `allowBackup=false`, `usesCleartextTraffic=false`, screenshot/task-switcher `FLAG_SECURE`. No file/storage permissions. |
| `core/src/main/kotlin/dev/rootark/core/auth/ServerOrigin.kt` | Pure Kotlin strict HTTPS origin parser with independent JUnit rejection tests. |
| `core/src/main/kotlin/dev/rootark/core/sync/ReadOnlyFileListPolicy.kt` | Explicit `listFiles` gate, protocol/version and metadata bounds; produces display-only rows with no ciphertext, nonce, key material or signatures. |
| `core/src/main/kotlin/dev/rootark/core/sync/ProtectedSyncContent.kt` | Explicit, fail-closed Sync v2 signed-envelope verifier and AES-256-GCM decryptor, with canonical JSON AAD and RFC 8949 deterministic CBOR Ed25519 proof bytes; requires independently pinned device public keys, explicit current revocation/epoch, and a fresh trust snapshot. |
| `app/src/main/java/dev/rootark/android/ProtectedSyncFetch.kt` | Internal HTTPS-only `GET /sync/v1/objects/:objectId` adapter, limited to 12 MiB/one object/identity encoding, no redirects or cache, strictly parsed full signed response. No native UI integration. |

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
./gradlew :app:testDebugUnitTest # HTTPS transport and trust-gated fetch tests against real Node response fixtures
./gradlew :app:assembleDebug  # Android launcher build (requires the Android SDK)
```

Set `ANDROID_HOME` or create `android/local.properties` with `sdk.dir=...` (not committed).

## Contract tests (run in Node, no JDK needed)

```
node --test --test-reporter=tap test/issue-64-android-contract.test.js test/issue-64-android-entry.test.js test/issue-64-android-filelist.test.js
```

- Path validator: the JS validator (`sync-client/rootark-sync-paths.js`) and the Kotlin validator must agree on every case in `portable-paths.json`.
- Wire models: every field of the Kotlin data classes in `core/src/main/kotlin/dev/rootark/core/sync/` must match a real server response in `core/src/test/resources/server-responses.json` (names, nullability, JSON types).
- The fixture is captured by calling the real route handlers in-process. Refresh it with `node scripts/issue-64-android-fixtures.js --write`. The contract test fails if the committed fixture drifts from a fresh capture.

## Verification and remaining gaps

- The `ZK65 Provider and Android Focused Regression` workflow runs `gradle --no-daemon :core:test :app:testDebugUnitTest :app:assembleDebug` with pinned Gradle 8.10.2, Temurin JDK 17 and Android SDK 35 on hosted Ubuntu. Exact draft PR #268 head `1f5793aa` passed the Kotlin core tests, app transport/ephemeral cryptography JVM tests, and native app compilation. The Node server/fixture contracts passed on hosted Ubuntu and Windows-2022, **3/3 jobs green**. This is compile/JVM evidence, not an emulator, physical Android, or live TLS handshake test.
- The standalone `ProtectedSyncContent.verifyAndDecrypt(record, fileKey, pinnedContext)` is available to Kotlin callers after a separate trusted provisioning path exists. The core requires a 32-byte caller-owned CEK; exact object/file/version/compartment/epoch scope; an independently provisioned device-to-Ed25519-SPKI binding; current revocation information; an independently obtained trust snapshot valid for no more than five minutes; a nonexpired signing proof; canonical AAD and signed SHA-256 byte digests; and AES-GCM authentication. It rejects MOVE/DELETE payloads, expired historical proofs, unsupported protocol versions, malformed paths and all untrusted identities. It holds keys and plaintext only in memory and does not log them. The tests verify actual Node CREATE/UPDATE route signatures and CBOR encoding, then exercise decryption and adversarial mutations with disposable in-memory test keys.
- **Integration gate:** native login/list grants no signing trust or CEK. The server cannot provision its own signing key pin, current epoch or revocation state to make data trusted. Missing authenticated device enrollment, owner-approved key transfer, current trusted registry/epoch snapshots, and protected-metadata contract block actual UI access and usable protected content. There is no plaintext download/export flow.
- **Bounded ciphertext fetch (internal only):** `ProtectedSyncFetch.fetchCiphertext(origin, authenticatedSession, objectId)` sends one bearer-authenticated HTTPS GET to `/sync/v1/objects/:objectId`, checks local `listFiles` before the server rechecks it, rejects redirects/HTTP errors, JSON responses larger than 12 MiB, encoded/compressed responses, invalid UTF-8, unrecognized fields and malformed records. It returns an **untrusted** `SyncRecord`, never plaintext. `withVerifiedContent(..., TrustedContentGrantProvider, callback)` refuses to fetch without a short-lived independently provisioned device pin/revocation/epoch context plus a caller-owned 32-byte CEK; it invokes `ProtectedSyncContent.verifyAndDecrypt`, passes authenticated plaintext only to an internal callback, and wipes plaintext and the one-shot CEK on exit. The grant provider has deliberately **no implementation in the app**, so ordinary login cannot enable decryption. No UI, Keystore or persistent decrypted cache is added.
- The app-JVM tests use a real captured Node `GET /sync/v1/objects/:id` response and an injectable `HttpsURLConnection` fixture to verify URL/header/HTTP/size/parser/permission/trust boundaries without connecting to the user's server. These do not establish emulator or physical-device compatibility, nor certificate-chain behavior on a real network.
- **Platform gate:** the JVM test environment provides Ed25519 through JDK 17. Android API 29 provider availability/behavior remains unverified; missing Ed25519 or AES/GCM is rejected by the core. Instrumented minimum-API and physical-device tests are required before app integration, with no fallback to server-supplied public keys.
- The native screen sends `POST /auth/login` and `POST /auth/login/2fa` to a strictly validated HTTPS origin and handles authenticated, TOTP challenge, mandatory 2FA-enrollment and generic error states. It disables redirects and caching, bounds responses, clears sensitive UI fields, drops sessions on backgrounding, disables view-state saving, and retains session data only in process memory. Enrollment itself still requires the web client.
- The Android adapter also supports authenticated read-only `GET /sync/v1/objects` after a login with explicit `listFiles: true`; the server independently enforces `listFiles` on this endpoint. Only name/path/size/content-type and tombstone state reach native TextViews. A 401 discards the local session; a 403 is displayed as a denial. Android revocation and privilege changes are enforced by the server on each request.
- The legacy list endpoint returns **complete records including ciphertext**, even though the Android UI never displays protected bytes. It has no pagination. The Android transport refuses a body over **1 MiB** or over **128 objects**, validates protocol v2 and display metadata, and reports an explicit error without showing a partial inventory. Large remote inventories therefore cannot be listed until a server-approved paginated metadata-only protocol exists.
- The native UI remains only a metadata viewer. The internal fetch and verification path has **no trusted key provisioning, key enrollment/revocation delivery, offline copies, protected metadata protocol, recovery or sync writes**. Metadata names and paths are **currently server visible**, so this must not be presented as a fully zero-knowledge native client. No physical-device/emulator HTTP behavior has been validated.
