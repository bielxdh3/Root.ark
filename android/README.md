> This Android prototype supports authenticated sign-in and bounded,
> read-only metadata browsing. It also includes internal ciphertext
> fetch/verification APIs, but no trusted-grant provider is installed and
> the native UI cannot decrypt protected content.

# Root.ark Android client (authentication + read-only metadata prototype)

Status: **native launcher with online login, 2FA, bounded authenticated read-only metadata pagination, plus an internal gated HTTPS ciphertext fetch/verification adapter.** The app-internal adapter calls the pure-JVM cryptographic core only when an external source supplies current independently pinned trust and a one-shot file CEK. No such trusted provider is installed; the native UI remains metadata-only. The app does not implement Keystore enrollment, device enrollment, recovery or a sync engine. Physical-device networking remains unvalidated; the design gates in `docs/architecture/android-client-architecture.md` remain open.

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
./gradlew :app:testDebugUnitTest # HTTPS transport, pagination and trust-gated fetch JVM tests
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

## Paginated metadata browsing

The **native browsing UI** uses authenticated metadata-only pages at `GET /sync/v1/objects?view=metadata&limit=64[&cursor=...]` instead of the former full-record list request. The server independently checks `listFiles` on every page. Each response must declare `view:"metadata"`, protocol v2, at most 64 entries and at most 128 KiB; the client accepts only a valid bounded cursor and never requests the ciphertext-bearing legacy list endpoint while browsing. The older unpaginated list limitations described above apply to the legacy API, **not** this native paged UI.

The UI retains one page in memory and follows an opaque cursor without merging inventory snapshots. Unauthorized 401 drops the session; 403 displays denial; 409 invalidates the page and requires a fresh start. "Atualizar desde o início" restarts at page one. Malformed/repeated cursors, changed snapshots and invalid metadata are rejected instead of silently showing partial results.

The pagination code depends on server support for the metadata-only inventory endpoint. The presence of the Android adapter does not imply that the endpoint is deployed: verify server support before using this screen. Contract and focused HTTP tests validate the response shape but do not establish physical-device/emulator networking behavior.

The internal `ProtectedSyncFetch`/`ProtectedSyncContent` APIs are not connected to this UI. The native screen remains metadata-only and cannot decrypt without a trusted grant provider and CEK. Metadata names/paths remain server-visible; this is not a Zero-Knowledge native client.

## Contract tests (run in Node, no JDK needed)

```
node --test --test-reporter=tap test/issue-64-android-contract.test.js test/issue-64-android-entry.test.js test/issue-64-android-filelist.test.js test/issue-64-android-pagination.test.js
```

- Path validator: the JS validator (`sync-client/rootark-sync-paths.js`) and the Kotlin validator must agree on every case in `portable-paths.json`.
- Wire models: every field of the Kotlin data classes in `core/src/main/kotlin/dev/rootark/core/sync/` must match a real server response in `core/src/test/resources/server-responses.json` (names, nullability, JSON types).
- The fixture is captured by calling the real route handlers in-process. Refresh it with `node scripts/issue-64-android-fixtures.js --write`. The contract test fails if the committed fixture drifts from a fresh capture.

## Security and platform boundaries

- The Kotlin/JVM tests exercise the portable core, HTTPS transport, and ephemeral cryptographic fixtures; `assembleDebug` compiles the native launcher. These checks do not establish emulator or physical-device compatibility, nor a live TLS handshake.
- The internal `ProtectedSyncContent.verifyAndDecrypt(record, fileKey, pinnedContext)` API is available to Kotlin callers only after a separate trusted provisioning path exists. The core requires a 32-byte caller-owned CEK; exact object/file/version/compartment/epoch scope; an independently provisioned device-to-Ed25519-SPKI binding; current revocation information; an independently obtained trust snapshot valid for no more than five minutes; a nonexpired signing proof; canonical AAD and signed SHA-256 byte digests; and AES-GCM authentication. It rejects MOVE/DELETE payloads, expired historical proofs, unsupported protocol versions, malformed paths and all untrusted identities. It holds keys and plaintext only in memory and does not log them. The tests verify actual Node CREATE/UPDATE route signatures and CBOR encoding, then exercise decryption and adversarial mutations with disposable in-memory test keys.
- **Integration gate:** native login/list grants no signing trust or CEK. The server cannot provision its own signing key pin, current epoch or revocation state to make data trusted. Missing authenticated device enrollment, owner-approved key transfer, current trusted registry/epoch snapshots, and protected-metadata contract block actual UI access and usable protected content. There is no plaintext download/export flow.
- **Bounded ciphertext fetch (internal only):** `ProtectedSyncFetch.fetchCiphertext(origin, authenticatedSession, objectId)` sends one bearer-authenticated HTTPS GET to `/sync/v1/objects/:objectId`, checks local `listFiles` before the server rechecks it, rejects redirects/HTTP errors, JSON responses larger than 12 MiB, encoded/compressed responses, invalid UTF-8, unrecognized fields and malformed records. It returns an **untrusted** `SyncRecord`, never plaintext. `withVerifiedContent(..., TrustedContentGrantProvider, callback)` refuses to fetch without a short-lived independently provisioned device pin/revocation/epoch context plus a caller-owned 32-byte CEK; it invokes `ProtectedSyncContent.verifyAndDecrypt`, passes authenticated plaintext only to an internal callback, and wipes plaintext and the one-shot CEK on exit. The grant provider has deliberately **no implementation in the app**, so ordinary login cannot enable decryption. No UI, Keystore or persistent decrypted cache is added.
- The app-JVM tests use a real captured Node `GET /sync/v1/objects/:id` response and an injectable `HttpsURLConnection` fixture to verify URL/header/HTTP/size/parser/permission/trust boundaries without connecting to the user's server. These do not establish emulator or physical-device compatibility, nor certificate-chain behavior on a real network.
- **Platform gate:** the JVM test environment provides Ed25519 through JDK 17. Android API 29 provider availability/behavior remains unverified; missing Ed25519 or AES/GCM is rejected by the core. Instrumented minimum-API and physical-device tests are required before app integration, with no fallback to server-supplied public keys.
- The native screen sends `POST /auth/login` and `POST /auth/login/2fa` to a strictly validated HTTPS origin and handles authenticated, TOTP challenge, mandatory 2FA-enrollment and generic error states. It disables redirects and caching, bounds responses, clears sensitive UI fields, drops sessions on backgrounding, disables view-state saving, and retains session data only in process memory. Enrollment itself still requires the web client.
- The compatibility adapter retains authenticated read-only `GET /sync/v1/objects` for legacy callers after a login with explicit `listFiles: true`; the server independently enforces `listFiles` on this endpoint. The native browsing UI uses the paginated metadata-only endpoint. Only name/path/size/content-type and tombstone state reach native TextViews. A 401 discards the local session; a 403 is displayed as a denial. Android revocation and privilege changes are enforced by the server on each request.
- The legacy list endpoint returns **complete records including ciphertext**, even though the Android UI never displays protected bytes. It has no pagination. The legacy transport refuses a body over **1 MiB** or over **128 objects**, validates protocol v2 and display metadata, and reports an explicit error without showing a partial inventory. The new paginated metadata-only endpoint is the supported path for large inventories and remains dependent on the server-side #255 implementation being present in the approved release.
- The native UI remains only a metadata viewer. The internal fetch and verification path has **no trusted key provisioning, key enrollment/revocation delivery, offline copies, protected metadata protocol, recovery or sync writes**. Metadata names and paths are **currently server visible**, so this must not be presented as a fully zero-knowledge native client. No physical-device/emulator HTTP behavior has been validated.
