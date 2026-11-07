# Root.ark Android client (paged metadata + trust-gated protected text prototype)

Status: **native HTTPS login + 2FA, bounded metadata-only pagination, temporary session-scoped offline metadata browsing, one-object encrypted ciphertext staging, and a per-row trust-gated protected-text action.** The offline screen can display up to eight previously fetched, authenticated HTTPS metadata pages when connectivity fails. They are explicitly historical, unsigned, advisory metadata. The optional ciphertext action downloads a single signed-envelope candidate (maximum 4 MiB over authenticated HTTPS) and encrypts the exact bytes with Android Keystore AES-256-GCM in the app's private, excluded-from-backup directory. Local SHA-256, GCM authentication, manifest/ciphertext digests, account, origin, per-login nonce, claimed device/revision/epoch, and object/version binding prevent local corruption and cross-session reuse. **The transport's signature, claimed device/epoch and current grant are NOT independently verified; no ciphertext is exposed for offline decrypt or rendered as plaintext.** There is no trusted Android CEK/device enrollment provider installed. The cache has room for one object and can be replaced by another; it is wiped with the Keystore key on logout, 401/403, relevant 409, app backgrounding and next startup. It is unavailable after restart. No hardware Keystore assurance has been measured. This remains an incremental, unreleased Android prototype. The architecture gates in `docs/architecture/android-client-architecture.md` remain open.

## Layout

| Path | Purpose |
|---|---|
| `core/` | Pure Kotlin/JVM module (no Android dependencies). Portable path validator, sync data classes, and the `RootArkApi` interface for the existing login and sync endpoints. |
| `core/src/test/resources/portable-paths.json` | Shared path-validator fixture. Used by the Kotlin JUnit test and by `test/issue-64-android-contract.test.js` (Node). |
| `app/` | Native Activity, HTTPS auth and read-only listing adapter. Internet permission only, `allowBackup=false`, `usesCleartextTraffic=false`, screenshot/task-switcher `FLAG_SECURE`. No file/storage permissions. |
| `core/src/main/kotlin/dev/rootark/core/auth/ServerOrigin.kt` | Pure Kotlin strict HTTPS origin parser with independent JUnit rejection tests. |
| `core/src/main/kotlin/dev/rootark/core/sync/ReadOnlyFileListPolicy.kt` | Explicit `listFiles` gate, protocol/version and metadata bounds; produces display-only rows with no ciphertext, nonce, key material or signatures. |
| `core/src/main/kotlin/dev/rootark/core/sync/PagedInventoryPolicy.kt` | Sync v2 `view=metadata` pagination contract: max 64 objects / 128 KiB per page, validated opaque cursors, no ciphertext in pages. |
| `app/src/test/resources/paged-server255-http.json` | Three HTTP metadata-page bodies (64+64+2 rows) captured from pinned PR #255 using 130 disposable, test-signed Sync v2 entries. Not a source of trusted signing keys or a production grant. |
| `core/src/main/kotlin/dev/rootark/core/sync/ProtectedSyncContent.kt` | Explicit, fail-closed Sync v2 signed-envelope verifier and AES-256-GCM decryptor, with canonical JSON AAD and RFC 8949 deterministic CBOR Ed25519 proof bytes; requires independently pinned device public keys, explicit current revocation/epoch, and a fresh trust snapshot. |
| `app/src/main/java/dev/rootark/android/ProtectedSyncFetch.kt` | Internal HTTPS-only `GET /sync/v1/objects/:objectId` adapter, limited to 12 MiB/one object/identity encoding, no redirects or cache, strictly parsed full signed response. Only callable by the protected viewer with separately provisioned trust and CEK. |
| `app/src/main/java/dev/rootark/android/VerifiedTextPreview.kt` | User-initiated bounded UTF-8 preview gate: opens a selected opaque object ID through `withVerifiedContent` only with an independently provisioned grant, rejects binary/oversized text, clears the temporary character buffer. |

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
node --test --test-reporter=tap test/issue-64-android-contract.test.js test/issue-64-android-entry.test.js test/issue-64-android-filelist.test.js test/issue-64-android-pagination.test.js test/issue-64-android-paged-protected-integration.test.js test/issue-64-android-verified-viewer.test.js
```

- Path validator: the JS validator (`sync-client/rootark-sync-paths.js`) and the Kotlin validator must agree on every case in `portable-paths.json`.
- Wire models: every field of the Kotlin data classes in `core/src/main/kotlin/dev/rootark/core/sync/` must match a real server response in `core/src/test/resources/server-responses.json` (names, nullability, JSON types).
- The fixture is captured by calling the real route handlers in-process. Refresh it with `node scripts/issue-64-android-fixtures.js --write`. The contract test fails if the committed fixture drifts from a fresh capture.

## Verification and remaining gaps

- The `ZK65 Provider and Android Focused Regression` workflow runs `gradle --no-daemon :core:test :app:testDebugUnitTest :app:assembleDebug` with pinned Gradle 8.10.2, Temurin JDK 17 and Android SDK 35 on hosted Ubuntu. Exact draft PR #268 head `1f5793aa` passed the Kotlin core tests, app transport/ephemeral cryptography JVM tests, and native app compilation. The Node server/fixture contracts passed on hosted Ubuntu and Windows-2022, **3/3 jobs green**. This is compile/JVM evidence, not an emulator, physical Android, or live TLS handshake test.
- The standalone `ProtectedSyncContent.verifyAndDecrypt(record, fileKey, pinnedContext)` is available to Kotlin callers after a separate trusted provisioning path exists. The core requires a 32-byte caller-owned CEK; exact object/file/version/compartment/epoch scope; an independently provisioned device-to-Ed25519-SPKI binding; current revocation information; an independently obtained trust snapshot valid for no more than five minutes; a nonexpired signing proof; canonical AAD and signed SHA-256 byte digests; and AES-GCM authentication. It rejects MOVE/DELETE payloads, expired historical proofs, unsupported protocol versions, malformed paths and all untrusted identities. It holds keys and plaintext only in memory and does not log them. The tests verify actual Node CREATE/UPDATE route signatures and CBOR encoding, then exercise decryption and adversarial mutations with disposable in-memory test keys.
- **Integration gate:** native login/list grants no signing trust or CEK. The server cannot provision its own signing key pin, current epoch or revocation state to make data trusted. Missing authenticated device enrollment, owner-approved key transfer, current trusted registry/epoch snapshots, and protected-metadata contract block actual UI access and usable protected content. There is no plaintext download/export flow.
- **Protected text viewer boundary:** each active read-only inventory row keeps the validated opaque `objectId` and offers a `Conteúdo protegido` action. Ordinary login opens a clearly **blocked** screen because `MainActivity.independentlyProvisionedGrantProvider()` deliberately returns `null`: there is no owner-approved Android device enrollment, independent trust snapshot, or CEK source. Once such a provider is reviewed and wired, the same UI action can call `VerifiedTextPreview.open()` on a background thread. This calls `ProtectedSyncFetch.withVerifiedContent` (single HTTPS GET, explicit `listFiles`, strict 12 MiB signed JSON, independent Ed25519 device pin/epoch/expiry and AES-GCM) before accepting any plaintext. A foreground-generation check prevents decryption if the window stops while HTTPS is in flight, and errors preserve 401/403 handling without plaintext. A tiny strict UTF-8 text preview (at most 64 KiB) is rendered only after verification; invalid UTF-8, binary control bytes, excess size, revoked/expired/wrong-epoch grants, tampered ciphertext and absent grants fail closed. No content is exported to files, share intents, clipboard, WebView, or notification; `FLAG_SECURE`, `onStop` and screen transitions clear the active TextView. Transient plaintext bytes and CEK are wiped in `withVerifiedContent`, and caller-owned preview chars are zeroed on success/error or lifecycle discard; Android's internal `String`/TextView copies are best-effort erased from view but cannot promise memory erasure against process compromise.
- **No automatic trust:** `TrustedContentGrantProvider` still has **no implementation** in the app; the blocked state is the actual shipped user behavior until a separate authenticated provisioning/revocation/CEK flow is approved. The app does not use the server's response or a user-entered value as a public-key pin. No Android Keystore, physical device evidence, usable protected download/export, or persistent plaintext cache is claimed. This combined draft is stacked on #275 (#272→#268→#267→#261), and incorporates #273 paging behavior without modifying either independently approved sibling PR.
- **Strict JSON boundary:** `StrictRfc8259Json` validates the bounded UTF-8 response *before* the Android `JSONObject` parser. Unlike desktop `org.json`, AOSP `JSONTokener` can overwrite duplicate object keys and accept comments, unquoted keys or alternative separators; the independent syntax gate rejects these, including duplicate aliases encoded with `\\u` escapes at nested levels. This hardens the untrusted ciphertext transport but is not an independent Ed25519 signing pin, trusted CEK provisioning, Android emulator run or released device feature.
- The app-JVM tests use a real captured Node `GET /sync/v1/objects/:id` response and an injectable `HttpsURLConnection` fixture to verify URL/header/HTTP/size/parser/permission/trust boundaries without connecting to the user's server. These do not establish emulator or physical-device compatibility, nor certificate-chain behavior on a real network.
- **Platform gate:** the JVM test environment provides Ed25519 through JDK 17. Android API 29 provider availability/behavior remains unverified; missing Ed25519 or AES/GCM is rejected by the core. Instrumented minimum-API and physical-device tests are required before app integration, with no fallback to server-supplied public keys.
- The native screen sends `POST /auth/login` and `POST /auth/login/2fa` to a strictly validated HTTPS origin and handles authenticated, TOTP challenge, mandatory 2FA-enrollment and generic error states. It disables redirects and caching, bounds responses, clears sensitive UI fields, drops sessions on backgrounding, disables view-state saving, and retains session data only in process memory. Enrollment itself still requires the web client.
- **Combined pagination + gated viewer:** after login with explicit `listFiles: true`, the native UI calls only `GET /sync/v1/objects?view=metadata&limit=64[&cursor=...]` for inventory browsing, validates protocol-v2 `view`, bounded JSON (128 KiB, strict UTF-8/RFC8259, 64 items), metadata shapes and cursor, and keeps one page in the UI. Selecting a live row passes only its validated opaque `objectId` to the #275 protected-content gate. The locked view can return to the same page; a 401 discards the local login, 403 denies listing, and 409 prompts a fresh snapshot instead of mixing cursors. No unbounded ciphertext-bearing legacy GET is used for inventory. The server independently enforces `listFiles` on every request.
- **Required separate backend dependency:** the metadata-only paginated endpoint belongs to PR #255 (tested exact SHA `3ccf955874271546b61ecac09d77227612d330fe`), which is *not* an ancestor of either #273 or #275. This app must not be deployed expecting pagination until the approved backend capability exists; it fails closed if only the legacy endpoint is present. Hosted Node regression tests check out the pinned server into a disposable worktree and exercise real signed-store HTTP 130 objects, 401/403, cross-account and 409 changed cursor. App JVM tests consume the captured metadata-only HTTP bodies and exercise native adapter parsing, 401/403/409 and selection into the default locked viewer. These prove no Android-device behavior.
- The native UI still lacks **trusted key provisioning, key enrollment/revocation delivery, offline copies, protected metadata protocol, recovery and sync writes**. Metadata names and paths are **currently server visible**; this is *not* a fully zero-knowledge Android release. No physical-device/emulator HTTPS behavior has been validated.
