package dev.rootark.android

import android.annotation.TargetApi
import android.os.Build
import android.security.keystore.KeyProperties
import dev.rootark.core.sync.IndependentOfflineOwnerPin
import dev.rootark.core.sync.OwnerOfflineFloorStore
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.json.JSONArray
import org.json.JSONObject
import java.nio.file.Files
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.spec.SecretKeySpec

@TargetApi(Build.VERSION_CODES.S)
class OwnerEnrollmentSecurityPolicyTest {
    @Test
    fun fingerprintResumeNeedsSameAccountOriginAndFreshMonotonicWindow() {
        val at = 10_000L
        fun allows(now: Long, origin: String, user: String) =
            OwnerFingerprintResumePolicy.canResume(at, now, "https://files.example.org", "alice", origin, user)
        assertTrue(allows(at + 1, "https://files.example.org", "alice"))
        assertTrue(allows(at + 300_000, "https://files.example.org", "alice"))
        assertFalse(allows(at + 300_001, "https://files.example.org", "alice"))
        assertFalse(allows(at - 1, "https://files.example.org", "alice"))
        assertFalse(allows(at + 1, "https://evil.example.org", "alice"))
        assertFalse(allows(at + 1, "https://files.example.org", "Alice"))
        assertFalse(OwnerFingerprintResumePolicy.canResume(0L, at, "https://files.example.org", "alice",
            "https://files.example.org", "alice"))
        assertFalse(OwnerFingerprintResumePolicy.canResume(at, at + 1, null, "alice",
            "https://files.example.org", "alice"))
    }

    @Test
    fun credentialResumeRequiresFreshExactAccountAndBoundedHardwareWindow() {
        val start = 100_000L
        fun approved(now: Long, origin: String, username: String) =
            OwnerCredentialResumePolicy.canResume(
                start, now, "https://files.example.org", "alice", origin, username,
            )
        assertTrue(approved(start + 1, "https://files.example.org", "alice"))
        assertTrue(approved(start + 25_000, "https://files.example.org", "alice"))
        assertFalse(approved(start + 25_001, "https://files.example.org", "alice"))
        assertFalse(approved(start - 1, "https://files.example.org", "alice"))
        assertFalse(approved(start + 1, "https://evil.example.org", "alice"))
        assertFalse(approved(start + 1, "https://files.example.org", "Alice"))
        assertFalse(OwnerCredentialResumePolicy.canResume(0, start,
            "https://files.example.org", "alice", "https://files.example.org", "alice"))
    }

    @Test
    fun provisionalHardwareFloorCannotRetireTheLastEnrolledRevision() {
        assertEquals(OwnerFloorRetirementPolicy.PROVISIONAL_ROLLBACK,
            OwnerFloorRetirementPolicy.afterOperation(floorSealed = false, enrollmentSaved = false))
        assertEquals(OwnerFloorRetirementPolicy.PRESERVE_PRIOR_FOR_RECOVERY,
            OwnerFloorRetirementPolicy.afterOperation(floorSealed = true, enrollmentSaved = false))
        assertEquals(OwnerFloorRetirementPolicy.RETIRE_PRIOR,
            OwnerFloorRetirementPolicy.afterOperation(floorSealed = true, enrollmentSaved = true))
        assertEquals(OwnerFloorRetirementPolicy.PROVISIONAL_ROLLBACK,
            OwnerFloorRetirementPolicy.afterOperation(floorSealed = false, enrollmentSaved = true))
    }

    @Test
    fun attemptedFloorSealMustPreserveHardwareAliasesEvenWhenSealCallbackNeverArrives() {
        // A rename may be durable even when the directory fsync or callback
        // throws. Absence of the completion callback is not proof of rollback.
        assertEquals(OwnerFloorRetirementPolicy.PRESERVE_PRIOR_FOR_RECOVERY,
            OwnerFloorRetirementPolicy.afterOperation(
                floorSealed = false, enrollmentSaved = false, floorAdvanceAttempted = true))
        assertEquals(OwnerFloorRetirementPolicy.PROVISIONAL_ROLLBACK,
            OwnerFloorRetirementPolicy.afterOperation(
                floorSealed = false, enrollmentSaved = false, floorAdvanceAttempted = false))
    }

    @Test
    fun floorStoreReportsAttemptBeforeItCanMutatePersistentFloor() {
        val root = Files.createTempDirectory("owner-floor-attempt").toFile()
        val attempted = AtomicBoolean(false)
        try {
            val store = OwnerOfflineFloorStore(
                root, SecretKeySpec(ByteArray(32) { 1 }, "AES"),
                allowFirstWrite = true,
                onAdvanceAttempted = { attempted.set(true) },
            )
            // Invalid input causes advance() to fail. Even this failed entry
            // into advanceAndUse must be conservatively reported to the owner
            // of the hardware alias rather than assumed safe for deletion.
            assertThrows(Exception::class.java) {
                store.advance(
                    IndependentOfflineOwnerPin(
                        "https://files.example.org", "alice", "p256:reader",
                        ByteArray(44) { 1 }, ByteArray(32) { 2 }, 1L,
                        Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 3 }),
                    ), 1L, "digest", 0L,
                )
            }
            assertTrue(attempted.get())
        } finally { root.deleteRecursively() }
    }

    @Test
    fun interruptedRenameBeforeSealCallbackMustNotAuthorizeHardwareAliasRetirement() {
        val root = Files.createTempDirectory("owner-floor-rename-fault").toFile()
        val attempted = AtomicBoolean(false)
        val sealed = AtomicBoolean(false)
        val digest = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(ByteArray(32) { 3 })
        val pin = IndependentOfflineOwnerPin(
            "https://files.example.org", "alice", "p256:reader",
            ByteArray(44) { 1 }, ByteArray(32) { 2 }, 1L, digest,
        )
        try {
            val store = OwnerOfflineFloorStore(
                root, SecretKeySpec(ByteArray(32) { 7 }, "AES"),
                allowFirstWrite = true,
                onAdvanceAttempted = { attempted.set(true) },
                onSealedFloor = { sealed.set(true) },
                afterFloorRename = { throw java.io.IOException("synthetic post-rename interruption") },
            )
            assertThrows(Exception::class.java) {
                store.advance(pin, 1L, digest, 1_800_000_000_000L)
            }
            assertTrue(attempted.get())
            assertFalse("Completion callback cannot be treated as proof of no rename", sealed.get())
            assertTrue("Atomic rename already installed a new sealed-file candidate",
                root.resolve("owner-floor-v1.bin").isFile)
            assertEquals(OwnerFloorRetirementPolicy.PRESERVE_PRIOR_FOR_RECOVERY,
                OwnerFloorRetirementPolicy.afterOperation(false, false, attempted.get()))
        } finally { root.deleteRecursively() }
    }

    @Test
    fun interruptedImportKeepsPriorEnrollmentAndDurableRecoveryMarkerUntilConfirmedSave() {
        val root = Files.createTempDirectory("owner-enrollment-recovery").toFile()
        val ownerSpki = ByteArray(44) { (it + 1).toByte() }
        val ownerHash = MessageDigest.getInstance("SHA-256").digest(ownerSpki)
        val previous = IndependentOfflineOwnerPin(
            "https://files.example.org", "alice", "p256:reader",
            ownerSpki, ownerHash, 1L,
            Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 1 }),
        )
        val next = previous.copy(
            exactRevision = 2L,
            exactDigest = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 2 }),
        )
        try {
            val oldPackage = "{\"signed\":\"old\"}".toByteArray()
            val signedCandidate = "{\"signed\":\"new\"}".toByteArray()
            val store = OwnerEnrollmentStore(root)
            store.save(previous, oldPackage, ecdhCapabilityVerified = true)
            assertFalse(store.hasPending())
            // Prepare before any hardware mutation. A process death before
            // the seal must NOT replace the previously committed enrollment.
            store.stage(next, signedCandidate, ecdhCapabilityVerified = true)
            val restarted = OwnerEnrollmentStore(root)
            assertTrue(restarted.hasPending())
            // An interrupted operation keeps its durable revision and identity
            // constraints across reopening, until a compatible retry commits.
            assertThrows(SecurityException::class.java) {
                restarted.stage(previous, oldPackage, ecdhCapabilityVerified = true)
            }
            assertThrows(SecurityException::class.java) {
                restarted.stage(next.copy(exactDigest = previous.exactDigest), signedCandidate,
                    ecdhCapabilityVerified = true)
            }
            assertTrue(restarted.hasPending())
            restarted.stage(next, signedCandidate, ecdhCapabilityVerified = true)
            val priorAfterCrash = restarted.load()!!
            assertEquals(1L, priorAfterCrash.pin.exactRevision)
            assertArrayEquals(oldPackage, priorAfterCrash.packageBytes)
            priorAfterCrash.pin.ownerPublicSpki.fill(0)
            priorAfterCrash.pin.ownerPublicSpkiSha256.fill(0)
            priorAfterCrash.packageBytes.fill(0)
            // A sealed floor WITHOUT a completed save must retain the marker.
            assertEquals(OwnerFloorRetirementPolicy.PRESERVE_PRIOR_FOR_RECOVERY,
                OwnerFloorRetirementPolicy.afterOperation(true, false))
            assertTrue(restarted.hasPending())
            // Only an explicit successful save and durable clear completes it.
            restarted.save(next, signedCandidate, ecdhCapabilityVerified = true)
            assertTrue(restarted.hasPending())
            restarted.clearPending()
            assertFalse(OwnerEnrollmentStore(root).hasPending())
            val committed = OwnerEnrollmentStore(root).load()!!
            assertEquals(2L, committed.pin.exactRevision)
            assertArrayEquals(signedCandidate, committed.packageBytes)
            committed.pin.ownerPublicSpki.fill(0)
            committed.pin.ownerPublicSpkiSha256.fill(0)
            committed.packageBytes.fill(0)
            oldPackage.fill(0)
            signedCandidate.fill(0)
        } finally {
            ownerSpki.fill(0)
            ownerHash.fill(0)
            root.deleteRecursively()
        }
    }

    @Test
    fun availabilityCheckNeverBlocksTheUiOnAnotherOwnerFloorOperation() {
        // MainActivity checks provider.isAvailable on its UI thread. A secured
        // background read intentionally holds this index lock through fetch
        // and plaintext consumption, so an availability *hint* must fail closed
        // instead of waiting for that remote operation and causing an ANR.
        val root = Files.createTempDirectory("owner-floor-ui-lock").toFile()
        val gate = OwnerOfflineHardwareFloor::class.java.getDeclaredField("processIndexLock")
            .apply { isAccessible = true }
            .get(OwnerOfflineHardwareFloor) as ReentrantLock
        val held = CountDownLatch(1)
        val release = CountDownLatch(1)
        val locker = Thread {
            gate.lock()
            try { held.countDown(); release.await(5, TimeUnit.SECONDS) }
            finally { gate.unlock() }
        }
        val executor = Executors.newSingleThreadExecutor()
        try {
            locker.start()
            assertTrue(held.await(3, TimeUnit.SECONDS))
            val result = executor.submit<Boolean> {
                OwnerOfflineHardwareFloor.isAvailable(
                    root, 1L, Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(ByteArray(32) { 1 }), 1_800_000_000_000L,
                )
            }
            assertFalse("UI availability must fail closed without waiting for a held hardware-floor lock",
                result.get(300, TimeUnit.MILLISECONDS))
        } finally {
            release.countDown()
            locker.join(3000)
            executor.shutdownNow()
            root.deleteRecursively()
        }
    }

    @Test
    fun softwareBackedInstallationKeyIsRefused() {
        val softwareKey = AndroidKeySecurityEvidence(
            securityLevel = KeyProperties.SECURITY_LEVEL_SOFTWARE,
            insideSecureHardware = false,
            userAuthenticationRequired = true,
            userAuthenticationType = KeyProperties.AUTH_DEVICE_CREDENTIAL,
            authenticationValiditySeconds = AndroidInstallationKey.AUTH_WINDOW_SECONDS,
            authenticationEnforcedBySecureHardware = false,
            purposes = KeyProperties.PURPOSE_AGREE_KEY,
            origin = KeyProperties.ORIGIN_GENERATED,
        )
        assertThrows(IllegalStateException::class.java) {
            AndroidKeySecurityPolicy.requireHardwareDeviceCredentialKey(
                softwareKey, KeyProperties.PURPOSE_AGREE_KEY,
            )
        }
    }

    @Test
    fun hardwareKeyMustRequireSecureDeviceCredentialForAgreement() {
        val hardwareKey = AndroidKeySecurityEvidence(
            securityLevel = KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
            insideSecureHardware = true,
            userAuthenticationRequired = true,
            userAuthenticationType = KeyProperties.AUTH_DEVICE_CREDENTIAL,
            authenticationValiditySeconds = AndroidInstallationKey.AUTH_WINDOW_SECONDS,
            authenticationEnforcedBySecureHardware = true,
            purposes = KeyProperties.PURPOSE_AGREE_KEY,
            origin = KeyProperties.ORIGIN_GENERATED,
        )
        AndroidKeySecurityPolicy.requireHardwareDeviceCredentialKey(
            hardwareKey, KeyProperties.PURPOSE_AGREE_KEY,
        )
        assertThrows(IllegalStateException::class.java) {
            AndroidKeySecurityPolicy.requireHardwareDeviceCredentialKey(
                hardwareKey.copy(userAuthenticationRequired = false), KeyProperties.PURPOSE_AGREE_KEY,
            )
        }
    }

    @Test
    fun providerRemainsDisabledUntilHardwareEcdhCapabilityIsVerifiedForPinnedAccount() {
        assertFalse(OwnerEnrollmentCapabilityPolicy.isEnabled(false, true, true))
        assertFalse(OwnerEnrollmentCapabilityPolicy.isEnabled(true, false, true))
        assertFalse(OwnerEnrollmentCapabilityPolicy.isEnabled(true, true, false))
        assertTrue(OwnerEnrollmentCapabilityPolicy.isEnabled(true, true, true))
    }

    @Test
    fun protectedViewerStaysLockedWithoutFreshOwnerGrant() {
        val provider = object : TrustedContentGrantProvider {
            override fun obtain(username: String, objectId: String): ProtectedContentGrant? = null
            override fun isAvailable(username: String, objectId: String): Boolean = false
        }
        val preview = VerifiedTextPreview(provider)
        assertFalse(preview.isAvailable("alice", "object-1"))
    }

    @Test
    fun strictOwnerPackageParserAcceptsExactV2ShapeAndRejectsDuplicateOrUnknownFields() {
        val head = JSONObject()
            .put("schema", "rootark-android-owner-head/v2")
            .put("origin", "https://files.example.org")
            .put("username", "alice")
            .put("readerDeviceId", "p256:test")
            .put("ownerRevision", 1L)
            .put("ownerDigest", "digest")
            .put("revokedDeviceIds", JSONArray())
            .put("issuedAtMillis", 1_800_000_000_000L)
            .put("expiresAtMillis", 1_800_000_300_000L)
            .put("signature", "signature")
        val grant = JSONObject()
            .put("schema", "rootark-android-cek-read-hpke/v2")
            .put("origin", "https://files.example.org")
            .put("username", "alice")
            .put("readerDeviceId", "p256:test")
            .put("ownerRevision", 1L)
            .put("ownerDigest", "digest")
            .put("objectId", "object-1")
            .put("fileId", "file-1")
            .put("versionId", "version-1")
            .put("compartmentId", "compartment-1")
            .put("keyEpoch", "epoch-1")
            .put("signerDeviceId", "signer-1")
            .put("signerPublicKeySpki", "signer-spki")
            .put("cekSha256", "cek-hash")
            .put("nonce", "nonce")
            .put("issuedAtMillis", 1_800_000_000_000L)
            .put("expiresAtMillis", 1_800_000_240_000L)
            .put("hpkeSuite", "DHKEM(P-256,HKDF-SHA256)/HKDF-SHA256/AES-256-GCM")
            .put("enc", "enc")
            .put("wrappedCek", "wrapped")
            .put("signature", "signature")
        val valid = JSONObject()
            .put("schema", "rootark-android-enrollment-package/v2")
            .put("ownerPublicSpki", "owner-spki")
            .put("head", head)
            .put("grant", grant)
        val parsed = OwnerEnrollmentPackageJson.parse(valid.toString().toByteArray(Charsets.UTF_8))
        assertEquals("alice", parsed.head.username)
        assertEquals("object-1", parsed.grant.objectId)
        assertThrows(Exception::class.java) {
            OwnerEnrollmentPackageJson.parse((valid.toString().dropLast(1) + ",\"extra\":true}").toByteArray())
        }
        assertThrows(Exception::class.java) {
            OwnerEnrollmentPackageJson.parse(
                "{\"schema\":\"one\",\"schema\":\"two\",\"ownerPublicSpki\":\"x\",\"head\":{},\"grant\":{}}".toByteArray(),
            )
        }
    }

    @Test
    fun ownerPinAndWrappedPackageRoundTripThroughNoBackupStore() {
        val root = Files.createTempDirectory("owner-enrollment-store").toFile()
        try {
            val store = OwnerEnrollmentStore(root)
            assertNull(store.load())
            val ownerSpki = ByteArray(44) { (it + 1).toByte() }
            val ownerHash = MessageDigest.getInstance("SHA-256").digest(ownerSpki)
            val pin = IndependentOfflineOwnerPin(
                "https://files.example.org", "alice", "p256:reader", ownerSpki, ownerHash,
                1, Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 7 }),
            )
            val packageBytes = "{\"ownerSigned\":true}".toByteArray()
            store.save(pin, packageBytes)
            val restored = store.load()!!
            assertEquals(pin.origin, restored.pin.origin)
            assertEquals(pin.username, restored.pin.username)
            assertEquals(pin.readerDeviceId, restored.pin.readerDeviceId)
            assertArrayEquals(ownerSpki, restored.pin.ownerPublicSpki)
            assertArrayEquals(ownerHash, restored.pin.ownerPublicSpkiSha256)
            assertArrayEquals(packageBytes, restored.packageBytes)
            assertFalse(restored.ecdhCapabilityVerified)
            store.save(pin, packageBytes, ecdhCapabilityVerified = true)
            val capabilityVerified = store.load()!!
            assertTrue(capabilityVerified.ecdhCapabilityVerified)
            capabilityVerified.pin.ownerPublicSpki.fill(0)
            capabilityVerified.pin.ownerPublicSpkiSha256.fill(0)
            capabilityVerified.packageBytes.fill(0)
            restored.pin.ownerPublicSpki.fill(0)
            restored.pin.ownerPublicSpkiSha256.fill(0)
            restored.packageBytes.fill(0)
            ownerSpki.fill(0)
            ownerHash.fill(0)
        } finally {
            root.deleteRecursively()
        }
    }
}
