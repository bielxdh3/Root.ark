package dev.rootark.core.sync

import java.io.Closeable
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.OpenOption
import java.nio.file.StandardOpenOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir

class OwnerPinnedOfflineAdmissionTest {
    @TempDir lateinit var root: Path
    private val fixture: JSONObject get() {
        val input = javaClass.getResourceAsStream("/owner-pinned-grant.json")
            ?: error("Node signed fixture missing")
        return JSONObject(input.bufferedReader().use { it.readText() })
    }
    private fun bytes(value: String) = Base64.getUrlDecoder().decode(value)
    private fun pin(json: JSONObject = fixture.getJSONObject("anchor")) = IndependentOfflineOwnerPin(
        json.getString("origin"), json.getString("username"), json.getString("readerDeviceId"),
        bytes(json.getString("ownerPublicSpki")), bytes(json.getString("ownerPublicSpkiSha256")),
        json.getLong("ownerRevision"), json.getString("ownerDigest"),
    )
    private fun head(json: JSONObject = fixture.getJSONObject("head")) = OwnerSignedOfflineHead(
        json.getString("schema"), json.getString("origin"), json.getString("username"),
        json.getString("readerDeviceId"), json.getLong("ownerRevision"), json.getString("ownerDigest"),
        json.getJSONArray("revokedDeviceIds").let { array ->
            (0 until array.length()).map { array.getString(it) }
        }, json.getLong("issuedAtMillis"), json.getLong("expiresAtMillis"),
        json.getString("signature"),
    )
    private fun grant(json: JSONObject = fixture.getJSONObject("grant")) =
        OwnerSignedOfflineCekGrant(
            json.getString("schema"), json.getString("origin"), json.getString("username"),
            json.getString("readerDeviceId"), json.getLong("ownerRevision"), json.getString("ownerDigest"),
            json.getString("objectId"), json.getString("fileId"), json.getString("versionId"),
            json.getString("compartmentId"), json.getString("keyEpoch"), json.getString("signerDeviceId"),
            json.getString("signerPublicKeySpki"), json.getString("cekSha256"),
            json.getString("nonce"), json.getLong("issuedAtMillis"),
            json.getLong("expiresAtMillis"), json.getString("signature"),
        )
    private fun cek() = ByteArray(32) { (it + 1).toByte() }
    private fun key() = SecretKeySpec(ByteArray(32) { (it + 12).toByte() }, "AES")
    private val at = 1_700_000_000_001L

    @Test fun ownerSignedGrantBindsExactKeyAndClearsBytes() {
        val input = cek()
        val result = OwnerPinnedOfflineAdmission.withAuthorizedCek(
            grant(), head(), pin(), input,
            OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true), at,
        ) { context, secret ->
            assertEquals("offline-owner", context.username)
            assertEquals("item-id-001", context.objectId)
            assertEquals("epoch-2", context.keyEpoch)
            assertEquals(setOf("issuer-001"), context.trustedDevicePublicKeys.keys)
            assertEquals(1_700_000_090_000L, context.snapshotValidUntilMillis)
            assertTrue(secret.contentEquals(cek()))
            context.fileId
        }
        assertEquals("file-id-001", result)
        assertTrue(input.all { it == 0.toByte() })
        assertTrue(root.resolve("owner-floor-v1.bin").toFile().isFile)
    }

    @Test fun revocationAndClockFloorPersistAcrossRestart() {
        val old = pin()
        val store = OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true)
        OwnerPinnedOfflineAdmission.observeHead(head(), old, store, at)
        val revoked = head(fixture.getJSONObject("revoked"))
        val current = old.copy(exactRevision = revoked.ownerRevision, exactDigest = revoked.ownerDigest)
        OwnerPinnedOfflineAdmission.observeHead(revoked, current, store, at + 1000)
        val restarted = OwnerOfflineFloorStore(root.toFile(), key())
        for (time in listOf(at - 2000, at + 2000)) {
            val secret = cek()
            assertThrows(ProtectedSyncException::class.java) {
                OwnerPinnedOfflineAdmission.withAuthorizedCek(
                    grant(), head(), old, secret, restarted, time,
                ) { _, _ -> error("stale grant was accepted") }
            }
            assertTrue(secret.all { it == 0.toByte() })
        }
    }

    @Test fun currentOwnerSignedRevocationDeniesAnOtherwiseValidCurrentCekGrant() {
        val signedRevocation = head(fixture.getJSONObject("revoked"))
        val newerGrant = grant(fixture.getJSONObject("revokedGrant"))
        val current = pin().copy(exactRevision = signedRevocation.ownerRevision,
            exactDigest = signedRevocation.ownerDigest)
        val bytes = cek()
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.withAuthorizedCek(
                newerGrant, signedRevocation, current, bytes,
                OwnerOfflineFloorStore(root.toFile(), key()), at,
            ) { _, _ -> error("owner-revoked reader/issuer was admitted") }
        }
        assertTrue(bytes.all { it == 0.toByte() })
    }

    @Test fun revokedSignedGrantPersistsNewerOwnerFloorBeforeDenialAcrossRestart() {
        val olderHead = head()
        val olderGrant = grant()
        val olderPin = pin()
        val initialCek = cek()
        OwnerPinnedOfflineAdmission.withAuthorizedCek(olderGrant, olderHead, olderPin,
            initialCek, OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true), at,
        ) { _, _ -> Unit }
        assertTrue(initialCek.all { it == 0.toByte() })

        val revoked = head(fixture.getJSONObject("revoked"))
        val revokedGrant = grant(fixture.getJSONObject("revokedGrant"))
        val newerPin = olderPin.copy(exactRevision = revoked.ownerRevision,
            exactDigest = revoked.ownerDigest)
        val revokedCek = cek()
        var invoked = false
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.withAuthorizedCek(revokedGrant, revoked, newerPin,
                revokedCek, OwnerOfflineFloorStore(root.toFile(), key()), at + 1000,
            ) { _, _ -> invoked = true }
        }
        assertTrue(!invoked && revokedCek.all { it == 0.toByte() },
            "revoked grant must not consume or retain caller CEK")

        // The newer owner head was signed and independently pinned, so its
        // revocation MUST survive even when the accompanying grant is denied.
        val replayCek = cek()
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.withAuthorizedCek(olderGrant, olderHead, olderPin,
                replayCek, OwnerOfflineFloorStore(root.toFile(), key()), at + 2000,
            ) { _, _ -> invoked = true }
        }
        assertTrue(!invoked && replayCek.all { it == 0.toByte() },
            "restarted reader must not replay the pre-revocation head and grant")

        // Explicit observeHead and repeated observation at the same revision
        // remain idempotent; neither path can lower the established floor.
        OwnerPinnedOfflineAdmission.observeHead(revoked, newerPin,
            OwnerOfflineFloorStore(root.toFile(), key()), at + 3000)
        OwnerPinnedOfflineAdmission.observeHead(revoked, newerPin,
            OwnerOfflineFloorStore(root.toFile(), key()), at + 4000)
        val duplicateCek = cek()
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.withAuthorizedCek(revokedGrant, revoked, newerPin,
                duplicateCek, OwnerOfflineFloorStore(root.toFile(), key()), at + 5000,
            ) { _, _ -> invoked = true }
        }
        assertTrue(!invoked && duplicateCek.all { it == 0.toByte() })
    }

    @Test fun newerRevocationCannotCommitWhileEarlierCekConsumerIsRunning() {
        val oldPin = pin()
        val revokedHead = head(fixture.getJSONObject("revoked"))
        val newerPin = oldPin.copy(exactRevision = revokedHead.ownerRevision,
            exactDigest = revokedHead.ownerDigest)
        OwnerPinnedOfflineAdmission.observeHead(head(), oldPin,
            OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true), at)

        val callbackEntered = CountDownLatch(1)
        val revocationAttemptFinished = CountDownLatch(1)
        val workers = Executors.newFixedThreadPool(2)
        val input = cek()
        try {
            // Two separate store instances use the REAL OS FileLock. Thread A
            // pauses inside the synchronous callback, before consuming CEK;
            // thread B attempts to persist a genuine signed revoked head.
            val reader = workers.submit<Boolean> {
                OwnerPinnedOfflineAdmission.withAuthorizedCek(grant(), head(), oldPin,
                    input, OwnerOfflineFloorStore(root.toFile(), key()), at + 1000) { _, secret ->
                    callbackEntered.countDown()
                    assertTrue(revocationAttemptFinished.await(10, TimeUnit.SECONDS),
                        "revocation contender must reach the same floor while callback is active")
                    assertTrue(secret.contentEquals(cek()))
                    true
                }
            }
            val revocation = workers.submit<Boolean> {
                assertTrue(callbackEntered.await(10, TimeUnit.SECONDS))
                try {
                    OwnerPinnedOfflineAdmission.observeHead(revokedHead, newerPin,
                        OwnerOfflineFloorStore(root.toFile(), key()), at + 2000)
                    true
                } catch (_: ProtectedSyncException) {
                    false
                } finally {
                    revocationAttemptFinished.countDown()
                }
            }
            assertTrue(reader.get(15, TimeUnit.SECONDS))
            assertTrue(!revocation.get(15, TimeUnit.SECONDS),
                "revocation must not commit between authorization and CEK consumption")
            assertTrue(input.all { it == 0.toByte() })
        } finally {
            workers.shutdownNow()
            assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS))
        }

        // After thread A finishes, the revoked signed head can durably advance;
        // an old grant cannot be replayed after the serialization point.
        OwnerPinnedOfflineAdmission.observeHead(revokedHead, newerPin,
            OwnerOfflineFloorStore(root.toFile(), key()), at + 3000)
        val replay = cek()
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.withAuthorizedCek(grant(), head(), oldPin,
                replay, OwnerOfflineFloorStore(root.toFile(), key()), at + 4000) {
                _, _ -> error("revoked floor replayed")
            }
        }
        assertTrue(replay.all { it == 0.toByte() })
    }

    @Test fun reentrantOwnerFloorObservationInsideConsumerFailsClosedAndWipesCek() {
        val currentPin = pin()
        val sameStore = OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true)
        val secret = cek()
        var nestedSucceeded = false
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.withAuthorizedCek(grant(), head(), currentPin,
                secret, sameStore, at) { _, _ ->
                OwnerPinnedOfflineAdmission.observeHead(head(), currentPin, sameStore, at + 1000)
                nestedSucceeded = true
            }
        }
        assertTrue(!nestedSucceeded && secret.all { it == 0.toByte() },
            "reentrant OS FileLock must reject and wipe the caller's CEK")
        // The outer transaction must still have persisted the signed head.
        OwnerPinnedOfflineAdmission.observeHead(head(), currentPin,
            OwnerOfflineFloorStore(root.toFile(), key()), at + 2000)
    }

    @Test fun forgedUnsignedOrUnpinnedNewerHeadCannotPoisonPriorAuthorizedFloor() {
        val olderHead = head()
        val olderGrant = grant()
        val olderPin = pin()
        OwnerPinnedOfflineAdmission.observeHead(olderHead, olderPin,
            OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true), at)
        val revoked = head(fixture.getJSONObject("revoked"))
        val revokedGrant = grant(fixture.getJSONObject("revokedGrant"))
        val newerPin = olderPin.copy(exactRevision = revoked.ownerRevision,
            exactDigest = revoked.ownerDigest)
        for ((candidateHead, candidatePin) in listOf(
            revoked.copy(signature = "") to newerPin,
            revoked.copy(revokedDeviceIds = emptyList()) to newerPin,
            revoked to olderPin,
        )) {
            val attemptedCek = cek()
            assertThrows(ProtectedSyncException::class.java) {
                OwnerPinnedOfflineAdmission.withAuthorizedCek(
                    revokedGrant, candidateHead, candidatePin, attemptedCek,
                    OwnerOfflineFloorStore(root.toFile(), key()), at + 1000,
                ) { _, _ -> error("unauthorized head released CEK") }
            }
            assertTrue(attemptedCek.all { it == 0.toByte() })
        }
        val validCek = cek()
        var accepted = false
        OwnerPinnedOfflineAdmission.withAuthorizedCek(olderGrant, olderHead, olderPin,
            validCek, OwnerOfflineFloorStore(root.toFile(), key()), at + 2000,
        ) { _, _ -> accepted = true }
        assertTrue(accepted && validCek.all { it == 0.toByte() },
            "invalid newer heads must never poison the earlier valid owner floor")
    }

    @Test fun forgedOwnerFieldsAndUnsignedRevocationFailClosed() {
        val fixed = pin()
        val authorized = grant()
        val signedHead = head()
        val mutations = listOf(
            authorized.copy(readerDeviceId = "other-device"),
            authorized.copy(objectId = "another-object"),
            authorized.copy(keyEpoch = "epoch-3"),
            authorized.copy(cekSha256 = fixed.exactDigest),
            authorized.copy(signerPublicKeySpki = Base64.getUrlEncoder()
                .withoutPadding().encodeToString(fixed.ownerPublicSpki)),
        )
        for (mutated in mutations) {
            val secret = cek()
            assertThrows(ProtectedSyncException::class.java) {
                OwnerPinnedOfflineAdmission.withAuthorizedCek(mutated, signedHead, fixed,
                    secret, OwnerOfflineFloorStore(root.toFile(), key()), at) {
                    _, _ -> error("forged grant was accepted")
                }
            }
            assertTrue(secret.all { it == 0.toByte() })
        }
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.observeHead(
                signedHead.copy(revokedDeviceIds = listOf("issuer-001")), fixed,
                OwnerOfflineFloorStore(root.toFile(), key()), at,
            )
        }
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.observeHead(signedHead,
                fixed.copy(ownerPublicSpkiSha256 = ByteArray(32)),
                OwnerOfflineFloorStore(root.toFile(), key()), at)
        }
    }

    @Test fun missingOrChangedKeystoreAndTamperedFloorDenyBeforeKeyUse() {
        val fixed = pin()
        val original = cek()
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.withAuthorizedCek(grant(), head(), fixed, original,
                OwnerOfflineFloorStore(root.toFile(), null), at) {
                _, _ -> error("absent keystore unlocked")
            }
        }
        assertTrue(original.all { it == 0.toByte() })
        OwnerPinnedOfflineAdmission.observeHead(head(), fixed,
            OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true), at)
        val wrong = cek()
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.withAuthorizedCek(grant(), head(), fixed, wrong,
                OwnerOfflineFloorStore(root.toFile(), SecretKeySpec(ByteArray(32), "AES")), at + 1) {
                _, _ -> error("replaced keystore unlocked")
            }
        }
        assertTrue(wrong.all { it == 0.toByte() })
        val sealed = root.resolve("owner-floor-v1.bin").toFile()
        val altered = sealed.readBytes()
        altered[altered.lastIndex] = (altered.last().toInt() xor 1).toByte()
        sealed.writeBytes(altered)
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.withAuthorizedCek(grant(), head(), fixed, cek(),
                OwnerOfflineFloorStore(root.toFile(), key()), at + 1) {
                _, _ -> error("tampered floor unlocked")
            }
        }
    }

    @Test fun expiredSnapshotAndThrownCallbackWipeCek() {
        val grant = grant()
        val current = head()
        val pinned = pin()
        val old = cek()
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.withAuthorizedCek(grant, current, pinned, old,
                OwnerOfflineFloorStore(root.toFile(), key()), at + 130000) {
                _, _ -> error("expired accepted")
            }
        }
        assertTrue(old.all { it == 0.toByte() })
        val secret = cek()
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.withAuthorizedCek(grant, current, pinned, secret,
                OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true), at) {
                _, _ -> throw IllegalArgumentException("never reveal exception details")
            }
        }
        assertTrue(secret.all { it == 0.toByte() })
    }

    @Test fun deletingCommittedFloorCannotBootstrapAnOlderGrantAfterRestart() {
        val originalPin = pin()
        val owner = OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true)
        OwnerPinnedOfflineAdmission.observeHead(head(), originalPin, owner, at)
        val revoked = head(fixture.getJSONObject("revoked"))
        val current = originalPin.copy(exactRevision = revoked.ownerRevision,
            exactDigest = revoked.ownerDigest)
        OwnerPinnedOfflineAdmission.observeHead(revoked, current, owner, at + 1000)
        val sealedFloor = root.resolve("owner-floor-v1.bin").toFile()
        assertTrue(sealedFloor.isFile)
        assertTrue(sealedFloor.delete(), "test attacker removes only sealed floor, preserving key")
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.observeHead(head(), originalPin, owner, at + 2000)
        }
        val bytes = cek()
        var consumed = false
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.withAuthorizedCek(grant(), head(), originalPin,
                bytes, OwnerOfflineFloorStore(root.toFile(), key()), at + 2000) { _, _ ->
                consumed = true
            }
        }
        assertTrue(!consumed, "removed floor released CEK despite stale owner head")
        assertTrue(bytes.all { it == 0.toByte() })
    }

    @Test fun fileLockRejectsBothConcurrentAdmissionInstancesAndRetainsNewestRevision() {
        val old = pin()
        OwnerPinnedOfflineAdmission.observeHead(head(), old,
            OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true), at)
        val revoked = head(fixture.getJSONObject("revoked"))
        val latest = old.copy(exactRevision = revoked.ownerRevision,
            exactDigest = revoked.ownerDigest)
        val older = OwnerOfflineFloorStore(root.toFile(), key())
        val newer = OwnerOfflineFloorStore(root.toFile(), key())
        val executor = Executors.newFixedThreadPool(2)
        val start = CountDownLatch(1)
        try {
            FileChannel.open(root.resolve("owner-floor-v1.lock"),
                StandardOpenOption.CREATE, StandardOpenOption.WRITE).use { channel ->
                channel.lock().use {
                    val oldAttempt = executor.submit<Boolean> {
                        start.await()
                        runCatching {
                            OwnerPinnedOfflineAdmission.observeHead(head(), old, older, at + 2000)
                        }.isFailure
                    }
                    val newAttempt = executor.submit<Boolean> {
                        start.await()
                        runCatching {
                            OwnerPinnedOfflineAdmission.observeHead(revoked, latest, newer, at + 1000)
                        }.isFailure
                    }
                    start.countDown()
                    assertTrue(oldAttempt.get(5, TimeUnit.SECONDS),
                        "stale writer must fail closed while another process owns floor lock")
                    assertTrue(newAttempt.get(5, TimeUnit.SECONDS),
                        "new writer must fail closed while another process owns floor lock")
                }
            }
            OwnerPinnedOfflineAdmission.observeHead(revoked, latest, newer, at + 3000)
            assertThrows(ProtectedSyncException::class.java) {
                OwnerPinnedOfflineAdmission.observeHead(head(), old, older, at + 4000)
            }
        } finally {
            executor.shutdownNow()
        }
    }

    @Test fun invalidPersistentLockPathDeniesBeforeCekConsumption() {
        val pinned = pin()
        OwnerPinnedOfflineAdmission.observeHead(head(), pinned,
            OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true), at)
        val lock = root.resolve("owner-floor-v1.lock").toFile()
        assertTrue(lock.isFile)
        assertTrue(lock.delete(), "disposable lock path must be removable for negative fixture")
        assertTrue(lock.mkdir(), "malicious directory occupies persistent lock path")
        val secret = cek()
        var consumed = false
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.withAuthorizedCek(grant(), head(), pinned, secret,
                OwnerOfflineFloorStore(root.toFile(), key()), at + 1) { _, _ ->
                consumed = true
            }
        }
        assertTrue(!consumed, "invalid lock must not release the CEK")
        assertTrue(secret.all { it == 0.toByte() })
    }

    @Test fun establishedFloorMissingStableLockDeniesAndNeverCreatesAnotherLock() {
        val old = pin()
        OwnerPinnedOfflineAdmission.observeHead(head(), old,
            OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true), at)
        val lock = root.resolve("owner-floor-v1.lock")
        val floor = root.resolve("owner-floor-v1.bin")
        val before = Files.readAllBytes(floor)
        Files.delete(lock)
        val revoked = head(fixture.getJSONObject("revoked"))
        val newer = old.copy(exactRevision = revoked.ownerRevision,
            exactDigest = revoked.ownerDigest)
        val bytes = cek()
        var consumed = false
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.withAuthorizedCek(grant(), head(), old, bytes,
                OwnerOfflineFloorStore(root.toFile(), key()), at + 1000) { _, _ ->
                consumed = true
            }
        }
        assertTrue(!consumed)
        assertTrue(bytes.all { it == 0.toByte() })
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.observeHead(revoked, newer,
                OwnerOfflineFloorStore(root.toFile(), key()), at + 1000)
        }
        assertTrue(!Files.exists(lock, LinkOption.NOFOLLOW_LINKS),
            "existing floor must not silently enroll a new stable-lock inode")
        assertTrue(Files.readAllBytes(floor).contentEquals(before),
            "failed admission must not rewrite an established sealed floor")
    }

    @Test fun twoJavaProcessesCannotTreatReplacedLockInodeAsIndependentFloorAuthority() {
        val original = pin()
        OwnerPinnedOfflineAdmission.observeHead(head(), original,
            OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true), at)
        val lock = root.resolve("owner-floor-v1.lock")
        val floor = root.resolve("owner-floor-v1.bin")
        val before = Files.readAllBytes(floor)
        val ready = root.resolve("held-old-lock.ready")
        val release = root.resolve("held-old-lock.release")
        val java = java.nio.file.Paths.get(System.getProperty("java.home"), "bin", "java")
        val child = ProcessBuilder(java.toString(), "-cp", System.getProperty("java.class.path"),
            "dev.rootark.core.sync.OwnerFloorLockHolderProcess", lock.toString(),
            ready.toString(), release.toString())
            .redirectErrorStream(true).start()
        try {
            val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while (!Files.exists(ready) && child.isAlive && System.nanoTime() < until) {
                Thread.sleep(20)
            }
            assertTrue(Files.exists(ready), "independent Java process failed to hold old fd")
            // The first process now owns a valid exclusive lock on the OLD
            // inode. An attacker removes the pathname and installs a new inode.
            Files.delete(lock)
            Files.write(lock, byteArrayOf(0x31), StandardOpenOption.CREATE_NEW)
            val revoked = head(fixture.getJSONObject("revoked"))
            val latest = original.copy(exactRevision = revoked.ownerRevision,
                exactDigest = revoked.ownerDigest)
            val bytes = cek()
            var consumed = false
            assertThrows(ProtectedSyncException::class.java) {
                OwnerPinnedOfflineAdmission.withAuthorizedCek(grant(), head(), original,
                    bytes, OwnerOfflineFloorStore(root.toFile(), key()), at + 1500) { _, _ ->
                    consumed = true
                }
            }
            assertTrue(!consumed)
            assertTrue(bytes.all { it == 0.toByte() })
            assertThrows(ProtectedSyncException::class.java) {
                OwnerPinnedOfflineAdmission.observeHead(revoked, latest,
                    OwnerOfflineFloorStore(root.toFile(), key()), at + 2000)
            }
            assertTrue(Files.readAllBytes(floor).contentEquals(before),
                "a second process cannot overwrite the floor while old fd remains locked")
        } finally {
            Files.writeString(release, "release")
            if (!child.waitFor(5, TimeUnit.SECONDS)) child.destroyForcibly()
            assertTrue(!child.isAlive, "left a Java lock-holder process running")
        }
    }

    @Test fun crashedLockHolderReleasesSameInodeAndPermitsFreshSignedHeadAfterRestart() {
        val old = pin()
        OwnerPinnedOfflineAdmission.observeHead(head(), old,
            OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true), at)
        val ready = root.resolve("holder-crash.ready")
        val release = root.resolve("holder-crash.release")
        val java = java.nio.file.Paths.get(System.getProperty("java.home"), "bin", "java")
        val child = ProcessBuilder(java.toString(), "-cp", System.getProperty("java.class.path"),
            "dev.rootark.core.sync.OwnerFloorLockHolderProcess",
            root.resolve("owner-floor-v1.lock").toString(), ready.toString(), release.toString())
            .redirectErrorStream(true).start()
        try {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while (!Files.exists(ready) && child.isAlive && System.nanoTime() < deadline)
                Thread.sleep(20)
            assertTrue(Files.exists(ready), "separate Java lock-holder never acquired file")
            assertThrows(ProtectedSyncException::class.java) {
                OwnerPinnedOfflineAdmission.observeHead(head(), old,
                    OwnerOfflineFloorStore(root.toFile(), key()), at + 1000)
            }
        } finally {
            // Abrupt termination closes the OS file descriptor and releases
            // the lock without removing its already-established pathname.
            child.destroyForcibly()
            assertTrue(child.waitFor(5, TimeUnit.SECONDS))
        }
        val revoked = head(fixture.getJSONObject("revoked"))
        val newer = old.copy(exactRevision = revoked.ownerRevision,
            exactDigest = revoked.ownerDigest)
        OwnerPinnedOfflineAdmission.observeHead(revoked, newer,
            OwnerOfflineFloorStore(root.toFile(), key()), at + 2000)
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.observeHead(head(), old,
                OwnerOfflineFloorStore(root.toFile(), key()), at + 3000)
        }
    }

    @Test fun firstEnrollmentRefusesPreexistingOrphanLockOrDanglingSymlink() {
        val lock = root.resolve("owner-floor-v1.lock")
        Files.write(lock, byteArrayOf(0x11), StandardOpenOption.CREATE_NEW)
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.observeHead(head(), pin(),
                OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true), at)
        }
        assertTrue(!Files.exists(root.resolve("owner-floor-v1.bin"), LinkOption.NOFOLLOW_LINKS))
        Files.delete(lock)
        Files.createSymbolicLink(lock, root.resolve("missing-lock-target"))
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.observeHead(head(), pin(),
                OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true), at)
        }
        assertTrue(Files.isSymbolicLink(lock))
    }

    @Test fun descriptorBoundEnrollmentFailsClosedWithoutActualDescriptorIdentity() {
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.observeHead(head(), pin(),
                OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true,
                    openDescriptorBoundLock = { file, createNew ->
                        val options: Array<OpenOption> = if (createNew)
                            arrayOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                                LinkOption.NOFOLLOW_LINKS)
                        else arrayOf(StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)
                        // An opened FileChannel without an fstat of ITS fd is
                        // insufficient, even when a path stat looks plausible.
                        OwnerFloorOpenedLock(FileChannel.open(file.toPath(), *options), null)
                    }), at)
        }
        assertTrue(!Files.exists(root.resolve("owner-floor-v1.bin"),
            LinkOption.NOFOLLOW_LINKS), "no unverifiable lock can seal an offline floor")
    }

    @Test fun verifiedOpenerContractPreservesLegitimateEnrollmentAndRestart() {
        // JVM-only functional mock. A pathname fileKey is NOT a substitute
        // for Android's Os.fstat(fd) under hostile A->B->A replacement.
        val functionalOpener: (java.io.File, Boolean) -> OwnerFloorOpenedLock = { file, createNew ->
            val options: Array<OpenOption> = if (createNew)
                arrayOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                    LinkOption.NOFOLLOW_LINKS)
            else arrayOf(StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)
            val channel = FileChannel.open(file.toPath(), *options)
            val fileKey = Files.readAttributes(file.toPath(), BasicFileAttributes::class.java,
                LinkOption.NOFOLLOW_LINKS).fileKey().toString()
            OwnerFloorOpenedLock(channel, fileKey)
        }
        val current = pin()
        OwnerPinnedOfflineAdmission.observeHead(head(), current,
            OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true,
                openDescriptorBoundLock = functionalOpener), at)
        val restarted = OwnerOfflineFloorStore(root.toFile(), key(),
            openDescriptorBoundLock = functionalOpener)
        OwnerPinnedOfflineAdmission.observeHead(head(), current, restarted, at + 1000)
        val secret = cek()
        var accepted = false
        OwnerPinnedOfflineAdmission.withAuthorizedCek(grant(), head(), current, secret,
            restarted, at + 1500) { _, _ -> accepted = true }
        assertTrue(accepted && secret.all { it == 0.toByte() },
            "a valid established lock still permits signed owner CEK on restart")
    }

    @Test fun twoProcessTransientABASwapDuringRealOpenRefusesWrongLockedInode() {
        if (System.getProperty("os.name").contains("Windows", ignoreCase = true)) return
        val old = pin()
        OwnerPinnedOfflineAdmission.observeHead(head(), old,
            OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true), at)
        val lockPath = root.resolve("owner-floor-v1.lock")
        val floor = root.resolve("owner-floor-v1.bin")
        val originalFloor = Files.readAllBytes(floor)
        val originalKey = Files.readAttributes(lockPath, BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS).fileKey().toString()
        val savedA = root.resolve("old-inode-A.parked")
        val savedB = root.resolve("new-inode-B.parked")
        val ready = root.resolve("held-A.ready")
        val release = root.resolve("held-A.release")
        val java = java.nio.file.Paths.get(System.getProperty("java.home"), "bin", "java")
        val child = ProcessBuilder(java.toString(), "-cp", System.getProperty("java.class.path"),
            "dev.rootark.core.sync.OwnerFloorLockHolderProcess",
            lockPath.toString(), ready.toString(), release.toString())
            .redirectErrorStream(true).start()
        try {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while (!Files.exists(ready) && child.isAlive && System.nanoTime() < deadline)
                Thread.sleep(20)
            assertTrue(Files.exists(ready), "another JVM must genuinely hold inode A")

            var openedB = false
            val hardened = OwnerOfflineFloorStore(root.toFile(), key(),
                openDescriptorBoundLock = { file, createNew ->
                    assertTrue(!createNew, "existing sealed floor cannot bootstrap a lock")
                    // Deterministic adversarial A->B->A swap DURING the real
                    // FileChannel.open; the old inode A remains locked in the
                    // separate process. The test captures B's actual inode
                    // while its pathname still names B, then restores A.
                    Files.move(file.toPath(), savedA)
                    Files.write(lockPath, byteArrayOf(0x31), StandardOpenOption.CREATE_NEW)
                    val newKey = Files.readAttributes(lockPath, BasicFileAttributes::class.java,
                        LinkOption.NOFOLLOW_LINKS).fileKey().toString()
                    assertTrue(newKey != originalKey)
                    val opened = FileChannel.open(lockPath, StandardOpenOption.WRITE,
                        LinkOption.NOFOLLOW_LINKS)
                    Files.move(lockPath, savedB)
                    Files.move(savedA, lockPath)
                    openedB = true
                    assertEquals(originalKey, Files.readAttributes(lockPath,
                        BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                        .fileKey().toString(), "path appears unchanged after ABA")
                    OwnerFloorOpenedLock(opened, newKey)
                })
            val cek = cek()
            var released = false
            assertThrows(ProtectedSyncException::class.java) {
                OwnerPinnedOfflineAdmission.withAuthorizedCek(grant(), head(), old,
                    cek, hardened, at + 1500) { _, _ -> released = true }
            }
            assertTrue(openedB, "attack must actually open replacement inode B")
            assertTrue(!released && cek.all { it == 0.toByte() },
                "second inode lock cannot authorize CEK while A is held")
            assertTrue(Files.readAllBytes(floor).contentEquals(originalFloor),
                "rejected ABA must not replace the sealed owner floor")
        } finally {
            Files.writeString(release, "release")
            if (!child.waitFor(5, TimeUnit.SECONDS)) child.destroyForcibly()
            assertTrue(!child.isAlive)
        }
    }

    @Test fun nativeDescriptorOwnerAndRawFdCloseExactlyOnceAfterAdmission() {
        val opens = AtomicInteger()
        val channelCloses = AtomicInteger()
        val rawCloses = AtomicInteger()
        val opener: (java.io.File, Boolean) -> OwnerFloorOpenedLock = { file, createNew ->
            val options: Array<OpenOption> = if (createNew)
                arrayOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                    LinkOption.NOFOLLOW_LINKS)
            else arrayOf(StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)
            val channel = FileChannel.open(file.toPath(), *options)
            val identity = Files.readAttributes(file.toPath(), BasicFileAttributes::class.java,
                LinkOption.NOFOLLOW_LINKS).fileKey().toString()
            opens.incrementAndGet()
            OwnerFloorOpenedLock(channel, identity,
                descriptorOwner = Closeable {
                    assertTrue(!channel.isOpen, "close the FileChannel before its owner")
                    channelCloses.incrementAndGet()
                },
                closeRawDescriptor = {
                    assertTrue(!channel.isOpen, "native Os.close must run AFTER channel close")
                    assertEquals(channelCloses.get(), rawCloses.get() + 1)
                    FileChannel.open(file.toPath(), StandardOpenOption.WRITE).use { probe ->
                        probe.tryLock().use { available ->
                            assertTrue(available != null && available.isValid,
                                "kernel lock must be released before raw fd closes")
                        }
                    }
                    rawCloses.incrementAndGet()
                })
        }
        val current = pin()
        OwnerPinnedOfflineAdmission.observeHead(head(), current,
            OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true,
                openDescriptorBoundLock = opener), at)
        OwnerPinnedOfflineAdmission.observeHead(head(), current,
            OwnerOfflineFloorStore(root.toFile(), key(),
                openDescriptorBoundLock = opener), at + 1000)
        val secret = cek()
        var released = false
        OwnerPinnedOfflineAdmission.withAuthorizedCek(grant(), head(), current, secret,
            OwnerOfflineFloorStore(root.toFile(), key(),
                openDescriptorBoundLock = opener), at + 1500) { _, _ -> released = true }
        assertTrue(released && secret.all { it == 0.toByte() })
        assertEquals(3, opens.get())
        assertEquals(opens.get(), channelCloses.get())
        assertEquals(opens.get(), rawCloses.get(),
            "every successful Os.open needs exactly one explicit Os.close")
    }

    @Test fun invalidDescriptorIdentityReleasesOwnedRawFdBeforeCek() {
        val original = pin()
        OwnerPinnedOfflineAdmission.observeHead(head(), original,
            OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true), at)
        val floorBefore = Files.readAllBytes(root.resolve("owner-floor-v1.bin"))
        var closeOwner = 0
        var closeRaw = 0
        val wrong = OwnerOfflineFloorStore(root.toFile(), key(),
            openDescriptorBoundLock = { file, createNew ->
                assertTrue(!createNew)
                val channel = FileChannel.open(file.toPath(), StandardOpenOption.WRITE,
                    LinkOption.NOFOLLOW_LINKS)
                OwnerFloorOpenedLock(channel, "wrong-inode", Closeable {
                    assertTrue(!channel.isOpen)
                    closeOwner++
                }, closeRawDescriptor = {
                    assertTrue(!channel.isOpen)
                    closeRaw++
                })
            })
        val secret = cek()
        var released = false
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineAdmission.withAuthorizedCek(grant(), head(), original,
                secret, wrong, at + 1500) { _, _ -> released = true }
        }
        assertTrue(!released && secret.all { it == 0.toByte() })
        assertEquals(1, closeOwner)
        assertEquals(1, closeRaw, "failed admission must explicitly release raw Os FD")
        assertTrue(Files.readAllBytes(root.resolve("owner-floor-v1.bin"))
            .contentEquals(floorBefore))
    }

    @Test fun rawFdCloseRunsOnceEvenWhenChannelOwnerCloseThrows() {
        val testPath = root.resolve("owner-fd-close-throws.lock")
        val channel = FileChannel.open(testPath, StandardOpenOption.CREATE_NEW,
            StandardOpenOption.WRITE)
        var ownerCloses = 0
        var rawCloses = 0
        val ownerFailure = IOException("synthetic descriptor owner close failed")
        val rawFailure = IOException("synthetic raw close failed")
        val opened = OwnerFloorOpenedLock(channel, "test", Closeable {
            assertTrue(!channel.isOpen, "channel always closes before owner")
            ownerCloses++
            throw ownerFailure
        }, closeRawDescriptor = {
            assertTrue(!channel.isOpen)
            rawCloses++
            throw rawFailure
        })
        val thrown = assertThrows(IOException::class.java) { opened.close() }
        assertTrue(thrown === ownerFailure)
        assertTrue(thrown.suppressed.any { it === rawFailure },
            "native close exception must be suppressed, not mask first close failure")
        opened.close()
        assertEquals(1, ownerCloses)
        assertEquals(1, rawCloses, "raw close must never retry an already closed fd")
    }

    @Test fun busyFloorLockStillClosesRawDescriptorWithoutReleasingOtherProcessAuthority() {
        val current = pin()
        OwnerPinnedOfflineAdmission.observeHead(head(), current,
            OwnerOfflineFloorStore(root.toFile(), key(), allowFirstWrite = true), at)
        val lockPath = root.resolve("owner-floor-v1.lock")
        val floorBefore = Files.readAllBytes(root.resolve("owner-floor-v1.bin"))
        var rawCloses = 0
        var ownerCloses = 0
        FileChannel.open(lockPath, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS).use { held ->
            held.lock().use { heldLock ->
                val blocked = OwnerOfflineFloorStore(root.toFile(), key(),
                    openDescriptorBoundLock = { file, createNew ->
                        assertTrue(!createNew)
                        val opened = FileChannel.open(file.toPath(), StandardOpenOption.WRITE,
                            LinkOption.NOFOLLOW_LINKS)
                        val identity = Files.readAttributes(file.toPath(),
                            BasicFileAttributes::class.java,
                            LinkOption.NOFOLLOW_LINKS).fileKey().toString()
                        OwnerFloorOpenedLock(opened, identity, Closeable {
                            assertTrue(!opened.isOpen)
                            ownerCloses++
                        }, closeRawDescriptor = {
                            assertTrue(!opened.isOpen)
                            rawCloses++
                        })
                    })
                val secret = cek()
                var released = false
                assertThrows(ProtectedSyncException::class.java) {
                    OwnerPinnedOfflineAdmission.withAuthorizedCek(grant(), head(), current,
                        secret, blocked, at + 1000) { _, _ -> released = true }
                }
                assertTrue(heldLock.isValid, "rejected contender must not release existing lock")
                assertTrue(!released && secret.all { it == 0.toByte() })
                assertEquals(1, ownerCloses)
                assertEquals(1, rawCloses,
                    "Os.open FD must close when FileChannel.tryLock throws or fails")
                assertTrue(Files.readAllBytes(root.resolve("owner-floor-v1.bin"))
                    .contentEquals(floorBefore))
            }
        }
    }
}

/** Real OS process, not a thread: holds the old inode lock during pathname replacement. */
object OwnerFloorLockHolderProcess {
    @JvmStatic fun main(args: Array<String>) {
        require(args.size == 3)
        val lock = java.nio.file.Paths.get(args[0])
        val ready = java.nio.file.Paths.get(args[1])
        val release = java.nio.file.Paths.get(args[2])
        FileChannel.open(lock, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS).use { channel ->
            channel.lock().use {
                Files.writeString(ready, "locked")
                val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
                while (!Files.exists(release) && System.nanoTime() < until) Thread.sleep(20)
            }
        }
    }
}
