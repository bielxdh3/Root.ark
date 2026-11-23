package dev.rootark.android

import dev.rootark.core.sync.OfflineSession
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.net.SocketTimeoutException
import java.nio.file.Files
import javax.crypto.KeyGenerator

class SessionCiphertextCacheTest {
    private val root = Files.createTempDirectory("rootark-cipher-cache-test").toFile()
    private val binding = OfflineSession("https://files.example.org:9443", "alice", "one-login-nonce")
    private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val body: ByteArray by lazy {
        val file = File(System.getProperty("rootark.fixture") ?: error("Missing real server fixture"))
        JSONObject(file.readText(Charsets.UTF_8)).getJSONObject("responses")
            .getJSONObject("sync.get.200").getJSONObject("body").toString().toByteArray(Charsets.UTF_8)
    }

    @After fun erase() { root.deleteRecursively() }

    @Test fun capturedSignedEnvelopeIsEncryptedAtRestAndBoundToTheLogin() {
        val cache = SessionCiphertextCache(root, binding, key)
        val snapshot = cache.save(binding, "fixture-object-1", body)
        assertEquals("fixture-object-1", snapshot.objectId)
        assertEquals("alice", snapshot.account)
        assertTrue(snapshot.revisionCounter >= 0L)
        assertTrue(snapshot.deviceId.isNotBlank())
        assertTrue(snapshot.epoch.isNotBlank())
        assertTrue(snapshot.envelopeSha256.isNotBlank())
        assertEquals(snapshot, cache.inspect(binding, "fixture-object-1"))
        val encrypted = root.listFiles()!!.single().readBytes()
        assertFalse(encrypted.contentEquals(body))
        assertFalse(String(encrypted, Charsets.ISO_8859_1).contains("fixture-object-1"))
        assertFalse(String(encrypted, Charsets.ISO_8859_1).contains("disposable-test-session"))
        assertThrows(SecurityException::class.java) {
            cache.inspect(binding.copy(sessionNonce = "another-login"), "fixture-object-1")
        }
        assertThrows(SecurityException::class.java) {
            cache.inspect(binding.copy(account = "bob"), "fixture-object-1")
        }
        assertThrows(SecurityException::class.java) {
            cache.inspect(binding.copy(origin = "https://other.example"), "fixture-object-1")
        }
    }

    @Test fun corruptionIsDetectedAndEvictedWithoutReturningCachedBytes() {
        val cache = SessionCiphertextCache(root, binding, key)
        cache.save(binding, "fixture-object-1", body)
        val file = root.listFiles()!!.single()
        val bytes = file.readBytes()
        bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
        file.writeBytes(bytes)
        assertThrows(SecurityException::class.java) { cache.inspect(binding, "fixture-object-1") }
        assertNull(cache.snapshot(binding))
        assertEquals(0, root.listFiles()!!.size)
    }

    @Test fun rejectsOversizeForgedAccountAndSameRevisionReplay() {
        val cache = SessionCiphertextCache(root, binding, key)
        assertThrows(SecurityException::class.java) {
            cache.save(binding, "fixture-object-1", ByteArray(SessionCiphertextCache.MAX_PACKET_BYTES + 1))
        }
        val forged = JSONObject(String(body, Charsets.UTF_8))
        forged.getJSONObject("authorization").put("username", "mallory")
        assertThrows(SecurityException::class.java) {
            cache.save(binding, "fixture-object-1", forged.toString().toByteArray())
        }
        val changedCiphertext = JSONObject(String(body, Charsets.UTF_8))
        changedCiphertext.put("ciphertext", "AQIDBA")
        assertThrows(SecurityException::class.java) {
            cache.save(binding, "fixture-object-1", changedCiphertext.toString().toByteArray())
        }
        val mismatchedProof = JSONObject(String(body, Charsets.UTF_8))
        mismatchedProof.getJSONObject("authorization").put("operationId", "different-operation")
        assertThrows(SecurityException::class.java) {
            cache.save(binding, "fixture-object-1", mismatchedProof.toString().toByteArray())
        }
        assertTrue(root.listFiles().isNullOrEmpty())
        cache.save(binding, "fixture-object-1", body)
        assertThrows(DuplicateCiphertextCaptureException::class.java) {
            cache.save(binding, "fixture-object-1", body)
        }
        assertEquals("fixture-object-1", cache.inspect(binding, "fixture-object-1").objectId)
    }

    @Test fun identicalReplayAndRejectedRemoteBytesDoNotEraseAnIntactCapture() {
        val cache = SessionCiphertextCache(root, binding, key)
        val original = cache.save(binding, "fixture-object-1", body)
        val encrypted = File(root, "packet.bin").readBytes()
        val duplicate = assertThrows(DuplicateCiphertextCaptureException::class.java) {
            cache.save(binding, "fixture-object-1", body)
        }
        var wipes = 0
        assertEquals(CiphertextCaptureUiResult.ALREADY_CAPTURED,
            CiphertextCaptureFailurePolicy.handle(duplicate) {
                wipes++
                cache.clear()
            })
        assertEquals(0, wipes)
        assertArrayEquals(encrypted, File(root, "packet.bin").readBytes())
        assertEquals(original, cache.inspect(binding, "fixture-object-1"))

        // The same revision and authorization with different GET bytes is still a replay.
        val differentBytes = JSONObject(String(body, Charsets.UTF_8)).toString(2).toByteArray()
        assertFalse(body.contentEquals(differentBytes))
        val replay = assertThrows(SecurityException::class.java) {
            cache.save(binding, "fixture-object-1", differentBytes)
        }
        assertFalse(replay is DuplicateCiphertextCaptureException)
        assertEquals(CiphertextCaptureUiResult.FAILED,
            CiphertextCaptureFailurePolicy.handle(replay) {
                wipes++
                cache.clear()
            })
        assertEquals(0, wipes)
        assertArrayEquals(encrypted, File(root, "packet.bin").readBytes())
        assertEquals(original, cache.inspect(binding, "fixture-object-1"))
    }

    @Test fun malformedRemoteGetAndBadAuthorizationCannotWipePreviouslyAuthenticatedCiphertext() {
        val cache = SessionCiphertextCache(root, binding, key)
        val original = cache.save(binding, "fixture-object-1", body)
        val sealed = File(root, "packet.bin").readBytes()
        var wipes = 0
        val maliciousPackets = listOf(
            "{incomplete-json".toByteArray(Charsets.UTF_8),
            ByteArray(SessionCiphertextCache.MAX_PACKET_BYTES + 1),
            JSONObject(String(body, Charsets.UTF_8)).apply {
                getJSONObject("authorization").put("username", "mallory")
            }.toString().toByteArray(Charsets.UTF_8),
        )
        for (candidate in maliciousPackets) {
            val failure = assertThrows(SecurityException::class.java) {
                cache.save(binding, "fixture-object-1", candidate)
            }
            assertEquals(CiphertextCaptureUiResult.FAILED,
                CiphertextCaptureFailurePolicy.handle(failure) {
                    wipes++
                    cache.clear()
                })
            assertEquals(0, wipes)
            assertArrayEquals(sealed, File(root, "packet.bin").readBytes())
            assertEquals(original, cache.inspect(binding, "fixture-object-1"))
        }
    }

    @Test fun forgedHigherRemoteRevisionCannotReplaceUnverifiedLocalCapture() {
        val cache = SessionCiphertextCache(root, binding, key)
        val original = cache.save(binding, "fixture-object-1", body)
        val sealed = File(root, "packet.bin").readBytes()
        val forged = JSONObject(String(body, Charsets.UTF_8))
        // Candidate metadata is self-consistent, but its unchanged Ed25519
        // signature does not authorize the new revision. Storage integrity
        // alone is not device authority: do not replace earlier ciphertext.
        forged.getJSONObject("revision").put("counter", original.revisionCounter + 1)
        forged.getJSONObject("authorization").getJSONObject("revision")
            .put("counter", original.revisionCounter + 1)
        val failure = assertThrows(SecurityException::class.java) {
            cache.save(binding, "fixture-object-1", forged.toString().toByteArray(Charsets.UTF_8))
        }
        var wipes = 0
        assertEquals(CiphertextCaptureUiResult.FAILED,
            CiphertextCaptureFailurePolicy.handle(failure) {
                wipes++
                cache.clear()
            })
        assertEquals(0, wipes)
        assertArrayEquals(sealed, File(root, "packet.bin").readBytes())
        assertEquals(original, cache.inspect(binding, "fixture-object-1"))
    }

    @Test fun genericSecurityExceptionFromRemoteFetchIsNotEvidenceOfLocalCacheCorruption() {
        val cache = SessionCiphertextCache(root, binding, key)
        val original = cache.save(binding, "fixture-object-1", body)
        val sealed = File(root, "packet.bin").readBytes()
        var wiped = false
        assertEquals(CiphertextCaptureUiResult.FAILED,
            CiphertextCaptureFailurePolicy.handle(SecurityException("invalid remote response")) {
                wiped = true
                cache.clear()
            })
        assertFalse(wiped)
        assertArrayEquals(sealed, File(root, "packet.bin").readBytes())
        assertEquals(original, cache.inspect(binding, "fixture-object-1"))
    }

    @Test fun corruptedCachedCiphertextCannotBeReusedByAnIdenticalGet() {
        val cache = SessionCiphertextCache(root, binding, key)
        cache.save(binding, "fixture-object-1", body)
        val file = File(root, "packet.bin")
        val bytes = file.readBytes()
        bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
        file.writeBytes(bytes)
        val failure = assertThrows(SecurityException::class.java) {
            cache.save(binding, "fixture-object-1", body)
        }
        assertFalse(failure is DuplicateCiphertextCaptureException)
        var wiped = false
        assertEquals(CiphertextCaptureUiResult.FAILED,
            CiphertextCaptureFailurePolicy.handle(failure) {
                wiped = true
                cache.clear()
            })
        assertTrue(wiped)
        assertTrue(root.listFiles().isNullOrEmpty())
    }

    @Test fun newerRevisionCannotSilentlyReplaceCorruptedEncryptedCapture() {
        val cache = SessionCiphertextCache(root, binding, key)
        cache.save(binding, "fixture-object-1", body)
        val sealed = File(root, "packet.bin")
        val tampered = sealed.readBytes()
        tampered[tampered.lastIndex] = (tampered.last().toInt() xor 1).toByte()
        sealed.writeBytes(tampered)

        // The remote envelope is only structurally checked here. Its claimed
        // incremented revision must not conceal local tampering with the
        // previously authenticated AEAD storage record.
        val next = JSONObject(String(body, Charsets.UTF_8))
        next.getJSONObject("revision").put("counter", 2)
        next.getJSONObject("authorization").getJSONObject("revision").put("counter", 2)
        assertThrows(SecurityException::class.java) {
            cache.save(binding, "fixture-object-1", next.toString().toByteArray())
        }
        assertNull(cache.snapshot(binding))
        assertTrue(root.listFiles().isNullOrEmpty())
    }

    @Test fun logoutErasesTheCiphertextAndRejectsInFlightCapture() {
        val cache = SessionCiphertextCache(root, binding, key)
        cache.save(binding, "fixture-object-1", body)
        cache.clear()
        assertTrue(root.listFiles().isNullOrEmpty())
        assertThrows(SecurityException::class.java) { cache.inspect(binding, "fixture-object-1") }
        assertThrows(SecurityException::class.java) { cache.save(binding, "fixture-object-1", body) }
        assertThrows(SecurityException::class.java) { cache.snapshot(binding) }
    }

    @Test fun failedNetworkRecaptureKeepsPreviouslyAuthenticatedCiphertext() {
        val cache = SessionCiphertextCache(root, binding, key)
        val original = cache.save(binding, "fixture-object-1", body)
        val ciphertext = File(root, "packet.bin").readBytes()
        var discards = 0

        // The new GET never returned a signed envelope: no observed integrity
        // failure or revocation justifies destroying the old local AEAD record.
        val result = CiphertextCaptureFailurePolicy.handle(SocketTimeoutException("fixture timeout")) {
            discards++
            cache.clear()
        }
        assertEquals(CiphertextCaptureUiResult.FAILED, result)
        assertEquals(0, discards)
        assertArrayEquals(ciphertext, File(root, "packet.bin").readBytes())
        assertEquals(original, cache.inspect(binding, "fixture-object-1"))
    }
}
