package dev.rootark.android

import dev.rootark.core.sync.OfflineSession
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import java.io.File
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
        assertTrue(root.listFiles().isNullOrEmpty())
        cache.save(binding, "fixture-object-1", body)
        assertThrows(SecurityException::class.java) { cache.save(binding, "fixture-object-1", body) }
        assertEquals("fixture-object-1", cache.inspect(binding, "fixture-object-1").objectId)
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
}
