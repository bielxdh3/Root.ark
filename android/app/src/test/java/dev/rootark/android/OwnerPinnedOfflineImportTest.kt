package dev.rootark.android

import dev.rootark.core.sync.IndependentOfflineOwnerPin
import dev.rootark.core.sync.OwnerOfflineFloorStore
import dev.rootark.core.sync.ProtectedSyncException
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.util.Base64
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.Rule
import org.junit.rules.TemporaryFolder

class OwnerPinnedOfflineImportTest {
    @get:Rule val root = TemporaryFolder()

    private val vector: JSONObject get() {
        val stream = javaClass.getResourceAsStream("/owner-pinned-grant.json")
            ?: error("Node fixture unavailable")
        return JSONObject(stream.bufferedReader().use { it.readText() })
    }
    private fun pin(): IndependentOfflineOwnerPin {
        val a = vector.getJSONObject("anchor")
        return IndependentOfflineOwnerPin(
            a.getString("origin"), a.getString("username"), a.getString("readerDeviceId"),
            Base64.getUrlDecoder().decode(a.getString("ownerPublicSpki")),
            Base64.getUrlDecoder().decode(a.getString("ownerPublicSpkiSha256")),
            a.getLong("ownerRevision"), a.getString("ownerDigest"),
        )
    }
    private fun head() = vector.getJSONObject("head").toString().toByteArray(StandardCharsets.UTF_8)
    private fun grant() = vector.getJSONObject("grant").toString().toByteArray(StandardCharsets.UTF_8)
    private fun cek() = ByteArray(32) { (it + 1).toByte() }
    private fun floor(firstUse: Boolean = false) = OwnerOfflineFloorStore(root.root,
        SecretKeySpec(ByteArray(32) { 19 }, "AES"), allowFirstWrite = firstUse)
    private val now = 1_700_000_000_001L

    @Test fun strictImportedOwnerFilesUnlockOnlyExpectedScope() {
        val signedHead = head()
        val signedGrant = grant()
        val rawKey = cek()
        val result = OwnerPinnedOfflineImport.withImportedGrant(
            signedHead, signedGrant, pin(), rawKey, floor(firstUse = true), now,
        ) { verified, key ->
            assertEquals("item-id-001", verified.objectId)
            assertEquals("epoch-2", verified.keyEpoch)
            assertTrue(key.contentEquals(cek()))
            verified.versionId
        }
        assertEquals("version-id-001", result)
        assertTrue(rawKey.all { it == 0.toByte() })
        assertTrue(signedHead.all { it == 0.toByte() })
        assertTrue(signedGrant.all { it == 0.toByte() })
    }

    @Test fun duplicateKeysAndUnpinnedSignedJsonDenyAndEraseInput() {
        val original = head().toString(StandardCharsets.UTF_8)
        val duplicate = ("{\"schema\":\"forged\"," + original.drop(1))
            .toByteArray(StandardCharsets.UTF_8)
        val input = cek()
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineImport.withImportedGrant(
                duplicate, grant(), pin(), input, floor(), now,
            ) { _, _ -> error("duplicate owner signature accepted") }
        }
        assertTrue(input.all { it == 0.toByte() })
        val tampered = grant().toString(StandardCharsets.UTF_8)
            .replace("epoch-2", "epoch-3").toByteArray(StandardCharsets.UTF_8)
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineImport.withImportedGrant(
                head(), tampered, pin(), cek(), floor(), now,
            ) { _, _ -> error("forged owner lease accepted") }
        }
    }

    @Test fun revokedHeadImportAcrossRestartDeniesOldSignedLease() {
        OwnerPinnedOfflineImport.observeSignedHead(head(), pin(), floor(firstUse = true), now)
        val revoked = vector.getJSONObject("revoked")
        val newer = pin().copy(exactRevision = revoked.getLong("ownerRevision"),
            exactDigest = revoked.getString("ownerDigest"))
        OwnerPinnedOfflineImport.observeSignedHead(
            revoked.toString().toByteArray(StandardCharsets.UTF_8), newer, floor(), now + 1000)
        assertThrows(ProtectedSyncException::class.java) {
            OwnerPinnedOfflineImport.withImportedGrant(
                head(), grant(), pin(), cek(), floor(), now + 2000,
            ) { _, _ -> error("offline stale grant accepted") }
        }
    }
}
