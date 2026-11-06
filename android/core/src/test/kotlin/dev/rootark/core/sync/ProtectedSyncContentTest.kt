package dev.rootark.core.sync

import org.json.JSONObject
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ProtectedSyncContentTest {
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()
    private fun nodeFixture(name: String): SyncRecord {
        val stream = javaClass.classLoader.getResourceAsStream("server-responses.json")
            ?: error("Missing signed real-Node fixture")
        val root = JSONObject(stream.bufferedReader(Charsets.UTF_8).use { it.readText() })
        return root.getJSONObject("responses").getJSONObject(name).getJSONObject("body").asRecord()
    }
    private val nodeRecord: SyncRecord by lazy { nodeFixture("sync.post.201") }

    private fun String.binary() = decoder.decode(this)
    private fun ByteArray.b64() = encoder.encodeToString(this)
    private fun hash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).b64()

    private fun JSONObject.optStringOrNull(name: String): String? =
        if (has(name) && !isNull(name)) getString(name) else null

    private fun JSONObject.asRevision() = SyncRevision(getLong("counter"), getString("deviceId"))

    private fun JSONObject.asMetadata() = SyncMetadata(
        fileId = optStringOrNull("fileId"),
        versionId = optStringOrNull("versionId"),
        path = optStringOrNull("path"),
        parentId = optStringOrNull("parentId"),
        name = optStringOrNull("name"),
        contentType = optStringOrNull("contentType"),
        size = if (has("size") && !isNull("size")) getLong("size") else null,
        keyEpoch = optStringOrNull("keyEpoch"),
        compartmentId = optStringOrNull("compartmentId"),
        deviceId = optStringOrNull("deviceId"),
        sourcePath = optStringOrNull("sourcePath"),
    )

    private fun JSONObject.asProof() = SyncAuthorizationProof(
        schemaVersion = getInt("schemaVersion"),
        type = getString("type"),
        suite = getString("suite"),
        protocolVersion = getInt("protocolVersion"),
        username = getString("username"),
        deviceId = getString("deviceId"),
        operationId = getString("operationId"),
        objectId = getString("objectId"),
        fileId = getString("fileId"),
        versionId = getString("versionId"),
        operation = getString("operation"),
        revision = getJSONObject("revision").asRevision(),
        baseRevision = optJSONObject("baseRevision")?.asRevision(),
        keyEpoch = getString("keyEpoch"),
        compartmentId = getString("compartmentId"),
        metadata = getJSONObject("metadata").asMetadata(),
        aadDigest = getString("aadDigest"),
        ciphertextDigest = getString("ciphertextDigest"),
        nonceDigest = getString("nonceDigest"),
        tagDigest = getString("tagDigest"),
        expiresAt = getLong("expiresAt"),
        replayId = getString("replayId"),
        idempotencyKey = getString("idempotencyKey"),
        publicKey = getString("publicKey"),
        signature = getString("signature"),
    )

    private fun JSONObject.asRecord() = SyncRecord(
        protocolVersion = getInt("protocolVersion"),
        operationId = getString("operationId"),
        objectId = getString("objectId"),
        fileId = getString("fileId"),
        versionId = getString("versionId"),
        operation = SyncOperationType.fromWire(getString("operation")),
        revision = getJSONObject("revision").asRevision(),
        baseRevision = optJSONObject("baseRevision")?.asRevision(),
        keyEpoch = getString("keyEpoch"),
        compartmentId = getString("compartmentId"),
        deviceId = getString("deviceId"),
        metadata = getJSONObject("metadata").asMetadata(),
        tombstone = getBoolean("tombstone"),
        ciphertext = getString("ciphertext"),
        nonce = getString("nonce"),
        tag = getString("tag"),
        aad = getString("aad"),
        authorization = optJSONObject("authorization")?.asProof(),
    )

    private fun context(record: SyncRecord, now: Long) = PinnedSyncReadContext(
        username = "alice",
        objectId = record.objectId,
        fileId = record.fileId,
        versionId = record.versionId,
        compartmentId = record.compartmentId,
        keyEpoch = record.keyEpoch,
        trustedDevicePublicKeys = mapOf(record.deviceId to record.authorization!!.publicKey),
        revokedDeviceIds = emptySet(),
        snapshotObtainedAtMillis = now - 5_000,
        snapshotValidUntilMillis = now + 30_000,
    )

    @Test
    fun verifiesActualNodeRouteSignedFixtureWithPinnedPublicKeyAndCanonicalCbor() {
        val proof = nodeRecord.authorization!!
        // The committed Node fixture's expiry is historical; test at capture-time
        // to exercise its real Node-generated RFC 8949 CBOR and Ed25519 signature.
        val now = proof.expiresAt - 10_000
        ProtectedSyncContent.verifySignedEnvelopeAt(nodeRecord, context(nodeRecord, now), now)

        assertFailsWith<ProtectedSyncException> {
            ProtectedSyncContent.verifySignedEnvelopeAt(
                nodeRecord.copy(authorization = proof.copy(signature = mutate(proof.signature))),
                context(nodeRecord, now), now,
            )
        }
        assertFailsWith<ProtectedSyncException> {
            ProtectedSyncContent.verifySignedEnvelopeAt(
                nodeRecord.copy(authorization = proof.copy(publicKey = mutate(proof.publicKey))),
                context(nodeRecord, now), now,
            )
        }
        assertFailsWith<ProtectedSyncException> {
            ProtectedSyncContent.verifySignedEnvelopeAt(nodeRecord, context(nodeRecord, now), proof.expiresAt)
        }
    }

    @Test
    fun verifiesActualNodeSignedUpdateWithBaseRevisionAndRejectsRevisionTamper() {
        val update = nodeFixture("sync.put.200.update")
        val proof = update.authorization!!
        val now = proof.expiresAt - 10_000
        ProtectedSyncContent.verifySignedEnvelopeAt(update, context(update, now), now)
        assertFailsWith<ProtectedSyncException> {
            ProtectedSyncContent.verifySignedEnvelopeAt(
                update.copy(baseRevision = update.baseRevision?.copy(counter = 100)),
                context(update, now), now,
            )
        }
    }

    private fun mutate(value: String): String = (if (value[0] == 'A') "B" else "A") + value.substring(1)

    /**
     * Builds a disposable signing key and CEK only in test memory. The signing
     * bytes are checked separately against a genuine Node fixture above.
     */
    private fun encryptedSample(): Triple<SyncRecord, ByteArray, Long> {
        val now = nodeRecord.authorization!!.expiresAt - 10_000
        val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val plaintext = "protected file contents 📄".toByteArray(Charsets.UTF_8)
        val aad = nodeRecord.aad.binary()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        val combined = cipher.doFinal(plaintext)
        val ciphertext = combined.copyOfRange(0, combined.size - 16).b64()
        val tag = combined.copyOfRange(combined.size - 16, combined.size).b64()

        val pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val original = nodeRecord.authorization!!
        val unsignedProof = original.copy(
            ciphertextDigest = hash(ciphertext.binary()),
            nonceDigest = hash(nonce),
            tagDigest = hash(tag.binary()),
            publicKey = pair.public.encoded.b64(),
            expiresAt = now + 60_000,
            signature = "",
        )
        val fields = mapOf<String, Any?>(
            "schemaVersion" to unsignedProof.schemaVersion,
            "type" to unsignedProof.type,
            "suite" to unsignedProof.suite,
            "protocolVersion" to unsignedProof.protocolVersion,
            "username" to unsignedProof.username,
            "deviceId" to unsignedProof.deviceId,
            "operationId" to unsignedProof.operationId,
            "objectId" to unsignedProof.objectId,
            "fileId" to unsignedProof.fileId,
            "versionId" to unsignedProof.versionId,
            "operation" to unsignedProof.operation,
            "revision" to mapOf("counter" to unsignedProof.revision.counter, "deviceId" to unsignedProof.revision.deviceId),
            "baseRevision" to null,
            "keyEpoch" to unsignedProof.keyEpoch,
            "compartmentId" to unsignedProof.compartmentId,
            "metadata" to mapOf(
                "compartmentId" to "private", "contentType" to "text/plain",
                "deviceId" to "fixture-device-a", "fileId" to "fixture-file-1",
                "keyEpoch" to "epoch-1", "name" to "readme.txt",
                "parentId" to "root", "path" to "docs/readme.txt",
                "size" to 5L, "versionId" to "fixture-version-1",
            ),
            "aadDigest" to unsignedProof.aadDigest,
            "ciphertextDigest" to unsignedProof.ciphertextDigest,
            "nonceDigest" to unsignedProof.nonceDigest,
            "tagDigest" to unsignedProof.tagDigest,
            "expiresAt" to unsignedProof.expiresAt,
            "replayId" to unsignedProof.replayId,
            "idempotencyKey" to unsignedProof.idempotencyKey,
            "publicKey" to unsignedProof.publicKey,
        )
        val prefix = "Root.ark/zk-1/authorization-manifest/v1".toByteArray(Charsets.US_ASCII)
        val message = prefix + byteArrayOf(0) + ProtectedSyncContent.canonicalCbor(fields)
        val signer = Signature.getInstance("Ed25519")
        signer.initSign(pair.private)
        signer.update(message)
        val record = nodeRecord.copy(
            ciphertext = ciphertext, nonce = nonce.b64(), tag = tag,
            authorization = unsignedProof.copy(signature = signer.sign().b64()),
        )
        return Triple(record, key, now)
    }

    @Test
    fun verifiesAndDecryptsGcmOnlyAfterSignedEnvelopeAndPinnedTrust() {
        val (record, key, now) = encryptedSample()
        assertContentEquals(
            "protected file contents 📄".toByteArray(Charsets.UTF_8),
            ProtectedSyncContent.verifyAndDecryptAt(record, key, context(record, now), now),
        )
    }

    @Test
    fun rejectsCiphertextNonceTagAadKeyAndSignatureTampering() {
        val (record, key, now) = encryptedSample()
        val trust = context(record, now)
        val proof = record.authorization!!
        val wrongKey = key.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val badRecords = listOf(
            record.copy(ciphertext = mutate(record.ciphertext)),
            record.copy(nonce = mutate(record.nonce)),
            record.copy(tag = mutate(record.tag)),
            record.copy(aad = mutate(record.aad)),
            record.copy(authorization = proof.copy(signature = mutate(proof.signature))),
            record.copy(authorization = proof.copy(aadDigest = mutate(proof.aadDigest))),
            record.copy(authorization = null),
        )
        for (bad in badRecords) {
            assertFailsWith<ProtectedSyncException> {
                ProtectedSyncContent.verifyAndDecryptAt(bad, key, trust, now)
            }
        }
        assertFailsWith<ProtectedSyncException> {
            ProtectedSyncContent.verifyAndDecryptAt(record, wrongKey, trust, now)
        }
    }

    @Test
    fun rejectsRevokedOrUnpinnedDeviceAndStaleOrMismatchedEpoch() {
        val (record, key, now) = encryptedSample()
        val trust = context(record, now)
        val badContexts = listOf(
            trust.copy(trustedDevicePublicKeys = emptyMap()),
            trust.copy(trustedDevicePublicKeys = mapOf(record.deviceId to mutate(record.authorization!!.publicKey))),
            trust.copy(revokedDeviceIds = setOf(record.deviceId)),
            trust.copy(keyEpoch = "epoch-2"),
            trust.copy(compartmentId = "other"),
            trust.copy(objectId = "other"),
            trust.copy(fileId = "other"),
            trust.copy(versionId = "other"),
            trust.copy(username = "other"),
            trust.copy(snapshotValidUntilMillis = now),
            trust.copy(snapshotObtainedAtMillis = now + 1),
        )
        for (bad in badContexts) {
            assertFailsWith<ProtectedSyncException> {
                ProtectedSyncContent.verifyAndDecryptAt(record, key, bad, now)
            }
        }
        assertFailsWith<ProtectedSyncException> {
            ProtectedSyncContent.verifyAndDecryptAt(record, key, trust, record.authorization!!.expiresAt)
        }
    }

    @Test
    fun rejectsPathsMetadataScopeProtocolAndNonContentOperations() {
        val (record, key, now) = encryptedSample()
        val trust = context(record, now)
        val badRecords = listOf(
            record.copy(protocolVersion = 1),
            record.copy(operation = SyncOperationType.DELETE, tombstone = true),
            record.copy(operation = SyncOperationType.MOVE),
            record.copy(metadata = record.metadata.copy(path = "../sensitive")),
            record.copy(metadata = record.metadata.copy(path = "/absolute")),
            record.copy(metadata = record.metadata.copy(name = "bad\u0000name")),
            record.copy(metadata = record.metadata.copy(size = -1)),
            record.copy(metadata = record.metadata.copy(keyEpoch = "epoch-2")),
            record.copy(deviceId = "other-device"),
            record.copy(revision = record.revision.copy(counter = -1)),
        )
        for (bad in badRecords) {
            assertFailsWith<ProtectedSyncException> {
                ProtectedSyncContent.verifyAndDecryptAt(bad, key, trust, now)
            }
        }
        assertTrue(ProtectedSyncContent.canonicalJson(
            mapOf("path" to "docs/📄.txt"),
        ).contains("📄"))
    }
}
