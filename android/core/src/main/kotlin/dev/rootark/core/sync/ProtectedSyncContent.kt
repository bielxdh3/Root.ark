package dev.rootark.core.sync

import dev.rootark.core.paths.PortablePathValidator
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Deliberately contains no attacker-controlled values or decrypted bytes. */
class ProtectedSyncException : SecurityException("Protected sync verification failed")

/**
 * Inputs must come from an independently authenticated device/epoch authority,
 * never from GET /sync/v1/objects or the signing proof being verified.
 * The caller must acquire a NEW snapshot when the trusted validity window ends.
 */
data class PinnedSyncReadContext(
    val username: String,
    val objectId: String,
    val fileId: String,
    val versionId: String,
    val compartmentId: String,
    val keyEpoch: String,
    val trustedDevicePublicKeys: Map<String, String>,
    val revokedDeviceIds: Set<String>,
    val snapshotObtainedAtMillis: Long,
    val snapshotValidUntilMillis: Long,
)

/**
 * Standalone Sync v2 encrypted-content primitive. No network, persistence,
 * device onboarding or permission decisions are exposed by this class.
 *
 * Historical proofs whose expiresAt has passed are deliberately rejected:
 * historical acceptance requires a separate authenticated admission ledger.
 * MOVE/DELETE payloads are not file content and are outside this API.
 *
 * JDK 17 provides Ed25519; on Android API 29 the platform provider may not.
 * Missing algorithms/providers cause a closed failure, never a downgrade.
 */
object ProtectedSyncContent {
    private const val MAX_CIPHERTEXT_BYTES = 8 * 1024 * 1024
    private const val MAX_METADATA_BYTES = 16 * 1024
    private const val MAX_TRUST_SNAPSHOT_AGE_MS = 5 * 60 * 1000L
    private const val SIGNING_DOMAIN = "Root.ark/zk-1/authorization-manifest/v1"
    private const val PROOF_TYPE = "rootark-sync-device-authorization-v1"
    private const val SUITE = "rootark-zk-1"
    private val ID = Regex("[A-Za-z0-9._:-]{1,160}")
    private val BASE64URL = Regex("[A-Za-z0-9_-]*")
    private val CONTROL = Regex("[\\u0000-\\u001f\\u007f]")
    private val SPKI_PREFIX = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    )

    fun verifyAndDecrypt(record: SyncRecord, fileKey: ByteArray, context: PinnedSyncReadContext): ByteArray =
        verifyAndDecryptAt(record, fileKey, context, System.currentTimeMillis())

    /** Clock injection is package-local and used only by disposable protocol fixtures. */
    internal fun verifyAndDecryptAt(
        record: SyncRecord,
        fileKey: ByteArray,
        context: PinnedSyncReadContext,
        nowMillis: Long,
    ): ByteArray {
        try {
            check(fileKey.size == 32)
            val verified = verifyEnvelopeAt(record, context, nowMillis)
            val decipher = Cipher.getInstance("AES/GCM/NoPadding")
            decipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(fileKey, "AES"), GCMParameterSpec(128, verified.nonce))
            decipher.updateAAD(verified.aad)
            val combined = ByteArray(verified.ciphertext.size + verified.tag.size)
            System.arraycopy(verified.ciphertext, 0, combined, 0, verified.ciphertext.size)
            System.arraycopy(verified.tag, 0, combined, verified.ciphertext.size, verified.tag.size)
            try {
                return decipher.doFinal(combined)
            } finally {
                combined.fill(0)
            }
        } catch (_: Exception) {
            throw ProtectedSyncException()
        }
    }

    /** Allows JVM interoperability tests to verify the original Node-signed fixture without its ephemeral CEK. */
    internal fun verifySignedEnvelopeAt(record: SyncRecord, context: PinnedSyncReadContext, nowMillis: Long) {
        verifyEnvelopeAt(record, context, nowMillis)
    }

    private data class VerifiedEnvelope(
        val ciphertext: ByteArray,
        val nonce: ByteArray,
        val tag: ByteArray,
        val aad: ByteArray,
    )

    private fun verifyEnvelopeAt(
        record: SyncRecord,
        context: PinnedSyncReadContext,
        nowMillis: Long,
    ): VerifiedEnvelope {
        try {
            check(record.protocolVersion == SYNC_PROTOCOL_VERSION)
            check(record.operation == SyncOperationType.CREATE || record.operation == SyncOperationType.UPDATE)
            check(!record.tombstone)
            check(nowMillis in 1..9_007_199_254_740_990L)
            check(context.snapshotObtainedAtMillis in 1..nowMillis)
            check(nowMillis < context.snapshotValidUntilMillis)
            check(nowMillis - context.snapshotObtainedAtMillis <= MAX_TRUST_SNAPSHOT_AGE_MS)
            check(context.snapshotValidUntilMillis - context.snapshotObtainedAtMillis <= MAX_TRUST_SNAPSHOT_AGE_MS)
            check(context.username.isNotBlank() && context.username.length <= 512)
            check(record.objectId == context.objectId && record.fileId == context.fileId)
            check(record.versionId == context.versionId)
            check(record.compartmentId == context.compartmentId && record.keyEpoch == context.keyEpoch)

            id(record.operationId)
            id(record.objectId)
            id(record.fileId)
            id(record.versionId)
            id(record.deviceId)
            id(record.compartmentId)
            id(record.keyEpoch)
            check(record.revision.counter in 0..9_007_199_254_740_991L && record.revision.deviceId == record.deviceId)
            id(record.revision.deviceId)
            record.baseRevision?.let {
                check(it.counter in 0..9_007_199_254_740_991L)
                id(it.deviceId)
            }
            val metadata = validatedMetadata(record)
            val aadMap = mapOf(
                "protocolVersion" to 2, "objectId" to record.objectId,
                "fileId" to record.fileId, "versionId" to record.versionId,
                "operation" to record.operation.wire, "revision" to revision(record.revision),
                "baseRevision" to record.baseRevision?.let(::revision),
                "keyEpoch" to record.keyEpoch, "compartmentId" to record.compartmentId,
                "deviceId" to record.deviceId, "metadata" to metadata,
                "tombstone" to record.tombstone,
            )
            val expectedAad = canonicalJson(aadMap).toByteArray(StandardCharsets.UTF_8)
            val cipherBytes = decode(record.ciphertext, MAX_CIPHERTEXT_BYTES, allowEmpty = true)
            val nonce = decode(record.nonce, 12)
            val tag = decode(record.tag, 16)
            val aad = decode(record.aad, 32 * 1024)
            check(MessageDigest.isEqual(aad, expectedAad))

            val proof = record.authorization ?: throw ProtectedSyncException()
            check(proof.schemaVersion == 1 && proof.type == PROOF_TYPE)
            check(proof.suite == SUITE && proof.protocolVersion == 2)
            check(proof.username == context.username && proof.deviceId == record.deviceId)
            check(proof.expiresAt in (nowMillis + 1)..9_007_199_254_740_991L)
            check(proof.operationId == record.operationId && proof.objectId == record.objectId)
            check(proof.fileId == record.fileId && proof.versionId == record.versionId)
            check(proof.operation == record.operation.wire && proof.revision == record.revision)
            check(proof.baseRevision == record.baseRevision && proof.metadata == record.metadata)
            check(proof.keyEpoch == record.keyEpoch && proof.compartmentId == record.compartmentId)
            check(proof.idempotencyKey.matches(Regex("[A-Za-z0-9_-]{16,128}")) ||
                (proof.idempotencyKey.matches(Regex("[A-Za-z0-9_-]{1,192}")) && proof.idempotencyKey.length % 4 != 1))
            check(proof.replayId.isNotEmpty() && proof.replayId.matches(BASE64URL) && proof.replayId.length % 4 != 1)
            check(MessageDigest.isEqual(decode(proof.aadDigest, 32), sha256(aad)))
            check(MessageDigest.isEqual(decode(proof.ciphertextDigest, 32), sha256(cipherBytes)))
            check(MessageDigest.isEqual(decode(proof.nonceDigest, 32), sha256(nonce)))
            check(MessageDigest.isEqual(decode(proof.tagDigest, 32), sha256(tag)))

            // Key equality is independent of the untrusted signature/proof.
            check(record.deviceId !in context.revokedDeviceIds)
            val independentlyPinned = context.trustedDevicePublicKeys[record.deviceId]
                ?: throw ProtectedSyncException()
            check(proof.publicKey == independentlyPinned)
            val publicDer = decode(independentlyPinned, 44)
            check(publicDer.copyOfRange(0, SPKI_PREFIX.size).contentEquals(SPKI_PREFIX))
            val publicKey = KeyFactory.getInstance("Ed25519")
                .generatePublic(X509EncodedKeySpec(publicDer))
            val unsigned = authorizationMap(proof, metadata)
            val signBytes = ByteArrayOutputStream().apply {
                write(SIGNING_DOMAIN.toByteArray(StandardCharsets.US_ASCII))
                write(0)
                write(canonicalCbor(unsigned))
            }.toByteArray()
            val verifier = Signature.getInstance("Ed25519")
            verifier.initVerify(publicKey)
            verifier.update(signBytes)
            check(verifier.verify(decode(proof.signature, 64)))
            return VerifiedEnvelope(cipherBytes, nonce, tag, aad)
        } catch (_: Exception) {
            throw ProtectedSyncException()
        }
    }

    private fun id(value: String) = check(value.matches(ID))

    private fun revision(value: SyncRevision): Map<String, Any?> =
        mapOf("counter" to value.counter, "deviceId" to value.deviceId)

    private fun validatedMetadata(record: SyncRecord): Map<String, Any?> {
        val m = record.metadata
        check(m.fileId == record.fileId && m.versionId == record.versionId)
        check(m.compartmentId == record.compartmentId && m.keyEpoch == record.keyEpoch)
        check(m.deviceId == record.deviceId && m.sourcePath == null)
        val path = m.path ?: throw ProtectedSyncException()
        PortablePathValidator.validate(path)
        for (optionalId in listOf(m.parentId)) optionalId?.let(::id)
        for (value in listOf(m.name, m.contentType)) {
            value?.let { check(it.isNotEmpty() && it.length <= 512 && !CONTROL.containsMatchIn(it)) }
        }
        check(m.size == null || m.size in 0..9_007_199_254_740_991L)
        val metadata = linkedMapOf<String, Any?>(
            "fileId" to m.fileId, "versionId" to m.versionId,
            "path" to m.path, "parentId" to m.parentId,
            "name" to m.name, "contentType" to m.contentType,
            "size" to m.size, "keyEpoch" to m.keyEpoch,
            "compartmentId" to m.compartmentId, "deviceId" to m.deviceId,
        ).filterValues { it != null }
        check(canonicalJson(metadata).toByteArray(StandardCharsets.UTF_8).size <= MAX_METADATA_BYTES)
        return metadata
    }

    private fun authorizationMap(proof: SyncAuthorizationProof, metadata: Map<String, Any?>) =
        mapOf<String, Any?>(
            "schemaVersion" to proof.schemaVersion, "type" to proof.type,
            "suite" to proof.suite, "protocolVersion" to proof.protocolVersion,
            "username" to proof.username, "deviceId" to proof.deviceId,
            "operationId" to proof.operationId, "objectId" to proof.objectId,
            "fileId" to proof.fileId, "versionId" to proof.versionId,
            "operation" to proof.operation, "revision" to revision(proof.revision),
            "baseRevision" to proof.baseRevision?.let(::revision),
            "keyEpoch" to proof.keyEpoch, "compartmentId" to proof.compartmentId,
            "metadata" to metadata, "aadDigest" to proof.aadDigest,
            "ciphertextDigest" to proof.ciphertextDigest, "nonceDigest" to proof.nonceDigest,
            "tagDigest" to proof.tagDigest, "expiresAt" to proof.expiresAt,
            "replayId" to proof.replayId, "idempotencyKey" to proof.idempotencyKey,
            "publicKey" to proof.publicKey,
        )

    private fun decode(value: String, maxSize: Int, allowEmpty: Boolean = false): ByteArray {
        check(value.matches(BASE64URL) && value.length % 4 != 1)
        check(allowEmpty || value.isNotEmpty())
        check(value.length <= ((maxSize + 2L) / 3L * 4L).toInt() + 2)
        val bytes = Base64.getUrlDecoder().decode(value)
        check(bytes.size <= maxSize && (allowEmpty || bytes.isNotEmpty()))
        check(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) == value)
        return bytes
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    /** Matches Node's sorted-key JSON.stringify AAD (UTF-16 key ordering). */
    internal fun canonicalJson(value: Any?): String = when (value) {
        null -> "null"
        is String -> escapeJson(value)
        is Boolean, is Int, is Long -> value.toString()
        is Map<*, *> -> value.keys.map { it as String }.sorted().joinToString(",", "{", "}") { key ->
            escapeJson(key) + ":" + canonicalJson(value[key])
        }
        else -> throw ProtectedSyncException()
    }

    private fun escapeJson(value: String): String = buildString {
        append('"')
        var i = 0
        while (i < value.length) {
            val char = value[i]
            when (char) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\b' -> append("\\b")
                '\u000c' -> append("\\f")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (char.isHighSurrogate() && i + 1 < value.length && value[i + 1].isLowSurrogate()) {
                    append(char)
                    append(value[++i])
                } else if (char.code < 32 || char.isSurrogate()) {
                    append("\\u")
                    append(char.code.toString(16).padStart(4, '0'))
                } else append(char)
            }
            i++
        }
        append('"')
    }

    /** RFC 8949 deterministic CBOR: minimal integers and length-first map ordering. */
    internal fun canonicalCbor(value: Any?): ByteArray = ByteArrayOutputStream().apply {
        fun header(major: Int, length: Long) {
            check(length >= 0)
            when {
                length < 24 -> write((major shl 5) or length.toInt())
                length <= 255 -> { write((major shl 5) or 24); write(length.toInt()) }
                length <= 65535 -> {
                    write((major shl 5) or 25)
                    write((length shr 8).toInt()); write(length.toInt())
                }
                length <= 0xffffffffL -> {
                    write((major shl 5) or 26)
                    for (shift in 24 downTo 0 step 8) write((length shr shift).toInt())
                }
                else -> {
                    write((major shl 5) or 27)
                    for (shift in 56 downTo 0 step 8) write((length shr shift).toInt())
                }
            }
        }
        fun bytesText(value: String): ByteArray {
            val bytes = value.toByteArray(StandardCharsets.UTF_8)
            val output = ByteArrayOutputStream()
            // Canonical strings use the same minimal CBOR major-3 prefix.
            val len = bytes.size.toLong()
            when {
                len < 24 -> output.write((3 shl 5) or len.toInt())
                len <= 255 -> { output.write(0x78); output.write(len.toInt()) }
                len <= 65535 -> {
                    output.write(0x79); output.write((len shr 8).toInt()); output.write(len.toInt())
                }
                else -> throw ProtectedSyncException()
            }
            output.write(bytes)
            return output.toByteArray()
        }
        fun compareBytes(a: ByteArray, b: ByteArray): Int {
            if (a.size != b.size) return a.size.compareTo(b.size)
            for (i in a.indices) {
                val diff = (a[i].toInt() and 255) - (b[i].toInt() and 255)
                if (diff != 0) return diff
            }
            return 0
        }
        fun encode(v: Any?) {
            when (v) {
                null -> write(0xf6)
                is Boolean -> write(if (v) 0xf5 else 0xf4)
                is String -> write(bytesText(v))
                is Int -> header(0, v.toLong())
                is Long -> header(0, v)
                is Map<*, *> -> {
                    val entries = v.entries.map {
                        val key = it.key as? String ?: throw ProtectedSyncException()
                        Pair(bytesText(key), it.value)
                    }.sortedWith { a, b -> compareBytes(a.first, b.first) }
                    header(5, entries.size.toLong())
                    for ((key, item) in entries) {
                        write(key)
                        encode(item)
                    }
                }
                else -> throw ProtectedSyncException()
            }
        }
        encode(value)
    }.toByteArray()
}
