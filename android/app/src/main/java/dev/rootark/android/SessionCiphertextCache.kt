package dev.rootark.android

import dev.rootark.core.sync.OfflineSession
import dev.rootark.core.sync.SyncRecord
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Untrusted server claims: valid AES-GCM storage never proves Ed25519 authorization. */
internal data class CapturedCiphertextSnapshot(
    val origin: String,
    val account: String,
    val objectId: String,
    val fileId: String,
    val versionId: String,
    val deviceId: String,
    val revisionCounter: Long,
    val epoch: String,
    val compartment: String,
    val envelopeSha256: String,
    val ciphertextDigest: String,
)

/** One bounded signed-envelope candidate encrypted for one login, never a plaintext cache. */
internal class SessionCiphertextCache(
    private val root: File,
    private val session: OfflineSession,
    private val key: SecretKey,
) {
    private var active = true
    private var saved: CapturedCiphertextSnapshot? = null
    private val file = File(root, "packet.bin")

    init {
        require(session.origin.startsWith("https://") && session.account.isNotBlank() &&
            session.sessionNonce.isNotBlank())
        purgeStale(root)
        if (!root.exists() && !root.mkdirs()) throw SecurityException("Private ciphertext directory unavailable")
    }

    @Synchronized fun save(
        requester: OfflineSession,
        expectedObjectId: String,
        bytes: ByteArray,
    ): CapturedCiphertextSnapshot {
        checkSession(requester)
        if (bytes.size !in 1..MAX_PACKET_BYTES) throw SecurityException("Oversized ciphertext packet")
        val record = try {
            StrictSyncRecordJson.parse(bytes)
        } catch (_: Exception) {
            throw SecurityException("Invalid signed-envelope candidate")
        }
        val snapshot = captureIdentity(record, expectedObjectId, bytes)
        val previous = saved
        if (previous != null && previous.objectId == snapshot.objectId &&
            snapshot.revisionCounter <= previous.revisionCounter) {
            throw SecurityException("Replay or conflicting revision")
        }
        val encrypted = try {
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.ENCRYPT_MODE, key)
                updateAAD(aad(snapshot))
                val nonce = iv
                if (nonce.size != IV_BYTES) throw SecurityException()
                MAGIC + nonce + doFinal(bytes)
            }
        } catch (_: Exception) {
            throw SecurityException("Private ciphertext encryption unavailable")
        }
        val temporary = File(root, "packet-${UUID.randomUUID()}.tmp")
        try {
            FileOutputStream(temporary).use { output ->
                output.write(encrypted)
                output.fd.sync()
            }
            Files.move(temporary.toPath(), file.toPath(),
                StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            saved = snapshot
            return snapshot
        } catch (_: Exception) {
            throw SecurityException("Private ciphertext capture failed")
        } finally {
            temporary.delete()
            encrypted.fill(0)
        }
    }

    /** Verifies only local storage integrity, never emits packet bytes or decrypted content. */
    @Synchronized fun inspect(requester: OfflineSession, objectId: String): CapturedCiphertextSnapshot {
        checkSession(requester)
        val snapshot = saved?.takeIf { it.objectId == objectId } ?: throw SecurityException("No captured packet")
        try {
            if (Files.isSymbolicLink(file.toPath()) ||
                file.length() !in (MAGIC.size + IV_BYTES + 16).toLong()..(MAX_PACKET_BYTES + MAGIC.size + IV_BYTES + 16).toLong()) {
                throw SecurityException()
            }
            val encoded = boundedRead(file, MAX_PACKET_BYTES + MAGIC.size + IV_BYTES + 16)
            if (!encoded.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) throw SecurityException()
            val nonce = encoded.copyOfRange(MAGIC.size, MAGIC.size + IV_BYTES)
            val bytes = Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, nonce))
                updateAAD(aad(snapshot))
                doFinal(encoded, MAGIC.size + IV_BYTES, encoded.size - MAGIC.size - IV_BYTES)
            }
            try {
                if (bytes.size !in 1..MAX_PACKET_BYTES ||
                    sha256(bytes) != snapshot.envelopeSha256 ||
                    captureIdentity(StrictSyncRecordJson.parse(bytes), objectId, bytes) != snapshot) {
                    throw SecurityException()
                }
                return snapshot
            } finally {
                bytes.fill(0)
                encoded.fill(0)
            }
        } catch (_: Exception) {
            saved = null
            file.delete()
            throw SecurityException("Cached ciphertext corrupted or invalid")
        }
    }

    @Synchronized fun snapshot(requester: OfflineSession): CapturedCiphertextSnapshot? {
        checkSession(requester)
        return saved
    }

    @Synchronized fun clear() {
        active = false
        saved = null
        purgeStale(root)
    }

    private fun checkSession(requester: OfflineSession) {
        if (!active || requester != session) throw SecurityException("Ciphertext session ended or mismatched")
    }

    private fun captureIdentity(record: SyncRecord, requested: String, body: ByteArray): CapturedCiphertextSnapshot {
        val proof = record.authorization ?: throw SecurityException()
        fun id(value: String) = value.matches(Regex("[A-Za-z0-9._:-]{1,160}"))
        if (record.objectId != requested || listOf(record.operationId, record.objectId, record.fileId, record.versionId,
                record.deviceId, record.keyEpoch, record.compartmentId).any { !id(it) } ||
            record.revision.deviceId != record.deviceId || record.revision.counter !in 0..9_007_199_254_740_991L ||
            proof.schemaVersion != 1 || proof.protocolVersion != 2 ||
            proof.type != "rootark-sync-device-authorization-v1" || proof.suite != "rootark-zk-1" ||
            proof.username != session.account || proof.deviceId != record.deviceId ||
            proof.operationId != record.operationId || proof.baseRevision != record.baseRevision ||
            proof.objectId != record.objectId || proof.fileId != record.fileId ||
            proof.versionId != record.versionId || proof.revision != record.revision ||
            proof.operation != record.operation.wire || proof.keyEpoch != record.keyEpoch ||
            proof.compartmentId != record.compartmentId || proof.metadata != record.metadata ||
            proof.signature.isBlank() || proof.publicKey.isBlank() ||
            record.metadata.keyEpoch != record.keyEpoch ||
            record.metadata.compartmentId != record.compartmentId ||
            record.metadata.fileId != record.fileId ||
            record.metadata.versionId != record.versionId ||
            record.metadata.deviceId != record.deviceId) throw SecurityException()
        verifyDigest(record.ciphertext, proof.ciphertextDigest, MAX_PACKET_BYTES)
        verifyDigest(record.nonce, proof.nonceDigest, IV_BYTES, true)
        verifyDigest(record.tag, proof.tagDigest, 16, true)
        verifyDigest(record.aad, proof.aadDigest, 32 * 1024)
        return CapturedCiphertextSnapshot(session.origin, session.account, requested, record.fileId,
            record.versionId, record.deviceId, record.revision.counter, record.keyEpoch, record.compartmentId,
            sha256(body), proof.ciphertextDigest)
    }

    private fun verifyDigest(value: String, digest: String, maxSize: Int, exact: Boolean = false) {
        try {
            if (!value.matches(Regex("[A-Za-z0-9_-]*")) || value.length % 4 == 1) throw SecurityException()
            val bytes = Base64.getUrlDecoder().decode(value)
            if (bytes.size > maxSize || (exact && bytes.size != maxSize) ||
                Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) != value ||
                sha256(bytes) != digest) throw SecurityException()
        } catch (_: Exception) {
            throw SecurityException("Invalid signed-envelope digest")
        }
    }

    private fun aad(snapshot: CapturedCiphertextSnapshot) = ByteArrayOutputStream().also { out ->
        DataOutputStream(out).use { data ->
            for (part in listOf("Root.ark/android/cipher-cache/v1", session.origin, session.account,
                    session.sessionNonce, snapshot.objectId, snapshot.fileId, snapshot.versionId,
                    snapshot.deviceId, snapshot.epoch, snapshot.compartment,
                    snapshot.envelopeSha256, snapshot.ciphertextDigest)) data.writeUTF(part)
            data.writeLong(snapshot.revisionCounter)
        }
    }.toByteArray()

    companion object {
        const val MAX_PACKET_BYTES = 4 * 1024 * 1024
        private const val IV_BYTES = 12
        private val MAGIC = "RKCACHE1".toByteArray(Charsets.US_ASCII)
        private fun sha256(bytes: ByteArray) = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(bytes))

        private fun boundedRead(file: File, limit: Int): ByteArray = FileInputStream(file).use { input ->
            val result = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                val count = input.read(buffer)
                if (count == -1) break
                if (count > limit - result.size()) throw SecurityException()
                result.write(buffer, 0, count)
            }
            result.toByteArray()
        }

        fun purgeStale(root: File) {
            if (!root.exists()) return
            if (!root.isDirectory || Files.isSymbolicLink(root.toPath())) throw SecurityException("Unsafe cache directory")
            val files = root.listFiles() ?: throw SecurityException("Unreadable cache directory")
            for (candidate in files) {
                if (!candidate.isFile && !Files.isSymbolicLink(candidate.toPath())) throw SecurityException("Unsafe cache entry")
                if (candidate.name != "packet.bin" &&
                    !candidate.name.matches(Regex("packet-[0-9a-f-]{36}\\.tmp"))) {
                    throw SecurityException("Unknown cache entry")
                }
                if (!candidate.delete()) throw SecurityException("Cache wipe failed")
            }
        }
    }
}
