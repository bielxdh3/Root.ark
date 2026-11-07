package dev.rootark.core.sync

import java.io.File
import java.io.Closeable
import java.net.URI
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.LinkOption
import java.nio.file.OpenOption
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Separately provisioned owner identity and EXACT current owner head. Neither comes from sync HTTP. */
data class IndependentOfflineOwnerPin(
    val origin: String, val username: String, val readerDeviceId: String,
    val ownerPublicSpki: ByteArray, val ownerPublicSpkiSha256: ByteArray,
    val exactRevision: Long, val exactDigest: String,
)

/** Owner-signed, bounded revocation snapshot; offline copies cannot learn about later revocations. */
data class OwnerSignedOfflineHead(
    val schema: String, val origin: String, val username: String, val readerDeviceId: String,
    val ownerRevision: Long, val ownerDigest: String, val revokedDeviceIds: List<String>,
    val issuedAtMillis: Long, val expiresAtMillis: Long, val signature: String,
) {
    internal fun fields(): Map<String, Any> = mapOf(
        "schema" to schema, "origin" to origin, "username" to username,
        "readerDeviceId" to readerDeviceId, "ownerRevision" to ownerRevision,
        "ownerDigest" to ownerDigest, "revokedDeviceIds" to revokedDeviceIds,
        "issuedAtMillis" to issuedAtMillis, "expiresAtMillis" to expiresAtMillis,
    )
}

/** No CEK bytes or private identity are embedded in this owner-signed read grant. */
data class OwnerSignedOfflineCekGrant(
    val schema: String, val origin: String, val username: String, val readerDeviceId: String,
    val ownerRevision: Long, val ownerDigest: String,
    val objectId: String, val fileId: String, val versionId: String,
    val compartmentId: String, val keyEpoch: String, val signerDeviceId: String,
    val signerPublicKeySpki: String, val cekSha256: String, val nonce: String,
    val issuedAtMillis: Long, val expiresAtMillis: Long, val signature: String,
) {
    internal fun fields(): Map<String, Any> = mapOf(
        "schema" to schema, "origin" to origin, "username" to username,
        "readerDeviceId" to readerDeviceId, "ownerRevision" to ownerRevision,
        "ownerDigest" to ownerDigest, "objectId" to objectId, "fileId" to fileId,
        "versionId" to versionId, "compartmentId" to compartmentId, "keyEpoch" to keyEpoch,
        "signerDeviceId" to signerDeviceId, "signerPublicKeySpki" to signerPublicKeySpki,
        "cekSha256" to cekSha256, "nonce" to nonce,
        "issuedAtMillis" to issuedAtMillis, "expiresAtMillis" to expiresAtMillis,
    )
}

/**
 * Verifies two independent Ed25519 owner assertions and consumes an owner-held
 * 32-byte CEK. A login, TLS sync reply, signed record itself or encrypted local
 * cache can never supply the independent owner pin and exact head.
 *
 * This is a development-only enrollment admission primitive, not an Android
 * hardware attestation, a recovery grant, an HPKE V2 wrap or a license for
 * offline plaintext UI. The caller must keep protected offline unlock disabled
 * until the owner approves a lease and real on-device security is measured.
 */
object OwnerPinnedOfflineAdmission {
    private const val HEAD_SCHEMA = "rootark-android-owner-head/v1"
    private const val GRANT_SCHEMA = "rootark-android-cek-read/v1"
    private const val MAX_LEASE_MILLIS = 300_000L
    private val IDENTIFIER = Regex("[A-Za-z0-9._:-]{1,160}")
    private val B64 = Regex("[A-Za-z0-9_-]+")
    private val SPKI_PREFIX = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    )

    /** This operation is usable after restart; revocation never releases a CEK. */
    fun observeHead(
        head: OwnerSignedOfflineHead, pin: IndependentOfflineOwnerPin,
        store: OwnerOfflineFloorStore, nowMillis: Long = System.currentTimeMillis(),
    ) {
        try {
            verifiedHead(head, pin, nowMillis)
            store.advance(pin, head.ownerRevision, head.ownerDigest, nowMillis)
        } catch (_: Exception) {
            throw ProtectedSyncException()
        }
    }

    /** Caller-owned CEK is erased even if signature, floor, keystore, or consumer rejects. */
    fun <T> withAuthorizedCek(
        grant: OwnerSignedOfflineCekGrant,
        head: OwnerSignedOfflineHead,
        pin: IndependentOfflineOwnerPin,
        fileKey: ByteArray,
        store: OwnerOfflineFloorStore,
        nowMillis: Long = System.currentTimeMillis(),
        consume: (PinnedSyncReadContext, ByteArray) -> T,
    ): T {
        try {
            verifiedHead(head, pin, nowMillis)
            // Persist the independently pinned, owner-signed head even if the
            // accompanying grant is revoked, invalid, or otherwise denied.
            // Keystore/floor failures must abort BEFORE any CEK callback.
            return store.advanceAndUse(pin, head.ownerRevision, head.ownerDigest, nowMillis) {
                check(grant.schema == GRANT_SCHEMA)
                check(grant.origin == pin.origin && grant.username == pin.username)
                check(grant.readerDeviceId == pin.readerDeviceId)
                check(grant.ownerRevision == head.ownerRevision &&
                    grant.ownerDigest == head.ownerDigest)
                for (id in listOf(grant.objectId, grant.fileId, grant.versionId,
                        grant.compartmentId, grant.keyEpoch, grant.signerDeviceId)) {
                    check(id.matches(IDENTIFIER))
                }
                check(grant.readerDeviceId !in head.revokedDeviceIds &&
                    grant.signerDeviceId !in head.revokedDeviceIds)
                validWindow(grant.issuedAtMillis, grant.expiresAtMillis, nowMillis)
                check(grant.issuedAtMillis >= head.issuedAtMillis - 30_000L)
                check(grant.expiresAtMillis <= head.expiresAtMillis)
                decode(grant.nonce, 16)
                decode(grant.cekSha256, 32)
                val signingSpki = decode(grant.signerPublicKeySpki, 44)
                check(signingSpki.copyOfRange(0, 12).contentEquals(SPKI_PREFIX))
                verifySignature(pin.ownerPublicSpki, "cek-read", grant.fields(), grant.signature)
                check(fileKey.size == 32)
                check(MessageDigest.isEqual(
                    MessageDigest.getInstance("SHA-256").digest(fileKey),
                    decode(grant.cekSha256, 32),
                ))
                val context = PinnedSyncReadContext(
                    username = pin.username, objectId = grant.objectId,
                    fileId = grant.fileId, versionId = grant.versionId,
                    compartmentId = grant.compartmentId, keyEpoch = grant.keyEpoch,
                    trustedDevicePublicKeys = mapOf(grant.signerDeviceId to grant.signerPublicKeySpki),
                    revokedDeviceIds = head.revokedDeviceIds.toSet(),
                    snapshotObtainedAtMillis = nowMillis,
                    snapshotValidUntilMillis = minOf(grant.expiresAtMillis, head.expiresAtMillis),
                )
                // Erase the caller's CEK before releasing the floor FileLock;
                // the outer finally also covers failures before this point.
                try { consume(context, fileKey) } finally { fileKey.fill(0) }
            }
        } catch (_: Exception) {
            throw ProtectedSyncException()
        } finally {
            fileKey.fill(0)
        }
    }

    private fun verifiedHead(head: OwnerSignedOfflineHead, pin: IndependentOfflineOwnerPin, now: Long) {
        check(head.schema == HEAD_SCHEMA)
        val uri = URI(pin.origin)
        check(uri.scheme == "https" && uri.host != null && uri.userInfo == null &&
            uri.query == null && uri.fragment == null && uri.rawPath.isNullOrEmpty())
        check(pin.username.isNotBlank() && pin.username.length <= 128)
        check(pin.readerDeviceId.matches(IDENTIFIER))
        check(head.origin == pin.origin && head.username == pin.username &&
            head.readerDeviceId == pin.readerDeviceId)
        check(pin.exactRevision >= 1 && head.ownerRevision == pin.exactRevision)
        check(head.ownerDigest == pin.exactDigest)
        decode(head.ownerDigest, 32)
        check(head.revokedDeviceIds.size <= 128 &&
            head.revokedDeviceIds.all { it.matches(IDENTIFIER) } &&
            head.revokedDeviceIds == head.revokedDeviceIds.distinct().sorted())
        validWindow(head.issuedAtMillis, head.expiresAtMillis, now)
        check(pin.ownerPublicSpki.size == 44 && pin.ownerPublicSpkiSha256.size == 32)
        check(pin.ownerPublicSpki.copyOfRange(0, 12).contentEquals(SPKI_PREFIX))
        check(MessageDigest.isEqual(
            MessageDigest.getInstance("SHA-256").digest(pin.ownerPublicSpki),
            pin.ownerPublicSpkiSha256,
        ))
        verifySignature(pin.ownerPublicSpki, "owner-head", head.fields(), head.signature)
    }

    private fun validWindow(issued: Long, expires: Long, now: Long) {
        check(issued > 0 && expires > issued && now > 0)
        check(expires - issued <= MAX_LEASE_MILLIS)
        check(issued <= now + 30_000L && now < expires)
    }

    private fun verifySignature(spki: ByteArray, kind: String, fields: Map<String, Any>,
                                encoded: String) {
        val signer = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(spki))
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(signer)
        verifier.update(("Root.ark/android/$kind/v1\u0000" + canonical(fields))
            .toByteArray(StandardCharsets.UTF_8))
        check(verifier.verify(decode(encoded, 64)))
    }

    private fun canonical(value: Any): String = when (value) {
        is List<*> -> value.joinToString(",", "[", "]") { canonical(it as String) }
        is Map<*, *> -> value.keys.map { it as String }.sorted().joinToString(",", "{", "}") {
            canonical(it) + ":" + canonical(value[it] ?: throw ProtectedSyncException())
        }
        else -> ProtectedSyncContent.canonicalJson(value)
    }

    internal fun decode(text: String, count: Int): ByteArray {
        check(text.matches(B64) && text.length <= ((count + 2) / 3) * 4 + 2)
        val data = Base64.getUrlDecoder().decode(text)
        check(data.size == count &&
            Base64.getUrlEncoder().withoutPadding().encodeToString(data) == text)
        return data
    }
}

/**
 * One encrypted, crash-atomic high-water floor in app-private no-backup storage.
 * The injected key MUST be loaded from hardware-backed AndroidKeyStore by the
 * Android adapter; JVM tests intentionally use a disposable software key.
 * This is not independently rollback-resistant hardware storage: restoring an
 * older *valid* sealed floor or both file and Keystore/OS state still requires
 * external monotonic owner-head verification. No local file can prove R1 custody.
 * First-use privilege must come only from a newly created hardware key; callers
 * with an existing key are denied if either sealed file or stable lock goes missing.
 * A previously sealed OFLOOR1 is NOT automatically migrated: it did not bind the
 * durable lock inode and requires independently approved re-provisioning.
 */
class OwnerFloorOpenedLock(
    val channel: FileChannel,
    // Supplied ONLY by a trusted native fstat(opened file descriptor).
    // A fresh stat of the pathname is not descriptor evidence.
    val descriptorIdentity: String?,
    // Keep the stream owning the same FileDescriptor strongly reachable for
    // the entire lock lifetime; channel.close alone is sufficient in the JVM
    // fixture, but the native Android FileOutputStream must not be finalized.
    private val descriptorOwner: Closeable? = null,
    // FileOutputStream(FileDescriptor) is NOT the native fd owner on Android.
    // The Os.open-created fd must be explicitly Os.close'd after its lock and
    // channel have been released, including on exceptional paths.
    private val closeRawDescriptor: (() -> Unit)? = null,
) : Closeable {
    private val closed = AtomicBoolean(false)

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        var failure: Throwable? = null
        fun closeStep(step: () -> Unit) {
            try { step() } catch (error: Throwable) {
                val first = failure
                if (first == null) failure = error
                else if (first !== error) first.addSuppressed(error)
            }
        }
        // Never close the raw fd while its advisory FileLock/Channel is live.
        // Even if the stream wrapper close throws, still call native Os.close.
        closeStep { channel.close() }
        if (descriptorOwner != null) closeStep { descriptorOwner.close() }
        if (closeRawDescriptor != null) closeStep { closeRawDescriptor.invoke() }
        failure?.let { throw it }
    }
}

class OwnerOfflineFloorStore(
    private val root: File,
    private val key: SecretKey?,
    allowFirstWrite: Boolean = false,
    // The Android adapter supplies an O_NOFOLLOW native open + fstat of the
    // SAME descriptor that owns the OS lock. Null is a JVM-only, non-hostile
    // private-directory compatibility mode; it proves NO hostile-path safety.
    private val openDescriptorBoundLock: ((File, Boolean) -> OwnerFloorOpenedLock)? = null,
) {
    private val destination get() = File(root, "owner-floor-v1.bin")
    private val lockFile get() = File(root, "owner-floor-v1.lock")
    private val random = SecureRandom()
    private data class Floor(val revision: Long, val digest: String,
        val seenMillis: Long, val lockIdentity: String)
    private var bootstrapPending = allowFirstWrite

    private fun validateRootPath() {
        var at: java.nio.file.Path? = root.toPath().toAbsolutePath().normalize()
        while (at != null) {
            check(!Files.isSymbolicLink(at))
            at = at.parent
        }
    }

    // Android/Linux returns a stable dev/inode fileKey. It is sealed *inside*
    // the floor; a second process locking a replacement pathname must not
    // claim that it holds the old, already-established file's authority.
    // If a platform cannot supply a stable identity, fail closed rather than
    // claiming that a pathname alone constitutes durable serialization.
    private fun lockIdentity(): String {
        val attrs = Files.readAttributes(lockFile.toPath(), BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS)
        check(attrs.isRegularFile && !attrs.isSymbolicLink)
        val value = attrs.fileKey()?.toString() ?: throw ProtectedSyncException()
        check(value.length in 1..256 && value.none { it == '\n' || it == '\r' || it == '\u0000' })
        return value
    }

    private fun syncDirectory() {
        FileChannel.open(root.toPath(), StandardOpenOption.READ).use { it.force(true) }
    }

    fun advance(
        pin: IndependentOfflineOwnerPin, revision: Long, digest: String, nowMillis: Long,
    ) {
        advanceAndUse(pin, revision, digest, nowMillis) { Unit }
    }

    /** The signed head's durable floor and CEK consumer share one OS FileLock. */
    @Synchronized internal fun <T> advanceAndUse(
        pin: IndependentOfflineOwnerPin, revision: Long, digest: String, nowMillis: Long,
        consume: () -> T,
    ): T {
        try {
            val secret = key ?: throw ProtectedSyncException()
            check(secret.algorithm == "AES" && secret.encoded?.size != 0)
            check(nowMillis > 0 && revision >= 1)
            validateRootPath()
            if (!root.exists()) check(root.mkdirs())
            validateRootPath()
            check(root.isDirectory && !Files.isSymbolicLink(root.toPath()))
            check(!Files.isSymbolicLink(destination.toPath()))
            // The lock path is persistent and must never be unlinked after use.
            // A per-instance synchronized method alone cannot serialize two
            // admissions or separate Android processes sharing this floor.
            check(!Files.isSymbolicLink(lockFile.toPath()))
            val hasFloor = Files.exists(destination.toPath(), LinkOption.NOFOLLOW_LINKS)
            val hasLock = Files.exists(lockFile.toPath(), LinkOption.NOFOLLOW_LINKS)
            if (hasFloor) {
                // Never silently create a fresh inode when the persisted floor
                // and Keystore identity already exist.
                check(hasLock && Files.isRegularFile(lockFile.toPath(), LinkOption.NOFOLLOW_LINKS))
            } else {
                // A stale lock without a floor is evidence of prior enrollment
                // or interrupted bootstrap, not a free re-enrollment grant.
                check(bootstrapPending && !hasLock)
            }
            val beforeOpen = if (hasFloor) lockIdentity() else null
            val options: Array<OpenOption> = if (hasFloor)
                arrayOf(StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)
            else arrayOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS)
            val opened = if (openDescriptorBoundLock != null) {
                openDescriptorBoundLock.invoke(lockFile, !hasFloor)
            } else {
                OwnerFloorOpenedLock(FileChannel.open(lockFile.toPath(), *options), null)
            }
            return opened.use { bound ->
                bound.channel.tryLock().use { lock ->
                    check(lock != null && lock.isValid)
                    val lockedIdentity = lockIdentity()
                    if (beforeOpen != null) check(lockedIdentity == beforeOpen)
                    // A->B->A replacement during open can make both pathname
                    // stats report inode A even though tryLock locked B. The
                    // Android native fstat must bind this exact open channel
                    // to the durable identity or deny BEFORE decrypt/CEK.
                    if (openDescriptorBoundLock != null) {
                        check(bound.descriptorIdentity == lockedIdentity)
                    }
                    check(!Files.isSymbolicLink(destination.toPath()))
                    // Persist new lock directory entry before any sealed floor
                    // can become durable; a crash must never yield a floor with
                    // a silently missing lock path.
                    if (!hasFloor) syncDirectory()
                    val aad = aad(pin)
                    // Read, compare, and atomically commit UNDER THE SAME lock.
                    val previous = read(secret, aad, lockedIdentity)
                    if (previous == null) {
                        check(bootstrapPending)
                        // A failed first write is terminal, not implicit
                        // re-enrollment with an existing Keystore identity.
                        bootstrapPending = false
                    } else {
                        bootstrapPending = false
                        check(nowMillis >= previous.seenMillis)
                        check(revision >= previous.revision)
                        if (revision == previous.revision) check(digest == previous.digest)
                    }
                    check(lockIdentity() == lockedIdentity)
                    if (openDescriptorBoundLock != null) {
                        check(bound.descriptorIdentity == lockedIdentity)
                    }
                    val iv = ByteArray(12).also(random::nextBytes)
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(Cipher.ENCRYPT_MODE, secret, GCMParameterSpec(128, iv))
                    cipher.updateAAD(aad)
                    val plaintext = "$revision\n$digest\n$nowMillis\n$lockedIdentity"
                        .toByteArray(StandardCharsets.US_ASCII)
                    val encrypted = try { cipher.doFinal(plaintext) } finally { plaintext.fill(0) }
                    val temporary = Files.createTempFile(root.toPath(), "owner-floor-", ".tmp")
                    try {
                        val tempIdentity = Files.readAttributes(temporary,
                            BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                            .fileKey()?.toString() ?: throw ProtectedSyncException()
                        val sealed = ByteBuffer.allocate(7 + iv.size + encrypted.size)
                        sealed.put("OFLOOR2".toByteArray(StandardCharsets.US_ASCII))
                        sealed.put(iv)
                        sealed.put(encrypted)
                        sealed.flip()
                        try {
                            FileChannel.open(temporary, StandardOpenOption.WRITE,
                                LinkOption.NOFOLLOW_LINKS).use { output ->
                                while (sealed.hasRemaining()) check(output.write(sealed) > 0)
                                output.force(true)
                            }
                        } finally { sealed.array().fill(0) }
                        check(Files.readAttributes(temporary, BasicFileAttributes::class.java,
                            LinkOption.NOFOLLOW_LINKS).fileKey()?.toString() == tempIdentity)
                        check(lockIdentity() == lockedIdentity)
                        if (openDescriptorBoundLock != null) {
                            check(bound.descriptorIdentity == lockedIdentity)
                        }
                        Files.move(temporary, destination.toPath(),
                            StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                        // A file fsync does not persist the directory rename.
                        // Deny admission if metadata or stable lock identity
                        // cannot be confirmed before the CEK callback can run.
                        syncDirectory()
                        check(lockIdentity() == lockedIdentity)
                        if (openDescriptorBoundLock != null) {
                            check(bound.descriptorIdentity == lockedIdentity)
                        }
                    } finally {
                        if (Files.exists(temporary, LinkOption.NOFOLLOW_LINKS))
                            Files.deleteIfExists(temporary)
                        iv.fill(0)
                        encrypted.fill(0)
                    }
                    // The callback is synchronous and runs while the SAME
                    // descriptor-bound lock remains valid. A newer signed
                    // observeHead cannot commit between floor validation and
                    // CEK use, even through a different store instance.
                    check(lock.isValid && lockIdentity() == lockedIdentity)
                    consume()
                }
            }
        } catch (_: Exception) {
            throw ProtectedSyncException()
        }
    }

    private fun aad(pin: IndependentOfflineOwnerPin): ByteArray =
        ("Root.ark/android/owner-floor/v1\u0000" + pin.origin + "\u0000" + pin.username +
            "\u0000" + pin.readerDeviceId + "\u0000" +
            Base64.getUrlEncoder().withoutPadding().encodeToString(pin.ownerPublicSpkiSha256))
            .toByteArray(StandardCharsets.UTF_8)

    private fun read(secret: SecretKey, aad: ByteArray, expectedLock: String): Floor? {
        if (!Files.exists(destination.toPath(), LinkOption.NOFOLLOW_LINKS)) return null
        check(Files.isRegularFile(destination.toPath(), LinkOption.NOFOLLOW_LINKS))
        val raw = FileChannel.open(destination.toPath(), StandardOpenOption.READ,
            LinkOption.NOFOLLOW_LINKS).use { channel ->
            val length = channel.size()
            check(length in 36..512)
            val buffer = ByteBuffer.allocate(length.toInt())
            while (buffer.hasRemaining()) check(channel.read(buffer) > 0)
            buffer.array()
        }
        try {
            check(raw.copyOfRange(0, 7).contentEquals("OFLOOR2".toByteArray(StandardCharsets.US_ASCII)))
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secret, GCMParameterSpec(128, raw.copyOfRange(7, 19)))
            cipher.updateAAD(aad)
            val plaintext = cipher.doFinal(raw, 19, raw.size - 19)
            try {
                val parts = String(plaintext, StandardCharsets.US_ASCII).split("\n")
                check(parts.size == 4)
                val revision = parts[0].toLong()
                OwnerPinnedOfflineAdmission.decode(parts[1], 32)
                val seen = parts[2].toLong()
                check(revision >= 1 && seen >= 1)
                check(parts[3] == expectedLock)
                return Floor(revision, parts[1], seen, parts[3])
            } finally { plaintext.fill(0) }
        } finally { raw.fill(0) }
    }
}
