package dev.rootark.android

import android.annotation.TargetApi
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.system.Os
import android.system.OsConstants
import dev.rootark.core.sync.IndependentOfflineOwnerPin
import dev.rootark.core.sync.OwnerFloorOpenedLock
import dev.rootark.core.sync.OwnerFloorRevisionIndex
import dev.rootark.core.sync.OwnerOfflineFloorStore
import java.io.File
import java.io.FileOutputStream
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardOpenOption
import java.security.KeyStore
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

internal data class OwnerOfflineFloorHandle(
    val store: OwnerOfflineFloorStore,
    val revision: Long,
    val alias: String,
    val seenAtMillis: Long,
    val sequence: Long,
    val floorRoot: File,
    val indexLock: OwnerFloorIndexLock,
    val sealedFloorCommitted: AtomicBoolean,
    val advanceAttempted: AtomicBoolean,
    val hadPendingAtStart: Boolean,
)

/** Retirement is separate from the durable floor write AND the durable enrollment save. */
internal enum class OwnerFloorRetirementPolicy {
    PROVISIONAL_ROLLBACK,
    PRESERVE_PRIOR_FOR_RECOVERY,
    RETIRE_PRIOR;

    companion object {
        fun afterOperation(floorSealed: Boolean, enrollmentSaved: Boolean,
                           floorAdvanceAttempted: Boolean = false): OwnerFloorRetirementPolicy =
            when {
                floorSealed && enrollmentSaved -> RETIRE_PRIOR
                floorSealed || floorAdvanceAttempted -> PRESERVE_PRIOR_FOR_RECOVERY
                else -> PROVISIONAL_ROLLBACK
            }
    }
}

internal class OwnerFloorIndexLock(
    private val channel: FileChannel,
    private val lock: FileLock,
    private val processLock: ReentrantLock,
) : AutoCloseable {
    override fun close() {
        try { if (lock.isValid) lock.release() }
        finally {
            try { channel.close() }
            finally { processLock.unlock() }
        }
    }
}

/** Hardware-authenticated per-use floor; alias high-water survives app-file and same-revision rollback. */
@TargetApi(Build.VERSION_CODES.S)
internal object OwnerOfflineHardwareFloor {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val AUTH_WINDOW_SECONDS = 30
    private val processIndexLock = ReentrantLock()

    private fun acquireIndexLock(noBackupRoot: File, availabilityOnly: Boolean = false): OwnerFloorIndexLock {
        // isAvailable runs on the Activity's UI thread. A protected fetch can
        // intentionally hold this lock for the duration of network I/O and
        // plaintext consumption; an availability hint must fail closed rather
        // than wait and freeze the UI. Real admissions keep the blocking lock.
        if (availabilityOnly) check(processIndexLock.tryLock())
        else processIndexLock.lock()
        var channel: FileChannel? = null
        try {
            val stateRoot = File(noBackupRoot, "owner-pinned-v2")
            check(stateRoot.isDirectory || stateRoot.mkdirs())
            validateNoSymlinkAncestors(stateRoot)
            val lockPath = File(stateRoot, "owner-floor-index-v2.lock").toPath()
            channel = FileChannel.open(
                lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS,
            )
            check(Files.isRegularFile(lockPath, LinkOption.NOFOLLOW_LINKS))
            val fileLock = (if (availabilityOnly) channel.tryLock() else channel.lock())
                ?: throw IllegalStateException("Owner floor index is busy")
            check(fileLock.isValid)
            return OwnerFloorIndexLock(channel, fileLock, processIndexLock)
        } catch (error: Throwable) {
            try { channel?.close() } catch (closeError: Throwable) {
                if (closeError !== error) error.addSuppressed(closeError)
            }
            processIndexLock.unlock()
            throw error
        }
    }

    private fun openPinnedLockDescriptor(file: File, createNew: Boolean): OwnerFloorOpenedLock {
        val flags = OsConstants.O_WRONLY or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC or
            (if (createNew) OsConstants.O_CREAT or OsConstants.O_EXCL else 0)
        val descriptor = Os.open(file.absolutePath, flags, 0x180)
        var owner: FileOutputStream? = null
        try {
            val stat = Os.fstat(descriptor)
            val identity = "(dev=${java.lang.Long.toHexString(stat.st_dev)},ino=${stat.st_ino})"
            owner = FileOutputStream(descriptor)
            return OwnerFloorOpenedLock(owner.channel, identity, owner,
                closeRawDescriptor = { Os.close(descriptor) })
        } catch (error: Throwable) {
            try { owner?.close() } catch (closeError: Throwable) {
                if (closeError !== error) error.addSuppressed(closeError)
            }
            try { Os.close(descriptor) } catch (closeError: Throwable) {
                if (closeError !== error) error.addSuppressed(closeError)
            }
            throw error
        }
    }

    fun open(
        noBackupRoot: File,
        pin: IndependentOfflineOwnerPin,
        revision: Long,
        ownerDigest: String,
        nowMillis: Long,
        allowInitialProvisioning: Boolean,
        prepareEnrollment: (() -> Unit)? = null,
    ): OwnerOfflineFloorHandle {
        var indexLock: OwnerFloorIndexLock? = null
        var createdAlias: String? = null
        var preparedEnrollment = false
        var hadPendingAtStart = false
        try {
            check(Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
            check(revision >= 1 && nowMillis > 0)
            check(pin.exactRevision in 1..revision && pin.exactDigest.isNotBlank())
            indexLock = acquireIndexLock(noBackupRoot)
            val digestBytes = Base64.getUrlDecoder().decode(ownerDigest)
            check(digestBytes.size == 32 &&
                Base64.getUrlEncoder().withoutPadding().encodeToString(digestBytes) == ownerDigest)
            val digestHex = digestBytes.joinToString("") { "%02x".format(it) }
            digestBytes.fill(0)

            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val aliases = keyStore.aliases().toList()
            val selection = OwnerFloorRevisionIndex.select(
                aliases, revision, digestHex, nowMillis, allowInitialProvisioning,
            )
            val next = selection.next
            val alias = next.alias
            check(!keyStore.containsAlias(alias))
            // The same process/cross-process index lock spans preparation,
            // alias allocation, floor seal, enrollment commit and retirement.
            // A concurrent protected read cannot race a staged revocation.
            hadPendingAtStart = OwnerEnrollmentStore(noBackupRoot).hasPending()
            if (prepareEnrollment == null) {
                check(!hadPendingAtStart)
            } else {
                prepareEnrollment()
                preparedEnrollment = true
            }
            createdAlias = alias
            val key = generateFloorKey(alias)
            validateHardwareKey(key)

            val floorRoot = File(File(noBackupRoot, "owner-pinned-v2"),
                "r$revision-$digestHex-t${next.seenAtMillis}-s${next.sequence}")
            validateNoSymlinkAncestors(floorRoot)
            val floorPath = File(floorRoot, "owner-floor-v1.bin").toPath()
            val lockPath = File(floorRoot, "owner-floor-v1.lock").toPath()
            val hasFloor = Files.exists(floorPath, LinkOption.NOFOLLOW_LINKS)
            val hasLock = Files.exists(lockPath, LinkOption.NOFOLLOW_LINKS)
            check(!hasFloor && !hasLock)

            val sealedFloorCommitted = AtomicBoolean(false)
            val advanceAttempted = AtomicBoolean(false)
            val store = OwnerOfflineFloorStore(
                floorRoot, key, allowFirstWrite = true,
                openDescriptorBoundLock = ::openPinnedLockDescriptor,
                onSealedFloor = { sealedFloorCommitted.set(true) },
                onAdvanceAttempted = { advanceAttempted.set(true) },
            )
            return OwnerOfflineFloorHandle(
                store, revision, alias, next.seenAtMillis, next.sequence, floorRoot, indexLock!!,
                sealedFloorCommitted, advanceAttempted, hadPendingAtStart,
            )
        } catch (error: Throwable) {
            // No floor write can have occurred before open() returns its
            // handle. Remove a partially provisioned alias on setup failure;
            // otherwise an unsupported software key could poison the index.
            val aliasRemoved = runCatching {
                val alias = createdAlias
                if (alias == null) true else {
                    val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
                    if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
                    !keyStore.containsAlias(alias)
                }
            }.getOrDefault(false)
            // open() never exposes a store capable of sealing before return.
            // Restore access to the previous committed enrollment only after
            // proving that any newly allocated hardware alias was deleted.
            if (preparedEnrollment && aliasRemoved && !hadPendingAtStart) {
                runCatching { OwnerEnrollmentStore(noBackupRoot).clearPending() }
            }
            runCatching { indexLock?.close() }
            if (error is Exception) throw SecurityException("Hardware-backed owner floor unavailable", error)
            throw error
        }
    }

    fun isAvailable(noBackupRoot: File, revision: Long, ownerDigest: String, nowMillis: Long): Boolean = runCatching {
        val indexLock = acquireIndexLock(noBackupRoot, availabilityOnly = true)
        try {
            check(!OwnerEnrollmentStore(noBackupRoot).hasPending())
            check(Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
            val digestBytes = Base64.getUrlDecoder().decode(ownerDigest)
            check(digestBytes.size == 32 &&
                Base64.getUrlEncoder().withoutPadding().encodeToString(digestBytes) == ownerDigest)
            val digestHex = digestBytes.joinToString("") { "%02x".format(it) }
            digestBytes.fill(0)
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val selection = OwnerFloorRevisionIndex.select(
                keyStore.aliases().toList(), revision, digestHex, nowMillis, allowInitialProvisioning = false,
            )
            val latest = selection.latest ?: return@runCatching false
            if (latest.revision != revision || latest.digest != digestHex) return@runCatching false
            val key = keyStore.getKey(latest.alias, null) as? SecretKey ?: return@runCatching false
            validateHardwareKey(key)
            true
        } finally { indexLock.close() }
    }.getOrDefault(false)

    /**
     * Never retire the last installed enrollment's aliases until BOTH its
     * replacement floor and signed/wrapped package have been durably saved.
     * A started seal that throws may have committed before the exception:
     * conservatively retain that alias (and all older aliases) for recovery.
     */
    fun retireOlder(handle: OwnerOfflineFloorHandle, enrollmentSaved: Boolean = true,
                    clearPreparedOnCommit: (() -> Unit)? = null,
                    clearPreparedOnAbort: (() -> Unit)? = null) {
        try {
            when (OwnerFloorRetirementPolicy.afterOperation(
                    handle.sealedFloorCommitted.get(), enrollmentSaved,
                    handle.advanceAttempted.get())) {
                OwnerFloorRetirementPolicy.PRESERVE_PRIOR_FOR_RECOVERY -> return
                OwnerFloorRetirementPolicy.PROVISIONAL_ROLLBACK -> {
                    // The core floor store, not a caller's guess, proves that
                    // advanceAndUse was never entered. Remove the provisional
                    // alias before lifting the staged fail-closed marker.
                    val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
                    if (keyStore.containsAlias(handle.alias)) keyStore.deleteEntry(handle.alias)
                    check(!keyStore.containsAlias(handle.alias))
                    // A failed retry cannot erase a pre-existing durable recovery constraint.
                    if (!handle.hadPendingAtStart) clearPreparedOnAbort?.invoke()
                    return
                }
                OwnerFloorRetirementPolicy.RETIRE_PRIOR -> Unit
            }
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val previous = OwnerFloorRevisionIndex.entries(keyStore.aliases().toList())
                .filter { it.alias != handle.alias }
            previous.forEach { entry -> runCatching { keyStore.deleteEntry(entry.alias) } }
            val stateRoot = handle.floorRoot.parentFile
            stateRoot?.listFiles()?.filter { candidate ->
                candidate != handle.floorRoot && !Files.isSymbolicLink(candidate.toPath()) &&
                    candidate.isDirectory && candidate.name.startsWith("r")
            }?.forEach { candidate -> runCatching { candidate.deleteRecursively() } }
        } catch (_: Exception) {
            // Retaining an older key cannot authorize rollback: the highest alias remains.
        } finally {
            // Still under the index lock: a second import cannot prepare a
            // different candidate between successful commit and marker clear.
            if (handle.sealedFloorCommitted.get() && enrollmentSaved) {
                runCatching { clearPreparedOnCommit?.invoke() }
            }
            runCatching { handle.indexLock.close() }
        }
    }

    private fun generateFloorKey(alias: String): SecretKey = KeyGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE,
    ).apply {
        init(KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(AUTH_WINDOW_SECONDS, KeyProperties.AUTH_DEVICE_CREDENTIAL)
            .build())
    }.generateKey()

    private fun validateHardwareKey(key: SecretKey) {
        check(key.encoded == null)
        val info = SecretKeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .getKeySpec(key, KeyInfo::class.java) as? KeyInfo
            ?: throw SecurityException("Owner floor KeyInfo unavailable")
        AndroidKeySecurityPolicy.requireHardwareDeviceCredentialKey(
            info.securityEvidence(), KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
        check(info.keySize == 256 && info.blockModes.contains(KeyProperties.BLOCK_MODE_GCM) &&
            info.encryptionPaddings.contains(KeyProperties.ENCRYPTION_PADDING_NONE))
    }

    private fun validateNoSymlinkAncestors(path: File) {
        var at: java.nio.file.Path? = path.toPath().toAbsolutePath().normalize()
        while (at != null) {
            check(!Files.isSymbolicLink(at))
            at = at.parent
        }
    }
}
