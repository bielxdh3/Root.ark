package dev.rootark.android

import android.system.Os
import android.system.OsConstants
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import dev.rootark.core.sync.OwnerOfflineFloorStore
import dev.rootark.core.sync.OwnerFloorOpenedLock
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/**
 * App-only adapter for the owner-signed high-water floor. KeyInfo is queried
 * from the actual platform; a software key is refused instead of being called
 * hardware-backed. No physical device or StrongBox property is claimed here.
 */
internal object OwnerOfflineHardwareFloor {
    private const val ALIAS = "dev.rootark.android.owner-floor-hardware-v1"

    private fun openPinnedLockDescriptor(file: File, createNew: Boolean): OwnerFloorOpenedLock {
        // Unlike java.nio FileChannel.open(), Android's Os.open/fstat keeps the
        // identity of the SAME fd which takes the advisory exclusive lock.
        // No pathname stat, symlink, or replacement inode may impersonate it.
        val flags = OsConstants.O_WRONLY or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC or
            (if (createNew) OsConstants.O_CREAT or OsConstants.O_EXCL else 0)
        val descriptor = Os.open(file.absolutePath, flags, 0x180) // 0600
        var owner: FileOutputStream? = null
        try {
            val stat = Os.fstat(descriptor)
            val identity = "(dev=${java.lang.Long.toHexString(stat.st_dev)},ino=${stat.st_ino})"
            owner = FileOutputStream(descriptor)
            return OwnerFloorOpenedLock(owner.channel, identity, owner,
                closeRawDescriptor = { Os.close(descriptor) })
        } catch (error: Throwable) {
            // A failed fstat/channel-wrapper construction is still an owned
            // native FD. Close the wrapper first, then the raw fd exactly once.
            try { owner?.close() } catch (closeError: Throwable) {
                if (closeError !== error) error.addSuppressed(closeError)
            }
            try { Os.close(descriptor) } catch (closeError: Throwable) {
                if (closeError !== error) error.addSuppressed(closeError)
            }
            throw error
        }
    }

    fun open(noBackupRoot: File): OwnerOfflineFloorStore {
        try {
            val state = File(noBackupRoot, "owner-pinned-v1")
            val keystore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val stored = keystore.getKey(ALIAS, null)
            val floorPath = File(state, "owner-floor-v1.bin").toPath()
            val lockPath = File(state, "owner-floor-v1.lock").toPath()
            // A dangling symlink is still an occupied or tampered path.
            val sealedFloorExists = Files.exists(floorPath, LinkOption.NOFOLLOW_LINKS)
            val previousLockExists = Files.exists(lockPath, LinkOption.NOFOLLOW_LINKS)
            if (stored == null && sealedFloorExists)
                throw SecurityException("Floor survived without its Keystore key")
            if (stored != null && !sealedFloorExists)
                throw SecurityException("Floor/key provisioning mismatch")
            if (stored != null && !previousLockExists)
                throw SecurityException("Established floor lost its stable lock")
            if (stored == null && previousLockExists)
                throw SecurityException("Previous enrollment state survived without its key")
            if ((sealedFloorExists && !Files.isRegularFile(floorPath, LinkOption.NOFOLLOW_LINKS)) ||
                (previousLockExists && !Files.isRegularFile(lockPath, LinkOption.NOFOLLOW_LINKS)))
                throw SecurityException("Owner floor path replaced")
            val key = (stored as? SecretKey) ?: KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
            ).apply {
                init(KeyGenParameterSpec.Builder(
                    ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true)
                    .setKeySize(256)
                    // The operator must authenticate locally. No silent
                    // software-provider fallback or permanent unlock window.
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationValidityDurationSeconds(30)
                    .build())
            }.generateKey()
            val info = SecretKeyFactory.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
            ).getKeySpec(key, KeyInfo::class.java) as? KeyInfo
                ?: throw SecurityException("KeyInfo unavailable")
            if (!info.isInsideSecureHardware || !info.isUserAuthenticationRequired ||
                info.userAuthenticationValidityDurationSeconds !in 0..30)
                throw SecurityException("Hardware authentication unavailable")
            // Reuse of a prior Keystore alias NEVER silently resets a missing
            // floor. Only a brand-new key starts a single first-write lease.
            return OwnerOfflineFloorStore(state, key, allowFirstWrite = stored == null,
                openDescriptorBoundLock = ::openPinnedLockDescriptor)
        } catch (_: Exception) {
            throw SecurityException("Owner offline floor unavailable")
        }
    }
}
