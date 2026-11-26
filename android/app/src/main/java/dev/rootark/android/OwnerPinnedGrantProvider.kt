package dev.rootark.android

import android.annotation.TargetApi
import android.content.Context
import android.os.Build
import dev.rootark.core.sync.OwnerEnrollmentAdmission
import dev.rootark.core.sync.PinnedSyncReadContext
import dev.rootark.core.sync.ProtectedSyncException

/** Production provider for imported owner-approved V2 packages; it never returns a raw CEK. */
internal class OwnerPinnedGrantProvider(
    private val context: Context,
    private val origin: String,
) : TrustedContentGrantProvider {
    private val enrollmentStore = OwnerEnrollmentStore(context.noBackupFilesDir)
    private val installationKey = AndroidInstallationKey(context)

    override fun obtain(username: String, objectId: String): ProtectedContentGrant? = null

    @TargetApi(Build.VERSION_CODES.TIRAMISU)
    override fun isAvailable(username: String, objectId: String): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return false
        // A verified newer owner head may have been staged but not sealed or
        // fully committed. Never release an older grant across that boundary.
        if (runCatching { enrollmentStore.hasPending() }.getOrDefault(true)) return false
        val stored = runCatching { enrollmentStore.load() }.getOrNull() ?: return false
        val available = try {
            if (!OwnerEnrollmentCapabilityPolicy.isEnabled(
                    stored.ecdhCapabilityVerified, stored.pin.origin == origin, stored.pin.username == username,
                )) false
            else {
                val identity = installationKey.publicIdentity(allowCreate = false)
                try {
                    val packageValue = OwnerEnrollmentPackageJson.parse(stored.packageBytes)
                    if (packageValue.grant.objectId != objectId) false
                    else {
                        val now = System.currentTimeMillis()
                        OwnerEnrollmentAdmission.validatePackage(
                            packageValue, stored.pin, identity.publicKey, now,
                        )
                        OwnerOfflineHardwareFloor.isAvailable(
                            context.noBackupFilesDir, packageValue.head.ownerRevision,
                            packageValue.head.ownerDigest, now,
                        )
                    }
                } finally { identity.publicKey.fill(0) }
            }
        } catch (_: Exception) {
            false
        } finally {
            stored.packageBytes.fill(0)
            stored.pin.ownerPublicSpki.fill(0)
            stored.pin.ownerPublicSpkiSha256.fill(0)
        }
        return available
    }

    @TargetApi(Build.VERSION_CODES.TIRAMISU)
    override fun <T> withGrant(
        username: String,
        objectId: String,
        consume: (PinnedSyncReadContext, ByteArray) -> T,
    ): T {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) throw ProtectedSyncException()
        if (runCatching { enrollmentStore.hasPending() }.getOrDefault(true)) {
            throw ProtectedSyncException()
        }
        val stored = enrollmentStore.load() ?: throw ProtectedSyncException()
        try {
            if (!OwnerEnrollmentCapabilityPolicy.isEnabled(
                    stored.ecdhCapabilityVerified, stored.pin.origin == origin, stored.pin.username == username,
                )) {
                throw ProtectedSyncException()
            }
            val identity = installationKey.publicIdentity(allowCreate = false)
            try {
                val packageValue = OwnerEnrollmentPackageJson.parse(stored.packageBytes)
                if (packageValue.grant.objectId != objectId) throw ProtectedSyncException()
                val now = System.currentTimeMillis()
                OwnerEnrollmentAdmission.validatePackage(
                    packageValue, stored.pin, identity.publicKey, now,
                )
                val floor = OwnerOfflineHardwareFloor.open(
                    context.noBackupFilesDir, stored.pin,
                    packageValue.head.ownerRevision, packageValue.head.ownerDigest,
                    nowMillis = now,
                    allowInitialProvisioning = false,
                )
                try {
                    return OwnerEnrollmentAdmission.withAuthorizedGrant(
                        packageValue, stored.pin, identity.publicKey, floor.store,
                        nowMillis = now,
                        agree = installationKey::agree,
                        consume = consume,
                    )
                } finally {
                    OwnerOfflineHardwareFloor.retireOlder(floor)
                }
            } finally {
                identity.publicKey.fill(0)
            }
        } finally {
            stored.packageBytes.fill(0)
            stored.pin.ownerPublicSpki.fill(0)
            stored.pin.ownerPublicSpkiSha256.fill(0)
        }
    }
}
