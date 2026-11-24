package dev.rootark.core.sync

import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

data class OwnerSignedOfflineHeadV2(
    val schema: String,
    val origin: String,
    val username: String,
    val readerDeviceId: String,
    val ownerRevision: Long,
    val ownerDigest: String,
    val revokedDeviceIds: List<String>,
    val issuedAtMillis: Long,
    val expiresAtMillis: Long,
    val signature: String,
) {
    internal fun fields(): Map<String, Any> = mapOf(
        "schema" to schema, "origin" to origin, "username" to username,
        "readerDeviceId" to readerDeviceId, "ownerRevision" to ownerRevision,
        "ownerDigest" to ownerDigest, "revokedDeviceIds" to revokedDeviceIds,
        "issuedAtMillis" to issuedAtMillis, "expiresAtMillis" to expiresAtMillis,
    )

    internal fun digestFields(): Map<String, Any> = mapOf(
        "origin" to origin, "username" to username, "readerDeviceId" to readerDeviceId,
        "ownerRevision" to ownerRevision, "revokedDeviceIds" to revokedDeviceIds,
        "issuedAtMillis" to issuedAtMillis, "expiresAtMillis" to expiresAtMillis,
    )
}

data class OwnerSignedOfflineWrappedCekGrant(
    val schema: String,
    val origin: String,
    val username: String,
    val readerDeviceId: String,
    val ownerRevision: Long,
    val ownerDigest: String,
    val objectId: String,
    val fileId: String,
    val versionId: String,
    val compartmentId: String,
    val keyEpoch: String,
    val signerDeviceId: String,
    val signerPublicKeySpki: String,
    val cekSha256: String,
    val nonce: String,
    val issuedAtMillis: Long,
    val expiresAtMillis: Long,
    val hpkeSuite: String,
    val enc: String,
    val wrappedCek: String,
    val signature: String,
) {
    internal fun contextFields(): Map<String, Any> = mapOf(
        "schema" to schema, "origin" to origin, "username" to username,
        "readerDeviceId" to readerDeviceId, "ownerRevision" to ownerRevision,
        "ownerDigest" to ownerDigest, "objectId" to objectId, "fileId" to fileId,
        "versionId" to versionId, "compartmentId" to compartmentId, "keyEpoch" to keyEpoch,
        "signerDeviceId" to signerDeviceId, "signerPublicKeySpki" to signerPublicKeySpki,
        "cekSha256" to cekSha256, "nonce" to nonce, "issuedAtMillis" to issuedAtMillis,
        "expiresAtMillis" to expiresAtMillis, "hpkeSuite" to hpkeSuite, "enc" to enc,
    )

    internal fun fields(): Map<String, Any> = contextFields() + ("wrappedCek" to wrappedCek)
}

data class OwnerEnrollmentPackage(
    val schema: String,
    val ownerPublicSpki: String,
    val head: OwnerSignedOfflineHeadV2,
    val grant: OwnerSignedOfflineWrappedCekGrant,
)

/** Verifies owner-pinned V2 grants and keeps the owner-floor lock through CEK use. */
object OwnerEnrollmentAdmission {
    const val PACKAGE_SCHEMA = "rootark-android-enrollment-package/v2"
    const val HEAD_SCHEMA = "rootark-android-owner-head/v2"
    const val GRANT_SCHEMA = "rootark-android-cek-read-hpke/v2"
    const val HPKE_SUITE = HpkeP256.SUITE
    private const val MAX_LEASE_MILLIS = 300_000L
    private const val MAX_SAFE_INTEGER = 9_007_199_254_740_991L
    private val IDENTIFIER = Regex("[A-Za-z0-9._:-]{1,160}")
    private val OWNER_SPKI_PREFIX = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    )

    /** Device identity is derived only from the canonical uncompressed P-256 public point. */
    @JvmStatic
    fun readerDeviceId(publicKey: ByteArray): String {
        HpkeP256.decodePublicKey(publicKey)
        val digest = MessageDigest.getInstance("SHA-256").digest(publicKey)
        return "p256:" + digest.joinToString("") { "%02x".format(it) }
    }

    @JvmStatic
    fun ownerFingerprint(ownerPublicSpki: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(ownerPublicSpki)
            .joinToString("") { "%02X".format(it) }

    /** Verify a complete imported package without unwrapping or persisting any CEK. */
    @JvmStatic
    fun validatePackage(
        packageValue: OwnerEnrollmentPackage,
        pin: IndependentOfflineOwnerPin,
        readerPublicKey: ByteArray,
        nowMillis: Long = System.currentTimeMillis(),
    ): PinnedSyncReadContext {
        try {
            check(packageValue.schema == PACKAGE_SCHEMA)
            verifyPackageOwnerKey(packageValue, pin)
            validatePin(pin, readerPublicKey)
            verifyHead(packageValue.head, pin, nowMillis)
            verifyGrant(packageValue.grant, packageValue.head, pin, nowMillis)
            return readContext(packageValue.grant, packageValue.head, nowMillis)
        } catch (error: Exception) {
            throw ProtectedSyncException(error)
        }
    }

    /** Verify a fresh signed head before allocating its monotonic AndroidKeyStore alias. */
    @JvmStatic
    fun validateHead(
        head: OwnerSignedOfflineHeadV2,
        pin: IndependentOfflineOwnerPin,
        readerPublicKey: ByteArray,
        nowMillis: Long = System.currentTimeMillis(),
    ) {
        try {
            validatePin(pin, readerPublicKey)
            verifyHead(head, pin, nowMillis)
        } catch (error: Exception) {
            throw ProtectedSyncException(error)
        }
    }

    /** Persist the newest verified owner head before the package is made available to the UI. */
    @JvmStatic
    fun observeHead(
        head: OwnerSignedOfflineHeadV2,
        pin: IndependentOfflineOwnerPin,
        readerPublicKey: ByteArray,
        store: OwnerOfflineFloorStore,
        nowMillis: Long = System.currentTimeMillis(),
    ): IndependentOfflineOwnerPin {
        try {
            validatePin(pin, readerPublicKey)
            verifyHead(head, pin, nowMillis)
            val advancedPin = pin.copy(exactRevision = head.ownerRevision, exactDigest = head.ownerDigest)
            store.advance(advancedPin, head.ownerRevision, head.ownerDigest, nowMillis)
            return advancedPin
        } catch (error: RootArkApiException) {
            throw error
        } catch (error: ProtectedSyncException) {
            throw error
        } catch (error: Exception) {
            throw ProtectedSyncException(error)
        }
    }

    /**
     * The callback runs while the owner floor's OS lock is held. The caller
     * must keep fetch, content verification and plaintext consumption inside it.
     */
    @JvmStatic
    fun <T> withAuthorizedGrant(
        packageValue: OwnerEnrollmentPackage,
        pin: IndependentOfflineOwnerPin,
        readerPublicKey: ByteArray,
        store: OwnerOfflineFloorStore,
        nowMillis: Long = System.currentTimeMillis(),
        agree: (ByteArray) -> ByteArray,
        consume: (PinnedSyncReadContext, ByteArray) -> T,
    ): T {
        try {
            check(packageValue.schema == PACKAGE_SCHEMA)
            verifyPackageOwnerKey(packageValue, pin)
            validatePin(pin, readerPublicKey)
            verifyHead(packageValue.head, pin, nowMillis)
            verifyGrant(packageValue.grant, packageValue.head, pin, nowMillis)
            val head = packageValue.head
            val grant = packageValue.grant
            val floorPin = pin.copy(exactRevision = head.ownerRevision, exactDigest = head.ownerDigest)
            return store.advanceAndUse(floorPin, head.ownerRevision, head.ownerDigest, nowMillis) {
                val enc = OwnerPinnedOfflineAdmission.decode(grant.enc, 65)
                val wrapped = OwnerPinnedOfflineAdmission.decode(grant.wrappedCek, 48)
                val contextBytes = canonical(grant.contextFields())
                val info = "Root.ark/android/cek-read-hpke/v2/info\u0000".toByteArray(StandardCharsets.US_ASCII) + contextBytes
                val aad = "Root.ark/android/cek-read-hpke/v2/aad\u0000".toByteArray(StandardCharsets.US_ASCII) + contextBytes
                try {
                    val dh = agree(enc)
                    val cek = try { HpkeP256.open(enc, readerPublicKey, dh, info, aad, wrapped) }
                    finally { dh.fill(0) }
                    try {
                        val expected = OwnerPinnedOfflineAdmission.decode(grant.cekSha256, 32)
                        val actual = MessageDigest.getInstance("SHA-256").digest(cek)
                        try { check(MessageDigest.isEqual(expected, actual)) }
                        finally { expected.fill(0); actual.fill(0) }
                        consume(readContext(grant, head, nowMillis), cek)
                    } finally {
                        cek.fill(0)
                    }
                } finally {
                    enc.fill(0)
                    wrapped.fill(0)
                    contextBytes.fill(0)
                    info.fill(0)
                    aad.fill(0)
                }
            }
        } catch (error: RootArkApiException) {
            throw error
        } catch (error: ProtectedSyncException) {
            throw error
        } catch (error: Exception) {
            throw ProtectedSyncException(error)
        }
    }

    private fun validatePin(pin: IndependentOfflineOwnerPin, readerPublicKey: ByteArray) {
        check(pin.origin.isNotBlank() && pin.username.length in 1..128)
        val uri = URI(pin.origin)
        check(uri.scheme == "https" && uri.host != null && uri.userInfo == null &&
            uri.query == null && uri.fragment == null && uri.rawPath.isNullOrEmpty())
        check(pin.ownerPublicSpki.size == 44 && pin.ownerPublicSpkiSha256.size == 32)
        check(pin.ownerPublicSpki.copyOfRange(0, 12).contentEquals(OWNER_SPKI_PREFIX))
        check(MessageDigest.isEqual(
            MessageDigest.getInstance("SHA-256").digest(pin.ownerPublicSpki),
            pin.ownerPublicSpkiSha256,
        ))
        check(pin.readerDeviceId == readerDeviceId(readerPublicKey))
        check(pin.exactRevision in 1..MAX_SAFE_INTEGER)
        OwnerPinnedOfflineAdmission.decode(pin.exactDigest, 32)
    }

    private fun verifyPackageOwnerKey(packageValue: OwnerEnrollmentPackage, pin: IndependentOfflineOwnerPin) {
        val ownerSpki = OwnerPinnedOfflineAdmission.decode(packageValue.ownerPublicSpki, 44)
        try { check(ownerSpki.contentEquals(pin.ownerPublicSpki)) }
        finally { ownerSpki.fill(0) }
    }

    private fun verifyHead(head: OwnerSignedOfflineHeadV2, pin: IndependentOfflineOwnerPin, now: Long) {
        check(head.schema == HEAD_SCHEMA)
        check(head.origin == pin.origin && head.username == pin.username &&
            head.readerDeviceId == pin.readerDeviceId)
        check(head.ownerRevision in pin.exactRevision..MAX_SAFE_INTEGER)
        if (head.ownerRevision == pin.exactRevision) check(head.ownerDigest == pin.exactDigest)
        val canonicalHead = canonical(head.digestFields())
        val digestInput = "Root.ark/android/owner-head-digest/v2\u0000".toByteArray(StandardCharsets.UTF_8) + canonicalHead
        val digest = MessageDigest.getInstance("SHA-256").digest(digestInput)
        canonicalHead.fill(0)
        digestInput.fill(0)
        val expectedDigest = OwnerPinnedOfflineAdmission.decode(head.ownerDigest, 32)
        try {
            check(MessageDigest.isEqual(digest, expectedDigest)) {
                "Owner head digest mismatch: ${Base64.getUrlEncoder().withoutPadding().encodeToString(digest)} != ${head.ownerDigest}"
            }
        }
        finally { digest.fill(0); expectedDigest.fill(0) }
        check(head.revokedDeviceIds.size <= 128 &&
            head.revokedDeviceIds.all { it.matches(IDENTIFIER) } &&
            head.revokedDeviceIds == head.revokedDeviceIds.distinct().sorted())
        validWindow(head.issuedAtMillis, head.expiresAtMillis, now)
        verifyOwnerSignature(pin.ownerPublicSpki, "owner-head-v2", head.fields(), head.signature)
    }

    private fun verifyGrant(
        grant: OwnerSignedOfflineWrappedCekGrant,
        head: OwnerSignedOfflineHeadV2,
        pin: IndependentOfflineOwnerPin,
        now: Long,
    ) {
        check(grant.schema == GRANT_SCHEMA && grant.hpkeSuite == HPKE_SUITE)
        check(grant.origin == pin.origin && grant.username == pin.username &&
            grant.readerDeviceId == pin.readerDeviceId)
        check(grant.ownerRevision == head.ownerRevision && grant.ownerDigest == head.ownerDigest)
        for (id in listOf(grant.objectId, grant.fileId, grant.versionId, grant.compartmentId,
                grant.keyEpoch, grant.signerDeviceId)) check(id.matches(IDENTIFIER))
        check(grant.readerDeviceId !in head.revokedDeviceIds && grant.signerDeviceId !in head.revokedDeviceIds)
        validWindow(grant.issuedAtMillis, grant.expiresAtMillis, now)
        check(grant.issuedAtMillis >= head.issuedAtMillis - 30_000L)
        check(grant.expiresAtMillis <= head.expiresAtMillis)
        OwnerPinnedOfflineAdmission.decode(grant.cekSha256, 32).fill(0)
        OwnerPinnedOfflineAdmission.decode(grant.nonce, 16).fill(0)
        val signerSpki = OwnerPinnedOfflineAdmission.decode(grant.signerPublicKeySpki, 44)
        check(signerSpki.copyOfRange(0, 12).contentEquals(OWNER_SPKI_PREFIX))
        val enc = OwnerPinnedOfflineAdmission.decode(grant.enc, 65)
        try { HpkeP256.decodePublicKey(enc) } finally { enc.fill(0) }
        val wrapped = OwnerPinnedOfflineAdmission.decode(grant.wrappedCek, 48)
        wrapped.fill(0)
        verifyOwnerSignature(pin.ownerPublicSpki, "cek-read-hpke-v2", grant.fields(), grant.signature)
    }

    private fun readContext(
        grant: OwnerSignedOfflineWrappedCekGrant,
        head: OwnerSignedOfflineHeadV2,
        now: Long,
    ) = PinnedSyncReadContext(
        username = grant.username,
        objectId = grant.objectId,
        fileId = grant.fileId,
        versionId = grant.versionId,
        compartmentId = grant.compartmentId,
        keyEpoch = grant.keyEpoch,
        trustedDevicePublicKeys = mapOf(grant.signerDeviceId to grant.signerPublicKeySpki),
        revokedDeviceIds = head.revokedDeviceIds.toSet(),
        snapshotObtainedAtMillis = now,
        snapshotValidUntilMillis = minOf(grant.expiresAtMillis, head.expiresAtMillis),
    )

    private fun validWindow(issued: Long, expires: Long, now: Long) {
        check(issued in 1..MAX_SAFE_INTEGER && expires in 1..MAX_SAFE_INTEGER &&
            now in 1..MAX_SAFE_INTEGER && expires > issued)
        check(expires - issued <= MAX_LEASE_MILLIS)
        check(issued <= now + 30_000L && now < expires)
    }

    private fun verifyOwnerSignature(spki: ByteArray, kind: String, fields: Map<String, Any>, encoded: String) {
        val signer = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(spki))
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(signer)
        val canonicalFields = canonical(fields)
        val signedMessage = "Root.ark/android/$kind\u0000".toByteArray(StandardCharsets.UTF_8) + canonicalFields
        canonicalFields.fill(0)
        verifier.update(signedMessage)
        signedMessage.fill(0)
        val signature = OwnerPinnedOfflineAdmission.decode(encoded, 64)
        try { check(verifier.verify(signature)) } finally { signature.fill(0) }
    }

    private fun canonical(value: Any): ByteArray =
        ProtectedSyncContent.canonicalJson(value).toByteArray(StandardCharsets.UTF_8)
}
