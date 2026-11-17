package dev.rootark.android

import dev.rootark.core.sync.IndependentOfflineOwnerPin
import dev.rootark.core.sync.OwnerOfflineFloorStore
import dev.rootark.core.sync.OwnerPinnedOfflineAdmission
import dev.rootark.core.sync.OwnerSignedOfflineCekGrant
import dev.rootark.core.sync.OwnerSignedOfflineHead
import dev.rootark.core.sync.PinnedSyncReadContext
import dev.rootark.core.sync.ProtectedSyncException
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import org.json.JSONObject

/**
 * Import boundary for two owner-signed files supplied via an independent
 * operator channel. No server response, login, untrusted self-pin or persistent
 * raw CEK is an acceptable authority. There is deliberately no automatic UI
 * release: physical Keystore / offline policy acceptance remains outstanding.
 */
internal object OwnerPinnedOfflineImport {
    private val HEAD_FIELDS = setOf(
        "schema", "origin", "username", "readerDeviceId", "ownerRevision", "ownerDigest",
        "revokedDeviceIds", "issuedAtMillis", "expiresAtMillis", "signature",
    )
    private val GRANT_FIELDS = setOf(
        "schema", "origin", "username", "readerDeviceId", "ownerRevision", "ownerDigest",
        "objectId", "fileId", "versionId", "compartmentId", "keyEpoch",
        "signerDeviceId", "signerPublicKeySpki", "cekSha256", "nonce",
        "issuedAtMillis", "expiresAtMillis", "signature",
    )

    fun observeSignedHead(
        signedHeadBytes: ByteArray, independentPin: IndependentOfflineOwnerPin,
        floor: OwnerOfflineFloorStore, nowMillis: Long = System.currentTimeMillis(),
    ) {
        try {
            OwnerPinnedOfflineAdmission.observeHead(
                parseHead(signedHeadBytes), independentPin, floor, nowMillis,
            )
        } catch (_: Exception) { throw ProtectedSyncException() }
        finally { signedHeadBytes.fill(0) }
    }

    fun <T> withImportedGrant(
        signedHeadBytes: ByteArray, signedGrantBytes: ByteArray,
        independentPin: IndependentOfflineOwnerPin, offlineCek: ByteArray,
        floor: OwnerOfflineFloorStore, nowMillis: Long = System.currentTimeMillis(),
        consume: (PinnedSyncReadContext, ByteArray) -> T,
    ): T {
        try {
            return OwnerPinnedOfflineAdmission.withAuthorizedCek(
                parseGrant(signedGrantBytes), parseHead(signedHeadBytes),
                independentPin, offlineCek, floor, nowMillis, consume,
            )
        } catch (_: Exception) {
            throw ProtectedSyncException()
        } finally {
            signedHeadBytes.fill(0)
            signedGrantBytes.fill(0)
            // Also erase if JSON failed before the core could consume the CEK.
            offlineCek.fill(0)
        }
    }

    private fun parseHead(bytes: ByteArray): OwnerSignedOfflineHead {
        val source = parsed(bytes, HEAD_FIELDS)
        val revoked = source.getJSONArray("revokedDeviceIds")
        if (revoked.length() > 128) throw ProtectedSyncException()
        val ids = (0 until revoked.length()).map { index ->
            revoked.get(index) as? String ?: throw ProtectedSyncException()
        }
        return OwnerSignedOfflineHead(
            string(source, "schema"), string(source, "origin"), string(source, "username"),
            string(source, "readerDeviceId"), number(source, "ownerRevision"),
            string(source, "ownerDigest"), ids,
            number(source, "issuedAtMillis"), number(source, "expiresAtMillis"),
            string(source, "signature"),
        )
    }

    private fun parseGrant(bytes: ByteArray): OwnerSignedOfflineCekGrant {
        val source = parsed(bytes, GRANT_FIELDS)
        return OwnerSignedOfflineCekGrant(
            string(source, "schema"), string(source, "origin"), string(source, "username"),
            string(source, "readerDeviceId"), number(source, "ownerRevision"),
            string(source, "ownerDigest"), string(source, "objectId"),
            string(source, "fileId"), string(source, "versionId"),
            string(source, "compartmentId"), string(source, "keyEpoch"),
            string(source, "signerDeviceId"), string(source, "signerPublicKeySpki"),
            string(source, "cekSha256"), string(source, "nonce"),
            number(source, "issuedAtMillis"), number(source, "expiresAtMillis"),
            string(source, "signature"),
        )
    }

    private fun parsed(bytes: ByteArray, fields: Set<String>): JSONObject {
        if (bytes.size !in 2..8192) throw ProtectedSyncException()
        val text = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes)).toString()
        StrictRfc8259Json.validate(text)
        val json = JSONObject(text)
        val keys = mutableSetOf<String>()
        val names = json.keys()
        while (names.hasNext()) keys.add(names.next())
        if (keys != fields) throw ProtectedSyncException()
        return json
    }

    private fun string(value: JSONObject, field: String): String =
        value.get(field) as? String ?: throw ProtectedSyncException()

    private fun number(value: JSONObject, field: String): Long = when (val raw = value.get(field)) {
        is Int -> raw.toLong()
        is Long -> raw
        else -> throw ProtectedSyncException()
    }
}
