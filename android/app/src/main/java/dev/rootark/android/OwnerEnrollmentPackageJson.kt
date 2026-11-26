package dev.rootark.android

import dev.rootark.core.sync.OwnerEnrollmentPackage
import dev.rootark.core.sync.OwnerSignedOfflineHeadV2
import dev.rootark.core.sync.OwnerSignedOfflineWrappedCekGrant
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import org.json.JSONObject
import org.json.JSONTokener

/** Strict JSON boundary for the independently transferred owner enrollment package. */
internal object OwnerEnrollmentPackageJson {
    private val PACKAGE_FIELDS = setOf("schema", "ownerPublicSpki", "head", "grant")
    private val HEAD_FIELDS = setOf(
        "schema", "origin", "username", "readerDeviceId", "ownerRevision", "ownerDigest",
        "revokedDeviceIds", "issuedAtMillis", "expiresAtMillis", "signature",
    )
    private val GRANT_FIELDS = setOf(
        "schema", "origin", "username", "readerDeviceId", "ownerRevision", "ownerDigest",
        "objectId", "fileId", "versionId", "compartmentId", "keyEpoch", "signerDeviceId",
        "signerPublicKeySpki", "cekSha256", "nonce", "issuedAtMillis", "expiresAtMillis",
        "hpkeSuite", "enc", "wrappedCek", "signature",
    )

    fun parse(bytes: ByteArray): OwnerEnrollmentPackage {
        try {
            if (bytes.size !in 2..32_768) throw ProtectedPackageException()
            val source = strictObject(bytes)
            exactKeys(source, PACKAGE_FIELDS)
            val head = objectValue(source, "head")
            val grant = objectValue(source, "grant")
            exactKeys(head, HEAD_FIELDS)
            exactKeys(grant, GRANT_FIELDS)
            val revoked = head.getJSONArray("revokedDeviceIds")
            if (revoked.length() > 128) throw ProtectedPackageException()
            val revokedIds = (0 until revoked.length()).map { index ->
                revoked.get(index) as? String ?: throw ProtectedPackageException()
            }
            return OwnerEnrollmentPackage(
                string(source, "schema"), string(source, "ownerPublicSpki"),
                OwnerSignedOfflineHeadV2(
                    string(head, "schema"), string(head, "origin"), string(head, "username"),
                    string(head, "readerDeviceId"), number(head, "ownerRevision"),
                    string(head, "ownerDigest"), revokedIds,
                    number(head, "issuedAtMillis"), number(head, "expiresAtMillis"),
                    string(head, "signature"),
                ),
                OwnerSignedOfflineWrappedCekGrant(
                    string(grant, "schema"), string(grant, "origin"), string(grant, "username"),
                    string(grant, "readerDeviceId"), number(grant, "ownerRevision"),
                    string(grant, "ownerDigest"), string(grant, "objectId"),
                    string(grant, "fileId"), string(grant, "versionId"),
                    string(grant, "compartmentId"), string(grant, "keyEpoch"),
                    string(grant, "signerDeviceId"), string(grant, "signerPublicKeySpki"),
                    string(grant, "cekSha256"), string(grant, "nonce"),
                    number(grant, "issuedAtMillis"), number(grant, "expiresAtMillis"),
                    string(grant, "hpkeSuite"), string(grant, "enc"),
                    string(grant, "wrappedCek"), string(grant, "signature"),
                ),
            )
        } catch (_: Exception) {
            throw ProtectedPackageException()
        }
    }

    private fun strictObject(bytes: ByteArray): JSONObject {
        val text = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes)).toString()
        StrictRfc8259Json.validate(text)
        val tokens = JSONTokener(text)
        val value = tokens.nextValue() as? JSONObject ?: throw ProtectedPackageException()
        if (tokens.nextClean() != '\u0000') throw ProtectedPackageException()
        return value
    }

    private fun objectValue(source: JSONObject, key: String): JSONObject =
        source.get(key) as? JSONObject ?: throw ProtectedPackageException()

    private fun exactKeys(source: JSONObject, expected: Set<String>) {
        val actual = mutableSetOf<String>()
        val names = source.keys()
        while (names.hasNext()) actual.add(names.next())
        if (actual != expected) throw ProtectedPackageException()
    }

    private fun string(source: JSONObject, key: String): String =
        source.get(key) as? String ?: throw ProtectedPackageException()

    private fun number(source: JSONObject, key: String): Long = when (val value = source.get(key)) {
        is Int -> value.toLong()
        is Long -> value
        else -> throw ProtectedPackageException()
    }

    private class ProtectedPackageException : IllegalArgumentException()
}
