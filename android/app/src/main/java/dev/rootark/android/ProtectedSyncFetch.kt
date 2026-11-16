package dev.rootark.android

import dev.rootark.core.auth.ServerOrigin
import dev.rootark.core.sync.LoginOutcome
import dev.rootark.core.sync.PinnedSyncReadContext
import dev.rootark.core.sync.ProtectedSyncContent
import dev.rootark.core.sync.ProtectedSyncException
import dev.rootark.core.sync.ReadOnlyFileListPolicy
import dev.rootark.core.sync.RootArkApiException
import dev.rootark.core.sync.SyncAuthorizationProof
import dev.rootark.core.sync.SyncMetadata
import dev.rootark.core.sync.SyncOperationType
import dev.rootark.core.sync.SyncRecord
import dev.rootark.core.sync.SyncRevision
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.URL
import java.net.URLConnection
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import javax.net.ssl.HttpsURLConnection
import org.json.JSONObject
import org.json.JSONTokener

/**
 * The 32-byte CEK is caller-owned, ephemeral and consumed by this boundary.
 * Its key, device pin and current registry state MUST be provisioned by an
 * independently authenticated authority outside the server's sync response.
 */
internal data class ProtectedContentGrant(
    val context: PinnedSyncReadContext,
    val fileKey: ByteArray,
)

/** Deliberately has no implementation: the current Android login is not a ZK grant. */
internal fun interface TrustedContentGrantProvider {
    fun obtain(username: String, objectId: String): ProtectedContentGrant?
}

/**
 * App-internal, HTTPS-only bounded ciphertext transport.
 *
 * fetchCiphertext() returns an UNTRUSTED remote record: it is never plaintext
 * and callers must not treat metadata or server-supplied device pins as truth.
 * withVerifiedContent() accepts externally provisioned trust + CEK, verifies
 * the signed v2 envelope/AES-GCM, and wipes key/plaintext after the callback.
 * This component is not wired to any UI or automatic download.
 */
internal class ProtectedSyncFetch(
    private val openConnection: (URL) -> URLConnection = { it.openConnection() },
) {
    companion object {
        // An 8 MiB ciphertext becomes ~11.2 MiB base64url, plus signed metadata/AAD.
        const val MAX_RESPONSE_BYTES = 12 * 1024 * 1024
        const val BODY_READ_DEADLINE_NANOS = 10_000_000_000L
        private val TOKEN = Regex("[A-Za-z0-9._~-]{1,4096}")
    }

    fun fetchCiphertext(
        origin: ServerOrigin,
        session: LoginOutcome.Authenticated,
        objectId: String,
    ): SyncRecord {
        // Validate before opening the connection; the server checks these anew.
        val url = origin.syncObjectUrl(objectId)
        if (!ReadOnlyFileListPolicy.canList(session.permissions) ||
            session.username.isBlank() || !session.token.matches(TOKEN)) {
            throw ProtectedSyncException()
        }
        if (url.protocol != "https") throw ProtectedSyncException()
        val connection = openConnection(url) as? HttpsURLConnection
            ?: throw IOException("TLS transport unavailable")
        try {
            connection.requestMethod = "GET"
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.connectTimeout = 10_000
            connection.readTimeout = 10_000
            connection.setRequestProperty("Authorization", "Bearer ${session.token}")
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Accept-Encoding", "identity")
            connection.setRequestProperty("Cache-Control", "no-store")
            val status = connection.responseCode
            if (status != 200) throw RootArkApiException(status)
            val type = connection.contentType?.substringBefore(';')?.trim()
            if (!"application/json".equals(type, ignoreCase = true) ||
                (connection.contentEncoding != null &&
                    !connection.contentEncoding.equals("identity", ignoreCase = true))) {
                throw IOException("Invalid protected sync response")
            }
            if (connection.contentLengthLong > MAX_RESPONSE_BYTES) {
                throw IOException("Protected sync response exceeds limit")
            }
            val deadlineNanos = System.nanoTime() + BODY_READ_DEADLINE_NANOS
            val body = connection.inputStream.use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                var size = 0
                while (true) {
                    if (System.nanoTime() > deadlineNanos) {
                        connection.disconnect()
                        throw IOException("Protected sync response read deadline exceeded")
                    }
                    val read = input.read(buffer)
                    if (read < 0) break
                    if (read > MAX_RESPONSE_BYTES - size) {
                        throw IOException("Protected sync response exceeds limit")
                    }
                    output.write(buffer, 0, read)
                    size += read
                }
                output.toByteArray()
            }
            val record = StrictSyncRecordJson.parse(body)
            if (record.objectId != objectId) throw IOException("Protected sync object mismatch")
            return record
        } finally {
            connection.disconnect()
        }
    }

    /**
     * No plaintext leaves this callback scope as a return value. Consumers must
     * themselves be approved protected-content handlers and never retain bytes.
     */
    fun withVerifiedContent(
        origin: ServerOrigin,
        session: LoginOutcome.Authenticated,
        objectId: String,
        grantProvider: TrustedContentGrantProvider,
        consume: (ByteArray) -> Unit,
    ) {
        origin.syncObjectUrl(objectId)
        if (!ReadOnlyFileListPolicy.canList(session.permissions)) throw ProtectedSyncException()
        var grant: ProtectedContentGrant? = null
        try {
            grant = grantProvider.obtain(session.username, objectId)
            val currentGrant = grant ?: throw ProtectedSyncException()
            val context = currentGrant.context
            if (currentGrant.fileKey.size != 32 ||
                context.username != session.username || context.objectId != objectId ||
                context.trustedDevicePublicKeys.isEmpty()) {
                throw ProtectedSyncException()
            }
            val record = fetchCiphertext(origin, session, objectId)
            val plaintext = ProtectedSyncContent.verifyAndDecrypt(record, currentGrant.fileKey, context)
            try {
                consume(plaintext)
            } finally {
                plaintext.fill(0)
            }
        } finally {
            grant?.fileKey?.fill(0)
        }
    }
}

/** Exact field/type validation before turning attacker-controlled JSON into a wire model. */
private object StrictSyncRecordJson {
    private val FIELDS = setOf(
        "protocolVersion", "operationId", "objectId", "fileId", "versionId",
        "operation", "revision", "baseRevision", "keyEpoch", "compartmentId",
        "deviceId", "metadata", "tombstone", "ciphertext", "nonce", "tag", "aad", "authorization",
    )
    private val META = setOf(
        "fileId", "versionId", "path", "parentId", "name", "contentType",
        "size", "keyEpoch", "compartmentId", "deviceId", "sourcePath",
    )
    private val PROOF = setOf(
        "schemaVersion", "type", "suite", "protocolVersion", "username",
        "deviceId", "operationId", "objectId", "fileId", "versionId",
        "operation", "revision", "baseRevision", "keyEpoch", "compartmentId",
        "metadata", "aadDigest", "ciphertextDigest", "nonceDigest", "tagDigest",
        "expiresAt", "replayId", "idempotencyKey", "publicKey", "signature",
    )

    fun parse(raw: ByteArray): SyncRecord {
        try {
            val chars = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(raw)).toString()
            val tokens = JSONTokener(chars)
            val json = JSONObject(tokens)
            if (tokens.nextClean() != '\u0000') throw IOException()
            exactKeys(json, FIELDS)
            val metadata = metadata(obj(json, "metadata"))
            val proof = proof(obj(json, "authorization"))
            val result = SyncRecord(
                protocolVersion = integer(json, "protocolVersion"),
                operationId = string(json, "operationId"),
                objectId = string(json, "objectId"),
                fileId = string(json, "fileId"),
                versionId = string(json, "versionId"),
                operation = SyncOperationType.fromWire(string(json, "operation")),
                revision = revision(obj(json, "revision")),
                baseRevision = nullableObject(json, "baseRevision")?.let(::revision),
                keyEpoch = string(json, "keyEpoch"),
                compartmentId = string(json, "compartmentId"),
                deviceId = string(json, "deviceId"),
                metadata = metadata,
                tombstone = bool(json, "tombstone"),
                ciphertext = string(json, "ciphertext"),
                nonce = string(json, "nonce"),
                tag = string(json, "tag"),
                aad = string(json, "aad"),
                authorization = proof,
            )
            if (result.protocolVersion != 2 || result.objectId.length !in 1..160 ||
                result.operation !in setOf(SyncOperationType.CREATE, SyncOperationType.UPDATE) ||
                result.tombstone) throw IOException()
            return result
        } catch (_: Exception) {
            throw IOException("Invalid protected sync response")
        }
    }

    private fun exactKeys(json: JSONObject, allowed: Set<String>, requireAll: Boolean = true) {
        val actual = mutableSetOf<String>()
        val keys = json.keys()
        while (keys.hasNext()) actual.add(keys.next())
        if (actual.any { it !in allowed } || (requireAll && actual != allowed)) {
            throw IOException()
        }
    }

    private fun obj(json: JSONObject, name: String) = json.opt(name) as? JSONObject ?: throw IOException()
    private fun nullableObject(json: JSONObject, name: String): JSONObject? =
        if (json.opt(name) == JSONObject.NULL) null else obj(json, name)
    private fun string(json: JSONObject, name: String) = json.opt(name) as? String ?: throw IOException()
    private fun optionalString(json: JSONObject, name: String): String? {
        val raw = json.opt(name)
        return if (raw == null || raw == JSONObject.NULL) null else raw as? String ?: throw IOException()
    }
    private fun number(json: JSONObject, name: String): Long {
        val raw = json.opt(name)
        return when (raw) {
            is Int -> raw.toLong()
            is Long -> raw
            else -> throw IOException()
        }.also { if (it !in 0..9_007_199_254_740_991L) throw IOException() }
    }
    private fun integer(json: JSONObject, name: String): Int {
        val value = number(json, name)
        if (value > Int.MAX_VALUE) throw IOException()
        return value.toInt()
    }
    private fun bool(json: JSONObject, name: String) = json.opt(name) as? Boolean ?: throw IOException()

    private fun revision(json: JSONObject): SyncRevision {
        exactKeys(json, setOf("counter", "deviceId"))
        return SyncRevision(number(json, "counter"), string(json, "deviceId"))
    }

    private fun metadata(json: JSONObject): SyncMetadata {
        exactKeys(json, META, requireAll = false)
        return SyncMetadata(
            fileId = optionalString(json, "fileId"),
            versionId = optionalString(json, "versionId"),
            path = optionalString(json, "path"),
            parentId = optionalString(json, "parentId"),
            name = optionalString(json, "name"),
            contentType = optionalString(json, "contentType"),
            size = if (json.has("size") && json.opt("size") != JSONObject.NULL) number(json, "size") else null,
            keyEpoch = optionalString(json, "keyEpoch"),
            compartmentId = optionalString(json, "compartmentId"),
            deviceId = optionalString(json, "deviceId"),
            sourcePath = optionalString(json, "sourcePath"),
        )
    }

    private fun proof(json: JSONObject): SyncAuthorizationProof {
        exactKeys(json, PROOF)
        return SyncAuthorizationProof(
            schemaVersion = integer(json, "schemaVersion"),
            type = string(json, "type"),
            suite = string(json, "suite"),
            protocolVersion = integer(json, "protocolVersion"),
            username = string(json, "username"),
            deviceId = string(json, "deviceId"),
            operationId = string(json, "operationId"),
            objectId = string(json, "objectId"),
            fileId = string(json, "fileId"),
            versionId = string(json, "versionId"),
            operation = string(json, "operation"),
            revision = revision(obj(json, "revision")),
            baseRevision = nullableObject(json, "baseRevision")?.let(::revision),
            keyEpoch = string(json, "keyEpoch"),
            compartmentId = string(json, "compartmentId"),
            metadata = metadata(obj(json, "metadata")),
            aadDigest = string(json, "aadDigest"),
            ciphertextDigest = string(json, "ciphertextDigest"),
            nonceDigest = string(json, "nonceDigest"),
            tagDigest = string(json, "tagDigest"),
            expiresAt = number(json, "expiresAt"),
            replayId = string(json, "replayId"),
            idempotencyKey = string(json, "idempotencyKey"),
            publicKey = string(json, "publicKey"),
            signature = string(json, "signature"),
        )
    }
}
