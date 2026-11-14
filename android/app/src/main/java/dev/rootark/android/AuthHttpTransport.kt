package dev.rootark.android

import dev.rootark.core.auth.ServerOrigin
import dev.rootark.core.sync.ReadOnlyFileListPolicy
import dev.rootark.core.sync.InventoryPage
import dev.rootark.core.sync.PagedInventoryPolicy
import dev.rootark.core.sync.LoginOutcome
import dev.rootark.core.sync.RootArkApiException
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.math.BigDecimal
import java.math.BigInteger
import java.net.HttpURLConnection
import java.nio.charset.StandardCharsets
import org.json.JSONException
import org.json.JSONObject

open class SyncListingException(message: String, cause: Throwable? = null) : IOException(message, cause)
class SyncListingLimitException(message: String) : SyncListingException(message)
class SyncListingValidationException(message: String, cause: Throwable? = null) : SyncListingException(message, cause)

/** HTTP adapter for canonical login/TOTP and the bounded, read-only sync listing. */
internal class AuthHttpTransport {
    fun login(origin: ServerOrigin, username: String, password: String): LoginOutcome {
        val (status, json) = post(origin.loginUrl(), JSONObject().put("username", username).put("password", password))
        if (status == 403) {
            if (json.opt("enrollmentRequired") != true) throw RootArkApiException(status)
            return LoginOutcome.EnrollmentRequired(
                true, requiredString(json, "token"), requiredString(json, "username"), requiredPositiveInt(json, "expiresIn")
            )
        }
        if (json.opt("challengeRequired") == true) {
            return LoginOutcome.ChallengeRequired(true, requiredString(json, "challengeId"), requiredPositiveInt(json, "expiresIn"))
        }
        return authenticated(json)
    }

    fun completeTwoFactorLogin(origin: ServerOrigin, challengeId: String, code: String): LoginOutcome.Authenticated {
        val (status, json) = post(origin.twoFactorUrl(), JSONObject().put("challengeId", challengeId).put("code", code))
        if (status != 200 || json.has("challengeRequired") || json.has("enrollmentRequired")) {
            throw IOException("Unexpected authentication response")
        }
        return authenticated(json)
    }

    /** The issue #66 endpoint returns metadata only; one page is retained at a time. */
    fun listInventoryPage(origin: ServerOrigin, token: String, cursor: String? = null): InventoryPage {
        require(token.isNotBlank() && token.length <= 4096)
        val connection = origin.syncInventoryUrl(cursor).openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "GET"
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.connectTimeout = 10_000
            connection.readTimeout = 10_000
            connection.setRequestProperty("Authorization", "Bearer $token")
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Cache-Control", "no-store")
            val status = connection.responseCode
            if (status != 200) throw RootArkApiException(status)
            val json = connection.inputStream.use { stream ->
                val out = ByteArrayOutputStream()
                val buffer = ByteArray(4096)
                var total = 0
                while (true) {
                    val count = stream.read(buffer)
                    if (count < 0) break
                    total += count
                    if (total > PagedInventoryPolicy.MAX_RESPONSE_BYTES) {
                        throw SyncListingLimitException("Inventory page exceeds limit")
                    }
                    out.write(buffer, 0, count)
                }
                try {
                    JSONObject(String(out.toByteArray(), StandardCharsets.UTF_8))
                } catch (e: JSONException) {
                    throw SyncListingValidationException("Malformed JSON in sync listing", e)
                }
            }
            return projectInventoryPage(json)
        } finally {
            connection.disconnect()
        }
    }

    internal fun projectInventoryPage(response: JSONObject): InventoryPage {
        val objects = response.optJSONArray("objects") ?: throw SyncListingValidationException("Invalid inventory page")
        if (objects.length() > PagedInventoryPolicy.MAX_ENTRIES) {
            throw SyncListingLimitException("Inventory page exceeds maximum entry limit")
        }
        val version = parseProtocolVersion(response.opt("protocolVersion"))
            ?: throw SyncListingValidationException("Invalid inventory page")
        val view = response.opt("view") as? String ?: throw SyncListingValidationException("Invalid inventory page")
        if (!response.has("nextCursor")) throw SyncListingValidationException("Invalid inventory page")
        val nextCursor = when (val value = response.opt("nextCursor")) {
            JSONObject.NULL -> null
            is String -> value
            else -> throw SyncListingValidationException("Invalid inventory cursor")
        }
        try {
            PagedInventoryPolicy.checkEnvelope(version, view, objects.length(), nextCursor)
            val rows = (0 until objects.length()).map { index ->
                val record = objects.optJSONObject(index) ?: throw SyncListingValidationException("Invalid sync listing")
                val metadata = record.optJSONObject("metadata") ?: throw SyncListingValidationException("Invalid sync listing")
                val deleted = record.opt("tombstone") as? Boolean ?: throw SyncListingValidationException("Invalid sync listing")
                val recordVersion = parseProtocolVersion(record.opt("protocolVersion"))
                    ?: throw SyncListingValidationException("Invalid sync listing")
                val revision = record.optJSONObject("revision") ?: throw SyncListingValidationException("Invalid sync listing")
                val counter = parseNonNegativeLong(revision.opt("counter"))
                    ?: throw SyncListingValidationException("Invalid sync listing")
                if (requiredListingString(revision, "deviceId").length > 256) {
                    throw SyncListingValidationException("Invalid sync listing")
                }

                ReadOnlyFileListPolicy.project(
                    protocolVersion = recordVersion,
                    objectId = requiredListingString(record, "objectId"),
                    operation = requiredListingString(record, "operation"),
                    tombstone = deleted,
                    name = optionalString(metadata, "name"),
                    path = optionalString(metadata, "path"),
                    size = optionalLong(metadata, "size"),
                    contentType = optionalString(metadata, "contentType"),
                )
            }
            return InventoryPage(rows, nextCursor)
        } catch (_: IllegalArgumentException) {
            throw SyncListingValidationException("Invalid or oversized inventory page")
        }
    }

    internal fun projectList(response: JSONObject): List<ReadOnlyFileRow> {
        val objects = response.optJSONArray("objects") ?: throw SyncListingValidationException("Invalid sync listing")
        if (objects.length() > ReadOnlyFileListPolicy.MAX_ENTRIES) {
            throw SyncListingLimitException("Sync listing exceeds maximum entry limit")
        }
        val version = parseProtocolVersion(response.opt("protocolVersion"))
            ?: throw SyncListingValidationException("Invalid sync listing")
        try {
            ReadOnlyFileListPolicy.checkEnvelope(version, objects.length())
            return (0 until objects.length()).map { index ->
                val record = objects.optJSONObject(index) ?: throw SyncListingValidationException("Invalid sync listing")
                val metadata = record.optJSONObject("metadata") ?: throw SyncListingValidationException("Invalid sync listing")
                val deleted = record.opt("tombstone") as? Boolean ?: throw SyncListingValidationException("Invalid sync listing")
                val recordVersion = parseProtocolVersion(record.opt("protocolVersion"))
                    ?: throw SyncListingValidationException("Invalid sync listing")
                val revision = record.optJSONObject("revision") ?: throw SyncListingValidationException("Invalid sync listing")
                val counter = parseNonNegativeLong(revision.opt("counter"))
                    ?: throw SyncListingValidationException("Invalid sync listing")
                if (requiredListingString(revision, "deviceId").length > 256) {
                    throw SyncListingValidationException("Invalid sync listing")
                }

                ReadOnlyFileListPolicy.project(
                    protocolVersion = recordVersion,
                    objectId = requiredListingString(record, "objectId"),
                    operation = requiredListingString(record, "operation"),
                    tombstone = deleted,
                    name = optionalString(metadata, "name"),
                    path = optionalString(metadata, "path"),
                    size = optionalLong(metadata, "size"),
                    contentType = optionalString(metadata, "contentType"),
                )
            }
        } catch (_: IllegalArgumentException) {
            throw SyncListingValidationException("Invalid sync listing")
        }
    }

    internal fun parseProtocolVersion(value: Any?): Int? = when (value) {
        is Int -> value
        is Short -> value.toInt()
        is Byte -> value.toInt()
        is Long -> if (value in Int.MIN_VALUE..Int.MAX_VALUE) value.toInt() else null
        is BigInteger -> try {
            value.intValueExact()
        } catch (_: ArithmeticException) {
            null
        }
        is BigDecimal -> exactBigDecimalInt(value)
        is Double, is Float -> null
        else -> null
    }

    internal fun parseNonNegativeLong(value: Any?): Long? = when (value) {
        is Int -> if (value >= 0) value.toLong() else null
        is Long -> if (value >= 0L) value else null
        is Short -> if (value >= 0) value.toLong() else null
        is Byte -> if (value >= 0) value.toLong() else null
        is BigInteger -> try {
            val l = value.longValueExact()
            if (l >= 0L) l else null
        } catch (_: ArithmeticException) {
            null
        }
        is BigDecimal -> exactBigDecimalLong(value)?.takeIf { it >= 0L }
        is Double, is Float -> null
        else -> null
    }

    internal fun parsePositiveInt(value: Any?): Int? = when (value) {
        is Int -> if (value > 0) value else null
        is Short -> if (value > 0) value.toInt() else null
        is Byte -> if (value > 0) value.toInt() else null
        is Long -> if (value in 1..Int.MAX_VALUE) value.toInt() else null
        is BigInteger -> try {
            val i = value.intValueExact()
            if (i > 0) i else null
        } catch (_: ArithmeticException) {
            null
        }
        is BigDecimal -> exactBigDecimalInt(value)?.takeIf { it > 0 }
        is Double, is Float -> null
        else -> null
    }

    private fun optionalString(json: JSONObject, key: String): String? {
        val value = json.opt(key)
        if (value == null || value == JSONObject.NULL) return null
        return value as? String ?: throw SyncListingValidationException("Invalid sync listing")
    }

    internal fun optionalLong(json: JSONObject, key: String): Long? {
        val value = json.opt(key)
        if (value == null || value == JSONObject.NULL) return null
        return when (value) {
            is Int -> value.toLong()
            is Long -> value
            is Short -> value.toLong()
            is Byte -> value.toLong()
            is BigInteger -> try {
                value.longValueExact()
            } catch (_: ArithmeticException) {
                throw SyncListingValidationException("Invalid sync listing")
            }
            is BigDecimal -> exactBigDecimalLong(value)
                ?: throw SyncListingValidationException("Invalid sync listing")
            is Double, is Float -> throw SyncListingValidationException("Invalid sync listing")
            else -> throw SyncListingValidationException("Invalid sync listing")
        }
    }

    private fun exactBigDecimalLong(value: BigDecimal): Long? {
        if (value.signum() == 0) return 0L
        if (value.scale() !in -19..64) return null
        val intDigits = value.precision().toLong() - value.scale().toLong()
        if (intDigits < 1L || intDigits > 19L) return null
        return try {
            value.longValueExact()
        } catch (_: ArithmeticException) {
            null
        }
    }

    private fun exactBigDecimalInt(value: BigDecimal): Int? =
        exactBigDecimalLong(value)?.takeIf { it in Int.MIN_VALUE..Int.MAX_VALUE }?.toInt()

    private fun authenticated(json: JSONObject): LoginOutcome.Authenticated {
        val rawPermissions = json.optJSONObject("permissions") ?: throw IOException("Unexpected authentication response")
        val permissions = mutableMapOf<String, Boolean>()
        val keys = rawPermissions.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            permissions[key] = rawPermissions.opt(key) as? Boolean ?: throw IOException("Unexpected authentication response")
        }
        return LoginOutcome.Authenticated(
            requiredString(json, "token"), requiredString(json, "username"), requiredString(json, "role"), permissions
        )
    }

    private fun requiredString(json: JSONObject, name: String): String =
        (json.opt(name) as? String)?.takeIf { it.isNotBlank() } ?: throw IOException("Unexpected authentication response")

    private fun requiredListingString(json: JSONObject, name: String): String =
        (json.opt(name) as? String)?.takeIf { it.isNotBlank() } ?: throw SyncListingValidationException("Invalid sync listing")

    private fun requiredPositiveInt(json: JSONObject, name: String): Int =
        parsePositiveInt(json.opt(name)) ?: throw IOException("Unexpected authentication response")

    private fun post(url: java.net.URL, body: JSONObject): Pair<Int, JSONObject> {
        val connection = url.openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "POST"
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.connectTimeout = 10_000
            connection.readTimeout = 10_000
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Cache-Control", "no-store")
            connection.doOutput = true
            connection.outputStream.use { it.write(body.toString().toByteArray(StandardCharsets.UTF_8)) }
            val status = connection.responseCode
            if (status != 200 && status != 403) throw RootArkApiException(status)
            val stream = (if (status == 200) connection.inputStream else connection.errorStream)
                ?: throw IOException("Missing authentication response")
            val json = stream.use { input ->
                val output = ByteArrayOutputStream()
                val chunk = ByteArray(4096)
                var total = 0
                while (true) {
                    val count = input.read(chunk)
                    if (count < 0) break
                    total += count
                    if (total > 16 * 1024) throw IOException("Authentication response exceeds limit")
                    output.write(chunk, 0, count)
                }
                try {
                    JSONObject(String(output.toByteArray(), StandardCharsets.UTF_8))
                } catch (e: JSONException) {
                    throw IOException("Malformed JSON in authentication response", e)
                }
            }
            return status to json
        } finally {
            connection.disconnect()
        }
    }
}
