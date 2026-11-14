package dev.rootark.android

import dev.rootark.core.auth.ServerOrigin
import dev.rootark.core.sync.ReadOnlyFileListPolicy
import dev.rootark.core.sync.InventoryPage
import dev.rootark.core.sync.PagedInventoryPolicy
import dev.rootark.core.sync.LoginOutcome
import dev.rootark.core.sync.RootArkApiException
import java.io.ByteArrayOutputStream
import java.io.IOException
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

    private fun projectInventoryPage(response: JSONObject): InventoryPage {
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
                if (requiredString(revision, "deviceId").length > 256) {
                    throw SyncListingValidationException("Invalid sync listing")
                }

                ReadOnlyFileListPolicy.project(
                    protocolVersion = recordVersion,
                    objectId = requiredString(record, "objectId"),
                    operation = requiredString(record, "operation"),
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
        }
    }

    private fun parseProtocolVersion(value: Any?): Int? = when (value) {
        is Int -> value
        is Long -> if (value in Int.MIN_VALUE..Int.MAX_VALUE) value.toInt() else null
        is Number -> {
            val i = value.toInt()
            if (value.toDouble() == i.toDouble()) i else null
        }
        else -> null
    }

    private fun parseNonNegativeLong(value: Any?): Long? = when (value) {
        is Int -> if (value >= 0) value.toLong() else null
        is Long -> if (value >= 0L) value else null
        is Number -> {
            val l = value.toLong()
            if (l >= 0L && value.toDouble() == l.toDouble()) l else null
        }
        else -> null
    }

    private fun parsePositiveInt(value: Any?): Int? = when (value) {
        is Int -> if (value > 0) value else null
        is Long -> if (value in 1..Int.MAX_VALUE) value.toInt() else null
        is Number -> {
            val i = value.toInt()
            if (i > 0 && value.toDouble() == i.toDouble()) i else null
        }
        else -> null
    }

    private fun optionalString(json: JSONObject, key: String): String? {
        val value = json.opt(key)
        if (value == null || value == JSONObject.NULL) return null
        return value as? String ?: throw SyncListingValidationException("Invalid sync listing")
    }

    private fun optionalLong(json: JSONObject, key: String): Long? {
        val value = json.opt(key)
        if (value == null || value == JSONObject.NULL) return null
        return when (value) {
            is Int -> value.toLong()
            is Long -> value
            is Number -> {
                val l = value.toLong()
                if (value.toDouble() == l.toDouble()) l else throw SyncListingValidationException("Invalid sync listing")
            }
            else -> throw SyncListingValidationException("Invalid sync listing")
        }
    }

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
