package dev.rootark.android

import dev.rootark.core.auth.ServerOrigin
import dev.rootark.core.sync.ReadOnlyFileListPolicy
import dev.rootark.core.sync.ReadOnlyFileRow
import dev.rootark.core.sync.LoginOutcome
import dev.rootark.core.sync.RootArkApiException
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.nio.charset.StandardCharsets
import org.json.JSONObject

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

    /** The server returns ciphertext in the unpaginated listing; never return it to UI callers. */
    fun listSyncObjects(origin: ServerOrigin, token: String): List<ReadOnlyFileRow> {
        require(token.isNotBlank() && token.length <= 4096)
        val connection = origin.syncListUrl().openConnection() as HttpURLConnection
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
                    if (total > ReadOnlyFileListPolicy.MAX_RESPONSE_BYTES) {
                        throw IOException("Sync listing exceeds limit")
                    }
                    out.write(buffer, 0, count)
                }
                JSONObject(String(out.toByteArray(), StandardCharsets.UTF_8))
            }
            return projectList(json)
        } finally {
            connection.disconnect()
        }
    }

    private fun projectList(response: JSONObject): List<ReadOnlyFileRow> {
        val objects = response.optJSONArray("objects") ?: throw IOException("Invalid sync listing")
        val version = response.opt("protocolVersion") as? Int ?: throw IOException("Invalid sync listing")
        try {
            ReadOnlyFileListPolicy.checkEnvelope(version, objects.length())
            return (0 until objects.length()).map { index ->
                val record = objects.optJSONObject(index) ?: throw IOException("Invalid sync listing")
                val metadata = record.optJSONObject("metadata") ?: throw IOException("Invalid sync listing")
                val deleted = record.opt("tombstone") as? Boolean ?: throw IOException("Invalid sync listing")
                val recordVersion = record.opt("protocolVersion") as? Int ?: throw IOException("Invalid sync listing")
                val revision = record.optJSONObject("revision") ?: throw IOException("Invalid sync listing")
                val counter = revision.opt("counter")
                if ((counter !is Int && counter !is Long) || (counter as Number).toLong() < 0L ||
                    requiredString(revision, "deviceId").length > 256) throw IOException("Invalid sync listing")

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
        } catch (_: IllegalArgumentException) {
            throw IOException("Invalid or oversized sync listing")
        }
    }

    private fun optionalString(json: JSONObject, key: String): String? {
        val value = json.opt(key)
        if (value == null || value == JSONObject.NULL) return null
        return value as? String ?: throw IOException("Invalid sync listing")
    }

    private fun optionalLong(json: JSONObject, key: String): Long? {
        val value = json.opt(key)
        if (value == null || value == JSONObject.NULL) return null
        return when (value) {
            is Int -> value.toLong()
            is Long -> value
            else -> throw IOException("Invalid sync listing")
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
        (json.opt(name) as? Int)?.takeIf { it > 0 } ?: throw IOException("Unexpected authentication response")

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
                JSONObject(String(output.toByteArray(), StandardCharsets.UTF_8))
            }
            return status to json
        } finally {
            connection.disconnect()
        }
    }
}
