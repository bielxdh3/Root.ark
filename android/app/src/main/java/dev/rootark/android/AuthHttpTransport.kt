package dev.rootark.android

import dev.rootark.core.auth.ServerOrigin
import dev.rootark.core.sync.LoginOutcome
import dev.rootark.core.sync.RootArkApiException
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.nio.charset.StandardCharsets
import org.json.JSONObject

/** HTTP adapter for the canonical login and TOTP routes. */
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
