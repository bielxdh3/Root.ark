package dev.rootark.core.auth

import dev.rootark.core.sync.PagedInventoryPolicy
import java.net.URI
import java.net.URL
import java.util.Locale

/** Strict single HTTPS origin for the existing Root.ark authentication endpoints. */
class ServerOrigin private constructor(private val origin: String) {
    fun loginUrl(): URL = URL("$origin/auth/login")

    fun twoFactorUrl(): URL = URL("$origin/auth/login/2fa")

    fun syncListUrl(): URL = URL("$origin/sync/v1/objects")

    /** Issue #66: metadata-only, bounded snapshot cursor; never the full ciphertext listing. */
    fun syncInventoryUrl(cursor: String? = null): URL {
        if (cursor != null) PagedInventoryPolicy.checkCursor(cursor, emptySet())
        return URL("$origin/sync/v1/objects?view=metadata&limit=64" +
            (if (cursor == null) "" else "&cursor=$cursor"))
    }

    /** A single unescaped protocol object ID, never an arbitrary path or user URL. */
    fun syncObjectUrl(objectId: String): URL {
        require(objectId.length in 1..160 && objectId != "." && objectId != ".." &&
            objectId.matches(Regex("[A-Za-z0-9._:-]+"))) { "Invalid sync object ID" }
        return URL("$origin/sync/v1/objects/$objectId")
    }

    companion object {
        fun parse(input: String): ServerOrigin {
            require(input.length <= 2048 && input.isNotBlank() && input == input.trim()) {
                "Invalid server origin"
            }
            val uri = try {
                URI(input)
            } catch (_: Exception) {
                throw IllegalArgumentException("Invalid server origin")
            }
            require(
                !uri.isOpaque && uri.scheme?.lowercase(Locale.ROOT) == "https" &&
                    uri.host != null && uri.rawUserInfo == null &&
                    (uri.rawPath.isNullOrEmpty() || uri.rawPath == "/") &&
                    uri.rawQuery == null && uri.rawFragment == null &&
                    (uri.port == -1 || uri.port in 1..65535)
            ) { "Invalid server origin" }

            val hostname = uri.host.lowercase(Locale.ROOT).let { host ->
                if (host.contains(':') && !host.startsWith('[')) "[$host]" else host
            }
            val port = if (uri.port == -1) "" else ":${uri.port}"
            return ServerOrigin("https://$hostname$port")
        }
    }
}
