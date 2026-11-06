package dev.rootark.android

import dev.rootark.core.auth.ServerOrigin
import dev.rootark.core.sync.LoginOutcome
import dev.rootark.core.sync.ProtectedSyncException
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/**
 * One-shot, user-initiated protected text interaction. The Android login is
 * never a content grant. A separate independently authenticated source must
 * deliver a fresh trusted device/epoch snapshot and a 32-byte CEK.
 *
 * Returned characters are caller-owned and MUST be cleared after rendering.
 * No plaintext is cached, exported or sent to a preview endpoint.
 */
internal class VerifiedTextPreview(
    private val trustedGrants: TrustedContentGrantProvider?,
    private val fetch: ProtectedSyncFetch = ProtectedSyncFetch(),
) {
    companion object {
        const val MAX_TEXT_BYTES = 64 * 1024

        fun decodeVerifiedText(plaintext: ByteArray): CharArray {
            if (plaintext.isEmpty() || plaintext.size > MAX_TEXT_BYTES) throw ProtectedSyncException()
            try {
                val decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(plaintext))
                try {
                    val chars = CharArray(decoded.remaining())
                    decoded.get(chars)
                    if (chars.any { it == '\u0000' || (it < ' ' && it != '\t' && it != '\n' && it != '\r') || it == '\u007f' }) {
                        chars.fill('\u0000')
                        throw ProtectedSyncException()
                    }
                    return chars
                } finally {
                    if (decoded.hasArray()) decoded.array().fill('\u0000')
                }
            } catch (_: CharacterCodingException) {
                throw ProtectedSyncException()
            }
        }
    }

    val available: Boolean get() = trustedGrants != null

    fun open(origin: ServerOrigin, session: LoginOutcome.Authenticated, objectId: String): CharArray {
        val provider = trustedGrants ?: throw ProtectedSyncException()
        var characters: CharArray? = null
        try {
            fetch.withVerifiedContent(origin, session, objectId, provider) { plaintext ->
                characters = decodeVerifiedText(plaintext)
            }
            return characters ?: throw ProtectedSyncException()
        } catch (_: Exception) {
            characters?.fill('\u0000')
            throw ProtectedSyncException()
        }
    }
}
