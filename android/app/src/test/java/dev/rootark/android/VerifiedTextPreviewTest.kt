package dev.rootark.android

import dev.rootark.core.auth.ServerOrigin
import dev.rootark.core.sync.LoginOutcome
import dev.rootark.core.sync.ProtectedSyncException
import java.io.IOException
import org.junit.Assert.*
import org.junit.Test

class VerifiedTextPreviewTest {
    private val origin = ServerOrigin.parse("https://files.example.org")
    private val session = LoginOutcome.Authenticated("token", "alice", "user", mapOf("listFiles" to true))

    @Test fun noProvisionedTrustBlocksBeforeAnyNetwork() {
        var attempts = 0
        val fetch = ProtectedSyncFetch { _ -> attempts++; throw AssertionError("Network forbidden") }
        val preview = VerifiedTextPreview(null, fetch)
        assertFalse(preview.available)
        assertThrows(ProtectedSyncException::class.java) {
            preview.open(origin, session, "object-1")
        }
        assertEquals(0, attempts)
    }

    @Test fun utf8PreviewIsSmallAndRejectsMalformedOrBinaryBodies() {
        val expected = "Protegido: olá ☃"
        val content = VerifiedTextPreview.decodeVerifiedText(expected.toByteArray(Charsets.UTF_8))
        assertEquals(expected, String(content))
        content.fill('\u0000')
        assertTrue(content.all { it == '\u0000' })
        assertThrows(ProtectedSyncException::class.java) {
            VerifiedTextPreview.decodeVerifiedText(ByteArray(64 * 1024 + 1))
        }
        assertThrows(ProtectedSyncException::class.java) {
            VerifiedTextPreview.decodeVerifiedText(byteArrayOf(0xc3.toByte(), 0x28))
        }
        assertThrows(ProtectedSyncException::class.java) {
            VerifiedTextPreview.decodeVerifiedText(byteArrayOf(0x00))
        }
    }
}
