package dev.rootark.android

import dev.rootark.core.auth.ServerOrigin
import dev.rootark.core.sync.LoginOutcome
import dev.rootark.core.sync.RootArkApiException
import java.math.BigInteger
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.URL
import java.security.Principal
import java.security.cert.Certificate
import javax.net.ssl.HttpsURLConnection
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Actual auth POST adapter with a disposable HTTPS response: no live credentials or network. */
class AuthHttpTransportAuthenticationTest {
    private val origin = ServerOrigin.parse("https://files.example.org:9443")
    private val authenticated = """{"token":"fixture-token","username":"alice","role":"user","permissions":{"listFiles":true}}"""

    private class SecureAuthResponse(
        url: URL,
        private val status: Int = 200,
        private val body: ByteArray,
        private val mime: String? = "application/json; charset=utf-8",
        private val encoding: String? = null,
        private val streaming: InputStream? = null,
    ) : HttpsURLConnection(url) {
        var disconnected = false
        val posted = ByteArrayOutputStream()
        override fun getResponseCode() = status
        override fun getInputStream(): InputStream = streaming ?: ByteArrayInputStream(body)
        override fun getErrorStream(): InputStream? = if (status == 403) ByteArrayInputStream(body) else null
        override fun getOutputStream() = posted
        override fun getContentType() = mime
        override fun getContentEncoding() = encoding
        override fun getContentLengthLong() = body.size.toLong()
        override fun disconnect() { disconnected = true }
        override fun usingProxy() = false
        override fun connect() = Unit
        override fun getCipherSuite() = "TLS_AES_128_GCM_SHA256"
        override fun getLocalCertificates(): Array<Certificate>? = null
        override fun getServerCertificates(): Array<Certificate> = emptyArray()
        override fun getPeerPrincipal(): Principal = Principal { "CN=fixture" }
        override fun getLocalPrincipal(): Principal? = null
    }

    @Test fun validHttpsLoginChallengeTwoFactorAndForbiddenRemainCompatible() {
        val challenge = """{"challengeRequired":true,"challengeId":"fixture-challenge","expiresIn":300}"""
        val responses = listOf(
            SecureAuthResponse(origin.loginUrl(), body = authenticated.toByteArray()),
            SecureAuthResponse(origin.loginUrl(), body = challenge.toByteArray()),
            SecureAuthResponse(origin.twoFactorUrl(), body = authenticated.toByteArray()),
            SecureAuthResponse(origin.loginUrl(), status = 403, body = """{"error":"denied"}""".toByteArray()),
        )
        var count = 0
        val transport = AuthHttpTransport(openAuthConnection = { responses[count++] })
        assertEquals("alice", (transport.login(origin, "alice", "secret") as LoginOutcome.Authenticated).username)
        assertEquals("fixture-challenge",
            (transport.login(origin, "alice", "secret") as LoginOutcome.ChallengeRequired).challengeId)
        assertEquals("fixture-token", transport.completeTwoFactorLogin(origin, "fixture-challenge", "123456").token)
        assertEquals(403, assertThrows(RootArkApiException::class.java) {
            transport.login(origin, "alice", "invalid")
        }.statusCode)
        assertEquals(4, count)
        assertTrue(responses.all { it.disconnected })
        assertTrue(responses.all { it.requestMethod == "POST" })
    }

    @Test fun malformedUtf8AndWrongContentTypeCannotAuthenticateOrCompleteTwoFactor() {
        val invalidUtf8 = authenticated.replace("alice", "aléce").toByteArray(Charsets.UTF_8)
        val position = invalidUtf8.indexOf(0xc3.toByte())
        assertTrue(position >= 0)
        invalidUtf8[position] = 0xff.toByte()
        val cases = listOf(
            SecureAuthResponse(origin.loginUrl(), body = invalidUtf8),
            SecureAuthResponse(origin.loginUrl(), body = authenticated.toByteArray(), mime = "text/plain"),
            SecureAuthResponse(origin.twoFactorUrl(), body = invalidUtf8),
            SecureAuthResponse(origin.twoFactorUrl(), body = authenticated.toByteArray(), mime = "text/html"),
            SecureAuthResponse(origin.loginUrl(), body =
                authenticated.replace("\"token\":\"fixture-token\"",
                    "\"token\":\"stale\",\"token\":\"fixture-token\"").toByteArray()),
            SecureAuthResponse(origin.loginUrl(), body = authenticated.toByteArray(), encoding = "gzip"),
        )
        for ((index, response) in cases.withIndex()) {
            val transport = AuthHttpTransport(openAuthConnection = { response })
            assertThrows("Invalid auth response must fail closed for case $index", IOException::class.java) {
                if (index == 2 || index == 3) {
                    transport.completeTwoFactorLogin(origin, "fixture-challenge", "123456")
                } else transport.login(origin, "alice", "secret")
            }
            assertTrue(response.disconnected)
        }
    }

    @Test fun tricklingHttpsAuthResponseStopsAtAbsoluteDeadlineRatherThanSocketIdle() {
        var nowNanos = 0L
        var reads = 0
        val trickle = object : InputStream() {
            override fun read(): Int = throw AssertionError("Expected bounded bulk read")
            override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                reads++
                // Nine seconds per byte remains below each 10s idle timeout.
                nowNanos += 9_000_000_000L
                buffer[offset] = '{'.code.toByte()
                return 1
            }
        }
        val response = SecureAuthResponse(origin.loginUrl(), body = ByteArray(0), streaming = trickle)
        val transport = AuthHttpTransport(clockNanos = { nowNanos },
            openAuthConnection = { response })
        val failure = assertThrows(IOException::class.java) {
            transport.login(origin, "alice", "fixture-password")
        }
        assertTrue(failure.message.orEmpty().contains("deadline"))
        assertEquals(4, reads)
        assertTrue(response.disconnected)
    }

    @Test fun bigIntegerListingNumbersStayExactOnTheApi29Minimum() {
        val transport = AuthHttpTransport()
        assertEquals(Int.MIN_VALUE, transport.parseProtocolVersion(BigInteger.valueOf(Int.MIN_VALUE.toLong())))
        assertEquals(Int.MAX_VALUE, transport.parseProtocolVersion(BigInteger.valueOf(Int.MAX_VALUE.toLong())))
        assertNull(transport.parseProtocolVersion(BigInteger.valueOf(Int.MAX_VALUE.toLong()).add(BigInteger.ONE)))
        assertEquals(Int.MAX_VALUE, transport.parsePositiveInt(BigInteger.valueOf(Int.MAX_VALUE.toLong())))
        assertNull(transport.parsePositiveInt(BigInteger.valueOf(Int.MAX_VALUE.toLong()).add(BigInteger.ONE)))
        assertNull(transport.parsePositiveInt(BigInteger.ZERO))

        assertEquals(Long.MAX_VALUE, transport.parseNonNegativeLong(BigInteger.valueOf(Long.MAX_VALUE)))
        assertNull(transport.parseNonNegativeLong(BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE)))
        assertNull(transport.parseNonNegativeLong(BigInteger.valueOf(-1)))
        assertEquals(Long.MIN_VALUE, transport.optionalLong(
            JSONObject().put("value", BigInteger.valueOf(Long.MIN_VALUE)), "value",
        ))
        assertEquals(Long.MAX_VALUE, transport.optionalLong(
            JSONObject().put("value", BigInteger.valueOf(Long.MAX_VALUE)), "value",
        ))
        assertThrows(SyncListingValidationException::class.java) {
            transport.optionalLong(
                JSONObject().put("value", BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE)), "value",
            )
        }
    }
}
