package dev.rootark.android

import dev.rootark.core.auth.ServerOrigin
import dev.rootark.core.sync.LoginOutcome
import dev.rootark.core.sync.PinnedSyncReadContext
import dev.rootark.core.sync.ProtectedSyncException
import dev.rootark.core.sync.RootArkApiException
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.net.URL
import java.net.URLConnection
import java.security.Principal
import java.security.cert.Certificate
import javax.net.ssl.HttpsURLConnection

class ProtectedSyncFetchTest {
    private val origin = ServerOrigin.parse("https://files.example.org:9443")
    private val session = LoginOutcome.Authenticated(
        "disposable-test-session", "alice", "user", mapOf("listFiles" to true)
    )
    private val response: ByteArray by lazy {
        val path = System.getProperty("rootark.fixture") ?: error("Missing captured Node HTTP fixture")
        val fixture = JSONObject(File(path).readText(Charsets.UTF_8))
        fixture.getJSONObject("responses").getJSONObject("sync.get.200")
            .getJSONObject("body").toString().toByteArray(Charsets.UTF_8)
    }

    private class SecureResponse(
        url: URL, var status: Int = 200, var payload: ByteArray = ByteArray(0),
        var mime: String? = "application/json; charset=utf-8",
        var encoding: String? = null, var declaredSize: Long = -1L,
    ) : HttpsURLConnection(url) {
        var opened = 0
        var disconnected = false
        override fun getResponseCode(): Int = status
        override fun getInputStream() = ByteArrayInputStream(payload).also { opened++ }
        override fun getContentType(): String? = mime
        override fun getContentEncoding(): String? = encoding
        override fun getContentLengthLong(): Long = declaredSize
        override fun disconnect() { disconnected = true }
        override fun usingProxy() = false
        override fun connect() = Unit
        override fun getCipherSuite() = "TLS_AES_128_GCM_SHA256"
        override fun getLocalCertificates(): Array<Certificate>? = null
        override fun getServerCertificates(): Array<Certificate> = emptyArray()
        override fun getPeerPrincipal(): Principal = Principal { "CN=test" }
        override fun getLocalPrincipal(): Principal? = null
    }

    private class Transport {
        var calls = 0
        var result: SecureResponse? = null
        var url: URL? = null
        fun open(url: URL): URLConnection {
            calls++
            this.url = url
            return (result ?: SecureResponse(url).also { result = it })
        }
    }

    @Test fun fetchesActualServerRecordWithBearerOverSingleBoundedHttpsGet() {
        val transport = Transport()
        val gateway = ProtectedSyncFetch { url ->
            transport.open(url).also { (it as SecureResponse).payload = response }
        }
        val record = gateway.fetchCiphertext(origin, session, "fixture-object-1")
        assertEquals("fixture-object-1", record.objectId)
        assertEquals("create", record.operation.wire)
        assertEquals("docs/readme.txt", record.metadata.path)
        assertNotNull(record.authorization)
        assertEquals(1, transport.calls)
        assertEquals("https://files.example.org:9443/sync/v1/objects/fixture-object-1", transport.url.toString())
        val conn = transport.result ?: error("unrecorded fake")
        assertEquals("GET", conn.requestMethod)
        assertEquals("Bearer disposable-test-session", conn.getRequestProperty("Authorization"))
        assertEquals("identity", conn.getRequestProperty("Accept-Encoding"))
        assertEquals("no-store", conn.getRequestProperty("Cache-Control"))
        assertFalse(conn.instanceFollowRedirects)
        assertFalse(conn.useCaches)
        assertTrue(conn.disconnected)
    }

    @Test fun failsClosedBeforeNetworkForUnprovisionedTrustOrMissingListPermission() {
        val transport = Transport()
        val gateway = ProtectedSyncFetch(transport::open)
        var delivered = false
        assertThrows(ProtectedSyncException::class.java) {
            gateway.withVerifiedContent(origin, session, "fixture-object-1", TrustedContentGrantProvider { _, _ -> null }) {
                delivered = true
            }
        }
        assertFalse(delivered)
        assertEquals(0, transport.calls)

        val denied = session.copy(permissions = mapOf("listFiles" to false))
        assertThrows(ProtectedSyncException::class.java) {
            gateway.fetchCiphertext(origin, denied, "fixture-object-1")
        }
        assertEquals(0, transport.calls)
    }

    @Test fun refusesInvalidObjectIdsWithoutAnyNetworkAndNeverUsesHttp() {
        val transport = Transport()
        val gateway = ProtectedSyncFetch(transport::open)
        for (bad in listOf("../outside", "a/b", "%2f", "a?x=1", "..", ".", "", "a".repeat(161))) {
            assertThrows(IllegalArgumentException::class.java) {
                gateway.fetchCiphertext(origin, session, bad)
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            ServerOrigin.parse("http://files.example.org")
        }
        assertEquals(0, transport.calls)
    }

    @Test fun enforcesNoRedirectOrHttpErrorWithNoBodyLeaks() {
        for (status in listOf(301, 302, 307, 308, 401, 403, 404, 500)) {
            val transport = Transport()
            val fake = SecureResponse(origin.syncObjectUrl("fixture-object-1"), status = status)
            transport.result = fake
            val failure = assertThrows(RootArkApiException::class.java) {
                ProtectedSyncFetch(transport::open).fetchCiphertext(origin, session, "fixture-object-1")
            }
            assertEquals(status, failure.statusCode)
            assertEquals(0, fake.opened)
            assertFalse(fake.instanceFollowRedirects)
            assertTrue(fake.disconnected)
        }
    }

    @Test fun enforcesContentLengthStreamingLimitAndJsonContentType() {
        val cases = listOf(
            SecureResponse(origin.syncObjectUrl("fixture-object-1"), payload = response, declaredSize = ProtectedSyncFetch.MAX_RESPONSE_BYTES.toLong() + 1),
            SecureResponse(origin.syncObjectUrl("fixture-object-1"), payload = ByteArray(ProtectedSyncFetch.MAX_RESPONSE_BYTES + 1)),
            SecureResponse(origin.syncObjectUrl("fixture-object-1"), payload = response, encoding = "gzip"),
            SecureResponse(origin.syncObjectUrl("fixture-object-1"), payload = response, mime = "text/html"),
            SecureResponse(origin.syncObjectUrl("fixture-object-1"), payload = "{}".toByteArray()),
            SecureResponse(origin.syncObjectUrl("fixture-object-1"), payload = response, mime = null),
        )
        for (fake in cases) {
            val gateway = ProtectedSyncFetch { fake }
            assertThrows(IOException::class.java) {
                gateway.fetchCiphertext(origin, session, "fixture-object-1")
            }
            assertTrue(fake.disconnected)
        }
    }

    @Test fun expiredOrUnpinnedContentCannotReachPlaintextCallbackAndCekIsCleared() {
        val source = JSONObject(String(response, Charsets.UTF_8))
        val proof = source.getJSONObject("authorization")
        val now = System.currentTimeMillis()
        val key = ByteArray(32) { 19 }
        val context = PinnedSyncReadContext(
            username = "alice", objectId = "fixture-object-1",
            fileId = "fixture-file-1", versionId = "fixture-version-1",
            compartmentId = "private", keyEpoch = "epoch-1",
            trustedDevicePublicKeys = mapOf("fixture-device-a" to proof.getString("publicKey")),
            revokedDeviceIds = setOf("fixture-device-a"),
            snapshotObtainedAtMillis = now - 5000L,
            snapshotValidUntilMillis = now + 20000L,
        )
        val fake = SecureResponse(origin.syncObjectUrl("fixture-object-1"), payload = response)
        val gateway = ProtectedSyncFetch { fake }
        var called = false
        assertThrows(ProtectedSyncException::class.java) {
            gateway.withVerifiedContent(
                origin, session, "fixture-object-1",
                TrustedContentGrantProvider { _, _ -> ProtectedContentGrant(context, key) },
            ) { called = true }
        }
        assertFalse(called)
        assertTrue(key.all { it == 0.toByte() })
        assertTrue(fake.disconnected)
    }
}
