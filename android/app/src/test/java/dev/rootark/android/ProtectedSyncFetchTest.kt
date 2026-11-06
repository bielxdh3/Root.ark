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
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.net.URL
import java.net.URLConnection
import java.security.Principal
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.Certificate
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
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
    private val base64 = Base64.getUrlEncoder().withoutPadding()
    private fun ByteArray.base64Url() = base64.encodeToString(this)
    private fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).base64Url()

    /** Independent test-only deterministic RFC 8949 CBOR encoder; no production crypto helpers. */
    private fun canonicalCbor(value: Any?): ByteArray {
        val out = ByteArrayOutputStream()
        fun header(type: Int, size: Long) {
            require(size >= 0)
            when {
                size < 24 -> out.write((type shl 5) or size.toInt())
                size <= 255 -> { out.write((type shl 5) or 24); out.write(size.toInt()) }
                size <= 65535 -> {
                    out.write((type shl 5) or 25)
                    out.write((size shr 8).toInt())
                    out.write(size.toInt())
                }
                size <= 0xffffffffL -> {
                    out.write((type shl 5) or 26)
                    for (shift in 24 downTo 0 step 8) out.write((size shr shift).toInt())
                }
                else -> {
                    out.write((type shl 5) or 27)
                    for (shift in 56 downTo 0 step 8) out.write((size shr shift).toInt())
                }
            }
        }
        fun encode(item: Any?) {
            when (item) {
                null -> out.write(0xf6)
                is Boolean -> out.write(if (item) 0xf5 else 0xf4)
                is Int -> header(0, item.toLong())
                is Long -> header(0, item)
                is String -> {
                    val bytes = item.toByteArray(Charsets.UTF_8)
                    header(3, bytes.size.toLong())
                    out.write(bytes)
                }
                is Map<*, *> -> {
                    val pairs = item.entries.map { entry ->
                        val key = entry.key as String
                        key to entry.value
                    }.sortedWith { a, b ->
                        val left = a.first.toByteArray(Charsets.UTF_8)
                        val right = b.first.toByteArray(Charsets.UTF_8)
                        val sizeDiff = left.size.compareTo(right.size)
                        if (sizeDiff != 0) sizeDiff else {
                            var diff = 0
                            for (i in left.indices) {
                                diff = (left[i].toInt() and 255) - (right[i].toInt() and 255)
                                if (diff != 0) break
                            }
                            diff
                        }
                    }
                    header(5, pairs.size.toLong())
                    for ((key, itemValue) in pairs) {
                        encode(key)
                        encode(itemValue)
                    }
                }
                else -> error("Unsupported test-only CBOR data")
            }
        }
        encode(value)
        return out.toByteArray()
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
            SecureResponse(origin.syncObjectUrl("fixture-object-1"), payload = response + " {} ".toByteArray()),
            SecureResponse(origin.syncObjectUrl("fixture-object-1"), payload = JSONObject(String(response)).put("objectId", "other").toString().toByteArray()),
            SecureResponse(origin.syncObjectUrl("fixture-object-1"), payload = JSONObject(String(response)).put("unexpected", "injected").toString().toByteArray()),
            SecureResponse(origin.syncObjectUrl("fixture-object-1"), payload = JSONObject(String(response)).put("protocolVersion", 1).toString().toByteArray()),
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

    @Test fun actualHttpsGetRejectsAmbiguousDuplicateAndNonStandardJsonBeforeOrgJson() {
        val original = String(response, Charsets.UTF_8)
        assertTrue(original.contains("\"objectId\":"))
        val badBodies = listOf(
            original.replaceFirst("\"objectId\":", "\"objectId\":\"wrong\",\"objectId\":"),
            original.replaceFirst("\"objectId\":", "\"obj\\u0065ctId\":\"wrong\",\"objectId\":"),
            original.replaceFirst("\"authorization\":{", "\"authorization\":{\"deviceId\":\"wrong\","),
            original.replaceFirst("\"objectId\":", "\"objectId\"="),
            "/* comment */$original",
        )
        badBodies.forEach { body ->
            val fake = SecureResponse(origin.syncObjectUrl("fixture-object-1"), payload = body.toByteArray(Charsets.UTF_8))
            assertThrows(IOException::class.java) {
                ProtectedSyncFetch { fake }.fetchCiphertext(origin, session, "fixture-object-1")
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

    @Test fun rejectsGrantIdentityMismatchBeforeFetchingAndErasesTransferredKey() {
        val transport = Transport()
        val gateway = ProtectedSyncFetch(transport::open)
        val now = System.currentTimeMillis()
        val disposableKey = ByteArray(32) { 42 }
        val badContext = PinnedSyncReadContext(
            username = "bob", objectId = "fixture-object-1",
            fileId = "fixture-file-1", versionId = "fixture-version-1",
            compartmentId = "private", keyEpoch = "epoch-1",
            trustedDevicePublicKeys = mapOf("fixture-device-a" to "independently-pinned-only"),
            revokedDeviceIds = emptySet(),
            snapshotObtainedAtMillis = now,
            snapshotValidUntilMillis = now + 30_000,
        )
        assertThrows(ProtectedSyncException::class.java) {
            gateway.withVerifiedContent(
                origin, session, "fixture-object-1",
                TrustedContentGrantProvider { _, _ -> ProtectedContentGrant(badContext, disposableKey) },
            ) { fail("Plaintext callback must remain gated") }
        }
        assertEquals(0, transport.calls)
        assertTrue(disposableKey.all { it == 0.toByte() })
    }

    @Test fun verifiedSignedHttpsObjectDecryptsInEphemeralCallbackAndWipesCekAndPlaintext() {
        val record = JSONObject(String(response, Charsets.UTF_8))
        val proof = record.getJSONObject("authorization")
        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val now = System.currentTimeMillis()
        val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cek = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val expectedPlaintext = "hello".toByteArray(Charsets.UTF_8)
        val aad = Base64.getUrlDecoder().decode(record.getString("aad"))
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(cek, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        val encrypted = cipher.doFinal(expectedPlaintext)
        val ciphertext = encrypted.copyOfRange(0, encrypted.size - 16)
        val tag = encrypted.copyOfRange(encrypted.size - 16, encrypted.size)
        record.put("ciphertext", ciphertext.base64Url())
        record.put("nonce", nonce.base64Url())
        record.put("tag", tag.base64Url())
        proof.put("aadDigest", digest(aad))
        proof.put("ciphertextDigest", digest(ciphertext))
        proof.put("nonceDigest", digest(nonce))
        proof.put("tagDigest", digest(tag))
        proof.put("expiresAt", now + 60_000)
        proof.put("publicKey", keyPair.public.encoded.base64Url())
        proof.remove("signature")
        val unsigned: Map<String, Any?> = proof.toMap()
        val signedBytes = "Root.ark/zk-1/authorization-manifest/v1".toByteArray(Charsets.US_ASCII) +
            byteArrayOf(0) + canonicalCbor(unsigned)
        val signer = Signature.getInstance("Ed25519")
        signer.initSign(keyPair.private)
        signer.update(signedBytes)
        proof.put("signature", signer.sign().base64Url())
        val context = PinnedSyncReadContext(
            username = "alice", objectId = "fixture-object-1",
            fileId = "fixture-file-1", versionId = "fixture-version-1",
            compartmentId = "private", keyEpoch = "epoch-1",
            trustedDevicePublicKeys = mapOf("fixture-device-a" to proof.getString("publicKey")),
            revokedDeviceIds = emptySet(),
            snapshotObtainedAtMillis = now - 2000L,
            snapshotValidUntilMillis = now + 30_000L,
        )
        val fake = SecureResponse(origin.syncObjectUrl("fixture-object-1"), payload = record.toString().toByteArray())
        val gateway = ProtectedSyncFetch { fake }
        val previewKey = cek.copyOf()
        var observed: ByteArray? = null
        var observedReference: ByteArray? = null
        gateway.withVerifiedContent(
            origin, session, "fixture-object-1",
            TrustedContentGrantProvider { _, _ -> ProtectedContentGrant(context, cek) },
        ) { bytes ->
            observed = bytes.copyOf()
            observedReference = bytes
        }
        assertArrayEquals(expectedPlaintext, observed)
        assertTrue(observedReference!!.all { it == 0.toByte() })
        assertTrue(cek.all { it == 0.toByte() })
        assertTrue(fake.disconnected)

        // The same real Ed25519/AES-GCM signed HTTP fixture reaches the user
        // interaction only through an independently supplied context and CEK.
        val viewer = VerifiedTextPreview(
            TrustedContentGrantProvider { username, id ->
                assertEquals("alice", username)
                assertEquals("fixture-object-1", id)
                ProtectedContentGrant(context, previewKey)
            },
            ProtectedSyncFetch {
                SecureResponse(origin.syncObjectUrl("fixture-object-1"), payload = record.toString().toByteArray())
            },
        )
        assertTrue(viewer.available)
        val text = viewer.open(origin, session, "fixture-object-1")
        try {
            assertEquals("hello", String(text))
        } finally {
            text.fill('\u0000')
        }
        assertTrue(previewKey.all { it == 0.toByte() })

        val invalid = JSONObject(record.toString()).put("ciphertext", "AAAA")
        val corruptedKey = ByteArray(32) { 11 }
        val corruptedViewer = VerifiedTextPreview(
            TrustedContentGrantProvider { _, _ -> ProtectedContentGrant(context, corruptedKey) },
            ProtectedSyncFetch {
                SecureResponse(origin.syncObjectUrl("fixture-object-1"), payload = invalid.toString().toByteArray())
            },
        )
        assertThrows(ProtectedSyncException::class.java) {
            corruptedViewer.open(origin, session, "fixture-object-1")
        }
        assertTrue(corruptedKey.all { it == 0.toByte() })

        for (status in listOf(401, 403)) {
            val deniedKey = ByteArray(32) { 7 }
            val deniedViewer = VerifiedTextPreview(
                TrustedContentGrantProvider { _, _ -> ProtectedContentGrant(context, deniedKey) },
                ProtectedSyncFetch {
                    SecureResponse(origin.syncObjectUrl("fixture-object-1"), status = status)
                },
            )
            val denied = assertThrows(RootArkApiException::class.java) {
                deniedViewer.open(origin, session, "fixture-object-1")
            }
            assertEquals(status, denied.statusCode)
            assertTrue(deniedKey.all { it == 0.toByte() })
        }
    }
}
