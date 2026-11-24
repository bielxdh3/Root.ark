package dev.rootark.core.sync

import java.io.File
import java.math.BigInteger
import java.nio.file.Files
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.KeyAgreement
import javax.crypto.spec.SecretKeySpec
import org.json.JSONArray
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class OwnerEnrollmentV2Test {
    @Test
    fun hardwareFloorRetirementRequiresProvenDurableSealEvenIfContentUseThrows() {
        val fixture = fixture()
        val root = Files.createTempDirectory("owner-enrollment-retirement").toFile()
        val committed = AtomicBoolean(false)
        try {
            val store = OwnerOfflineFloorStore(
                root, SecretKeySpec(ByteArray(32) { (it + 17).toByte() }, "AES"),
                allowFirstWrite = true,
                onSealedFloor = {
                    assertTrue(File(root, "owner-floor-v1.bin").isFile)
                    committed.set(true)
                },
            )
            assertThrows(ProtectedSyncException::class.java) {
                OwnerEnrollmentAdmission.withAuthorizedGrant(
                    fixture.packageValue, fixture.pin, fixture.readerPublic, store, fixture.now,
                    agree = { enc -> agree(fixture.reader, enc) },
                ) { _, _ ->
                    assertTrue(committed.get(), "the durable floor must be confirmed before CEK use")
                    throw IllegalStateException("simulated protected consumer failure")
                }
            }
            assertTrue(committed.get(), "a failed consumer cannot hide an already sealed floor")

            val obstructedRoot = File(root, "blocked-root").apply { writeText("not a directory") }
            val uncommitted = AtomicBoolean(false)
            val broken = OwnerOfflineFloorStore(
                obstructedRoot, SecretKeySpec(ByteArray(32) { (it + 27).toByte() }, "AES"),
                allowFirstWrite = true, onSealedFloor = { uncommitted.set(true) },
            )
            assertThrows(ProtectedSyncException::class.java) {
                OwnerEnrollmentAdmission.observeHead(
                    fixture.packageValue.head, fixture.pin, fixture.readerPublic, broken, fixture.now,
                )
            }
            assertFalse(uncommitted.get(), "a failed pre-write setup must preserve the previous hardware floor")
        } finally {
            root.deleteRecursively()
            destroy(fixture)
        }
    }

    @Test
    fun nodeGeneratedRfc9180P256VectorOpensInKotlinAndErasesTheCek() {
        val fixture = fixture()
        try {
            val root = Files.createTempDirectory("owner-enrollment-v2").toFile()
            val store = OwnerOfflineFloorStore(root, SecretKeySpec(ByteArray(32) { (it + 1).toByte() }, "AES"), true)
            var retained: ByteArray? = null
            var consumedReference: ByteArray? = null
            OwnerEnrollmentAdmission.withAuthorizedGrant(
                fixture.packageValue, fixture.pin, fixture.readerPublic, store, fixture.now,
                agree = { enc -> agree(fixture.reader, enc) },
            ) { context, cek ->
                consumedReference = cek
                assertEquals("alice", context.username)
                assertEquals("object-1", context.objectId)
                assertEquals("file-1", context.fileId)
                assertEquals("version-1", context.versionId)
                assertEquals("compartment-1", context.compartmentId)
                assertEquals("epoch-1", context.keyEpoch)
                assertArrayEquals(fixture.cek, cek)
                retained = cek.copyOf()
            }
            assertArrayEquals(fixture.cek, retained!!)
            assertArrayEquals(ByteArray(32), consumedReference!!, "the CEK buffer must be erased after consumption")
            assertTrue(retained!!.isNotEmpty())
            retained!!.fill(0)
            root.deleteRecursively()
        } finally {
            destroy(fixture)
        }
    }

    @Test
    fun cekIsErasedWhenProtectedContentConsumerThrows() {
        val fixture = fixture()
        val root = Files.createTempDirectory("owner-enrollment-cek-throw").toFile()
        var consumedReference: ByteArray? = null
        try {
            val store = OwnerOfflineFloorStore(
                root, SecretKeySpec(ByteArray(32) { (it + 31).toByte() }, "AES"), true,
            )
            assertThrows(ProtectedSyncException::class.java) {
                OwnerEnrollmentAdmission.withAuthorizedGrant(
                    fixture.packageValue, fixture.pin, fixture.readerPublic, store, fixture.now,
                    agree = { enc -> agree(fixture.reader, enc) },
                ) { _, cek ->
                    consumedReference = cek
                    throw IllegalStateException("simulated fetch/decrypt/consume failure")
                }
            }
            assertArrayEquals(ByteArray(32), consumedReference!!)
        } finally {
            root.deleteRecursively()
            destroy(fixture)
        }
    }

    @Test
    fun hpkeReceiverErasesDhWhenMalformedEncIsRejected() {
        val dh = ByteArray(32) { (it + 1).toByte() }
        try {
            assertThrows(IllegalArgumentException::class.java) {
                HpkeP256.open(
                    ByteArray(65).also { it[0] = 0x04 }, ByteArray(65), dh,
                    ByteArray(0), ByteArray(0), ByteArray(48),
                )
            }
            assertArrayEquals(ByteArray(32), dh)
        } finally { dh.fill(0) }
    }

    @Test
    fun sameReaderDeviceIdDifferentInstallationKeyCannotUnwrapGrant() {
        val fixture = fixture()
        val secondReader = p256()
        val secondPublic = rawPublic(secondReader)
        try {
            assertNotEquals(fixture.pin.readerDeviceId, OwnerEnrollmentAdmission.readerDeviceId(secondPublic))
            assertThrows(ProtectedSyncException::class.java) {
                OwnerEnrollmentAdmission.validatePackage(
                    fixture.packageValue, fixture.pin, secondPublic, fixture.now,
                )
            }
        } finally {
            destroy(fixture)
            secondPublic.fill(0)
        }
    }

    @Test
    fun badOwnerSignatureAndStaleHeadLeaseAreRejected() {
        val fixture = fixture()
        try {
            val badSignature = fixture.packageValue.copy(
                grant = fixture.packageValue.grant.copy(
                    signature = flipLast(fixture.packageValue.grant.signature),
                ),
            )
            assertThrows(ProtectedSyncException::class.java) {
                OwnerEnrollmentAdmission.validatePackage(badSignature, fixture.pin, fixture.readerPublic, fixture.now)
            }
            val badHeadSignature = fixture.packageValue.copy(
                head = fixture.packageValue.head.copy(
                    signature = flipLast(fixture.packageValue.head.signature),
                ),
            )
            assertThrows(ProtectedSyncException::class.java) {
                OwnerEnrollmentAdmission.validatePackage(
                    badHeadSignature, fixture.pin, fixture.readerPublic, fixture.now,
                )
            }
            assertThrows(ProtectedSyncException::class.java) {
                OwnerEnrollmentAdmission.validatePackage(
                    fixture.packageValue, fixture.pin, fixture.readerPublic, fixture.now + 240_001,
                )
            }
            assertThrows(ProtectedSyncException::class.java) {
                OwnerEnrollmentAdmission.validatePackage(
                    fixture.packageValue, fixture.pin, fixture.readerPublic, fixture.now + 300_001,
                )
            }
        } finally {
            destroy(fixture)
        }
    }

    @Test
    fun ownerResigningChangedObjectIdCannotReuseOldHpkeCiphertext() {
        val fixture = fixture()
        try {
            val altered = fixture.packageValue.grant.copy(objectId = "object-2")
            val canonical = ProtectedSyncContent.canonicalJson(altered.fields()).toByteArray(Charsets.UTF_8)
            val message = "Root.ark/android/cek-read-hpke-v2\u0000".toByteArray(Charsets.UTF_8) + canonical
            val privateKey = java.security.KeyFactory.getInstance("Ed25519").generatePrivate(
                java.security.spec.PKCS8EncodedKeySpec(fixture.ownerPrivatePkcs8),
            )
            val signature = java.security.Signature.getInstance("Ed25519").run {
                initSign(privateKey)
                update(message)
                sign()
            }
            canonical.fill(0)
            message.fill(0)
            val resigned = altered.copy(signature = b64(signature))
            signature.fill(0)
            val tamperedPackage = fixture.packageValue.copy(grant = resigned)
            val root = Files.createTempDirectory("owner-enrollment-aad").toFile()
            val store = OwnerOfflineFloorStore(root, SecretKeySpec(ByteArray(32) { (it + 21).toByte() }, "AES"), true)
            var consumed = false
            assertThrows(ProtectedSyncException::class.java) {
                OwnerEnrollmentAdmission.withAuthorizedGrant(
                    tamperedPackage, fixture.pin, fixture.readerPublic, store, fixture.now,
                    agree = { enc -> agree(fixture.reader, enc) },
                ) { _, _ -> consumed = true }
            }
            assertFalse(consumed)
            root.deleteRecursively()
        } finally {
            destroy(fixture)
        }
    }

    @Test
    fun signedRevocationRejectsGrantButStillAdvancesTheDurableHead() {
        val fixture = fixture(revoked = true)
        try {
            assertThrows(ProtectedSyncException::class.java) {
                OwnerEnrollmentAdmission.validatePackage(
                    fixture.packageValue, fixture.pin, fixture.readerPublic, fixture.now,
                )
            }
            val root = Files.createTempDirectory("owner-enrollment-revoked").toFile()
            val store = OwnerOfflineFloorStore(root, SecretKeySpec(ByteArray(32) { (it + 7).toByte() }, "AES"), true)
            val advanced = OwnerEnrollmentAdmission.observeHead(
                fixture.packageValue.head, fixture.pin, fixture.readerPublic, store, fixture.now,
            )
            assertEquals(fixture.packageValue.head.ownerRevision, advanced.exactRevision)
            assertEquals(fixture.packageValue.head.ownerDigest, advanced.exactDigest)
            assertTrue(File(root, "owner-floor-v1.bin").isFile)
            root.deleteRecursively()
        } finally {
            destroy(fixture)
        }
    }

    @Test
    fun replayedOlderOwnerHeadIsRejectedAfterNewerRevocationWasPersisted() {
        val owner = ed25519()
        val signer = ed25519()
        val reader = p256()
        val readerPublic = rawPublic(reader)
        val cek = ByteArray(32).also(SecureRandom()::nextBytes)
        val now = 1_800_000_000_000L
        val root = Files.createTempDirectory("owner-enrollment-replay").toFile()
        try {
            val original = buildFixture(owner, signer, reader, readerPublic, cek, now, 1, emptyList())
            val revoked = buildFixture(
                owner, signer, reader, readerPublic, cek, now + 1, 2,
                listOf(OwnerEnrollmentAdmission.readerDeviceId(readerPublic)),
            )
            val store = OwnerOfflineFloorStore(
                root, SecretKeySpec(ByteArray(32) { (it + 61).toByte() }, "AES"), true,
            )
            val advancedPin = OwnerEnrollmentAdmission.observeHead(
                revoked.packageValue.head, original.pin, readerPublic, store, now + 1,
            )
            assertEquals(2L, advancedPin.exactRevision)
            assertThrows(ProtectedSyncException::class.java) {
                OwnerEnrollmentAdmission.validateHead(
                    original.packageValue.head, advancedPin, readerPublic, now + 2,
                )
            }
            assertThrows(ProtectedSyncException::class.java) {
                OwnerEnrollmentAdmission.validatePackage(
                    original.packageValue, advancedPin, readerPublic, now + 2,
                )
            }
            destroy(original)
            destroy(revoked)
        } finally {
            root.deleteRecursively()
            readerPublic.fill(0)
            cek.fill(0)
        }
    }

    @Test
    fun v2FloorLockBlocksNewRevocationUntilProtectedConsumeCompletes() {
        val owner = ed25519()
        val signer = ed25519()
        val reader = p256()
        val readerPublic = rawPublic(reader)
        val cek = ByteArray(32).also(SecureRandom()::nextBytes)
        val now = 1_800_000_000_000L
        val root = Files.createTempDirectory("owner-enrollment-v2-lock").toFile()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val current = buildFixture(owner, signer, reader, readerPublic, cek, now, 1, emptyList())
            val revoked = buildFixture(
                owner, signer, reader, readerPublic, cek, now + 1, 2,
                listOf(OwnerEnrollmentAdmission.readerDeviceId(readerPublic)),
            )
            val keyBytes = ByteArray(32) { (it + 81).toByte() }
            val activeStore = OwnerOfflineFloorStore(root, SecretKeySpec(keyBytes, "AES"), true)
            val consumer = executor.submit<String> {
                OwnerEnrollmentAdmission.withAuthorizedGrant(
                    current.packageValue, current.pin, readerPublic, activeStore, now,
                    agree = { enc -> agree(reader, enc) },
                ) { _, _ ->
                    entered.countDown()
                    check(release.await(5, TimeUnit.SECONDS))
                    "consumed"
                }
            }
            assertTrue(entered.await(5, TimeUnit.SECONDS), "V2 consume callback did not enter under the floor lock")
            val competingStore = OwnerOfflineFloorStore(root, SecretKeySpec(keyBytes, "AES"), false)
            assertThrows(ProtectedSyncException::class.java) {
                OwnerEnrollmentAdmission.observeHead(
                    revoked.packageValue.head, current.pin, readerPublic, competingStore, now + 1,
                )
            }
            release.countDown()
            assertEquals("consumed", consumer.get(5, TimeUnit.SECONDS))
            val advanced = OwnerEnrollmentAdmission.observeHead(
                revoked.packageValue.head, current.pin, readerPublic,
                OwnerOfflineFloorStore(root, SecretKeySpec(keyBytes, "AES"), false), now + 1,
            )
            assertEquals(2L, advanced.exactRevision)
            destroy(current)
            destroy(revoked)
            keyBytes.fill(0)
        } finally {
            release.countDown()
            executor.shutdownNow()
            root.deleteRecursively()
            readerPublic.fill(0)
            cek.fill(0)
        }
    }

    @Test
    fun hardwareAliasIndexDoesNotAcceptInconsistentClockAcrossRevisionAdvance() {
        val oldDigest = "11".repeat(32)
        val newDigest = "22".repeat(32)
        val old = OwnerFloorRevisionIndex.aliasFor(1, oldDigest, 1_800_000_000_100L, 1)
        val newerRevisionWithRolledBackClock = OwnerFloorRevisionIndex.aliasFor(
            2, newDigest, 1_800_000_000_090L, 1,
        )
        assertThrows(ProtectedSyncException::class.java) {
            OwnerFloorRevisionIndex.select(
                listOf(old, newerRevisionWithRolledBackClock), 2, newDigest,
                1_800_000_000_090L, allowInitialProvisioning = false,
            )
        }
        assertThrows(ProtectedSyncException::class.java) {
            OwnerFloorRevisionIndex.select(
                listOf(old, newerRevisionWithRolledBackClock), 2, newDigest,
                1_800_000_000_110L, allowInitialProvisioning = false,
            )
        }
    }

    @Test
    fun restartedFloorAcceptsCurrentHeadAndASealedFileRollbackFails() {
        val owner = ed25519()
        val signer = ed25519()
        val reader = p256()
        val readerPublic = rawPublic(reader)
        val cek = ByteArray(32).also(SecureRandom()::nextBytes)
        val now = 1_800_000_000_000L
        try {
            val first = buildFixture(owner, signer, reader, readerPublic, cek, now, 1, emptyList())
            val firstPin = first.pin
            val firstRoot = Files.createTempDirectory("owner-floor-restart-r1").toFile()
            val firstKey = SecretKeySpec(ByteArray(32) { (it + 10).toByte() }, "AES")
            OwnerEnrollmentAdmission.observeHead(
                first.packageValue.head, firstPin, readerPublic,
                OwnerOfflineFloorStore(firstRoot, firstKey, true), now,
            )
            val savedOldFloor = File(firstRoot, "owner-floor-v1.bin").readBytes()
            OwnerEnrollmentAdmission.observeHead(
                first.packageValue.head, firstPin, readerPublic,
                OwnerOfflineFloorStore(firstRoot, firstKey, false), now + 1,
            )

            val sameRevisionRoot = Files.createTempDirectory("owner-floor-same-revision").toFile()
            val sameRevisionKey = SecretKeySpec(ByteArray(32) { (it + 50).toByte() }, "AES")
            OwnerEnrollmentAdmission.observeHead(
                first.packageValue.head, firstPin, readerPublic,
                OwnerOfflineFloorStore(sameRevisionRoot, sameRevisionKey, true), now + 1,
            )
            Files.write(File(sameRevisionRoot, "owner-floor-v1.bin").toPath(), savedOldFloor)
            assertThrows(ProtectedSyncException::class.java) {
                OwnerEnrollmentAdmission.observeHead(
                    first.packageValue.head, firstPin, readerPublic,
                    OwnerOfflineFloorStore(sameRevisionRoot, sameRevisionKey, false), now + 2,
                )
            }

            val second = buildFixture(owner, signer, reader, readerPublic, cek, now + 2, 2, emptyList())
            val secondRoot = Files.createTempDirectory("owner-floor-restart-r2").toFile()
            val secondKey = SecretKeySpec(ByteArray(32) { (it + 90).toByte() }, "AES")
            val secondPin = OwnerEnrollmentAdmission.observeHead(
                second.packageValue.head, firstPin, readerPublic,
                OwnerOfflineFloorStore(secondRoot, secondKey, true), now + 2,
            )
            Files.write(File(secondRoot, "owner-floor-v1.bin").toPath(), savedOldFloor)
            assertThrows(ProtectedSyncException::class.java) {
                OwnerEnrollmentAdmission.observeHead(
                    second.packageValue.head, secondPin, readerPublic,
                    OwnerOfflineFloorStore(secondRoot, secondKey, false), now + 3,
                )
            }

            val firstDigestHex = digestHex(first.packageValue.head.ownerDigest)
            val secondDigestHex = digestHex(second.packageValue.head.ownerDigest)
            val alias1 = OwnerFloorRevisionIndex.aliasFor(1, firstDigestHex, now, 1)
            val alias2 = OwnerFloorRevisionIndex.aliasFor(2, secondDigestHex, now + 2, 1)
            assertThrows(ProtectedSyncException::class.java) {
                OwnerFloorRevisionIndex.select(listOf(alias1, alias2), 1, firstDigestHex, now + 3, false)
            }
            val current = OwnerFloorRevisionIndex.select(listOf(alias1, alias2), 2,
                secondDigestHex, now + 2, false)
            assertEquals(alias2, current.latest?.alias)
            assertEquals(2L, current.next.sequence)
            assertThrows(ProtectedSyncException::class.java) {
                OwnerFloorRevisionIndex.select(listOf(alias2), 2, secondDigestHex, now + 1, false)
            }
            savedOldFloor.fill(0)
            firstRoot.deleteRecursively()
            sameRevisionRoot.deleteRecursively()
            secondRoot.deleteRecursively()
            destroy(first)
            destroy(second)
        } finally {
            readerPublic.fill(0)
            cek.fill(0)
        }
    }

    @Test
    fun nodeVectorIsDeterministicAndContainsNoPrivateKeyOrRawCek() {
        val fixture = fixture()
        try {
            val ownerPrivate = b64(fixture.ownerPrivatePkcs8)
            val signerPrivate = b64(fixture.signerPrivatePkcs8)
            val cek = b64(fixture.cek)
            assertFalse(fixture.vectorJson.contains(ownerPrivate))
            assertFalse(fixture.vectorJson.contains(signerPrivate))
            assertFalse(fixture.vectorJson.contains(cek))
            val regenerated = runNode(fixture.inputJson)
            assertEquals(fixture.vectorJson, regenerated)
        } finally {
            destroy(fixture)
        }
    }

    private data class BuiltFixture(
        val packageValue: OwnerEnrollmentPackage,
        val pin: IndependentOfflineOwnerPin,
        val reader: KeyPair,
        val readerPublic: ByteArray,
        val cek: ByteArray,
        val now: Long,
        val ownerPrivatePkcs8: ByteArray,
        val signerPrivatePkcs8: ByteArray,
        val inputJson: String,
        val vectorJson: String,
    )

    private fun fixture(revoked: Boolean = false): BuiltFixture {
        val owner = ed25519()
        val signer = ed25519()
        val reader = p256()
        val readerPublic = rawPublic(reader)
        val cek = ByteArray(32).also(SecureRandom()::nextBytes)
        val built = buildFixture(owner, signer, reader, readerPublic, cek, 1_800_000_000_000L, 1,
            if (revoked) listOf(OwnerEnrollmentAdmission.readerDeviceId(readerPublic)) else emptyList())
        cek.fill(0)
        readerPublic.fill(0)
        return built
    }

    private fun buildFixture(
        owner: KeyPair,
        signer: KeyPair,
        reader: KeyPair,
        readerPublic: ByteArray,
        cek: ByteArray,
        now: Long,
        revision: Long,
        revoked: List<String>,
    ): BuiltFixture {
        val readerId = OwnerEnrollmentAdmission.readerDeviceId(readerPublic)
        val input = JSONObject()
            .put("ownerPrivatePkcs8", b64(owner.private.encoded))
            .put("signerPrivatePkcs8", b64(signer.private.encoded))
            .put("readerPublicKey", b64(readerPublic))
            .put("readerDeviceId", readerId)
            .put("cek", b64(cek))
            .put("nowMillis", now)
            .put("origin", "https://files.example.org")
            .put("username", "alice")
            .put("revokedDeviceIds", JSONArray(revoked))
            .put("ownerRevision", revision)
        val inputJson = input.toString()
        val output = runNode(inputJson)
        val root = JSONObject(output)
        val head = root.getJSONObject("head")
        val grant = root.getJSONObject("grant")
        val packageValue = OwnerEnrollmentPackage(
            root.getString("schema"), root.getString("ownerPublicSpki"),
            OwnerSignedOfflineHeadV2(
                head.getString("schema"), head.getString("origin"), head.getString("username"),
                head.getString("readerDeviceId"), head.getLong("ownerRevision"), head.getString("ownerDigest"),
                (0 until head.getJSONArray("revokedDeviceIds").length()).map { head.getJSONArray("revokedDeviceIds").getString(it) },
                head.getLong("issuedAtMillis"), head.getLong("expiresAtMillis"), head.getString("signature"),
            ),
            OwnerSignedOfflineWrappedCekGrant(
                grant.getString("schema"), grant.getString("origin"), grant.getString("username"),
                grant.getString("readerDeviceId"), grant.getLong("ownerRevision"), grant.getString("ownerDigest"),
                grant.getString("objectId"), grant.getString("fileId"), grant.getString("versionId"),
                grant.getString("compartmentId"), grant.getString("keyEpoch"), grant.getString("signerDeviceId"),
                grant.getString("signerPublicKeySpki"), grant.getString("cekSha256"), grant.getString("nonce"),
                grant.getLong("issuedAtMillis"), grant.getLong("expiresAtMillis"), grant.getString("hpkeSuite"),
                grant.getString("enc"), grant.getString("wrappedCek"), grant.getString("signature"),
            ),
        )
        val digestInput = ("Root.ark/android/owner-head-digest/v2\u0000" +
            ProtectedSyncContent.canonicalJson(packageValue.head.digestFields())).toByteArray(Charsets.UTF_8)
        val recomputedDigest = b64(MessageDigest.getInstance("SHA-256").digest(digestInput))
        check(recomputedDigest == packageValue.head.ownerDigest) {
            "Node/Kotlin owner-head canonicalization mismatch: ${ProtectedSyncContent.canonicalJson(packageValue.head.digestFields())}; expected=$recomputedDigest actual=${packageValue.head.ownerDigest}"
        }
        val ownerSpki = Base64.getUrlDecoder().decode(packageValue.ownerPublicSpki)
        val pin = IndependentOfflineOwnerPin(
            "https://files.example.org", "alice", readerId, ownerSpki,
            MessageDigest.getInstance("SHA-256").digest(ownerSpki), revision, packageValue.head.ownerDigest,
        )
        return BuiltFixture(
            packageValue, pin, reader, readerPublic.copyOf(), cek.copyOf(), now,
            owner.private.encoded.copyOf(), signer.private.encoded.copyOf(), inputJson, output,
        )
    }

    private fun destroy(fixture: BuiltFixture) {
        fixture.cek.fill(0)
        fixture.readerPublic.fill(0)
        fixture.pin.ownerPublicSpki.fill(0)
        fixture.pin.ownerPublicSpkiSha256.fill(0)
        fixture.ownerPrivatePkcs8.fill(0)
        fixture.signerPrivatePkcs8.fill(0)
    }

    private fun runNode(input: String): String {
        val script = File(javaClass.getResource("/owner-enrollment-vector.js")!!.toURI())
        val node = System.getenv("ROOTARK_NODE_BIN") ?: "node"
        val process = ProcessBuilder(node, script.absolutePath).redirectErrorStream(true).start()
        process.outputStream.use { it.write(input.toByteArray(Charsets.UTF_8)) }
        val output = process.inputStream.use { it.readBytes() }.toString(Charsets.UTF_8)
        val exit = process.waitFor()
        assertEquals(0, exit, "Node test-vector generator failed: $output")
        return output
    }

    private fun agree(reader: KeyPair, enc: ByteArray): ByteArray = KeyAgreement.getInstance("ECDH").run {
        init(reader.private)
        doPhase(HpkeP256.decodePublicKey(enc), true)
        generateSecret()
    }

    private fun ed25519(): KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    private fun p256(): KeyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    private fun rawPublic(pair: KeyPair): ByteArray {
        val public = pair.public as ECPublicKey
        fun coordinate(value: BigInteger): ByteArray {
            val bytes = value.toByteArray().let {
                if (it.size == 33 && it[0] == 0.toByte()) it.copyOfRange(1, 33) else it
            }
            return ByteArray(32).also { bytes.copyInto(it, 32 - bytes.size) }
        }
        val point = public.getW()
        return byteArrayOf(0x04) + coordinate(point.getAffineX()) + coordinate(point.getAffineY())
    }

    private fun b64(value: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(value)

    private fun flipLast(value: String): String {
        val last = value.last()
        return value.dropLast(1) + if (last == 'A') 'B' else 'A'
    }

    private fun digestHex(encoded: String): String = Base64.getUrlDecoder().decode(encoded)
        .joinToString("") { "%02x".format(it) }
}
