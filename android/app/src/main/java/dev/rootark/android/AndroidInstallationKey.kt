package dev.rootark.android

import android.annotation.TargetApi
import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import dev.rootark.core.sync.HpkeP256
import dev.rootark.core.sync.OwnerEnrollmentAdmission
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyAgreement

internal data class AndroidInstallationIdentity(
    val publicKey: ByteArray,
    val readerDeviceId: String,
    val securityLevel: Int,
)

/** Non-exportable, user-authenticated P-256 ECDH identity in AndroidKeyStore. */
internal class AndroidInstallationKey(private val context: Context) {
    @TargetApi(Build.VERSION_CODES.S)
    fun publicIdentity(allowCreate: Boolean): AndroidInstallationIdentity {
        requireApiAndCredential()
        val keyStore = androidKeyStore()
        val exists = keyStore.containsAlias(ALIAS)
        if (!exists) {
            check(allowCreate) { "Enrolled installation key is missing" }
            generate()
        }
        try {
            val privateKey = keyStore.getKey(ALIAS, null) as? PrivateKey
                ?: throw SecurityException("Installation key unavailable")
            check(privateKey.encoded == null)
            val publicKey = keyStore.getCertificate(ALIAS)?.publicKey as? ECPublicKey
                ?: throw SecurityException("Installation public key unavailable")
            val info = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
                .getKeySpec(privateKey, KeyInfo::class.java) as? KeyInfo
                ?: throw SecurityException("Installation KeyInfo unavailable")
            AndroidKeySecurityPolicy.requireHardwareDeviceCredentialKey(
                info.securityEvidence(), KeyProperties.PURPOSE_AGREE_KEY,
            )
            check(info.keySize == 256)
            val raw = publicKey.toUncompressedPoint()
            HpkeP256.decodePublicKey(raw)
            return AndroidInstallationIdentity(
                raw, OwnerEnrollmentAdmission.readerDeviceId(raw), info.securityLevel,
            )
        } catch (error: Exception) {
            throw SecurityException("Hardware-backed Android P-256 enrollment key unavailable", error)
        }
    }

    /** The AndroidKeyStore provider performs ECDH without exporting the private scalar. */
    @TargetApi(Build.VERSION_CODES.S)
    fun agree(enc: ByteArray): ByteArray {
        requireApiAndCredential()
        val identity = publicIdentity(allowCreate = false)
        identity.publicKey.fill(0)
        val ephemeral = HpkeP256.decodePublicKey(enc)
        val privateKey = androidKeyStore().getKey(ALIAS, null) as? PrivateKey
            ?: throw SecurityException("Installation private key unavailable")
        check(privateKey.encoded == null)
        val agreement = KeyAgreement.getInstance("ECDH", ANDROID_KEYSTORE)
        agreement.init(privateKey)
        agreement.doPhase(ephemeral, true)
        val secret = agreement.generateSecret()
        if (secret.size != 32) {
            secret.fill(0)
            throw SecurityException("AndroidKeyStore returned an invalid P-256 shared secret")
        }
        return secret
    }

    /** Exercise the actual AndroidKeyStore ECDH operation after the credential prompt. */
    @TargetApi(Build.VERSION_CODES.S)
    fun requireAgreementSupport() {
        requireApiAndCredential()
        // The standard P-256 generator point is a public peer. No software
        // recipient key or software ECDH fallback is created for this probe.
        val encodedPublic = P256_GENERATOR_POINT.copyOf()
        try {
            val shared = agree(encodedPublic)
            try { check(shared.size == 32) }
            finally { shared.fill(0) }
        } finally {
            encodedPublic.fill(0)
        }
    }

    @TargetApi(Build.VERSION_CODES.S)
    private fun generate() {
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        generator.initialize(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_AGREE_KEY)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(AUTH_WINDOW_SECONDS, KeyProperties.AUTH_DEVICE_CREDENTIAL)
                .build(),
        )
        generator.generateKeyPair()
    }

    @TargetApi(Build.VERSION_CODES.S)
    private fun requireApiAndCredential() {
        // V2 also verifies owner Ed25519 signatures, provided by Android at
        // API 33+. Do not create an installation key for an unusable V2 client.
        check(Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) { "Owner-signed Android enrollment requires API 33" }
        val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
            ?: throw SecurityException("Device credential service unavailable")
        check(keyguard.isDeviceSecure) { "A secure device credential is required" }
    }

    private fun androidKeyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun ECPublicKey.toUncompressedPoint(): ByteArray {
        check(params.curve.field.fieldSize == 256 && params.order.bitLength() == 256)
        val point = getW()
        return byteArrayOf(0x04) + coordinate(point.getAffineX()) + coordinate(point.getAffineY())
    }

    private fun coordinate(value: BigInteger): ByteArray {
        val encoded = value.toByteArray()
        val unsigned = if (encoded.size == 33 && encoded[0] == 0.toByte()) encoded.copyOfRange(1, 33)
            else encoded
        check(unsigned.size <= 32)
        return ByteArray(32).also { unsigned.copyInto(it, 32 - unsigned.size) }
    }

    companion object {
        const val AUTH_WINDOW_SECONDS = 30
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val ALIAS = "dev.rootark.android.installation-ecdh-p256-v2"
        private val P256_GENERATOR_POINT = hex(
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )

        private fun hex(value: String): ByteArray = ByteArray(value.length / 2) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }
}
