package dev.rootark.core.sync

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** RFC 9180 base-mode receiver for DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM. */
object HpkeP256 {
    const val SUITE = "DHKEM(P-256,HKDF-SHA256)/HKDF-SHA256/AES-256-GCM"
    private val VERSION = "HPKE-v1".toByteArray(Charsets.US_ASCII)
    private val KEM_SUITE = "KEM".toByteArray(Charsets.US_ASCII) + i2osp(0x0010, 2)
    private val HPKE_SUITE = "HPKE".toByteArray(Charsets.US_ASCII) +
        i2osp(0x0010, 2) + i2osp(0x0001, 2) + i2osp(0x0002, 2)
    private val P256_P = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
    private val P256_A = P256_P.subtract(BigInteger.valueOf(3))
    private val P256_B = BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)

    /** Decode and validate the canonical SEC1 uncompressed P-256 point (04 || X || Y). */
    @JvmStatic
    fun decodePublicKey(raw: ByteArray): java.security.PublicKey {
        require(raw.size == 65 && raw[0] == 0x04.toByte())
        val parameters = AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec("secp256r1"))
        }.getParameterSpec(ECParameterSpec::class.java)
        val x = BigInteger(1, raw.copyOfRange(1, 33))
        val y = BigInteger(1, raw.copyOfRange(33, 65))
        require(x < P256_P && y < P256_P)
        val lhs = y.multiply(y).mod(P256_P)
        val rhs = x.multiply(x).multiply(x).add(P256_A.multiply(x)).add(P256_B).mod(P256_P)
        require(lhs == rhs)
        return KeyFactory.getInstance("EC").generatePublic(
            ECPublicKeySpec(java.security.spec.ECPoint(x, y), parameters),
        )
    }

    /**
     * Open one HPKE base-mode message. [dh] is the 32-byte ECDH result produced
     * by the recipient key provider. This method erases the supplied DH buffer
     * and all derived key material on both success and failure.
     */
    @JvmStatic
    fun open(
        enc: ByteArray,
        recipientPublicKey: ByteArray,
        dh: ByteArray,
        info: ByteArray,
        aad: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray {
        var eaePrk: ByteArray? = null
        var sharedSecret: ByteArray? = null
        var pskIdHash: ByteArray? = null
        var infoHash: ByteArray? = null
        var secret: ByteArray? = null
        var key: ByteArray? = null
        var nonce: ByteArray? = null
        var kemContext: ByteArray? = null
        var keyScheduleContext: ByteArray? = null
        try {
            require(dh.size == 32 && ciphertext.size == 48)
            decodePublicKey(enc)
            decodePublicKey(recipientPublicKey)
            kemContext = enc + recipientPublicKey
            eaePrk = labeledExtract(ByteArray(0), "eae_prk", dh, KEM_SUITE)
            sharedSecret = labeledExpand(eaePrk, "shared_secret", kemContext, 32, KEM_SUITE)
            pskIdHash = labeledExtract(ByteArray(0), "psk_id_hash", ByteArray(0), HPKE_SUITE)
            infoHash = labeledExtract(ByteArray(0), "info_hash", info, HPKE_SUITE)
            keyScheduleContext = byteArrayOf(0) + pskIdHash + infoHash // mode_base
            secret = labeledExtract(sharedSecret, "secret", ByteArray(0), HPKE_SUITE)
            key = labeledExpand(secret, "key", keyScheduleContext, 32, HPKE_SUITE)
            nonce = labeledExpand(secret, "base_nonce", keyScheduleContext, 12, HPKE_SUITE)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(aad)
            return cipher.doFinal(ciphertext)
        } finally {
            dh.fill(0)
            eaePrk?.fill(0)
            sharedSecret?.fill(0)
            pskIdHash?.fill(0)
            infoHash?.fill(0)
            secret?.fill(0)
            key?.fill(0)
            nonce?.fill(0)
            kemContext?.fill(0)
            keyScheduleContext?.fill(0)
        }
    }

    private fun labeledExtract(salt: ByteArray, label: String, ikm: ByteArray, suite: ByteArray): ByteArray {
        val labeledIkm = VERSION + suite + label.toByteArray(Charsets.US_ASCII) + ikm
        return try { hkdfExtract(salt, labeledIkm) } finally { labeledIkm.fill(0) }
    }

    private fun labeledExpand(
        prk: ByteArray, label: String, info: ByteArray, length: Int, suite: ByteArray,
    ): ByteArray {
        val labeledInfo = i2osp(length, 2) + VERSION + suite + label.toByteArray(Charsets.US_ASCII) + info
        return try { hkdfExpand(prk, labeledInfo, length) } finally { labeledInfo.fill(0) }
    }

    private fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val actualSalt = if (salt.isEmpty()) ByteArray(32) else salt
        return hmac(actualSalt, ikm)
    }

    private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..(255 * 32))
        val output = ByteArray(length)
        var previous = ByteArray(0)
        var offset = 0
        var counter = 1
        try {
            while (offset < length) {
                val blockInput = previous + info + byteArrayOf(counter.toByte())
                val next = try { hmac(prk, blockInput) } finally { blockInput.fill(0) }
                previous.fill(0)
                previous = next
                val count = minOf(next.size, length - offset)
                next.copyInto(output, offset, 0, count)
                offset += count
                counter++
            }
            return output
        } catch (error: Throwable) {
            output.fill(0)
            throw error
        } finally {
            previous.fill(0)
        }
    }

    private fun hmac(key: ByteArray, input: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256"))
            doFinal(input)
        }

    private fun i2osp(value: Int, length: Int): ByteArray {
        require(value >= 0 && length in 1..4 && value.toLong() < (1L shl (length * 8)))
        return ByteArray(length) { index ->
            (value ushr ((length - index - 1) * 8)).toByte()
        }
    }
}
