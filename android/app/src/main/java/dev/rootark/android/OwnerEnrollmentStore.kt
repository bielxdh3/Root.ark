package dev.rootark.android

import dev.rootark.core.sync.IndependentOfflineOwnerPin
import java.io.File
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.util.Base64
import org.json.JSONObject

internal data class StoredOwnerEnrollment(
    val pin: IndependentOfflineOwnerPin,
    val packageBytes: ByteArray,
    val ecdhCapabilityVerified: Boolean,
)

/** Stores only a public owner pin and an owner-signed, CEK-wrapped package in no-backup storage. */
internal class OwnerEnrollmentStore(noBackupRoot: File) {
    private val root = File(noBackupRoot, "owner-enrollment-v2")
    private val destination = File(root, "enrollment-v2.json")
    private val pending = File(root, "pending-enrollment-v2.json")

    /**
     * Durable, non-authoritative recovery hint. The signed/wrapped candidate is
     * written BEFORE a new hardware high-water alias can be allocated. It is
     * never used as a trusted enrollment by load() or the grant provider.
     * After an interrupted seal the user must reimport an owner-signed package.
     */
    fun stage(pin: IndependentOfflineOwnerPin, packageBytes: ByteArray,
              ecdhCapabilityVerified: Boolean) {
        // Called while the hardware-floor index lock is held. A durable
        // pending head is a recovery constraint, not an authorization source.
        val staged = read(pending)
        try {
            if (staged != null) {
                val prior = staged.pin
                if (pin.origin != prior.origin || pin.username != prior.username ||
                    pin.readerDeviceId != prior.readerDeviceId ||
                    !pin.ownerPublicSpki.contentEquals(prior.ownerPublicSpki) ||
                    !pin.ownerPublicSpkiSha256.contentEquals(prior.ownerPublicSpkiSha256) ||
                    pin.exactRevision < prior.exactRevision ||
                    (pin.exactRevision == prior.exactRevision && pin.exactDigest != prior.exactDigest)) {
                    throw SecurityException("Pending owner enrollment is incompatible")
                }
            }
            write(pending, pin, packageBytes, ecdhCapabilityVerified)
        } finally {
            staged?.pin?.ownerPublicSpki?.fill(0)
            staged?.pin?.ownerPublicSpkiSha256?.fill(0)
            staged?.packageBytes?.fill(0)
        }
    }

    fun hasPending(): Boolean {
        validateRoot(create = false)
        check(!Files.isSymbolicLink(pending.toPath()))
        return Files.exists(pending.toPath(), LinkOption.NOFOLLOW_LINKS).also { exists ->
            if (exists) check(Files.isRegularFile(pending.toPath(), LinkOption.NOFOLLOW_LINKS))
        }
    }

    fun clearPending() {
        validateRoot(create = false)
        check(!Files.isSymbolicLink(pending.toPath()))
        if (Files.deleteIfExists(pending.toPath())) {
            FileChannel.open(root.toPath(), StandardOpenOption.READ).use { it.force(true) }
        }
    }

    fun load(): StoredOwnerEnrollment? = read(destination)

    private fun read(target: File): StoredOwnerEnrollment? {
        try {
            validateRoot(create = false)
            check(!Files.isSymbolicLink(target.toPath()))
            if (!Files.exists(target.toPath(), LinkOption.NOFOLLOW_LINKS)) return null
            check(Files.isRegularFile(target.toPath(), LinkOption.NOFOLLOW_LINKS))
            val bytes = FileChannel.open(target.toPath(), StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS).use { channel ->
                val size = channel.size()
                check(size in 2..65_536)
                val buffer = ByteBuffer.allocate(size.toInt())
                while (buffer.hasRemaining()) check(channel.read(buffer) > 0)
                buffer.array()
            }
            try {
                val text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString()
                StrictRfc8259Json.validate(text)
                val json = JSONObject(text)
                exactKeys(json, setOf(
                    "schema", "origin", "username", "readerDeviceId", "ownerPublicSpki",
                    "ownerPublicSpkiSha256", "exactRevision", "exactDigest", "package",
                    "ecdhCapabilityVerified",
                ))
                check(json.getString("schema") == STORE_SCHEMA)
                val owner = decode(json.getString("ownerPublicSpki"), 44)
                val ownerHash = decode(json.getString("ownerPublicSpkiSha256"), 32)
                val packageBytes = decodeVariable(json.getString("package"), 32_768)
                return StoredOwnerEnrollment(
                    IndependentOfflineOwnerPin(
                        json.getString("origin"), json.getString("username"),
                        json.getString("readerDeviceId"), owner, ownerHash,
                        exactLong(json, "exactRevision"), json.getString("exactDigest"),
                    ),
                    packageBytes,
                    json.get("ecdhCapabilityVerified") as? Boolean
                        ?: throw SecurityException("Invalid ECDH capability state"),
                )
            } finally { bytes.fill(0) }
        } catch (_: Exception) {
            throw SecurityException("Owner enrollment storage unavailable")
        }
    }

    fun save(
        pin: IndependentOfflineOwnerPin,
        packageBytes: ByteArray,
        ecdhCapabilityVerified: Boolean = false,
    ) = write(destination, pin, packageBytes, ecdhCapabilityVerified)

    private fun write(target: File, pin: IndependentOfflineOwnerPin,
                      packageBytes: ByteArray, ecdhCapabilityVerified: Boolean) {
        try {
            check(packageBytes.size in 2..32_768)
            validateRoot(create = true)
            val json = JSONObject()
                .put("schema", STORE_SCHEMA)
                .put("origin", pin.origin)
                .put("username", pin.username)
                .put("readerDeviceId", pin.readerDeviceId)
                .put("ownerPublicSpki", encode(pin.ownerPublicSpki))
                .put("ownerPublicSpkiSha256", encode(pin.ownerPublicSpkiSha256))
                .put("exactRevision", pin.exactRevision)
                .put("exactDigest", pin.exactDigest)
                .put("package", encode(packageBytes))
                .put("ecdhCapabilityVerified", ecdhCapabilityVerified)
            val encoded = json.toString().toByteArray(StandardCharsets.UTF_8)
            val temporary = Files.createTempFile(root.toPath(), "enrollment-", ".tmp")
            try {
                FileChannel.open(temporary, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS).use { channel ->
                    val buffer = ByteBuffer.wrap(encoded)
                    while (buffer.hasRemaining()) check(channel.write(buffer) > 0)
                    channel.force(true)
                }
                check(!Files.isSymbolicLink(target.toPath()))
                Files.move(temporary, target.toPath(),
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                FileChannel.open(root.toPath(), StandardOpenOption.READ).use { it.force(true) }
            } finally {
                encoded.fill(0)
                Files.deleteIfExists(temporary)
            }
        } catch (_: Exception) {
            throw SecurityException("Owner enrollment could not be stored")
        }
    }

    private fun validateRoot(create: Boolean) {
        var at: java.nio.file.Path? = root.toPath().toAbsolutePath().normalize()
        while (at != null) {
            check(!Files.isSymbolicLink(at))
            at = at.parent
        }
        if (!Files.exists(root.toPath(), LinkOption.NOFOLLOW_LINKS)) {
            if (!create) return
            check(root.mkdirs())
        }
        check(Files.isDirectory(root.toPath(), LinkOption.NOFOLLOW_LINKS))
        check(!Files.isSymbolicLink(destination.toPath()))
    }

    private fun exactKeys(source: JSONObject, expected: Set<String>) {
        val actual = mutableSetOf<String>()
        val keys = source.keys()
        while (keys.hasNext()) actual.add(keys.next())
        check(actual == expected)
    }

    private fun exactLong(source: JSONObject, key: String): Long = when (val value = source.get(key)) {
        is Int -> value.toLong()
        is Long -> value
        else -> throw SecurityException("Invalid owner enrollment number")
    }

    private fun decode(value: String, size: Int): ByteArray = decodeVariable(value, size).also {
        check(it.size == size)
    }

    private fun decodeVariable(value: String, maximum: Int): ByteArray {
        check(value.matches(BASE64URL) && value.length <= ((maximum + 2) / 3) * 4 + 2)
        val bytes = Base64.getUrlDecoder().decode(value)
        check(bytes.size <= maximum && encode(bytes) == value)
        return bytes
    }

    private fun encode(value: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(value)

    companion object {
        private const val STORE_SCHEMA = "rootark-android-local-enrollment/v2"
        private val BASE64URL = Regex("[A-Za-z0-9_-]+")
    }
}
