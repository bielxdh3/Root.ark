package dev.rootark.core.auth

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class ServerOriginTest {
    @Test
    fun `HTTPS origin creates exactly the existing auth routes`() {
        val origin = ServerOrigin.parse("https://vault.example.test:8443/")
        assertEquals("https://vault.example.test:8443/auth/login", origin.loginUrl().toString())
        assertEquals("https://vault.example.test:8443/auth/login/2fa", origin.twoFactorUrl().toString())
        assertEquals("https://vault.example.test/auth/login", ServerOrigin.parse("https://vault.example.test").loginUrl().toString())
        assertEquals("https://[::1]:443/auth/login", ServerOrigin.parse("https://[::1]:443").loginUrl().toString())
    }

    @Test
    fun `no credentials can leave through cleartext, altered host, URL credentials, or path`() {
        val invalid = listOf(
            "http://vault.example.test", "https://vault.example.test.evil.test/path",
            "https://user:password@vault.example.test", "https://vault.example.test@evil.test",
            "https://vault.example.test/auth", "https://vault.example.test//auth",
            "https://vault.example.test/%2Fauth", "https://vault.example.test?next=evil",
            "https://vault.example.test#auth", "https://vault.example.test:0",
            "https://", "https://vault.example.test\n", "ftp://vault.example.test"
        )
        for (candidate in invalid) {
            assertThrows(IllegalArgumentException::class.java, { ServerOrigin.parse(candidate) }, "accepted $candidate")
        }
    }
}
