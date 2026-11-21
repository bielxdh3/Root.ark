package dev.rootark.android

import dev.rootark.core.sync.RootArkApiException
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class InventoryPageFailureMessageTest {
    @Test fun listingLimitHasItsOwnSafeMessage() {
        val message = inventoryPageFailureMessage(SyncListingLimitException("private fixture detail"))
        assertEquals(
            "Não foi possível carregar a página de inventário. A resposta excede os limites de tamanho ou estrutura (128 KiB / 64 registros).",
            message,
        )
        assertFalse(message.contains("private fixture detail"))
    }

    @Test fun listingValidationHasItsOwnSafeMessage() {
        val message = inventoryPageFailureMessage(
            SyncListingValidationException("private fixture detail", IllegalArgumentException("secret"))
        )
        assertEquals(
            "Não foi possível carregar a página de inventário. Os dados retornados pelo servidor são inválidos.",
            message,
        )
        assertFalse(message.contains("private fixture detail"))
        assertFalse(message.contains("secret"))
    }

    @Test fun timeoutHasItsOwnMessage() {
        assertEquals("A solicitação do inventário excedeu o tempo limite. Tente novamente.",
            inventoryPageFailureMessage(SocketTimeoutException("fixture")))
    }

    @Test fun unknownHostHasItsOwnMessage() {
        assertEquals("Não foi possível localizar o servidor. Verifique a conexão e o endereço.",
            inventoryPageFailureMessage(UnknownHostException("fixture")))
    }

    @Test fun connectionFailuresShareAnActionableMessage() {
        val expected = "Não foi possível conectar ao servidor. Verifique a conexão e tente novamente."
        assertEquals(expected, inventoryPageFailureMessage(ConnectException("fixture")))
        assertEquals(expected, inventoryPageFailureMessage(NoRouteToHostException("fixture")))
    }

    @Test fun secureConnectionFailureHasItsOwnMessage() {
        assertEquals("Não foi possível estabelecer uma conexão segura com o servidor. Verifique o endereço e tente novamente.",
            inventoryPageFailureMessage(SSLException("fixture")))
    }

    @Test fun unknownOrMissingFailureUsesNeutralMessage() {
        val expected = "Não foi possível carregar a página de inventário. Tente novamente."
        assertEquals(expected, inventoryPageFailureMessage(IllegalStateException("fixture")))
        assertEquals(expected, inventoryPageFailureMessage(null))
        assertEquals(expected, inventoryPageFailureMessage(RootArkApiException(500)))
    }

    @Test fun rateLimitHasItsOwnMessage() {
        assertEquals("Muitas solicitações de inventário. Aguarde um pouco antes de tentar novamente.",
            inventoryPageFailureMessage(RootArkApiException(429)))
    }

    @Test fun serviceUnavailableHasItsOwnMessage() {
        assertEquals("O inventário está temporariamente indisponível no servidor. Tente novamente mais tarde.",
            inventoryPageFailureMessage(RootArkApiException(503)))
    }
}
