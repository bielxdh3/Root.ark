package dev.rootark.android

import dev.rootark.core.sync.RootArkApiException
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLException
import org.junit.Assert.assertEquals
import org.junit.Test

class InventoryListFailureMessageTest {
    @Test fun knownLimitKeepsLegacyBounds() {
        assertEquals("Não foi possível carregar a lista. A resposta excede o limite do protótipo (1 MiB / 128 registros).",
            inventoryListFailureMessage(SyncListingLimitException("fixture")))
    }

    @Test fun invalidResponseKeepsItsMessage() {
        assertEquals("Não foi possível carregar a lista. Os dados de sincronização retornados pelo servidor são inválidos.",
            inventoryListFailureMessage(SyncListingValidationException("fixture")))
    }

    @Test fun timeoutHasItsOwnMessage() {
        assertEquals("A solicitação da lista excedeu o tempo limite. Tente novamente.",
            inventoryListFailureMessage(SocketTimeoutException("fixture")))
    }

    @Test fun unknownHostHasItsOwnMessage() {
        assertEquals("Não foi possível localizar o servidor. Verifique a conexão e o endereço.",
            inventoryListFailureMessage(UnknownHostException("fixture")))
    }

    @Test fun connectionFailuresShareAnActionableMessage() {
        val expected = "Não foi possível conectar ao servidor. Verifique a conexão e tente novamente."
        assertEquals(expected, inventoryListFailureMessage(ConnectException("fixture")))
        assertEquals(expected, inventoryListFailureMessage(NoRouteToHostException("fixture")))
    }

    @Test fun secureConnectionFailureHasItsOwnMessage() {
        assertEquals("Não foi possível estabelecer uma conexão segura com o servidor. Verifique o endereço e tente novamente.",
            inventoryListFailureMessage(SSLException("fixture")))
    }

    @Test fun rateLimitHasItsOwnMessage() {
        assertEquals("Muitas solicitações de listagem. Aguarde um pouco antes de tentar novamente.",
            inventoryListFailureMessage(RootArkApiException(429)))
    }

    @Test fun serviceUnavailableHasItsOwnMessage() {
        assertEquals("A lista está temporariamente indisponível no servidor. Tente novamente mais tarde.",
            inventoryListFailureMessage(RootArkApiException(503)))
    }

    @Test fun unknownOrMissingFailureUsesNeutralMessage() {
        val expected = "Não foi possível carregar a lista. Tente novamente."
        assertEquals(expected, inventoryListFailureMessage(IllegalStateException("fixture")))
        assertEquals(expected, inventoryListFailureMessage(null))
        assertEquals(expected, inventoryListFailureMessage(RootArkApiException(500)))
    }
}
