package dev.rootark.android

import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLException
import org.junit.Assert.assertEquals
import org.junit.Test

class InventoryPageFailureMessageTest {
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
    }
}
