package dev.rootark.android

import dev.rootark.core.sync.RootArkApiException
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLException

/** Presentation only: never include raw exception text in a user-facing message. */
internal fun inventoryPageRequestFailureMessage(failure: Exception?): String = when (failure) {
    is SocketTimeoutException ->
        "A solicitação do inventário excedeu o tempo limite. Tente novamente."
    is UnknownHostException ->
        "Não foi possível localizar o servidor. Verifique a conexão e o endereço."
    is ConnectException, is NoRouteToHostException ->
        "Não foi possível conectar ao servidor. Verifique a conexão e tente novamente."
    is SSLException ->
        "Não foi possível estabelecer uma conexão segura com o servidor. Verifique o endereço e tente novamente."
    is RootArkApiException -> when (failure.statusCode) {
        429 -> "Muitas solicitações de inventário. Aguarde um pouco antes de tentar novamente."
        503 -> "O inventário está temporariamente indisponível no servidor. Tente novamente mais tarde."
        else -> "Não foi possível carregar a página de inventário. Tente novamente."
    }
    else ->
        "Não foi possível carregar a página de inventário. Tente novamente."
}
