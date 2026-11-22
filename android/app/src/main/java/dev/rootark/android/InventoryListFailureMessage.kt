package dev.rootark.android

import dev.rootark.core.sync.RootArkApiException
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLException

/** Preserve the legacy list contract for callers and regressions.
 * The paged inventory UI uses inventoryPageFailureMessage instead: its
 * response limit is smaller and its cursor errors are handled separately.
 */
internal fun inventoryListFailureMessage(failure: Exception?): String = when (failure) {
    is SyncListingLimitException ->
        "Não foi possível carregar a lista. A resposta excede o limite do protótipo (1 MiB / 128 registros)."
    is SyncListingValidationException ->
        "Não foi possível carregar a lista. Os dados de sincronização retornados pelo servidor são inválidos."
    else -> inventoryListRequestFailureMessage(failure)
}

/** Presentation for the legacy, non-paginated inventory list. */
internal fun inventoryListRequestFailureMessage(failure: Exception?): String = when (failure) {
    is SocketTimeoutException ->
        "A solicitação da lista excedeu o tempo limite. Tente novamente."
    is UnknownHostException ->
        "Não foi possível localizar o servidor. Verifique a conexão e o endereço."
    is ConnectException, is NoRouteToHostException ->
        "Não foi possível conectar ao servidor. Verifique a conexão e tente novamente."
    is SSLException ->
        "Não foi possível estabelecer uma conexão segura com o servidor. Verifique o endereço e tente novamente."
    is RootArkApiException -> when (failure.statusCode) {
        429 -> "Muitas solicitações de listagem. Aguarde um pouco antes de tentar novamente."
        503 -> "A lista está temporariamente indisponível no servidor. Tente novamente mais tarde."
        else -> "Não foi possível carregar a lista. Tente novamente."
    }
    else -> "Não foi possível carregar a lista. Tente novamente."
}
