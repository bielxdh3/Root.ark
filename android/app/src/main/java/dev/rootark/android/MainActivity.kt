package dev.rootark.android

import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import dev.rootark.core.auth.ServerOrigin
import dev.rootark.core.sync.LoginOutcome
import dev.rootark.core.sync.InventoryPage
import dev.rootark.core.sync.PagedInventoryPolicy
import dev.rootark.core.sync.ReadOnlyFileListPolicy
import dev.rootark.core.sync.RootArkApiException
import dev.rootark.core.sync.OfflineSession
import dev.rootark.core.sync.SessionOfflineInventory
import java.io.File
import java.util.UUID

/** Authenticated metadata browsing with an explicit, provisioned-only protected text viewer. */
class MainActivity : Activity() {
    private val transport = AuthHttpTransport()
    private var serverField: EditText? = null
    private var usernameField: EditText? = null
    private var passwordField: EditText? = null
    private var codeField: EditText? = null
    private var activeOrigin: ServerOrigin? = null
    private var challengeId: String? = null
    private var sessionToken: String? = null
    private var sessionUsername: String? = null
    private var authenticatedSession: LoginOutcome.Authenticated? = null
    private var securePreviewText: TextView? = null
    private var sessionCanListFiles = false
    private var offlineSession: OfflineSession? = null
    private var offlineInventory: SessionOfflineInventory? = null
    private var ciphertextCache: SessionCiphertextCache? = null
    private val ciphertextRoot: File get() = File(noBackupFilesDir, "ciphertext-staging-v1")
    @Volatile private var generation = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(null)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        showLogin()
    }

    override fun onStop() {
        super.onStop()
        generation++
        clearSensitiveState()
        showLogin()
    }

    private fun clearSensitiveState() {
        val cache = ciphertextCache
        ciphertextCache = null
        runCatching { cache?.clear() }
        runCatching { LocalCipherCacheKey.erase() }
        runCatching { SessionCiphertextCache.purgeStale(ciphertextRoot) }
        offlineInventory?.clear()
        offlineInventory = null
        offlineSession = null
        securePreviewText?.text = ""
        securePreviewText = null
        sessionToken = null
        sessionUsername = null
        authenticatedSession = null
        sessionCanListFiles = false
        challengeId = null
        activeOrigin = null
        passwordField?.text?.clear()
        codeField?.text?.clear()
        passwordField = null
        codeField = null
    }

    private fun showLogin(message: String? = null, savedServer: String = "", savedUser: String = "") {
        clearSensitiveState()
        val layout = screen("Root.ark", "Acesso online. A visualização protegida exige confiança independente do dispositivo.")
        serverField = field(layout, "Servidor HTTPS", savedServer, false)
        usernameField = field(layout, "Usuário", savedUser, false)
        passwordField = field(layout, "Senha", "", true)
        if (message != null) text(layout, message)
        button(layout, "Entrar") {
            val server = serverField?.text?.toString().orEmpty()
            val username = usernameField?.text?.toString().orEmpty().trim()
            val password = passwordField?.text?.toString().orEmpty()
            if (username.isEmpty() || username.length > 128 || password.isEmpty() || password.length > 1024) {
                showLogin("Informe credenciais válidas.", server, username)
                return@button
            }
            val origin = try {
                ServerOrigin.parse(server)
            } catch (_: IllegalArgumentException) {
                showLogin("Informe a origem HTTPS do servidor, sem caminho ou parâmetros.", server, username)
                return@button
            }
            passwordField?.text?.clear()
            runRequest({ transport.login(origin, username, password) }) { result, failure ->
                if (result == null) {
                    showLogin(errorText(failure), server, username)
                    return@runRequest
                }
                when (result) {
                    is LoginOutcome.Authenticated -> showAuthenticated(result, origin)
                    is LoginOutcome.ChallengeRequired -> {
                        activeOrigin = origin
                        challengeId = result.challengeId
                        showTwoFactor()
                    }
                    is LoginOutcome.EnrollmentRequired -> showLogin(
                        "Sua conta exige cadastro de 2FA. Faça o cadastro pelo cliente web autorizado.", server, username
                    )
                }
            }
        }
    }

    private fun showTwoFactor(message: String? = null) {
        val layout = screen("Verificação em duas etapas", "Informe o código do autenticador ou um código de recuperação.")
        codeField = field(layout, "Código 2FA", "", true)
        if (message != null) text(layout, message)
        button(layout, "Verificar") {
            val origin = activeOrigin ?: return@button
            val challenge = challengeId ?: return@button
            val code = codeField?.text?.toString().orEmpty().trim()
            if (code.length !in 6..256) {
                codeField?.text?.clear()
                showTwoFactor("Informe um código válido.")
                return@button
            }
            codeField?.text?.clear()
            runRequest({ transport.completeTwoFactorLogin(origin, challenge, code) }) { result, failure ->
                if (result != null) showAuthenticated(result, origin)
                else showTwoFactor(errorText(failure))
            }
        }
        button(layout, "Voltar ao login") { showLogin() }
    }

    private fun showAuthenticated(result: LoginOutcome.Authenticated, origin: ServerOrigin) {
        clearSensitiveState()
        sessionToken = result.token
        authenticatedSession = result
        activeOrigin = origin
        sessionUsername = result.username
        sessionCanListFiles = ReadOnlyFileListPolicy.canList(result.permissions)
        if (sessionCanListFiles) {
            offlineSession = OfflineSession(
                origin.loginUrl().toString().removeSuffix("/auth/login"),
                result.username,
                UUID.randomUUID().toString(),
            )
            offlineInventory = SessionOfflineInventory(offlineSession!!)
            ciphertextCache = runCatching {
                SessionCiphertextCache(ciphertextRoot, offlineSession!!, LocalCipherCacheKey.rotateForLogin())
            }.getOrNull()
        }
        showSession()
    }

    private fun showSession(message: String? = null) {
        val username = sessionUsername ?: return showLogin()
        val layout = screen("Acesso confirmado", "Sessão de $username autenticada em memória.")
        text(layout, "Listagem de metadados. Conteúdo protegido só é aberto após verificação local e autorização independente.")
        if (message != null) text(layout, message)
        if (sessionCanListFiles) {
            button(layout, "Listar arquivos (somente leitura)") { loadInventoryPage() }
            val binding = offlineSession
            val cache = offlineInventory
            if (binding != null && cache != null && cache.pages(binding).isNotEmpty()) {
                button(layout, "Consultar páginas capturadas (offline)") { showOfflineInventory(0) }
                button(layout, "Apagar inventário desta sessão") {
                    cache.clear()
                    showSession("Inventário temporário apagado.")
                }
            }
            val candidate = if (binding != null) runCatching { ciphertextCache?.snapshot(binding) }.getOrNull() else null
            if (candidate != null) {
                text(layout, "Ciphertext criptografado em armazenamento privado: ${candidate.objectId} " +
                    "(época ${candidate.epoch}, revisão ${candidate.revisionCounter}). " +
                    "Integridade local e assinatura são verificações distintas; conteúdo continua bloqueado.")
                button(layout, "Conferir integridade da captura local") {
                    val stored = ciphertextCache ?: return@button
                    val requestGeneration = ++generation
                    screen("Verificação offline", "Conferindo apenas AES-GCM e integridade dos bytes armazenados...")
                    Thread {
                        val intact = runCatching { stored.inspect(binding!!, candidate.objectId) }.isSuccess
                        runOnUiThread {
                            if (generation == requestGeneration && !isFinishing && !isDestroyed) {
                                showSession(if (intact) "Captura local íntegra. Assinatura e autorização NÃO verificadas."
                                    else "Captura local corrompida ou indisponível; os bytes foram descartados.")
                            }
                        }
                    }.start()
                }
                button(layout, "Apagar captura de ciphertext") {
                    val stored = ciphertextCache
                    ciphertextCache = null
                    runCatching { stored?.clear() }
                    runCatching { LocalCipherCacheKey.erase() }
                    showSession("Captura criptografada encerrada para esta sessão.")
                }
            }
        } else {
            text(layout, "Esta conta não possui permissão listFiles.")
        }
        button(layout, "Encerrar acesso local") { showLogin() }
    }

    private fun loadInventoryPage(cursor: String? = null, pageNumber: Int = 1, usedCursors: Set<String> = emptySet()) {
        if (!sessionCanListFiles) return
        val origin = activeOrigin ?: return
        val token = sessionToken ?: return
        if (cursor != null && (pageNumber <= 1 || pageNumber > 100_000 ||
                runCatching { PagedInventoryPolicy.checkCursor(cursor, usedCursors) }.isFailure)) {
            showSession("Cursor de inventário inválido. Reinicie a listagem.")
            return
        }
        runRequest({ transport.listInventoryPage(origin, token, cursor) }) { page, failure ->
            if (page != null) {
                val used = usedCursors + listOfNotNull(cursor)
                val next = page.nextCursor
                if (next != null && runCatching {
                    PagedInventoryPolicy.checkCursor(next, used)
                }.isFailure) {
                    showSession("Inventário retornou cursor repetido. Reinicie a listagem.")
                } else {
                    val binding = offlineSession
                    val cache = offlineInventory
                    if (binding != null && cache != null &&
                        runCatching { cache.capture(binding, pageNumber, page) }.isFailure) {
                        cache.clear()
                    }
                    showInventoryPage(page, pageNumber, used)
                }
            } else when ((failure as? RootArkApiException)?.statusCode) {
                401 -> showLogin("Sessão expirada ou revogada. Faça login novamente.")
                403 -> showLogin("Acesso à lista revogado (403). Faça login novamente.")
                409 -> {
                    offlineInventory?.clear()
                    runCatching { ciphertextCache?.clear() }
                    ciphertextCache = null
                    runCatching { LocalCipherCacheKey.erase() }
                    showSession("Inventário mudou no servidor. Reinicie a listagem para obter um novo snapshot.")
                }
                else -> showSession("Não foi possível carregar a página de inventário (limite: 128 KiB / 64 registros).")
            }
        }
    }

    private fun showInventoryPage(page: InventoryPage, pageNumber: Int, usedCursors: Set<String>) {
        val layout = screen("Inventário · página $pageNumber", "${page.rows.size} metadados de sincronização. Nenhum conteúdo descriptografado.")
        if (page.rows.isEmpty()) text(layout, "Nenhum registro disponível.")
        for (row in page.rows) {
            text(layout, row.name + if (row.deleted) " (excluído)" else "")
            val details = listOfNotNull(
                row.path?.let { "Caminho: $it" },
                row.size?.let { "Tamanho: $it bytes" },
                row.contentType?.let { "Tipo: $it" },
            ).joinToString(" · ")
            if (details.isNotEmpty()) text(layout, details)
            if (!row.deleted) button(layout, "Conteúdo protegido") {
                showProtectedObject(row.objectId) { showInventoryPage(page, pageNumber, usedCursors) }
            }
        }
        val next = page.nextCursor
        if (next != null) button(layout, "Próxima página") { loadInventoryPage(next, pageNumber + 1, usedCursors) }
        val binding = offlineSession
        val cache = offlineInventory
        if (binding != null && cache != null && cache.pages(binding).isNotEmpty()) {
            button(layout, "Consultar cópia temporária (offline)") { showOfflineInventory(0) }
        }
        button(layout, "Atualizar desde o início") { loadInventoryPage() }
        button(layout, "Voltar") { showSession() }
        button(layout, "Encerrar acesso local") { showLogin() }
    }

    private fun showOfflineInventory(index: Int) {
        if (!sessionCanListFiles || sessionToken == null) return showLogin()
        val binding = offlineSession ?: return showLogin()
        val cache = offlineInventory ?: return showLogin()
        val pages = cache.pages(binding)
        if (index !in pages.indices) return showSession("Não há página salva nesta sessão.")
        val page = pages[index]
        val layout = screen(
            "Inventário offline · página ${page.number}",
            "Cópia temporária de metadados recebidos por HTTPS autenticado nesta sessão. " +
                "Pode estar desatualizada; não é prova assinada, autorização atual ou conteúdo verificado.",
        )
        if (page.rows.isEmpty()) text(layout, "Nenhum registro capturado nesta página.")
        val candidate = runCatching { ciphertextCache?.snapshot(binding) }.getOrNull()
        if (candidate != null) {
            text(layout, "Há uma captura de ciphertext criptografada de ${candidate.objectId}. " +
                "Assinatura, dispositivo e autorização atual NÃO verificados. Sem acesso ao conteúdo offline.")
        }
        for (row in page.rows) {
            text(layout, row.name + if (row.deleted) " (excluído no momento da captura)" else "")
            val details = listOfNotNull(
                row.path?.let { "Caminho capturado: $it" },
                row.size?.let { "Tamanho informado: $it bytes" },
                row.contentType?.let { "Tipo informado: $it" },
            ).joinToString(" · ")
            if (details.isNotEmpty()) text(layout, details)
        }
        if (index > 0) button(layout, "Página capturada anterior") { showOfflineInventory(index - 1) }
        if (index + 1 < pages.size) button(layout, "Próxima página capturada") { showOfflineInventory(index + 1) }
        text(layout, "Somente as primeiras ${SessionOfflineInventory.MAX_PAGES} páginas podem ficar em memória. " +
            "O inventário é apagado ao encerrar a sessão ou sair do aplicativo.")
        button(layout, "Apagar cópia temporária") {
            cache.clear()
            showSession("Inventário temporário apagado.")
        }
        button(layout, "Voltar") { showSession() }
        button(layout, "Encerrar acesso local") { showLogin() }
    }

    /**
     * Explicit integration gate for a future independently approved Android
     * enrollment/recovery authority. The server login and wire JSON cannot
     * manufacture CEKs, device pins, revocation state or epoch authority.
     * The current product deliberately has no such provider.
     */
    private fun independentlyProvisionedGrantProvider(): TrustedContentGrantProvider? = null

    private fun showProtectedObject(objectId: String, backToPage: () -> Unit) {
        val origin = activeOrigin ?: return showLogin()
        val session = authenticatedSession ?: return showLogin()
        if (!sessionCanListFiles) return showSession("Sem permissão para ler arquivos.")
        val preview = VerifiedTextPreview(independentlyProvisionedGrantProvider())
        val layout = screen("Conteúdo protegido", "Apenas texto UTF-8 verificado localmente pode ser exibido.")
        if (!preview.available) {
            text(layout, "Bloqueado: este dispositivo ainda não recebeu uma autorização de chave e época verificável. Use um dispositivo autorizado.")
        } else {
            button(layout, "Abrir texto verificado") {
                val requestGeneration = generation + 1
                runRequest({
                    preview.open(origin, session, objectId) { generation == requestGeneration }
                }) { characters, failure ->
                    if (characters != null) {
                        try {
                            val view = screen("Texto verificado", "Conteúdo autenticado localmente. Feche para descartá-lo da tela.")
                            securePreviewText = text(view, String(characters)).apply {
                                isSaveEnabled = false
                                importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
                                setTextIsSelectable(false)
                            }
                            button(view, "Fechar conteúdo") { backToPage() }
                        } finally {
                            characters.fill('\u0000')
                        }
                    } else when ((failure as? RootArkApiException)?.statusCode) {
                        401 -> showLogin("Sessão expirada ou revogada. Faça login novamente.")
                        403 -> showLogin("Acesso ao arquivo revogado (403). Faça login novamente.")
                        404, 409 -> {
                            offlineInventory?.clear()
                            runCatching { ciphertextCache?.clear() }
                            ciphertextCache = null
                            runCatching { LocalCipherCacheKey.erase() }
                            showSession("Época ou objeto alterado. Captura local descartada.")
                        }
                        else -> showSession("Conteúdo indisponível. Autorização ou verificação criptográfica não confirmada.")
                    }
                }
            }
        }
        val binding = offlineSession
        val stored = ciphertextCache
        if (binding != null && stored != null) {
            text(layout, "É possível guardar até 4 MiB de ciphertext assinado recebido via HTTPS. " +
                "O cache local é cifrado com Android Keystore e NÃO autoriza abrir conteúdo offline.")
            button(layout, "Capturar ciphertext criptografado") {
                runRequest({
                    val packet = ProtectedSyncFetch().fetchPacket(
                        origin, session, objectId, SessionCiphertextCache.MAX_PACKET_BYTES
                    )
                    try { stored.save(binding, objectId, packet.bytes) }
                    finally { packet.bytes.fill(0) }
                }) { captured, failure ->
                    if (captured != null) {
                        showSession("Ciphertext capturado em AES-GCM local. A assinatura e a autoridade do dispositivo " +
                            "ainda precisam ser verificadas independentemente; conteúdo indisponível offline.")
                    } else when ((failure as? RootArkApiException)?.statusCode) {
                        401, 403 -> showLogin("Sessão ou autorização revogada. Faça login novamente.")
                        404, 409 -> {
                            offlineInventory?.clear()
                            runCatching { stored.clear() }
                            ciphertextCache = null
                            runCatching { LocalCipherCacheKey.erase() }
                            showSession("Objeto mudou no servidor. Captura descartada.")
                        }
                        else -> {
                            val state = CiphertextCaptureFailurePolicy.handle(failure) {
                                runCatching { stored.clear() }
                                ciphertextCache = null
                                runCatching { LocalCipherCacheKey.erase() }
                            }
                            showSession(if (state == CiphertextCaptureUiResult.ALREADY_CAPTURED)
                                "Este ciphertext já estava capturado e íntegro nesta sessão. " +
                                    "Assinatura e autorização independente continuam pendentes."
                            else "Não foi possível capturar ciphertext. Limite de 4 MiB ou integridade inválida.")
                        }
                    }
                }
            }
        }
        button(layout, "Voltar") { backToPage() }
    }

    private fun <T> runRequest(operation: () -> T, done: (T?, Exception?) -> Unit) {
        val started = ++generation
        screen("Conectando", "Aguardando resposta do servidor...")
        Thread {
            var response: T? = null
            var failure: Exception? = null
            try {
                response = operation()
            } catch (caught: Exception) {
                failure = caught
            }
            val completedResponse = response
            val completedFailure = failure
            runOnUiThread {
                if (generation == started && !isFinishing && !isDestroyed) done(completedResponse, completedFailure)
                else if (completedResponse is CharArray) completedResponse.fill('\u0000')
            }
        }.start()
    }

    private fun errorText(error: Exception?): String = when ((error as? RootArkApiException)?.statusCode) {
        401, 400 -> "Credenciais ou código inválidos."
        429 -> "Muitas tentativas. Tente mais tarde."
        503 -> "Autenticação indisponível no servidor."
        else -> "Não foi possível autenticar. Confira a conexão HTTPS e tente novamente."
    }

    private fun screen(title: String, description: String): LinearLayout {
        securePreviewText?.text = ""
        securePreviewText = null
        val scroll = ScrollView(this)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val padding = (24 * resources.displayMetrics.density).toInt()
            setPadding(padding, padding, padding, padding)
        }
        scroll.addView(layout)
        text(layout, title).textSize = 24f
        text(layout, description)
        setContentView(scroll)
        return layout
    }

    private fun text(layout: LinearLayout, value: String): TextView = TextView(this).also {
        it.text = value
        it.setPadding(0, 0, 0, (16 * resources.displayMetrics.density).toInt())
        layout.addView(it)
    }

    private fun field(layout: LinearLayout, label: String, value: String, secret: Boolean): EditText =
        EditText(this).also {
            it.hint = label
            it.setText(value)
            it.inputType = if (secret) InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                else InputType.TYPE_CLASS_TEXT
            it.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            it.isSaveEnabled = false
            it.layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
            )
            layout.addView(it)
        }

    private fun button(layout: LinearLayout, label: String, action: () -> Unit) {
        val view = Button(this)
        view.text = label
        view.filterTouchesWhenObscured = true
        view.setOnClickListener { action() }
        layout.addView(view)
    }
}
