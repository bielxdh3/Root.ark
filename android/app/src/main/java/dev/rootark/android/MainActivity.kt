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
import dev.rootark.core.sync.ReadOnlyFileListPolicy
import dev.rootark.core.sync.InventoryPage
import dev.rootark.core.sync.PagedInventoryPolicy
import dev.rootark.core.sync.RootArkApiException

/** Online auth and read-only metadata listing; protected files and device keys remain gated. */
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
    private var sessionCanListFiles = false
    private var generation = 0

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
        sessionToken = null
        sessionUsername = null
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
        val layout = screen("Root.ark", "Acesso online. Arquivos protegidos ainda não estão disponíveis no Android.")
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
        activeOrigin = origin
        sessionUsername = result.username
        sessionCanListFiles = ReadOnlyFileListPolicy.canList(result.permissions)
        showSession()
    }

    private fun showSession(message: String? = null) {
        val username = sessionUsername ?: return showLogin()
        val layout = screen("Acesso confirmado", "Sessão de $username autenticada em memória.")
        text(layout, "Somente metadados de sincronização. O conteúdo criptografado permanece inacessível.")
        if (message != null) text(layout, message)
        if (sessionCanListFiles) {
            button(layout, "Listar arquivos (somente leitura)") { loadInventoryPage() }
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
                    showInventoryPage(page, pageNumber, used)
                }
            } else when ((failure as? RootArkApiException)?.statusCode) {
                401 -> showLogin("Sessão expirada ou revogada. Faça login novamente.")
                403 -> showSession("Servidor negou acesso à lista (403).")
                409 -> showSession("Inventário mudou no servidor. Reinicie a listagem para obter um novo snapshot.")
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
        }
        val next = page.nextCursor
        if (next != null) button(layout, "Próxima página") { loadInventoryPage(next, pageNumber + 1, usedCursors) }
        button(layout, "Atualizar desde o início") { loadInventoryPage() }
        button(layout, "Voltar") { showSession() }
        button(layout, "Encerrar acesso local") { showLogin() }
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
            runOnUiThread {
                if (generation == started && !isFinishing && !isDestroyed) done(response, failure)
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
