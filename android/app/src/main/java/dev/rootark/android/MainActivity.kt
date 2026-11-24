package dev.rootark.android

import android.annotation.TargetApi
import android.app.Activity
import android.app.KeyguardManager
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.SystemClock
import android.text.InputType
import android.os.Build
import android.view.View
import android.view.WindowInsets
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
import dev.rootark.core.sync.IndependentOfflineOwnerPin
import dev.rootark.core.sync.OwnerEnrollmentAdmission
import java.io.File
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID

internal data class InventoryPagingTracker(
    val cursor: String? = null,
    val pageNumber: Int = 1,
    val usedCursors: Set<String> = emptySet(),
    val previousCursors: List<String?> = emptyList(),
) {
    fun advance(nextCursor: String?): InventoryPagingTracker {
        val history = previousCursors + cursor
        return InventoryPagingTracker(
            cursor = nextCursor,
            pageNumber = pageNumber + 1,
            usedCursors = history.filterNotNull().toSet(),
            previousCursors = history,
        )
    }

    fun previous(): InventoryPagingTracker? {
        if (pageNumber <= 1 || !isValid()) return null
        val history = previousCursors.dropLast(1)
        return InventoryPagingTracker(
            cursor = previousCursors.last(),
            pageNumber = pageNumber - 1,
            usedCursors = history.filterNotNull().toSet(),
            previousCursors = history,
        ).takeIf { it.isValid() }
    }

    fun isValid(): Boolean {
        if (pageNumber !in 1..PagedInventoryPolicy.MAX_PAGES
            || previousCursors.size != pageNumber - 1) return false
        if (pageNumber == 1) return cursor == null && usedCursors.isEmpty()
        if (previousCursors.firstOrNull() != null) return false
        val priorCursors = previousCursors.filterNotNull()
        if (priorCursors.size != previousCursors.size - 1 ||
            priorCursors.toSet().size != priorCursors.size || usedCursors != priorCursors.toSet()
        ) return false
        val currentCursor = cursor ?: return false
        return runCatching { PagedInventoryPolicy.checkCursor(currentCursor, usedCursors) }.isSuccess
    }
}

/** Authenticated metadata browsing with an explicit, provisioned-only protected text viewer. */
class MainActivity : Activity() {
    companion object {
        private const val REQUEST_OWNER_PACKAGE = 64
        private const val REQUEST_DEVICE_CREDENTIAL = 65
        private const val MAX_OWNER_PACKAGE_BYTES = 32_768
    }

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
    private val securePreviewText = SecurePreviewBuffer()
    private var sessionCanListFiles = false
    private var offlineSession: OfflineSession? = null
    private var offlineInventory: SessionOfflineInventory? = null
    private var ciphertextCache: SessionCiphertextCache? = null
    private val ciphertextRoot: File get() = File(noBackupFilesDir, "ciphertext-staging-v1")
    @Volatile private var generation = 0
    @Volatile private var isForeground = false
    private var pendingDeviceCredentialAction: (() -> Unit)? = null
    private var pendingDeviceCredentialCancel: (() -> Unit)? = null
    private var pendingOwnerImportOrigin: String? = null
    private var pendingOwnerImportUsername: String? = null
    private var pendingOwnerImportBytes: ByteArray? = null
    private var pendingOwnerImportPublicKey: ByteArray? = null
    private var pendingOwnerImportPin: IndependentOfflineOwnerPin? = null
    private var pendingOwnerFingerprintConfirmation = false
    private var pendingOwnerFingerprintStartedAtElapsedMs: Long = 0L
    private var pendingOwnerDocumentAwaitingLogin = false
    private var pendingOwnerDocumentStartedAtElapsedMs: Long = 0L
    private var pendingOwnerCredentialAtElapsedMs: Long = 0L
    private var pendingOwnerCredentialInitialProvisioning = false
    // Metadata only. No server token, credentials, CEK, plaintext or callback
    // retaining LoginOutcome is allowed to outlive the Keyguard backgrounding.
    private data class PendingProtectedRead(
        val origin: String, val username: String, val objectId: String,
        val credentialAtElapsedMs: Long,
    )
    private var pendingProtectedRead: PendingProtectedRead? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(null)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        showLogin()
    }

    override fun onStart() {
        super.onStart()
        isForeground = true
    }

    override fun onStop() {
        super.onStop()
        isForeground = false
        generation++
        val now = SystemClock.elapsedRealtime()
        // Comparing an independent owner fingerprint may require switching to
        // another app on this SAME device. Retain only the signed/wrapped
        // package and public identity for a bounded reauthenticated retry;
        // server session tokens, plaintext and preview are always discarded.
        val pausedFingerprint = pendingOwnerFingerprintConfirmation &&
            pendingDeviceCredentialAction == null &&
            OwnerFingerprintResumePolicy.isWithinWindow(
                pendingOwnerFingerprintStartedAtElapsedMs, now,
            ) && pendingOwnerImportBytes != null && pendingOwnerImportPublicKey != null
        val pausedDocument = pendingOwnerDocumentAwaitingLogin &&
            OwnerFingerprintResumePolicy.isWithinWindow(pendingOwnerDocumentStartedAtElapsedMs, now)
        val pausedOwnerCredential = OwnerCredentialResumePolicy.isWithinWindow(
            pendingOwnerCredentialAtElapsedMs, now)
        val pausedProtectedRead = pendingProtectedRead?.let {
            OwnerCredentialResumePolicy.isWithinWindow(it.credentialAtElapsedMs, now)
        } == true
        val credentialInFlight = pendingDeviceCredentialAction != null
        if (!pausedFingerprint && !pausedDocument && !pausedOwnerCredential && !credentialInFlight) clearPendingOwnerImport()
        if (!pausedProtectedRead) pendingProtectedRead = null
        clearSensitiveState()
        if (pausedFingerprint) {
            showLogin("Confirme o fingerprint independente e entre novamente na mesma conta para continuar o enrollment.",
                pendingOwnerImportOrigin.orEmpty(), pendingOwnerImportUsername.orEmpty(), preservePendingReauthentication = true)
        } else if (pausedDocument || pausedOwnerCredential) {
            showLogin("Retome a importação somente após um novo login na mesma origem e conta.",
                pendingOwnerImportOrigin.orEmpty(), pendingOwnerImportUsername.orEmpty(), preservePendingReauthentication = true)
        } else if (pausedProtectedRead) {
            val pending = pendingProtectedRead!!
            showLogin("Faça login novamente na mesma conta para concluir a abertura autenticada.",
                pending.origin, pending.username, preservePendingReauthentication = true)
        } else showLogin(preservePendingReauthentication = credentialInFlight)
    }

    override fun onDestroy() {
        pendingDeviceCredentialAction = null
        pendingDeviceCredentialCancel = null
        pendingProtectedRead = null
        clearPendingOwnerImport()
        super.onDestroy()
    }

    @Deprecated("The legacy result callback is used for the platform document and credential intents.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            REQUEST_OWNER_PACKAGE -> {
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                    pendingOwnerImportOrigin = null
                    pendingOwnerImportUsername = null
                    clearPendingOwnerImport()
                    showLogin("Enrollment protegido exige Android 13 ou superior.")
                    return
                }
                val origin = pendingOwnerImportOrigin
                val username = pendingOwnerImportUsername
                val uri = data?.data
                if (resultCode != RESULT_OK || uri == null || origin == null || username == null) {
                    clearPendingOwnerImport()
                    showLogin("Importação do pacote cancelada.")
                    return
                }
                try {
                    // DocumentsUI normally stops our Activity and erases its
                    // bearer. An old origin/username label is NOT authority to
                    // import: store bounded signed bytes, then require login.
                    pendingOwnerImportBytes = readOwnerPackage(uri)
                    pendingOwnerDocumentAwaitingLogin = true
                    pendingOwnerDocumentStartedAtElapsedMs = SystemClock.elapsedRealtime()
                    showLogin("Documento selecionado. Entre novamente na mesma conta para validar o pacote.",
                        origin, username, preservePendingReauthentication = true)
                } catch (_: Exception) {
                    clearPendingOwnerImport()
                    showLogin("Pacote inválido ou identidade de hardware indisponível. O acesso protegido continua bloqueado.")
                }
            }
            REQUEST_DEVICE_CREDENTIAL -> {
                val action = pendingDeviceCredentialAction
                val cancel = pendingDeviceCredentialCancel
                pendingDeviceCredentialAction = null
                pendingDeviceCredentialCancel = null
                if (resultCode == RESULT_OK && action != null) {
                    // Actions may schedule a *new* login-bound continuation.
                    // Do not erase that continuation in a generic finally.
                    try { action() }
                    catch (_: Exception) {
                        clearPendingOwnerImport()
                        pendingProtectedRead = null
                        showLogin("A operação protegida falhou após a credencial local.")
                    }
                }
                else {
                    try {
                        cancel?.invoke()
                        if (cancel == null) showLogin("Autenticação local cancelada.")
                    } finally { clearPendingOwnerImport() }
                }
            }
        }
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
        securePreviewText.clear()
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

    private fun showLogin(message: String? = null, savedServer: String = "", savedUser: String = "",
                          preservePendingReauthentication: Boolean = false) {
        if (!preservePendingReauthentication) {
            pendingProtectedRead = null
            if (pendingOwnerDocumentAwaitingLogin || pendingOwnerCredentialAtElapsedMs != 0L) clearPendingOwnerImport()
        }
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
        if (resumeOwnerFingerprintAfterLogin(result, origin)) return
        if (resumeOwnerDocumentAfterLogin(result, origin)) return
        if (resumeOwnerCredentialAfterLogin(result, origin)) return
        if (resumeProtectedReadAfterLogin(result, origin)) return
        showSession()
    }

    /** Resume the *independent* first-pin comparison after a new real login. */
    private fun resumeOwnerFingerprintAfterLogin(result: LoginOutcome.Authenticated, origin: ServerOrigin): Boolean {
        if (!pendingOwnerFingerprintConfirmation) return false
        val authenticatedOrigin = origin.loginUrl().toString().removeSuffix("/auth/login")
        val validBinding = OwnerFingerprintResumePolicy.canResume(
            pendingOwnerFingerprintStartedAtElapsedMs, SystemClock.elapsedRealtime(),
            pendingOwnerImportOrigin, pendingOwnerImportUsername, authenticatedOrigin, result.username,
        )
        val savedPackage = pendingOwnerImportBytes
        val savedKey = pendingOwnerImportPublicKey
        if (!validBinding || savedPackage == null || savedKey == null ||
            Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            clearPendingOwnerImport()
            showSession("Enrollment não retomado: conta, origem, prazo ou chave incompatível. Reimporte o pacote.")
            return true
        }
        var copiedPackage: ByteArray? = null
        var checkedKey: ByteArray? = null
        try {
            // A new pin in storage or a replaced hardware identity must never
            // be silently trusted as the previous out-of-band comparison.
            val existingEnrollment = OwnerEnrollmentStore(noBackupFilesDir).load()
            try { check(existingEnrollment == null) }
            finally {
                existingEnrollment?.packageBytes?.fill(0)
                existingEnrollment?.pin?.ownerPublicSpki?.fill(0)
                existingEnrollment?.pin?.ownerPublicSpkiSha256?.fill(0)
            }
            val identity = AndroidInstallationKey(this).publicIdentity(allowCreate = false)
            checkedKey = identity.publicKey
            check(MessageDigest.isEqual(identity.publicKey, savedKey))
            val copied = savedPackage.copyOf()
            copiedPackage = copied
            val parsed = OwnerEnrollmentPackageJson.parse(copied)
            check(parsed.head.origin == authenticatedOrigin && parsed.head.username == result.username)
            val startedAt = pendingOwnerFingerprintStartedAtElapsedMs
            clearPendingOwnerImport()
            pendingOwnerFingerprintStartedAtElapsedMs = startedAt
            showOwnerFingerprintConfirmation(copied, parsed, identity, authenticatedOrigin, result.username)
            copiedPackage = null // new fingerprint screen owns this signed, wrapped package
            checkedKey = null // its pending state now owns the public hardware identity
        } catch (_: Exception) {
            copiedPackage?.fill(0)
            checkedKey?.fill(0)
            clearPendingOwnerImport()
            showSession("Enrollment não retomado: confirmação independente indisponível. Reimporte o pacote.")
        }
        return true
    }

    /** The document picker is NOT a trusted continuation of the pre-background login. */
    private fun resumeOwnerDocumentAfterLogin(result: LoginOutcome.Authenticated, origin: ServerOrigin): Boolean {
        if (!pendingOwnerDocumentAwaitingLogin) return false
        val originText = origin.loginUrl().toString().removeSuffix("/auth/login")
        val allowed = OwnerFingerprintResumePolicy.canResume(
            pendingOwnerDocumentStartedAtElapsedMs, SystemClock.elapsedRealtime(),
            pendingOwnerImportOrigin, pendingOwnerImportUsername, originText, result.username,
        )
        val bytes = pendingOwnerImportBytes
        pendingOwnerDocumentAwaitingLogin = false
        pendingOwnerDocumentStartedAtElapsedMs = 0L
        if (!allowed || bytes == null || !isForeground) {
            clearPendingOwnerImport()
            showSession("Importação cancelada: autentique novamente na origem e conta corretas.")
            return true
        }
        continueOwnerPackageAfterLogin(bytes, originText, result.username)
        return true
    }

    @TargetApi(Build.VERSION_CODES.TIRAMISU)
    private fun continueOwnerPackageAfterLogin(bytes: ByteArray, origin: String, username: String) {
        try {
            val packageValue = OwnerEnrollmentPackageJson.parse(bytes)
            val enrollmentStore = OwnerEnrollmentStore(noBackupFilesDir)
            val existing = enrollmentStore.load()
            val identity = AndroidInstallationKey(this).publicIdentity(allowCreate = existing == null)
            pendingOwnerImportPublicKey = identity.publicKey
            if (existing != null) {
                try {
                    val packageOwner = Base64.getUrlDecoder().decode(packageValue.ownerPublicSpki)
                    try {
                        check(packageOwner.contentEquals(existing.pin.ownerPublicSpki))
                        check(existing.pin.origin == origin && existing.pin.username == username &&
                            existing.pin.readerDeviceId == identity.readerDeviceId)
                    } finally { packageOwner.fill(0) }
                    pendingOwnerImportPin = existing.pin
                    requestDeviceCredentialThen(
                        action = { deferOwnerImportAfterCredential(bytes, existing.pin, identity.publicKey, false) },
                        cancel = { clearPendingOwnerImport(); showLogin("Autenticação local cancelada.") },
                    )
                } finally { existing.packageBytes.fill(0) }
            } else {
                showOwnerFingerprintConfirmation(bytes, packageValue, identity, origin, username)
            }
        } catch (_: Exception) {
            clearPendingOwnerImport()
            showLogin("Pacote inválido, assinatura ou hardware não aceito. Enrollment bloqueado.")
        }
    }

    private fun deferOwnerImportAfterCredential(
        bytes: ByteArray, pin: IndependentOfflineOwnerPin,
        publicKey: ByteArray, allowInitialProvisioning: Boolean,
    ) {
        check(pendingOwnerImportBytes === bytes && pendingOwnerImportPublicKey === publicKey)
        pendingOwnerImportPin = pin
        pendingOwnerImportOrigin = pin.origin
        pendingOwnerImportUsername = pin.username
        pendingOwnerCredentialInitialProvisioning = allowInitialProvisioning
        pendingOwnerCredentialAtElapsedMs = SystemClock.elapsedRealtime()
        pendingOwnerFingerprintConfirmation = false
        showLogin("Credencial local confirmada. Entre novamente na mesma conta para persistir a autorização.",
            pin.origin, pin.username, preservePendingReauthentication = true)
    }

    private fun resumeOwnerCredentialAfterLogin(result: LoginOutcome.Authenticated, origin: ServerOrigin): Boolean {
        if (pendingOwnerCredentialAtElapsedMs == 0L) return false
        val originText = origin.loginUrl().toString().removeSuffix("/auth/login")
        val allowed = OwnerCredentialResumePolicy.canResume(
            pendingOwnerCredentialAtElapsedMs, SystemClock.elapsedRealtime(),
            pendingOwnerImportOrigin, pendingOwnerImportUsername, originText, result.username,
        )
        val bytes = pendingOwnerImportBytes
        val pin = pendingOwnerImportPin
        val publicKey = pendingOwnerImportPublicKey
        if (!allowed || !isForeground || bytes == null || pin == null || publicKey == null) {
            clearPendingOwnerImport()
            showSession("A janela de credencial ou a conta expirou. Reimporte o pacote com autorização nova.")
            return true
        }
        val initial = pendingOwnerCredentialInitialProvisioning
        val credentialAtElapsedMs = pendingOwnerCredentialAtElapsedMs
        // Transfer exclusive ownership of these buffers to ONE worker.
        // The UI must never wait for the cross-process floor lock while a
        // protected HTTPS fetch holds it. Only a fresh login produced the
        // server session; no token is retained in this worker's arguments.
        pendingOwnerImportBytes = null
        pendingOwnerImportPin = null
        pendingOwnerImportPublicKey = null
        pendingOwnerImportOrigin = null
        pendingOwnerImportUsername = null
        pendingOwnerCredentialAtElapsedMs = 0L
        pendingOwnerCredentialInitialProvisioning = false
        runCheckedRequest({ stillActive ->
            importOwnerPackage(bytes, pin, publicKey, initial, credentialAtElapsedMs, stillActive)
        }) { message, _ ->
            showLogin(message ?: "Identidade, credencial ou hardware não confirmados. Enrollment bloqueado.")
        }
        return true
    }

    private fun deferProtectedReadAfterCredential(origin: String, username: String, objectId: String) {
        pendingProtectedRead = PendingProtectedRead(origin, username, objectId, SystemClock.elapsedRealtime())
        showLogin("Credencial local confirmada. Entre novamente para abrir o objeto protegido.",
            origin, username, preservePendingReauthentication = true)
    }

    private fun resumeProtectedReadAfterLogin(result: LoginOutcome.Authenticated, origin: ServerOrigin): Boolean {
        val pending = pendingProtectedRead ?: return false
        pendingProtectedRead = null // one-use intent; never replay on subsequent logins
        val originText = origin.loginUrl().toString().removeSuffix("/auth/login")
        if (!isForeground || !sessionCanListFiles || !OwnerCredentialResumePolicy.canResume(
                pending.credentialAtElapsedMs, SystemClock.elapsedRealtime(),
                pending.origin, pending.username, originText, result.username,
            )) {
            showSession("A credencial local expirou ou a conta mudou. Recomece a abertura protegida.")
            return true
        }
        // The new login is authenticated; the Keystore still independently
        // requires a valid 30-second hardware-auth window before agreement.
        showProtectedObject(pending.objectId, { showSession() }, confirmedCredential = true)
        return true
    }

    private fun showSession(message: String? = null) {
        val username = sessionUsername ?: return showLogin()
        val layout = screen("Acesso confirmado", "Sessão de $username autenticada em memória.")
        text(layout, "Listagem de metadados. Conteúdo protegido só é aberto após verificação local e autorização independente.")
        if (message != null) text(layout, message)
        button(layout, "Identidade e autorização do dispositivo") { showDeviceEnrollment() }
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

    private fun showDeviceEnrollment() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return showSession("Enrollment protegido exige Android 13 ou superior com Ed25519 e AndroidKeyStore P-256 por hardware.")
        }
        val username = sessionUsername ?: return showLogin()
        val origin = activeOrigin ?: return showLogin()
        val store = OwnerEnrollmentStore(noBackupFilesDir)
        val stored = try {
            store.load()
        } catch (_: Exception) {
            return showSession("O estado de enrollment está corrompido. A autorização local foi bloqueada.")
        }
        val identity = try {
            AndroidInstallationKey(this).publicIdentity(allowCreate = stored == null)
        } catch (_: Exception) {
            stored?.packageBytes?.fill(0)
            return showSession("Enrollment exige Android 13+, credencial de bloqueio, Ed25519 e ECDH P-256 no Android Keystore com hardware TEE/StrongBox.")
        }
        val publicKeyText = Base64.getUrlEncoder().withoutPadding().encodeToString(identity.publicKey)
        val layout = screen("Enrollment seguro do dispositivo", "A chave privada permanece no Android Keystore. O identificador abaixo é derivado da chave pública desta instalação.")
        if (runCatching { store.hasPending() }.getOrDefault(true)) {
            text(layout, "Existe uma importação protegida interrompida ou não confirmada. O viewer está bloqueado. Reimporte um pacote assinado atual do mesmo proprietário e dispositivo para recuperar; não restaure uma revisão antiga.")
        }
        text(layout, "Device ID: ${identity.readerDeviceId}")
        text(layout, "Nível AndroidKeyStore: ${if (identity.securityLevel == android.security.keystore.KeyProperties.SECURITY_LEVEL_STRONGBOX) "StrongBox" else "Trusted Environment (TEE)"}")
        text(layout, "Chave pública P-256 (SEC1, base64url): $publicKeyText")
        button(layout, "Copiar identidade pública para o proprietário") {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.setPrimaryClip(ClipData.newPlainText("Root.ark Android device", "${identity.readerDeviceId}\n$publicKeyText"))
            showDeviceEnrollment()
        }
        if (stored == null) {
            text(layout, "Nenhum pin do proprietário foi importado. O fingerprint do owner será confirmado por você usando um canal independente.")
        } else {
            try {
                val packageValue = OwnerEnrollmentPackageJson.parse(stored.packageBytes)
                val fingerprint = OwnerEnrollmentAdmission.ownerFingerprint(stored.pin.ownerPublicSpki)
                text(layout, "Owner pin SHA-256: $fingerprint")
                val grantValid = runCatching {
                    OwnerEnrollmentAdmission.validatePackage(
                        packageValue, stored.pin, identity.publicKey, System.currentTimeMillis(),
                    )
                }.isSuccess
                val floorValid = OwnerOfflineHardwareFloor.isAvailable(
                    noBackupFilesDir, packageValue.head.ownerRevision, packageValue.head.ownerDigest,
                    System.currentTimeMillis(),
                )
                val sameAccount = stored.pin.origin == origin.loginUrl().toString().removeSuffix("/auth/login") &&
                    stored.pin.username == username
                val status = when {
                    !sameAccount -> "Pin vinculado a outra conta ou origem. Conteúdo protegido bloqueado."
                    !grantValid -> "Grant ausente, expirado, revogado ou assinatura inválida. Conteúdo protegido bloqueado."
                    !floorValid -> "Floor de hardware ausente, inconsistente ou com rollback. Conteúdo protegido bloqueado."
                    !stored.ecdhCapabilityVerified -> "Grant owner-signed válido, mas ECDH P-256 por hardware não foi confirmado. Provider desabilitado; reimporte após autenticar em dispositivo compatível."
                    else -> "Grant owner-signed e ECDH hardware válidos para ${packageValue.grant.objectId}."
                }
                text(layout, status)
            } catch (_: Exception) {
                text(layout, "O pacote salvo não passou pela verificação. Conteúdo protegido bloqueado.")
            } finally {
                stored.packageBytes.fill(0)
            }
        }
        button(layout, "Importar pacote assinado do proprietário") { startOwnerPackagePicker() }
        button(layout, "Voltar") { showSession() }
        identity.publicKey.fill(0)
    }

    private fun startOwnerPackagePicker() {
        val origin = activeOrigin ?: return showLogin()
        val username = sessionUsername ?: return showLogin()
        pendingOwnerImportOrigin = origin.loginUrl().toString().removeSuffix("/auth/login")
        pendingOwnerImportUsername = username
        val picker = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/json"
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        try {
            startActivityForResult(picker, REQUEST_OWNER_PACKAGE)
        } catch (_: Exception) {
            pendingOwnerImportOrigin = null
            pendingOwnerImportUsername = null
            showSession("Seletor de arquivos indisponível.")
        }
    }

    @TargetApi(Build.VERSION_CODES.S)
    private fun showOwnerFingerprintConfirmation(
        packageBytes: ByteArray,
        packageValue: dev.rootark.core.sync.OwnerEnrollmentPackage,
        identity: AndroidInstallationIdentity,
        origin: String,
        username: String,
    ) {
        val ownerSpki = try { Base64.getUrlDecoder().decode(packageValue.ownerPublicSpki) }
        catch (_: Exception) {
            clearPendingOwnerImport()
            return showLogin("Chave pública do proprietário inválida.")
        }
        pendingOwnerImportBytes = packageBytes
        pendingOwnerImportPublicKey = identity.publicKey
        pendingOwnerImportOrigin = origin
        pendingOwnerImportUsername = username
        pendingOwnerFingerprintConfirmation = true
        if (pendingOwnerFingerprintStartedAtElapsedMs == 0L) {
            pendingOwnerFingerprintStartedAtElapsedMs = SystemClock.elapsedRealtime()
        }
        val fingerprint = OwnerEnrollmentAdmission.ownerFingerprint(ownerSpki)
        val layout = screen(
            "Confirmar pin independente",
            "Compare o SHA-256 abaixo com o fingerprint recebido por um canal independente do arquivo e do servidor. O pacote não pode estabelecer seu próprio pin.",
        )
        text(layout, fingerprint)
        val confirmation = field(layout, "Digite o fingerprint SHA-256 (64 caracteres hex)", "", false)
        button(layout, "Confirmar pin e autenticar dispositivo") {
            val entered = confirmation.text.toString().filterNot { it.isWhitespace() || it == ':' }.uppercase()
            if (entered != fingerprint) {
                ownerSpki.fill(0)
                clearPendingOwnerImport()
                showLogin("Fingerprint independente não confere. Nenhum pin foi salvo.")
                return@button
            }
            val ownerHash = MessageDigest.getInstance("SHA-256").digest(ownerSpki)
            val pin = IndependentOfflineOwnerPin(
                origin, username, identity.readerDeviceId, ownerSpki.copyOf(), ownerHash,
                packageValue.head.ownerRevision, packageValue.head.ownerDigest,
            )
            pendingOwnerImportPin = pin
            // Device credential is the next trust boundary; the fingerprint
            // confirmation itself no longer needs an out-of-band retry.
            pendingOwnerFingerprintConfirmation = false
            requestDeviceCredentialThen(
                action = { deferOwnerImportAfterCredential(packageBytes, pin, identity.publicKey, true) },
                cancel = {
                    ownerSpki.fill(0)
                    clearPendingOwnerImport()
                    showLogin("Autenticação local cancelada; nenhum enrollment foi ativado.")
                },
            )
            ownerSpki.fill(0)
        }
        button(layout, "Cancelar") {
            ownerSpki.fill(0)
            clearPendingOwnerImport()
            showLogin("Importação cancelada.")
        }
    }

    @TargetApi(Build.VERSION_CODES.S)
    private fun importOwnerPackage(
        packageBytes: ByteArray,
        pin: IndependentOfflineOwnerPin,
        readerPublicKey: ByteArray,
        allowInitialProvisioning: Boolean,
        approvedAtElapsedMs: Long,
        stillActive: () -> Boolean,
    ): String {
        return try {
            check(stillActive() && OwnerCredentialResumePolicy.isWithinWindow(
                approvedAtElapsedMs, SystemClock.elapsedRealtime()))
            val identity = AndroidInstallationKey(this).publicIdentity(allowCreate = false)
            try {
                check(MessageDigest.isEqual(identity.publicKey, readerPublicKey) &&
                    identity.readerDeviceId == pin.readerDeviceId)
            } finally { identity.publicKey.fill(0) }
            val packageValue = OwnerEnrollmentPackageJson.parse(packageBytes)
            val packageOwner = Base64.getUrlDecoder().decode(packageValue.ownerPublicSpki)
            check(packageOwner.contentEquals(pin.ownerPublicSpki))
            packageOwner.fill(0)
            check(packageValue.head.origin == pin.origin && packageValue.head.username == pin.username &&
                packageValue.head.readerDeviceId == OwnerEnrollmentAdmission.readerDeviceId(readerPublicKey))
            val headObservedAt = System.currentTimeMillis()
            OwnerEnrollmentAdmission.validateHead(
                packageValue.head, pin, readerPublicKey, headObservedAt,
            )
            val grantValid = runCatching {
                OwnerEnrollmentAdmission.validatePackage(
                    packageValue, pin, readerPublicKey, headObservedAt,
                )
            }.isSuccess
            // Probe actual hardware ECDH after the signed head is verified,
            // but before the floor AES operation consumes the credential
            // window. A failed probe never prevents signed revocation update.
            val ecdhSupported = grantValid && runCatching {
                AndroidInstallationKey(this).requireAgreementSupport()
            }.isSuccess
            val enrollmentStore = OwnerEnrollmentStore(noBackupFilesDir)
            val preparedPin = pin.copy(
                exactRevision = packageValue.head.ownerRevision,
                exactDigest = packageValue.head.ownerDigest,
            )
            // A competing protected read can hold the index lock through a
            // network request. Only this worker may block; the Activity UI
            // stays responsive. Revalidate auth and lifecycle after waiting.
            val floor = OwnerOfflineHardwareFloor.open(
                noBackupFilesDir, pin, packageValue.head.ownerRevision, packageValue.head.ownerDigest,
                nowMillis = headObservedAt,
                allowInitialProvisioning = allowInitialProvisioning,
                prepareEnrollment = {
                    // Written under the SAME cross-process index lock and
                    // before creating the hardware high-water alias.
                    enrollmentStore.stage(
                        preparedPin, packageBytes,
                        ecdhCapabilityVerified = grantValid && ecdhSupported,
                    )
                },
            )
            var enrollmentSaved = false
            try {
                check(stillActive() && OwnerCredentialResumePolicy.isWithinWindow(
                    approvedAtElapsedMs, SystemClock.elapsedRealtime()))
                val updatedPin = OwnerEnrollmentAdmission.observeHead(
                    packageValue.head, pin, readerPublicKey, floor.store, headObservedAt,
                )
                // From the durable seal onward, cancellation is NOT a reason
                // to skip saving the corresponding signed enrollment. An
                // interrupted save leaves the staged recovery marker, fails
                // closed and never retires the prior hardware identities.
                // Persist the signed head and revocation even if this device
                // cannot execute P-256 agreement. The provider capability is
                // enabled only when both grant validation and the real
                // hardware ECDH probe succeeded.
                enrollmentStore.save(
                    updatedPin, packageBytes,
                    ecdhCapabilityVerified = grantValid && ecdhSupported,
                )
                enrollmentSaved = true
                if (grantValid && ecdhSupported) {
                    "Pin e pacote do proprietário importados. Faça login novamente para abrir somente os objetos autorizados."
                } else if (grantValid) {
                    "Head do proprietário persistido, mas o ECDH P-256 por hardware não foi confirmado (suporte ou credencial expirada). Viewer permanece bloqueado; reimporte após corrigir o dispositivo."
                } else {
                    "Head assinado e revogação atualizados. O grant está inválido, expirado ou revogado; o viewer permanece bloqueado."
                }
            } finally {
                OwnerOfflineHardwareFloor.retireOlder(
                    floor, enrollmentSaved = enrollmentSaved,
                    clearPreparedOnCommit = enrollmentStore::clearPending,
                    clearPreparedOnAbort = enrollmentStore::clearPending,
                )
            }
        } catch (_: Exception) {
            "Pacote não aceito. A assinatura, identidade, lease ou floor de hardware não foi confirmada."
        } finally {
            packageBytes.fill(0)
            readerPublicKey.fill(0)
            pin.ownerPublicSpki.fill(0)
            pin.ownerPublicSpkiSha256.fill(0)
        }
    }

    private fun readOwnerPackage(uri: Uri): ByteArray {
        val input = contentResolver.openInputStream(uri) ?: throw SecurityException("Package unavailable")
        input.use { stream ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(4096)
            while (true) {
                val count = stream.read(buffer)
                if (count < 0) break
                if (count > MAX_OWNER_PACKAGE_BYTES - output.size()) throw SecurityException("Package too large")
                output.write(buffer, 0, count)
            }
            buffer.fill(0)
            return output.toByteArray()
        }
    }

    private fun requestDeviceCredentialThen(action: () -> Unit, cancel: () -> Unit = { showLogin() }) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return cancel()
        val keyguard = getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager ?: return cancel()
        if (!keyguard.isDeviceSecure) return cancel()
        val intent = keyguard.createConfirmDeviceCredentialIntent(
            "Autorizar Root.ark", "Confirme a credencial deste dispositivo para usar a chave protegida.",
        ) ?: return cancel()
        pendingDeviceCredentialAction = action
        pendingDeviceCredentialCancel = cancel
        try {
            startActivityForResult(intent, REQUEST_DEVICE_CREDENTIAL)
        } catch (_: Exception) {
            pendingDeviceCredentialAction = null
            pendingDeviceCredentialCancel = null
            cancel()
            clearPendingOwnerImport()
        }
    }

    private fun clearPendingOwnerImport() {
        // A document picker may still be on screen before it returns a URI:
        // preserve only its account/origin labels in that case. Once a package
        // was read, cancellation must also erase those labels.
        val hadPackage = pendingOwnerImportBytes != null || pendingOwnerImportPublicKey != null ||
            pendingOwnerImportPin != null || pendingOwnerFingerprintConfirmation
        pendingOwnerImportBytes?.fill(0)
        pendingOwnerImportPublicKey?.fill(0)
        pendingOwnerImportPin?.ownerPublicSpki?.fill(0)
        pendingOwnerImportPin?.ownerPublicSpkiSha256?.fill(0)
        pendingOwnerImportBytes = null
        pendingOwnerImportPublicKey = null
        pendingOwnerImportPin = null
        if (hadPackage) {
            pendingOwnerImportOrigin = null
            pendingOwnerImportUsername = null
        }
        pendingOwnerFingerprintConfirmation = false
        pendingOwnerFingerprintStartedAtElapsedMs = 0L
        pendingOwnerDocumentAwaitingLogin = false
        pendingOwnerDocumentStartedAtElapsedMs = 0L
        pendingOwnerCredentialAtElapsedMs = 0L
        pendingOwnerCredentialInitialProvisioning = false
    }

    private fun loadInventoryPage(tracker: InventoryPagingTracker = InventoryPagingTracker()) {
        if (!sessionCanListFiles) return
        val origin = activeOrigin ?: return
        val token = sessionToken ?: return
        if (!tracker.isValid()) {
            showSession("Cursor de inventário inválido. Reinicie a listagem.")
            return
        }
        runRequest({ transport.listInventoryPage(origin, token, tracker.cursor, tracker.usedCursors) }) { page, failure ->
            if (page != null) {
                val nextTracker = tracker.advance(page.nextCursor)
                val next = page.nextCursor
                if (next != null && PagedInventoryPolicy.hasNextPage(tracker.pageNumber, next)
                    && (!nextTracker.isValid() || runCatching {
                    PagedInventoryPolicy.checkCursor(next, nextTracker.usedCursors)
                }.isFailure)) {
                    showSession("Inventário retornou cursor repetido. Reinicie a listagem.")
                } else {
                    val binding = offlineSession
                    val cache = offlineInventory
                    if (binding != null && cache != null &&
                        runCatching { cache.capture(binding, tracker.pageNumber, page) }.isFailure) {
                        cache.clear()
                    }
                    showInventoryPage(page, tracker, nextTracker)
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
                else -> showSession(inventoryPageFailureMessage(failure))
            }
        }
    }

    private fun showInventoryPage(page: InventoryPage, tracker: InventoryPagingTracker, nextTracker: InventoryPagingTracker) {
        val layout = screen("Inventário · página ${tracker.pageNumber}", "${page.rows.size} metadados de sincronização. Nenhum conteúdo descriptografado.")
        if (page.rows.isEmpty()) text(layout, "Nenhum registro disponível.")
        for (row in page.rows) {
            text(layout, row.name + if (row.deleted) " (excluído)" else "")
            val details = listOfNotNull(
                row.path?.let { "Caminho: $it" },
                row.size?.let { "Tamanho: $it bytes" },
                row.contentType?.let { "Tipo: $it" },
            ).joinToString(" · ")
            if (details.isNotEmpty()) text(layout, details)
            if (!row.deleted) button(layout, "Conteúdo protegido", accessibilityLabel = protectedContentAccessibilityLabel(row)) {
                showProtectedObject(row.objectId, backToPage = { showInventoryPage(page, tracker, nextTracker) })
            }
        }
        val previous = tracker.previous()
        if (previous != null) button(layout, "Página anterior") { loadInventoryPage(previous) }
        val next = nextTracker.cursor
        if (PagedInventoryPolicy.hasNextPage(tracker.pageNumber, next) && nextTracker.isValid()) {
            button(layout, "Próxima página") { loadInventoryPage(nextTracker) }
        }
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

    /** Server login and sync JSON never manufacture owner pins or CEK grants. */
    private fun independentlyProvisionedGrantProvider(): TrustedContentGrantProvider? {
        val origin = activeOrigin?.loginUrl()?.toString()?.removeSuffix("/auth/login") ?: return null
        return OwnerPinnedGrantProvider(this, origin)
    }

    private fun showProtectedObject(
        objectId: String, backToPage: () -> Unit, confirmedCredential: Boolean = false,
    ) {
        val origin = activeOrigin ?: return showLogin()
        val username = sessionUsername ?: return showLogin()
        if (!sessionCanListFiles) return showSession("Sem permissão para ler arquivos.")
        val preview = VerifiedTextPreview(independentlyProvisionedGrantProvider())
        val layout = screen("Conteúdo protegido", "Apenas texto UTF-8 verificado localmente pode ser exibido.")
        if (!preview.isAvailable(username, objectId)) {
            text(layout, "Bloqueado: este dispositivo ainda não recebeu uma autorização de chave e época verificável. Use um dispositivo autorizado.")
            button(layout, "Configurar enrollment do dispositivo") { showDeviceEnrollment() }
        } else {
            if (!confirmedCredential) {
                button(layout, "Autenticar e abrir texto verificado") {
                    requestDeviceCredentialThen(
                        action = {
                            deferProtectedReadAfterCredential(
                                origin.loginUrl().toString().removeSuffix("/auth/login"), username, objectId,
                            )
                        },
                        cancel = { showLogin("A autenticação do dispositivo foi cancelada.") },
                    )
                }
            } else {
                // Only a fresh post-Keyguard server login can reach this path.
                // The action parked during Keyguard contains no bearer, and
                // Keystore independently enforces its own auth-window expiry.
                val currentSession = authenticatedSession ?: return showLogin()
                val currentOrigin = activeOrigin ?: return showLogin()
                if (!isForeground || currentSession.username != username ||
                    currentOrigin.loginUrl().toString() != origin.loginUrl().toString() ||
                    !sessionCanListFiles) return showLogin("Sessão alterada; conteúdo protegido bloqueado.")
                runCheckedRequest({ stillActive ->
                        preview.open(currentOrigin, currentSession, objectId, stillActive)
                    }) { characters, failure ->
                        if (characters != null) {
                            try {
                                val view = screen("Texto verificado", "Conteúdo autenticado localmente. Feche para descartá-lo da tela.")
                                val previewText = TextView(this).apply {
                                    isSaveEnabled = false
                                    importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
                                    setTextIsSelectable(false)
                                    setPadding(0, 0, 0, (16 * resources.displayMetrics.density).toInt())
                                }
                                securePreviewText.show(characters, { retained ->
                                    previewText.setText(retained, 0, retained.size)
                                    view.addView(previewText)
                                }, { previewText.text = "" })
                                button(view, "Fechar conteúdo") {
                                    securePreviewText.clear()
                                    backToPage()
                                }
                            } catch (failure: Throwable) {
                                characters.fill('\u0000')
                                securePreviewText.clear()
                                throw failure
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
                    val currentSession = authenticatedSession ?: throw dev.rootark.core.sync.ProtectedSyncException()
                    val packet = ProtectedSyncFetch().fetchPacket(
                        origin, currentSession, objectId, SessionCiphertextCache.MAX_PACKET_BYTES
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

    private fun <T> runCheckedRequest(operation: (stillActive: () -> Boolean) -> T, done: (T?, Exception?) -> Unit) {
        val startedGeneration = ++generation
        val stillActive = { isForeground && generation == startedGeneration && !isFinishing && !isDestroyed }
        screen("Conectando", "Aguardando resposta do servidor...")
        Thread {
            var response: T? = null
            var failure: Exception? = null
            try {
                response = operation(stillActive)
            } catch (caught: Throwable) {
                failure = if (caught is Exception) caught else RuntimeException(caught)
            }
            val completedResponse = response
            val completedFailure = failure
            runOnUiThread {
                if (stillActive()) done(completedResponse, completedFailure)
                else if (completedResponse is CharArray) completedResponse.fill('\u0000')
            }
        }.start()
    }

    private fun <T> runRequest(operation: () -> T, done: (T?, Exception?) -> Unit) =
        runCheckedRequest({ _ -> operation() }, done)

    private fun errorText(error: Exception?): String = when ((error as? RootArkApiException)?.statusCode) {
        401, 400 -> "Credenciais ou código inválidos."
        429 -> "Muitas tentativas. Tente mais tarde."
        503 -> "Autenticação indisponível no servidor."
        else -> "Não foi possível autenticar. Confira a conexão HTTPS e tente novamente."
    }

    private fun screen(title: String, description: String): LinearLayout {
        securePreviewText.clear()
        val scroll = ScrollView(this)
        if (Build.VERSION.SDK_INT >= 35) {
            // Keep the platform default keyboard behavior on older Android versions.
            val mode = window.attributes.softInputMode
            val resizeMode = (mode and WindowManager.LayoutParams.SOFT_INPUT_MASK_ADJUST.inv()) or
                WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE
            if (mode != resizeMode) window.setSoftInputMode(resizeMode)
            scroll.setOnApplyWindowInsetsListener { view, insets ->
                val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
                val ime = insets.getInsets(WindowInsets.Type.ime())
                val padding = ScreenInsets(bars.left, bars.top, bars.right, bars.bottom)
                    .union(ScreenInsets(ime.left, ime.top, ime.right, ime.bottom))
                view.setPadding(padding.left, padding.top, padding.right, padding.bottom)
                insets
            }
        }
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val padding = (24 * resources.displayMetrics.density).toInt()
            setPadding(padding, padding, padding, padding)
        }
        scroll.addView(layout)
        text(layout, title).apply {
            textSize = 24f
            isAccessibilityHeading = true
        }
        text(layout, description)
        setContentView(scroll)
        if (Build.VERSION.SDK_INT >= 35) scroll.requestApplyInsets()
        return layout
    }

    private fun text(layout: LinearLayout, value: String): TextView = TextView(this).also {
        it.text = value
        it.setPadding(0, 0, 0, (16 * resources.displayMetrics.density).toInt())
        layout.addView(it)
    }

    private fun field(layout: LinearLayout, label: String, value: String, secret: Boolean): EditText =
        EditText(this).also {
            it.id = View.generateViewId()
            layout.addView(TextView(this).apply {
                text = label
                labelFor = it.id
            })
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

    private fun button(layout: LinearLayout, label: String, accessibilityLabel: String? = null, action: () -> Unit) {
        val view = Button(this)
        view.text = label
        if (accessibilityLabel != null) view.contentDescription = accessibilityLabel
        view.filterTouchesWhenObscured = true
        view.setOnClickListener { action() }
        layout.addView(view)
    }
}
