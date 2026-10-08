(function () {
  "use strict";

  const api = window.RootarkApi;
  const loginForm = document.getElementById("login-form");
  const totpForm = document.getElementById("totp-form");
  const enrollForm = document.getElementById("enroll-form");
  const recoveryStep = document.getElementById("recovery-step");
  const errorRegion = document.getElementById("auth-error");
  const loginTitle = document.getElementById("login-title");
  const loginIntro = document.getElementById("login-intro");
  const eyebrow = document.getElementById("login-eyebrow");
  const loginButton = document.getElementById("login-submit");
  let challengeId = null;
  let enrollmentToken = null;
  let busy = false;

  try {
    const theme = localStorage.getItem("rootark-theme");
    if (theme === "dark" || theme === "light") document.documentElement.dataset.theme = theme;
  } catch (_) {}

  function message(text) {
    errorRegion.textContent = String(text || "");
  }

  function clearEnrollmentDetails() {
    document.getElementById("enroll-secret").textContent = "";
    const qr = document.getElementById("enroll-qr");
    qr.removeAttribute("src");
    qr.hidden = true;
  }

  function setBusy(form, value, label) {
    busy = value;
    const button = form.querySelector('button[type="submit"]');
    if (!button) return;
    button.disabled = value;
    if (value) {
      button.dataset.originalLabel = button.textContent;
      button.textContent = label || "Aguarde…";
    } else if (button.dataset.originalLabel) {
      button.textContent = button.dataset.originalLabel;
      delete button.dataset.originalLabel;
    }
  }

  function showStep(step) {
    loginForm.hidden = step !== "login";
    totpForm.hidden = step !== "totp";
    enrollForm.hidden = step !== "enroll";
    recoveryStep.hidden = step !== "recovery";
    errorRegion.textContent = "";
    if (step === "login") {
      eyebrow.textContent = "ACESSO SEGURO";
      loginTitle.textContent = "Entrar";
      loginIntro.textContent = "Use suas credenciais para acessar seu espaço.";
      document.getElementById("username").focus();
    } else if (step === "totp") {
      eyebrow.textContent = "VERIFICAÇÃO ADICIONAL";
      loginTitle.textContent = "Confirme sua identidade";
      loginIntro.textContent = "Sua conta usa autenticação de dois fatores.";
      document.getElementById("totp-code").focus();
    } else if (step === "recovery") {
      eyebrow.textContent = "CONFIGURAÇÃO CONCLUÍDA";
      loginTitle.textContent = "Autenticação ativada";
      loginIntro.textContent = "Guarde os códigos de recuperação. Depois, entre novamente com sua senha e o código do aplicativo.";
      document.getElementById("recovery-step-title").focus();
    } else {
      eyebrow.textContent = "CONFIGURAÇÃO NECESSÁRIA";
      loginTitle.textContent = "Ative a autenticação";
      loginIntro.textContent = "Configure um aplicativo de autenticação para concluir o acesso.";
      document.getElementById("enroll-code").focus();
    }
  }

  function friendlyError(error, fallback, isPasswordLogin) {
    if (error && error.status === 401 && isPasswordLogin) return "Usuário ou senha não conferem.";
    if (error && error.status === 429) return "Muitas tentativas. Aguarde um pouco e tente novamente.";
    if (error && error.status === 0) return error.message;
    return (error && error.message) || fallback;
  }

  function destination() {
    const value = new URLSearchParams(window.location.search).get("returnTo");
    if (!value || value[0] !== "/" || value.startsWith("//")) return "/index.html";
    try {
      const target = new URL(value, window.location.origin);
      if (target.origin !== window.location.origin) return "/index.html";
      if (target.pathname === "/login.html") return "/index.html";
      return target.pathname + target.search + target.hash;
    } catch (_) {
      return "/index.html";
    }
  }

  function finishLogin() {
    window.location.assign(destination());
  }

  async function completeEnrollment(token) {
    enrollmentToken = token;
    const response = await api.post("/auth/2fa/enroll", {}, { token: enrollmentToken });
    const qr = document.getElementById("enroll-qr");
    if (typeof response.qrCode === "string" && response.qrCode.startsWith("data:image/png;base64,")) {
      qr.src = response.qrCode;
      qr.hidden = false;
    } else {
      qr.hidden = true;
      qr.removeAttribute("src");
    }
    document.getElementById("enroll-secret").textContent = String(response.secret || "");
    showStep("enroll");
  }

  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    message("");
    setBusy(loginForm, true, "Verificando…");
    try {
      const form = new FormData(loginForm);
      const response = await api.post("/auth/login", {
        username: form.get("username"),
        password: form.get("password"),
      });
      document.getElementById("password").value = "";
      if (response.challengeRequired) {
        challengeId = response.challengeId;
        if (!challengeId) throw new Error("Não foi possível iniciar a verificação.");
        showStep("totp");
        return;
      }
      finishLogin();
    } catch (error) {
      const payload = error && error.payload;
      if (error && error.status === 403 && payload && payload.enrollmentRequired && payload.token) {
        document.getElementById("password").value = "";
        try {
          await completeEnrollment(payload.token);
        } catch (enrollError) {
          enrollmentToken = null;
          clearEnrollmentDetails();
          showStep("login");
          message(friendlyError(enrollError, "Não foi possível iniciar a configuração de autenticação."));
        }
      } else {
        message(friendlyError(error, "Não foi possível entrar. Tente novamente.", true));
      }
    } finally {
      setBusy(loginForm, false);
    }
  });

  totpForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy || !challengeId) return;
    message("");
    setBusy(totpForm, true, "Verificando…");
    try {
      const code = new FormData(totpForm).get("code");
      await api.post("/auth/login/2fa", { challengeId, code });
      challengeId = null;
      finishLogin();
    } catch (error) {
      message(friendlyError(error, "Código inválido ou expirado. Confira o aplicativo e tente novamente."));
      document.getElementById("totp-code").select();
    } finally {
      setBusy(totpForm, false);
    }
  });

  enrollForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy || !enrollmentToken) return;
    message("");
    setBusy(enrollForm, true, "Ativando…");
    try {
      const code = new FormData(enrollForm).get("code");
      const result = await api.post("/auth/2fa/confirm", { code }, { token: enrollmentToken });
      enrollmentToken = null;
      clearEnrollmentDetails();
      if (result && result.loginRequired) {
        const codes = Array.isArray(result.recoveryCodes) ? result.recoveryCodes.map(String).filter(Boolean) : [];
        document.getElementById("recovery-codes").value = codes.join("\n");
        showStep("recovery");
        return;
      }
      finishLogin();
    } catch (error) {
      message(friendlyError(error, "Código inválido. Confira o aplicativo e tente novamente."));
      document.getElementById("enroll-code").select();
    } finally {
      setBusy(enrollForm, false);
    }
  });

  document.getElementById("back-to-login").addEventListener("click", () => {
    challengeId = null;
    totpForm.reset();
    showStep("login");
  });
  document.getElementById("cancel-enroll").addEventListener("click", () => {
    enrollmentToken = null;
    enrollForm.reset();
    clearEnrollmentDetails();
    loginForm.reset();
    showStep("login");
  });
  document.getElementById("continue-after-enroll").addEventListener("click", () => {
    document.getElementById("recovery-codes").value = "";
    showStep("login");
    loginIntro.textContent = "A autenticação foi ativada. Entre novamente para iniciar uma sessão protegida.";
    const passwordInput = document.getElementById("password");
    passwordInput.value = "";
    passwordInput.focus();
  });

  api.get("/auth/me").then(finishLogin).catch(() => {
    document.getElementById("username").focus();
  });
})();
