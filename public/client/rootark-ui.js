(function () {
  "use strict";

  const NAV_ITEMS = [
    { key: "files", label: "Arquivos", href: "/index.html", permission: "listFiles", section: "workspace" },
    { key: "history", label: "Histórico", href: "/index.html#/history", permission: "listFiles", section: "workspace" },
    { key: "trash", label: "Lixeira", href: "/index.html#/trash", permission: "listFiles", section: "workspace" },
    { key: "analytics", label: "Visão geral", href: "/dashboard.html", permission: "viewAnalytics", section: "insights" },
    { key: "audit", label: "Auditoria", href: "/audit.html", permission: "viewAuditLogs", section: "insights" },
    { key: "backups", label: "Backups", href: "/backups.html", permission: "manageBackups", section: "administration" },
    { key: "admin", label: "Administração", href: "/admin.html", permission: "manageUsers", section: "administration" },
  ];

  function escape(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, (char) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;",
    })[char]);
  }

  function formatBytes(value) {
    const bytes = Number(value);
    if (!Number.isFinite(bytes) || bytes < 0) return "—";
    if (bytes < 1024) return bytes + " B";
    const units = ["KB", "MB", "GB", "TB"];
    let size = bytes;
    let unit = -1;
    do { size /= 1024; unit += 1; } while (size >= 1024 && unit < units.length - 1);
    return size.toLocaleString("pt-BR", { maximumFractionDigits: 1 }) + " " + units[unit];
  }

  function formatDate(value, options) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    return new Intl.DateTimeFormat("pt-BR", options || { dateStyle: "medium", timeStyle: "short" }).format(date);
  }

  function canSee(item, user) {
    if (item.key === "files" || item.key === "history" || item.key === "trash") return Boolean(user.permissions && user.permissions[item.permission]);
    if (user.role === "admin" || user.role === "superadmin") return true;
    if (item.key === "admin") return Boolean(user.permissions && user.permissions.manageUsers);
    if (["analytics", "audit", "backups"].includes(item.key) && user.permissions && user.permissions.manageUsers) return true;
    return Boolean(user.permissions && user.permissions[item.permission]);
  }

  function navMarkup(active, user) {
    const groups = [
      ["workspace", "Espaço de trabalho"],
      ["insights", "Análise"],
      ["administration", "Gestão"],
    ];
    return groups.map(([section, title]) => {
      const links = NAV_ITEMS.filter((item) => item.section === section && canSee(item, user));
      if (!links.length) return "";
      return '<div class="nav-group"><p class="nav-label">' + title + '</p><nav aria-label="' + title + '">' +
        links.map((item) => '<a class="nav-link' + (active === item.key ? " is-active" : "") +
          '" href="' + item.href + '"' + (active === item.key ? ' aria-current="page"' : "") +
          '><span class="nav-marker" aria-hidden="true"></span><span>' + item.label + '</span></a>').join("") +
        "</nav></div>";
    }).join("");
  }

  function roleLabel(role) {
    const labels = { admin: "Administrador", superadmin: "Administrador", user: "Usuário", manager: "Gestor" };
    return labels[role] || "Conta";
  }

  function mount(options) {
    const opts = options || {};
    const user = opts.user || { username: "Conta", role: "", permissions: {} };
    const name = escape(user.username || "Conta");
    const title = escape(opts.title || "Espaço de trabalho");
    const description = escape(opts.description || "");
    const active = opts.active || "";
    const root = document.getElementById("app-root");
    if (!root) return;

    root.innerHTML = [
      '<a class="skip-link" href="#main">Pular para o conteúdo</a>',
      '<div class="app-frame">',
      '  <aside class="sidebar" id="app-sidebar" aria-label="Navegação principal">',
      '    <a class="brand" href="/index.html" aria-label="Root.ark, arquivos">',
      '      <img src="/assets/logo.svg" width="34" height="34" alt="" />',
      '      <span class="brand-wordmark">Root<span>.ark</span></span>',
      "    </a>",
      '    <div class="workspace-switcher"><span class="workspace-symbol" aria-hidden="true">R</span><span><strong>Meu espaço</strong><small>Armazenamento</small></span><span class="chevron" aria-hidden="true">⌄</span></div>',
      '    <div class="primary-navigation">' + navMarkup(active, user) + "</div>",
      '    <div class="sidebar-footer"><span class="status-dot" aria-hidden="true"></span><span>Serviço disponível</span><button type="button" class="icon-button theme-toggle" data-action="theme" aria-label="Alternar tema">◐</button></div>',
      "  </aside>",
      '  <div class="app-column">',
      '    <header class="topbar">',
      '      <button type="button" class="icon-button mobile-menu" data-action="menu" aria-label="Abrir navegação" aria-controls="app-sidebar" aria-expanded="false"><span aria-hidden="true">☰</span></button>',
      '      <div class="topbar-context"><span class="topbar-kicker">ROOT.ARK</span><span class="topbar-divider" aria-hidden="true">/</span><span>' + title + "</span></div>",
      '      <div class="topbar-actions"><span class="topbar-secure"><span aria-hidden="true">●</span> Sessão protegida</span>',
      '        <details class="account-menu"><summary><span class="avatar" aria-hidden="true">' + escape(name.slice(0, 1).toUpperCase()) + '</span><span class="account-name">' + name + '</span><span class="chevron" aria-hidden="true">⌄</span></summary>',
      '          <div class="account-popover"><strong>' + name + '</strong><span>' + escape(roleLabel(user.role)) + '</span><button type="button" data-action="logout">Sair da conta</button></div>',
      "        </details>",
      "      </div>",
      "    </header>",
      '    <main class="main-content" id="main" tabindex="-1">',
      '      <div class="page-heading"><div><p class="eyebrow">' + escape(opts.eyebrow || "ROOT.ARK / ESPAÇO DE TRABALHO") + '</p><h1>' + title + "</h1>" +
        (description ? '<p class="page-description">' + description + "</p>" : "") + "</div>" +
        (opts.toolbar ? '<div class="page-toolbar">' + opts.toolbar + "</div>" : "") + "</div>",
      '      <div id="page-content">' + (opts.content || "") + "</div>",
      "    </main>",
      '    <footer class="app-footer"><span>Root.ark</span><span>Seu espaço, organizado.</span></footer>',
      "  </div>",
      '  <dialog class="app-dialog" id="app-dialog" aria-labelledby="dialog-title"></dialog>',
      '  <div class="toast-region" id="toast-region" aria-live="polite" aria-atomic="true"></div>',
      "</div>",
    ].join("");

    const menuButton = root.querySelector('[data-action="menu"]');
    if (menuButton) menuButton.addEventListener("click", () => {
      const open = root.classList.toggle("nav-open");
      menuButton.setAttribute("aria-expanded", String(open));
      menuButton.setAttribute("aria-label", open ? "Fechar navegação" : "Abrir navegação");
    });
    const themeButton = root.querySelector('[data-action="theme"]');
    if (themeButton) themeButton.addEventListener("click", toggleTheme);
    const logoutButton = root.querySelector('[data-action="logout"]');
    if (logoutButton) logoutButton.addEventListener("click", logout);
  }

  function closeMobileNav(event) {
    const root = document.getElementById("app-root");
    if (!root || !root.classList.contains("nav-open") || event.target.closest(".sidebar, .mobile-menu")) return;
    root.classList.remove("nav-open");
    const button = root.querySelector(".mobile-menu");
    if (button) {
      button.setAttribute("aria-expanded", "false");
      button.setAttribute("aria-label", "Abrir navegação");
    }
  }

  document.addEventListener("click", closeMobileNav);

  function toggleTheme() {
    const current = document.documentElement.dataset.theme || "light";
    const next = current === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("rootark-theme", next); } catch (_) {}
  }

  function initTheme() {
    try {
      const saved = localStorage.getItem("rootark-theme");
      if (saved === "dark" || saved === "light") document.documentElement.dataset.theme = saved;
    } catch (_) {}
  }

  function toast(message, tone) {
    const region = document.getElementById("toast-region");
    if (!region) return;
    const item = document.createElement("div");
    item.className = "toast" + (tone ? " toast-" + tone : "");
    item.setAttribute("role", tone === "error" ? "alert" : "status");
    item.textContent = String(message || "");
    region.append(item);
    window.setTimeout(() => item.remove(), 5000);
  }

  function dialog(options) {
    const opts = options || {};
    const element = document.getElementById("app-dialog");
    if (!element) return Promise.resolve(null);
    element.innerHTML = [
      '<form method="dialog" class="dialog-card">',
      '  <div class="dialog-heading"><div><p class="eyebrow">' + escape(opts.eyebrow || "CONFIRMAÇÃO") + '</p><h2 id="dialog-title">' + escape(opts.title || "Confirmar ação") + "</h2></div>",
      '  <button type="button" class="icon-button" data-dialog-cancel aria-label="Fechar">×</button></div>',
      '  <div class="dialog-body">' + (opts.content || "") + "</div>",
      '  <div class="dialog-actions"><button type="button" class="button button-quiet" data-dialog-cancel>' + escape(opts.cancelLabel || "Cancelar") + "</button>" +
        '<button type="submit" value="confirm" class="button' + (opts.danger ? " button-danger" : " button-primary") + '">' + escape(opts.confirmLabel || "Confirmar") + "</button></div>",
      "</form>",
    ].join("");

    return new Promise((resolve) => {
      const form = element.querySelector("form");
      const outsideClick = (event) => {
        if (event.target === element) element.close("cancel");
      };
      const finish = () => {
        const result = element.returnValue === "confirm" ? new FormData(form) : null;
        element.removeEventListener("click", outsideClick);
        element.innerHTML = "";
        resolve(result);
      };
      element.addEventListener("close", finish, { once: true });
      element.querySelectorAll("[data-dialog-cancel]").forEach((button) => button.addEventListener("click", () => {
        element.close("cancel");
      }));
      form.addEventListener("submit", (event) => {
        event.preventDefault();
        element.close("confirm");
      });
      element.addEventListener("click", outsideClick);
      element.showModal();
      const focusTarget = element.querySelector("input, select, textarea") || element.querySelector("[data-dialog-cancel]");
      if (focusTarget) focusTarget.focus();
    });
  }

  function redirectToLogin() {
    window.dispatchEvent(new Event("rootark:logout"));
    const destination = window.location.pathname + window.location.hash;
    window.location.assign("/login.html?returnTo=" + encodeURIComponent(destination));
  }

  async function logout() {
    window.dispatchEvent(new Event("rootark:logout"));
    try { await window.RootarkApi.post("/auth/logout", {}); } catch (_) {}
    window.location.assign("/login.html");
  }

  async function getSession() {
    return window.RootarkApi.get("/auth/me");
  }

  initTheme();
  window.RootarkUI = Object.freeze({
    escape,
    formatBytes,
    formatDate,
    roleLabel,
    mount,
    toast,
    dialog,
    getSession,
    redirectToLogin,
    logout,
  });
})();
