(function () {
  "use strict";
  const api = window.RootarkApi;
  const ui = window.RootarkUI;
  const view = document.body.dataset.rootarkView;
  const pageContent = () => document.getElementById("page-content");
  const PERMISSIONS = [
    ["upload", "Enviar arquivos"], ["approve", "Aprovar envios"], ["delete", "Excluir arquivos"],
    ["listFiles", "Ver arquivos"], ["listPending", "Ver pendentes"], ["createFolders", "Criar pastas"],
    ["viewAnalytics", "Ver análise"], ["viewAuditLogs", "Ver auditoria"], ["manageBackups", "Gerenciar backups"],
    ["manageTrash", "Gerenciar lixeira"], ["manageUsers", "Gerenciar usuários"],
  ];
  const esc = (value) => ui.escape(value == null ? "" : value);
  const asArray = (value) => Array.isArray(value) ? value : [];
  const numeric = (value) => Number.isFinite(Number(value)) ? Number(value) : 0;
  const count = (value) => numeric(value).toLocaleString("pt-BR", { maximumFractionDigits: 0 });

  function publicError(error, fallback) {
    if (error && error.status === 401) { ui.redirectToLogin(); return ""; }
    if (error && error.status === 403) return "Sua conta não tem permissão para esta ação.";
    if (error && error.status === 503 && error.payload?.cleanupPending) return "Backup restaurado, mas a limpeza temporária falhou. Reinicie todas as instâncias; o serviço tentará remover a área temporária antes de aceitar novas solicitações.";
    if (error && error.status === 503 && error.payload?.restartRequired) return "Backup restaurado. Reinicie todas as instâncias do servidor para liberar o acesso.";
    if (error && error.status === 503 && error.payload?.recoveryRequired) return "O servidor está bloqueado durante a recuperação do backup. Reinicie todas as instâncias e revise o estado antes de tentar novamente.";
    const message = String(error && error.message || "");
    if (!message || error.status >= 500 || /[A-Za-z]:[\\/]|(?:^|[\s"'(])\/(?:[^/\s]+\/){2,}/.test(message)) return fallback;
    return message;
  }
  function setFeedback(element, message, tone) {
    if (!element) return;
    const text = String(message || "");
    element.textContent = text;
    element.hidden = !text;
    element.className = tone === "error" ? "feedback feedback-error" : "feedback";
    element.setAttribute("role", tone === "error" ? "alert" : "status");
  }
  function tableState(colspan, message, kind) {
    const state = kind === "error" ? "feedback feedback-error" : kind === "loading" ? "muted" : "empty-inline";
    return `<tr><td colspan="${colspan}" class="${state}" role="${kind === "error" ? "alert" : "status"}">${esc(message)}</td></tr>`;
  }
  function mount(user, options) { ui.mount(Object.assign({ user }, options)); return pageContent(); }
  function noAccess(target, message) {
    target.innerHTML = `<section class="panel" role="alert"><div class="notice notice-danger"><div><strong>Acesso indisponível</strong><p>${esc(message)}</p></div></div></section>`;
  }
  function confirmAction(options) {
    return ui.dialog(Object.assign({ eyebrow: "CONFIRMAÇÃO", cancelLabel: "Cancelar", confirmLabel: "Continuar" }, options)).then((result) => result !== null);
  }
  function connectRealtime(sources, refresh) {
    if (!window.WebSocket) return;
    let socket, retryTimer, refreshTimer, closed = false;
    const connect = () => {
      if (closed) return;
      try {
        const protocol = location.protocol === "https:" ? "wss:" : "ws:";
        socket = new WebSocket(`${protocol}//${location.host}/ws`);
      } catch (_) { retryTimer = setTimeout(connect, 5000); return; }
      socket.addEventListener("message", (event) => {
        let message;
        try { message = JSON.parse(event.data); } catch (_) { return; }
        if (message.event !== "data:changed" || !sources.includes(message.payload && message.payload.source)) return;
        clearTimeout(refreshTimer);
        refreshTimer = setTimeout(() => refresh().catch(() => {}), 350);
      });
      socket.addEventListener("close", () => { if (!closed) retryTimer = setTimeout(connect, 5000); });
    };
    addEventListener("pagehide", () => {
      closed = true; clearTimeout(retryTimer); clearTimeout(refreshTimer);
      if (socket && socket.readyState < WebSocket.CLOSING) socket.close();
    }, { once: true });
    connect();
  }

  function adminMarkup() {
    return `
      <div class="stack page-stack" id="admin-view">
        <form id="create-user-form" class="panel section-card">
          <div class="section-heading"><div><h2>Criar conta</h2><p>Cadastre uma conta e defina permissões iniciais.</p></div></div>
          <div class="form-grid">
            <div class="field-row"><label for="new-username">Usuário</label><input class="field" id="new-username" name="username" type="text" autocomplete="off" required /></div>
            <div class="field-row"><label for="new-password">Senha inicial</label><input class="field" id="new-password" name="password" type="password" autocomplete="new-password" required /></div>
            <div class="field-row"><label for="new-role">Cargo</label><select class="field" id="new-role" name="role"><option value="user">Usuário</option><option value="admin">Administrador</option></select></div>
          </div>
          <fieldset class="panel permission-fieldset"><legend>Permissões da conta</legend><div id="create-permissions" class="grid grid-3 permission-grid"></div></fieldset>
          <div class="toolbar"><button class="button button-primary" type="submit">Criar conta</button><p id="create-user-feedback" class="feedback" aria-live="polite" hidden></p></div>
        </form>
        <section class="panel section-card" aria-labelledby="users-title">
          <div class="section-heading"><div><h2 id="users-title">Contas</h2><p>Revise permissões e contas cadastradas.</p></div><button type="button" class="button button-quiet" data-action="refresh-users">Atualizar</button></div>
          <div class="table-wrap"><table class="data-table"><thead><tr><th scope="col">Usuário</th><th scope="col">Cargo</th><th scope="col">Permissões</th><th scope="col">Ações</th></tr></thead><tbody id="users-body">${tableState(4, "Carregando contas…", "loading")}</tbody></table></div>
        </section>
        <section class="panel section-card" aria-labelledby="groups-title">
          <div class="section-heading"><div><h2 id="groups-title">Grupos</h2><p>Grupos podem conceder acesso adicional a pastas; os acessos individuais permanecem separados.</p></div></div>
          <form id="create-group-form"><div class="form-grid">
            <div class="field-row"><label for="new-group-name">Nome do grupo</label><input class="field" id="new-group-name" name="name" type="text" maxlength="80" required /></div>
            <div class="field-row"><label for="new-group-members">Membros</label><input class="field" id="new-group-members" name="members" type="text" aria-describedby="group-members-hint" placeholder="ana, bruno" /><small class="field-help" id="group-members-hint">Separe os nomes de usuário por vírgula.</small></div>
          </div><div class="toolbar"><button class="button button-primary" type="submit">Criar grupo</button><p id="group-feedback" class="feedback" aria-live="polite" hidden></p></div></form>
          <div class="table-wrap"><table class="data-table"><thead><tr><th scope="col">Grupo</th><th scope="col">Membros atuais</th><th scope="col">Atualizar membros</th><th scope="col">Ações</th></tr></thead><tbody id="groups-body">${tableState(4, "Carregando grupos…", "loading")}</tbody></table></div>
        </section>
        <section class="panel section-card" aria-labelledby="quarantine-title">
          <div class="section-heading"><div><h2 id="quarantine-title">Quarentena de envios</h2><p>Itens isolados pela verificação de segurança não aparecem na área de arquivos.</p></div><button type="button" class="button button-quiet" data-action="refresh-quarantine">Atualizar</button></div>
          <div class="table-wrap"><table class="data-table"><thead><tr><th scope="col">Arquivo</th><th scope="col">Usuário</th><th scope="col">Motivo</th><th scope="col">Data</th><th scope="col">Tamanho</th><th scope="col">Ações</th></tr></thead><tbody id="quarantine-body">${tableState(6, "Carregando quarentena…", "loading")}</tbody></table></div>
        </section>
        <section class="panel section-card" aria-labelledby="file-access-title">
          <div class="section-heading"><div><h2 id="file-access-title">Acesso individual a arquivos</h2><p>Sem contas selecionadas, o arquivo herda o acesso configurado para a pasta.</p></div></div>
          <div class="form-grid"><div class="field-row"><label for="access-folder">Pasta</label><select class="field" id="access-folder"><option value="">Carregando pastas…</option></select></div><div class="field-row"><label for="access-file">Arquivo</label><select class="field" id="access-file" disabled><option value="">Selecione uma pasta</option></select></div></div>
          <fieldset class="panel permission-fieldset"><legend>Contas com acesso direto</legend><div id="file-access-users" class="grid grid-3 permission-grid"><p class="muted" role="status">Selecione uma pasta e um arquivo.</p></div></fieldset>
          <div class="toolbar"><button id="save-file-access" class="button button-primary" type="button" disabled>Salvar acesso</button><p id="file-access-feedback" class="feedback" aria-live="polite" hidden></p></div>
        </section>
      </div>`;
  }

  async function initAdmin(user, target) {
    if (!user.permissions || !user.permissions.manageUsers) {
      noAccess(target, "A administração de contas, grupos e quarentena exige a permissão manageUsers."); return;
    }
    target.innerHTML = adminMarkup();
    let users = [], groups = [], quarantine = [], folders = [], eligibleUsers = [], allowedUsers = [];
    const usersBody = document.getElementById("users-body");
    const groupsBody = document.getElementById("groups-body");
    const quarantineBody = document.getElementById("quarantine-body");
    const folderSelect = document.getElementById("access-folder");
    const fileSelect = document.getElementById("access-file");
    const accessUsers = document.getElementById("file-access-users");
    const saveAccess = document.getElementById("save-file-access");
    const createGrid = document.getElementById("create-permissions");

    function renderCreatePermissions() {
      const admin = document.getElementById("new-role").value === "admin";
      createGrid.innerHTML = PERMISSIONS.map(([key, label]) => `<label class="checkbox-row permission-option" for="create-perm-${key}"><input id="create-perm-${key}" name="permission-${key}" type="checkbox" ${admin || key === "listFiles" ? "checked" : ""} ${admin ? "disabled" : ""} /><span>${esc(label)}</span></label>`).join("");
    }    function renderUsers() {
      if (!users.length) { usersBody.innerHTML = tableState(4, "Nenhuma conta cadastrada.", "empty"); return; }
      usersBody.innerHTML = users.map((account, index) => {
        const username = String(account.username || "");
        const isSelf = username === user.username;
        const isAdmin = account.role === "admin";
        const chips = PERMISSIONS.map(([key, label]) => {
          const enabled = Boolean(account.permissions && account.permissions[key]);
          const disabled = isAdmin || (isSelf && key === "manageUsers");
          const title = isAdmin ? "As permissões de administrador são definidas pelo servidor." : isSelf && key === "manageUsers" ? "Você não pode remover sua própria permissão de administração." : `${enabled ? "Remover" : "Conceder"} ${label}`;
          return `<button type="button" class="button button-small permission-chip ${enabled ? "button-primary" : "button-quiet"}" data-action="toggle-permission" data-user-index="${index}" data-permission="${key}" aria-pressed="${enabled}" title="${esc(title)}" ${disabled ? "disabled" : ""}>${esc(label)}</button>`;
        }).join("");
        return `<tr><th scope="row">${esc(username)}${isSelf ? ' <span class="badge badge-primary">Você</span>' : ""}</th><td>${esc(ui.roleLabel(account.role))}${account.disabled ? ' <span class="badge badge-warning">Desativada</span>' : ""}</td><td><div class="row-actions permission-chip-list">${chips}</div></td><td>${isSelf ? '<span class="muted">Conta atual</span>' : `<button type="button" class="button button-danger button-small" data-action="delete-user" data-user-index="${index}">Excluir conta</button>`}</td></tr>`;
      }).join("");
    }
    function renderGroups() {
      if (!groups.length) { groupsBody.innerHTML = tableState(4, "Nenhum grupo cadastrado.", "empty"); return; }
      groupsBody.innerHTML = groups.map((group, index) => {
        const members = asArray(group.members).map(String);
        return `<tr><th scope="row">${esc(group.name)}</th><td>${members.length ? esc(members.join(", ")) : '<span class="muted">Sem membros</span>'}</td><td><input class="field" type="text" data-group-members="${index}" value="${esc(members.join(", "))}" aria-label="Membros de ${esc(group.name)}" /></td><td><div class="row-actions"><button type="button" class="button button-primary button-small" data-action="save-group" data-group-index="${index}">Salvar</button><button type="button" class="button button-danger button-small" data-action="delete-group" data-group-index="${index}">Excluir</button></div></td></tr>`;
      }).join("");
    }
    function renderQuarantine() {
      if (!quarantine.length) { quarantineBody.innerHTML = tableState(6, "Nenhum arquivo em quarentena.", "empty"); return; }
      quarantineBody.innerHTML = quarantine.map((item, index) => `<tr><th scope="row">${esc(item.originalFilename || "Arquivo sem nome")}</th><td>${esc(item.uploader || "—")}</td><td>${esc(item.reason || item.scanResult && item.scanResult.status || "Bloqueado")}</td><td>${esc(ui.formatDate(item.timestamp))}</td><td>${esc(ui.formatBytes(item.size))}</td><td><button type="button" class="button button-danger button-small" data-action="delete-quarantine" data-quarantine-index="${index}">Excluir</button></td></tr>`).join("");
    }
    function renderAccessUsers(message, kind) {
      if (message) {
        const state = kind === "error" ? "error-state" : "empty-inline muted";
        accessUsers.innerHTML = `<p class="${state}" role="${kind === "error" ? "alert" : "status"}">${esc(message)}</p>`;
        saveAccess.disabled = true;
        return;
      }
      if (!fileSelect.value) {
        accessUsers.innerHTML = '<p class="empty-inline muted" role="status">Selecione um arquivo para revisar o acesso.</p>';
        saveAccess.disabled = true;
        return;
      }
      if (!eligibleUsers.length) {
        accessUsers.innerHTML = '<p class="empty-inline muted" role="status">Nenhuma conta elegível para este arquivo.</p>';
        saveAccess.disabled = true;
        return;
      }
      accessUsers.innerHTML = eligibleUsers.map((username, index) => `<label class="checkbox-row permission-option" for="access-user-${index}"><input id="access-user-${index}" type="checkbox" data-access-username="${esc(username)}" ${allowedUsers.includes(username) ? "checked" : ""} /><span>${esc(username)}</span></label>`).join("");
      saveAccess.disabled = false;
    }
    async function loadUsers() {
      usersBody.innerHTML = tableState(4, "Carregando contas…", "loading");
      try { users = asArray(await api.get("/users")); renderUsers(); }
      catch (error) { users = []; usersBody.innerHTML = tableState(4, publicError(error, "Não foi possível carregar as contas."), "error"); }
    }
    async function loadGroups() {
      groupsBody.innerHTML = tableState(4, "Carregando grupos…", "loading");
      try { groups = asArray(await api.get("/groups")); renderGroups(); }
      catch (error) { groups = []; groupsBody.innerHTML = tableState(4, publicError(error, "Não foi possível carregar os grupos."), "error"); }
    }
    async function loadQuarantine() {
      quarantineBody.innerHTML = tableState(6, "Carregando quarentena…", "loading");
      try { quarantine = asArray(await api.get("/quarantine")); renderQuarantine(); }
      catch (error) { quarantine = []; quarantineBody.innerHTML = tableState(6, publicError(error, "Não foi possível carregar a quarentena."), "error"); }
    }
    async function loadFolders() {
      folderSelect.innerHTML = '<option value="">Carregando pastas…</option>';
      try {
        folders = asArray(await api.get("/folders"));
        if (!folders.length) {
          folderSelect.innerHTML = '<option value="">Nenhuma pasta disponível</option>';
          fileSelect.innerHTML = '<option value="">Nenhum arquivo disponível</option>';
          fileSelect.disabled = true;
          renderAccessUsers("Nenhuma pasta disponível.");
          return;
        }
        folderSelect.innerHTML = folders.map((folder) => `<option value="${esc(folder.id)}">${esc(folder.name || "Pasta")}</option>`).join("");
        await loadFiles();
      } catch (error) {
        folders = [];
        folderSelect.innerHTML = '<option value="">Falha ao carregar pastas</option>';
        fileSelect.innerHTML = '<option value="">Indisponível</option>';
        fileSelect.disabled = true;
        renderAccessUsers(publicError(error, "Falha ao carregar pastas."), "error");
      }
    }
    async function loadFiles() {
      const folderId = folderSelect.value;
      allowedUsers = [];
      eligibleUsers = [];
      if (!folderId) {
        fileSelect.innerHTML = '<option value="">Nenhuma pasta selecionada</option>';
        fileSelect.disabled = true;
        renderAccessUsers();
        return;
      }
      fileSelect.disabled = true;
      fileSelect.innerHTML = '<option value="">Carregando arquivos…</option>';
      renderAccessUsers("Carregando arquivos da pasta…");
      try {
        const files = asArray(await api.get(api.query("/list", { folderId })));
        if (!files.length) {
          fileSelect.innerHTML = '<option value="">Nenhum arquivo disponível</option>';
          renderAccessUsers("Nenhum arquivo disponível nesta pasta.");
          return;
        }
        fileSelect.innerHTML = files.map((file) => `<option value="${esc(file.name)}">${esc(file.name)}</option>`).join("");
        fileSelect.disabled = false;
        await loadSelectedFileAccess();
      } catch (error) {
        fileSelect.innerHTML = '<option value="">Falha ao carregar arquivos</option>';
        renderAccessUsers(publicError(error, "Falha ao carregar arquivos da pasta."), "error");
      }
    }
    async function loadSelectedFileAccess() {
      const folderId = folderSelect.value, name = fileSelect.value;
      allowedUsers = [];
      eligibleUsers = [];
      if (!folderId || !name) { renderAccessUsers(); return; }
      renderAccessUsers("Carregando permissões do arquivo…");
      try {
        const result = await api.get(api.query("/file-access", { folderId, name }));
        allowedUsers = asArray(result.allowedUsers).map(String);
        eligibleUsers = Array.isArray(result.eligibleUsers)
          ? result.eligibleUsers.map((item) => typeof item === "string" ? item : item && item.username).filter(Boolean).map(String)
          : users.map((account) => String(account.username || "")).filter(Boolean);
        renderAccessUsers();
      } catch (error) { renderAccessUsers(publicError(error, "Falha ao carregar permissões do arquivo."), "error"); }
    }

    renderCreatePermissions();
    document.getElementById("new-role").addEventListener("change", renderCreatePermissions);
    document.getElementById("create-user-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = event.currentTarget, values = new FormData(form), role = String(values.get("role") || "user");
      const permissions = Object.fromEntries(PERMISSIONS.map(([key]) => [key, role === "admin" || values.get(`permission-${key}`) === "on"]));
      const feedback = document.getElementById("create-user-feedback"), button = form.querySelector("button[type='submit']");
      button.disabled = true; setFeedback(feedback, "Criando conta…");
      try {
        await api.post("/users", { username: String(values.get("username") || "").trim(), password: String(values.get("password") || ""), role, permissions });
        form.reset(); renderCreatePermissions(); setFeedback(feedback, "Conta criada.", "success"); ui.toast("Conta criada.", "success");
        await Promise.all([loadUsers(), loadGroups()]);
      } catch (error) { const message = publicError(error, "Não foi possível criar a conta."); if (message) setFeedback(feedback, message, "error"); }
      finally { button.disabled = false; }
    });
    document.getElementById("create-group-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = event.currentTarget, values = new FormData(form), members = String(values.get("members") || "").split(",").map((item) => item.trim()).filter(Boolean);
      const button = form.querySelector("button[type='submit']"), feedback = document.getElementById("group-feedback");
      button.disabled = true; setFeedback(feedback, "Criando grupo…");
      try {
        await api.post("/groups", { name: String(values.get("name") || "").trim(), members });
        form.reset(); setFeedback(feedback, "Grupo criado.", "success"); ui.toast("Grupo criado.", "success"); await loadGroups();
      } catch (error) { const message = publicError(error, "Não foi possível criar o grupo."); if (message) setFeedback(feedback, message, "error"); }
      finally { button.disabled = false; }
    });    folderSelect.addEventListener("change", loadFiles);
    fileSelect.addEventListener("change", loadSelectedFileAccess);
    saveAccess.addEventListener("click", async () => {
      const folderId = folderSelect.value, name = fileSelect.value;
      if (!folderId || !name) { setFeedback(document.getElementById("file-access-feedback"), "Selecione uma pasta e um arquivo.", "error"); return; }
      const selected = Array.from(accessUsers.querySelectorAll("input[data-access-username]:checked")).map((input) => input.dataset.accessUsername);
      saveAccess.disabled = true;
      const feedback = document.getElementById("file-access-feedback"); setFeedback(feedback, "Salvando acesso…");
      try {
        await api.put("/file-access", { folderId, name, allowedUsers: selected, public: selected.length === 0 });
        allowedUsers = selected;
        setFeedback(feedback, selected.length ? "Acesso individual salvo." : "O arquivo herdará o acesso da pasta.", "success");
        ui.toast("Acesso do arquivo atualizado.", "success");
      } catch (error) { const message = publicError(error, "Não foi possível salvar o acesso do arquivo."); if (message) setFeedback(feedback, message, "error"); }
      finally { saveAccess.disabled = !fileSelect.value || !eligibleUsers.length; }
    });
    target.addEventListener("click", async (event) => {
      const button = event.target.closest("button[data-action]");
      if (!button) return;
      const action = button.dataset.action;
      if (action === "refresh-users") return loadUsers();
      if (action === "refresh-quarantine") return loadQuarantine();
      if (action === "toggle-permission") {
        const account = users[Number(button.dataset.userIndex)], key = button.dataset.permission;
        if (!account || !PERMISSIONS.some(([permission]) => permission === key)) return;
        button.disabled = true;
        try {
          const enabled = !Boolean(account.permissions && account.permissions[key]);
          await api.put(`/users/${encodeURIComponent(account.username)}`, { permissions: { [key]: enabled } });
          ui.toast(`Permissão atualizada para ${account.username}.`, "success"); await loadUsers();
        } catch (error) { const message = publicError(error, "Não foi possível atualizar a permissão."); if (message) ui.toast(message, "error"); button.disabled = false; }
        return;
      }
      if (action === "delete-user") {
        const account = users[Number(button.dataset.userIndex)]; if (!account) return;
        const accepted = await confirmAction({ eyebrow: "EXCLUIR CONTA", title: "Excluir esta conta?", content: `<p>A conta <strong>${esc(account.username)}</strong> será removida e suas sessões serão invalidadas.</p>`, confirmLabel: "Excluir conta", danger: true });
        if (!accepted) return;
        button.disabled = true;
        try { await api.delete(`/users/${encodeURIComponent(account.username)}`); ui.toast("Conta excluída.", "success"); await Promise.all([loadUsers(), loadGroups()]); }
        catch (error) { const message = publicError(error, "Não foi possível excluir a conta."); if (message) ui.toast(message, "error"); button.disabled = false; }
        return;
      }
      if (action === "save-group") {
        const index = Number(button.dataset.groupIndex), group = groups[index], input = target.querySelector(`[data-group-members="${index}"]`);
        if (!group || !input) return;
        const members = input.value.split(",").map((item) => item.trim()).filter(Boolean);
        button.disabled = true;
        try { await api.put(`/groups/${encodeURIComponent(group.id)}/members`, { members }); setFeedback(document.getElementById("group-feedback"), "Membros atualizados.", "success"); ui.toast("Membros do grupo atualizados.", "success"); await loadGroups(); }
        catch (error) { const message = publicError(error, "Não foi possível atualizar os membros."); if (message) setFeedback(document.getElementById("group-feedback"), message, "error"); button.disabled = false; }
        return;
      }
      if (action === "delete-group") {
        const group = groups[Number(button.dataset.groupIndex)]; if (!group) return;
        const accepted = await confirmAction({ eyebrow: "EXCLUIR GRUPO", title: "Excluir este grupo?", content: `<p><strong>${esc(group.name)}</strong> será removido das pastas vinculadas. O acesso concedido por esse grupo será revogado; permissões individuais permanecem.</p>`, confirmLabel: "Excluir grupo", danger: true });
        if (!accepted) return;
        button.disabled = true;
        try { await api.delete(`/groups/${encodeURIComponent(group.id)}`); setFeedback(document.getElementById("group-feedback"), "Grupo excluído.", "success"); ui.toast("Grupo excluído.", "success"); await Promise.all([loadGroups(), loadFolders()]); }
        catch (error) { const message = publicError(error, "Não foi possível excluir o grupo."); if (message) setFeedback(document.getElementById("group-feedback"), message, "error"); button.disabled = false; }
        return;
      }
      if (action === "delete-quarantine") {
        const item = quarantine[Number(button.dataset.quarantineIndex)]; if (!item) return;
        const accepted = await confirmAction({ eyebrow: "REMOÇÃO DEFINITIVA", title: "Excluir o item da quarentena?", content: `<p><strong>${esc(item.originalFilename || "Arquivo sem nome")}</strong> será removido permanentemente da quarentena.</p>`, confirmLabel: "Excluir permanentemente", danger: true });
        if (!accepted) return;
        button.disabled = true;
        try { await api.delete(`/quarantine/${encodeURIComponent(item.id)}`); ui.toast("Item removido da quarentena.", "success"); await loadQuarantine(); }
        catch (error) { const message = publicError(error, "Não foi possível remover o item da quarentena."); if (message) ui.toast(message, "error"); button.disabled = false; }
      }
    });
    await loadUsers();
    await Promise.all([loadGroups(), loadQuarantine(), loadFolders()]);
  }

  function dashboardMarkup() {
    return `
      <div class="stack page-stack" id="dashboard-view">
        <section class="grid grid-4 metric-grid" aria-label="Indicadores principais">
          <article class="panel metric-card"><span class="metric-label">Total de envios</span><strong class="metric-value" id="metric-uploads">—</strong></article><article class="panel metric-card"><span class="metric-label">Total de downloads</span><strong class="metric-value" id="metric-downloads">—</strong></article>
          <article class="panel metric-card"><span class="metric-label">Usuários ativos hoje</span><strong class="metric-value" id="metric-active-users">—</strong></article><article class="panel metric-card"><span class="metric-label">Armazenamento usado</span><strong class="metric-value" id="metric-storage">—</strong></article>
        </section>
        <div class="grid grid-2 content-grid">
          <section class="panel section-card" aria-labelledby="uploads-title"><div class="section-heading"><div><h2 id="uploads-title">Envios por mês</h2><p>Últimos seis meses.</p></div></div><div id="uploads-by-month" class="stack bar-list" role="list" aria-live="polite"><p class="muted" role="status">Carregando…</p></div></section>
          <section class="panel section-card" aria-labelledby="active-title"><div class="section-heading"><div><h2 id="active-title">Atividade de acesso</h2><p>Contas distintas por dia nos últimos 30 dias.</p></div></div><div id="active-users" class="stack bar-list" role="list" aria-live="polite"><p class="muted" role="status">Carregando…</p></div></section>
          <section class="panel section-card" aria-labelledby="downloads-title"><div class="section-heading"><div><h2 id="downloads-title">Arquivos mais baixados</h2><p>Até dez arquivos.</p></div></div><div id="top-downloads" class="stack rank-list" role="list" aria-live="polite"><p class="muted" role="status">Carregando…</p></div></section>
          <section class="panel section-card" aria-labelledby="types-title"><div class="section-heading"><div><h2 id="types-title">Tipos de arquivo</h2><p>Distribuição dos envios registrados.</p></div></div><div id="file-types" class="stack bar-list" role="list" aria-live="polite"><p class="muted" role="status">Carregando…</p></div></section>
        </div>
        <section class="panel section-card" aria-labelledby="recent-title"><div class="section-heading"><div><h2 id="recent-title">Atividade recente</h2><p>Eventos recentes registrados pelo serviço.</p></div><button type="button" class="button button-quiet" data-action="refresh-dashboard">Atualizar</button></div><ol id="recent-activity" class="stack activity-list" aria-live="polite"><li class="muted" role="status">Carregando…</li></ol></section>
        <p id="dashboard-feedback" class="feedback" aria-live="polite" hidden></p>
      </div>`;
  }
  function renderBars(items, container, labelKey, valueKey, options) {
    const list = asArray(items), opts = options || {};
    if (!list.length) { container.innerHTML = '<p class="empty-state" role="status">Nenhum dado disponível para o período.</p>'; return; }
    const max = Math.max(1, ...list.map((item) => Math.max(0, numeric(item[valueKey]))));
    container.innerHTML = list.map((item) => {
      const label = String(item[labelKey] == null ? "—" : item[labelKey]), value = Math.max(0, numeric(item[valueKey]));
      const extra = opts.extraKey ? `<small class="soft">${esc(ui.formatBytes(item[opts.extraKey]))}</small>` : "";
      return `<div class="pending-row" role="listitem"><div><span>${esc(label)}</span><br /><progress max="${max}" value="${value}" aria-label="${esc(label)}: ${count(value)}"></progress>${extra}</div><strong>${count(value)}</strong></div>`;
    }).join("");
  }
  function eventDescription(event) {
    const username = String(event.username || "Sistema"), filename = String(event.filename || "");
    const descriptions = {
      upload: filename ? `${username} enviou ${filename}` : `${username} enviou um arquivo`,
      download: filename ? `${username} baixou ${filename}` : `${username} baixou um arquivo`,
      delete: filename ? `${username} excluiu ${filename}` : `${username} excluiu um arquivo`,
      login: `${username} iniciou uma sessão`,
      approval: filename ? `${username} aprovou ${filename}` : `${username} aprovou um envio`,
      rejection: filename ? `${username} recusou ${filename}` : `${username} recusou um envio`,
      restore: filename ? `${username} restaurou ${filename}` : `${username} restaurou um item`,
      versionDeletion: filename ? `${username} removeu uma versão de ${filename}` : `${username} removeu uma versão`,
    };
    return descriptions[event.type] || `${username} · ${String(event.type || "Evento")}`;
  }
  async function initDashboard(user, target) {
    const canView = user.role === "admin" || user.permissions && (user.permissions.manageUsers || user.permissions.viewAnalytics);
    if (!canView) { noAccess(target, "A análise exige a permissão viewAnalytics."); return; }
    target.innerHTML = dashboardMarkup();
    const metric = { uploads: document.getElementById("metric-uploads"), downloads: document.getElementById("metric-downloads"), active: document.getElementById("metric-active-users"), storage: document.getElementById("metric-storage") };
    async function loadDashboard() {
      const [summary, months, active, downloads, types, recent] = await Promise.all([
        api.get("/analytics/summary"), api.get("/analytics/uploads-by-month?months=6"), api.get("/analytics/active-users?days=30"),
        api.get("/analytics/downloads-by-file?limit=10"), api.get("/analytics/file-types"), api.get("/analytics/recent?limit=20"),
      ]);
      metric.uploads.textContent = count(summary.totalUploads); metric.downloads.textContent = count(summary.totalDownloads);
      metric.active.textContent = count(summary.activeUsersToday); metric.storage.textContent = ui.formatBytes(summary.storageUsed);
      renderBars(months, document.getElementById("uploads-by-month"), "month", "count", { extraKey: "totalSize" });
      renderBars(active, document.getElementById("active-users"), "date", "uniqueUsers");
      const downloadList = asArray(downloads), maxDownloads = Math.max(1, ...downloadList.map((item) => Math.max(0, numeric(item.downloads))));
      document.getElementById("top-downloads").innerHTML = downloadList.length ? downloadList.map((item, index) => {
        const value = Math.max(0, numeric(item.downloads));
        return `<div class="pending-row" role="listitem"><span class="badge badge-primary" aria-hidden="true">${index + 1}</span><div><span>${esc(item.filename || "Arquivo")}</span><br /><progress max="${maxDownloads}" value="${value}" aria-label="${esc(item.filename || "Arquivo")}: ${count(value)} downloads"></progress></div><strong>${count(value)}</strong></div>`;
      }).join("") : '<p class="empty-state" role="status">Nenhum download registrado.</p>';
      renderBars(asArray(types).slice(0, 8), document.getElementById("file-types"), "extension", "count", { extraKey: "totalSize" });
      const activity = document.getElementById("recent-activity"), events = asArray(recent);
      activity.innerHTML = events.length ? events.map((item) => `<li class="pending-row"><span>${esc(eventDescription(item))}</span><time datetime="${esc(item.timestamp || "")}">${esc(ui.formatDate(item.timestamp))}</time></li>`).join("") : '<li class="empty-inline muted" role="status">Nenhuma atividade registrada.</li>';
      setFeedback(document.getElementById("dashboard-feedback"), "");
    }
    target.addEventListener("click", (event) => {
      const button = event.target.closest('[data-action="refresh-dashboard"]'); if (!button) return;
      button.disabled = true;
      loadDashboard().catch((error) => { const message = publicError(error, "Não foi possível atualizar a análise."); if (message) setFeedback(document.getElementById("dashboard-feedback"), message, "error"); }).finally(() => { button.disabled = false; });
    });
    try { await loadDashboard(); connectRealtime(["analytics", "audit", "history", "pending"], loadDashboard); }
    catch (error) {
      const message = publicError(error, "Não foi possível carregar a análise.");
      if (message) setFeedback(document.getElementById("dashboard-feedback"), message, "error");
      for (const id of ["uploads-by-month", "active-users", "top-downloads", "file-types", "recent-activity"]) {
        const element = document.getElementById(id); if (element) element.innerHTML = `<p class="error-state" role="alert">${esc(message || "Não foi possível carregar os dados.")}</p>`;
      }
    }
  }  function auditMarkup() {
    return `
      <div class="stack page-stack" id="audit-view">
        <form id="audit-filter-form" class="panel section-card">
          <div class="section-heading"><div><h2>Filtros</h2><p>Filtre eventos pelo usuário, tipo, resultado ou período.</p></div></div>
          <div class="form-grid audit-filter-grid">
            <div class="field-row"><label for="audit-username">Usuário</label><input class="field" id="audit-username" name="username" type="text" autocomplete="off" /></div>
            <div class="field-row"><label for="audit-event-type">Evento</label><select class="field" id="audit-event-type" name="eventType"><option value="">Todos os eventos</option><option value="auth.login.success">Login bem-sucedido</option><option value="auth.login.failed">Login falho</option><option value="file.upload">Envio de arquivo</option><option value="file.download">Download</option><option value="file.delete">Exclusão de arquivo</option><option value="file.approve">Aprovação</option><option value="user.permission.changed">Permissão alterada</option><option value="user.deleted">Conta excluída</option><option value="system.anomaly.detected">Anomalia</option></select></div>
            <div class="field-row"><label for="audit-severity">Severidade</label><select class="field" id="audit-severity" name="severity"><option value="">Todas</option><option value="info">Informação</option><option value="warning">Aviso</option><option value="error">Erro</option><option value="critical">Crítica</option></select></div>
            <div class="field-row"><label for="audit-result">Resultado</label><select class="field" id="audit-result" name="result"><option value="">Todos</option><option value="success">Sucesso</option><option value="failure">Falha</option><option value="partial">Parcial</option></select></div>
            <div class="field-row"><label for="audit-start-date">De</label><input class="field" id="audit-start-date" name="startDate" type="date" /></div>
            <div class="field-row"><label for="audit-end-date">Até</label><input class="field" id="audit-end-date" name="endDate" type="date" /></div>
          </div>
          <div class="toolbar"><button class="button button-primary" type="submit">Aplicar filtros</button><button id="audit-export" class="button button-quiet" type="button">Exportar CSV</button><p id="audit-filter-feedback" class="feedback" aria-live="polite" hidden></p></div>
        </form>
        <section class="grid grid-3 metric-grid" aria-label="Resumo da auditoria"><article class="panel metric-card"><span class="metric-label">Total de registros</span><strong class="metric-value" id="audit-total">—</strong></article><article class="panel metric-card"><span class="metric-label">Eventos críticos</span><strong class="metric-value" id="audit-critical">—</strong></article><article class="panel metric-card"><span class="metric-label">Logins falhos</span><strong class="metric-value" id="audit-failed-logins">—</strong></article></section>
        <section class="panel section-card" aria-labelledby="audit-table-title">
          <div class="section-heading"><div><h2 id="audit-table-title">Registros</h2><p id="audit-page-info" aria-live="polite">Carregando…</p></div><button type="button" class="button button-quiet" data-action="refresh-audit">Atualizar</button></div>
          <div class="table-wrap"><table class="data-table audit-table"><thead><tr><th scope="col">Data e hora</th><th scope="col">Evento</th><th scope="col">Severidade</th><th scope="col">Usuário</th><th scope="col">IP</th><th scope="col">Alvo</th><th scope="col">Resultado</th><th scope="col">Detalhes</th></tr></thead><tbody id="audit-body">${tableState(8, "Carregando registros…", "loading")}</tbody></table></div>
          <nav class="toolbar" aria-label="Paginação dos registros de auditoria"><button type="button" class="button button-quiet" data-action="audit-previous" disabled>Anterior</button><button type="button" class="button button-quiet" data-action="audit-next" disabled>Próxima</button></nav>
        </section>
        <dialog id="audit-detail-dialog" class="preview-dialog" aria-labelledby="audit-detail-title"><div class="preview-dialog-heading"><h2 id="audit-detail-title">Detalhes do registro</h2><form method="dialog"><button type="submit" class="button button-quiet">Fechar</button></form></div><div class="preview-dialog-body"><pre id="audit-detail-content" class="preview-text-content"></pre></div></dialog>
      </div>`;
  }
  async function initAudit(user, target) {
    const canView = user.role === "admin" || user.permissions && (user.permissions.manageUsers || user.permissions.viewAuditLogs);
    if (!canView) { noAccess(target, "A auditoria exige a permissão viewAuditLogs."); return; }
    target.innerHTML = auditMarkup();
    let currentPage = 1, totalPages = 1, currentFilters = {}, currentLogs = [];
    const body = document.getElementById("audit-body"), prev = target.querySelector('[data-action="audit-previous"]');
    const next = target.querySelector('[data-action="audit-next"]'), pageInfo = document.getElementById("audit-page-info");
    function updatePagination(page, pages) {
      currentPage = page; totalPages = Math.max(1, pages);
      prev.disabled = currentPage <= 1; next.disabled = currentPage >= totalPages;
      pageInfo.textContent = `Página ${currentPage} de ${totalPages}`;
    }
    function renderLogs(logs) {
      currentLogs = asArray(logs);
      if (!currentLogs.length) { body.innerHTML = tableState(8, "Nenhum registro encontrado com esses filtros.", "empty"); return; }
      const severities = new Set(["info", "warning", "error", "critical"]), results = new Set(["success", "failure", "partial"]);
      body.innerHTML = currentLogs.map((log, index) => {
        const severity = severities.has(log.severity) ? log.severity : "neutral", result = results.has(log.result) ? log.result : "neutral";
        const severityBadge = severity === "critical" || severity === "error" ? "badge-danger" : severity === "warning" ? "badge-warning" : severity === "info" ? "badge-primary" : "";
        const resultBadge = result === "failure" ? "badge-danger" : result === "partial" ? "badge-warning" : result === "success" ? "badge-success" : "";
        const rawIp = log.actor && log.actor.ip;
        const ip = ["::1", "::ffff:127.0.0.1", "127.0.0.1"].includes(rawIp) ? "localhost" : rawIp || "—";
        const targetLabel = log.target ? `${String(log.target.type || "alvo")}: ${String(log.target.id || "—")}` : "—";
        return `<tr><td data-label="Data e hora"><time datetime="${esc(log.timestamp || "")}">${esc(ui.formatDate(log.timestamp))}</time></td><td data-label="Evento">${esc(log.eventType || "—")}</td><td data-label="Severidade"><span class="badge ${severityBadge}">${esc(log.severity || "—")}</span></td><td data-label="Usuário">${esc(log.actor && log.actor.username || "Sistema")}</td><td data-label="IP">${esc(ip)}</td><td data-label="Alvo">${esc(targetLabel)}</td><td data-label="Resultado"><span class="badge ${resultBadge}">${esc(log.result || "—")}</span></td><td data-label="Detalhes"><button type="button" class="button button-quiet button-small" data-action="audit-details" data-log-index="${index}">Ver detalhes</button></td></tr>`;
      }).join("");
    }
    async function loadSummary() {
      try {
        const summary = await api.get("/audit/summary");
        document.getElementById("audit-total").textContent = count(summary.totalLogs);
        document.getElementById("audit-critical").textContent = count(summary.bySeverity && summary.bySeverity.critical);
        document.getElementById("audit-failed-logins").textContent = count(summary.failedLogins);
      } catch (error) { const message = publicError(error, "Não foi possível carregar o resumo da auditoria."); if (message) setFeedback(document.getElementById("audit-filter-feedback"), message, "error"); }
    }
    async function loadLogs() {
      body.innerHTML = tableState(8, "Carregando registros…", "loading");
      try {
        const data = await api.get(api.query("/audit/logs", Object.assign({ page: currentPage, limit: 50 }, currentFilters)));
        const pages = Math.max(1, Math.ceil(numeric(data.total) / Math.max(1, numeric(data.limit) || 50)));
        updatePagination(numeric(data.page) || currentPage, pages); renderLogs(data.logs);
      } catch (error) {
        const message = publicError(error, "Não foi possível carregar os registros de auditoria.");
        body.innerHTML = tableState(8, message || "Não foi possível carregar os registros.", "error"); pageInfo.textContent = "Registros indisponíveis";
      }
    }
    document.getElementById("audit-filter-form").addEventListener("submit", (event) => {
      event.preventDefault();
      const values = new FormData(event.currentTarget), startDate = String(values.get("startDate") || ""), endDate = String(values.get("endDate") || "");
      if (startDate && endDate && startDate > endDate) { setFeedback(document.getElementById("audit-filter-feedback"), "A data inicial deve ser anterior à data final.", "error"); return; }
      currentFilters = Object.fromEntries(["username", "eventType", "severity", "result", "startDate", "endDate"].map((key) => [key, String(values.get(key) || "").trim()]).filter(([, value]) => value));
      currentPage = 1; setFeedback(document.getElementById("audit-filter-feedback"), ""); loadLogs();
    });
    document.getElementById("audit-export").addEventListener("click", async (event) => {
      const button = event.currentTarget; button.disabled = true;
      const feedback = document.getElementById("audit-filter-feedback"); setFeedback(feedback, "Preparando CSV…");
      try { await api.download(api.query("/audit/export", Object.assign({ format: "csv" }, currentFilters)), "rootark-audit.csv", { method: "POST" }); setFeedback(feedback, "Exportação iniciada.", "success"); }
      catch (error) { const message = publicError(error, "Não foi possível exportar os registros."); if (message) setFeedback(feedback, message, "error"); }
      finally { button.disabled = false; }
    });
    target.addEventListener("click", (event) => {
      const button = event.target.closest("button[data-action]"); if (!button) return;
      if (button.dataset.action === "audit-previous" && currentPage > 1) { currentPage -= 1; loadLogs(); }
      else if (button.dataset.action === "audit-next" && currentPage < totalPages) { currentPage += 1; loadLogs(); }
      else if (button.dataset.action === "refresh-audit") {
        button.disabled = true; Promise.all([loadSummary(), loadLogs()]).finally(() => { button.disabled = false; });
      } else if (button.dataset.action === "audit-details") {
        const log = currentLogs[Number(button.dataset.logIndex)]; if (!log) return;
        document.getElementById("audit-detail-content").textContent = JSON.stringify({ actor: log.actor || null, target: log.target || null, action: log.action || "", result: log.result || "", details: log.details || {} }, null, 2);
        document.getElementById("audit-detail-dialog").showModal();
      }
    });
    await Promise.all([loadSummary(), loadLogs()]);
    connectRealtime(["audit", "analytics"], () => Promise.all([loadSummary(), loadLogs()]));
    const summaryTimer = window.setInterval(loadSummary, 30000);
    window.addEventListener("pagehide", () => window.clearInterval(summaryTimer), { once: true });
  }  function backupsMarkup() {
    return `
      <div class="stack page-stack" id="backups-view">
        <section id="backup-warning" class="notice notice-warning" role="status" hidden></section>
        <section id="create-backup-panel" class="panel section-card" aria-labelledby="create-backup-title"><div class="section-heading"><div><h2 id="create-backup-title">Criar backup manual</h2><p>O processo cria um arquivo de backup e registra o resultado.</p></div><button id="create-backup" type="button" class="button button-primary">Criar backup</button></div><p id="backup-feedback" class="feedback" aria-live="polite" hidden></p></section>
        <section class="panel section-card" aria-labelledby="backups-title"><div class="section-heading"><div><h2 id="backups-title">Histórico de backups</h2><p>Consulte manifestos, baixe arquivos ou restaure um backup.</p></div><button type="button" class="button button-quiet" data-action="refresh-backups">Atualizar</button></div><div class="table-wrap"><table class="data-table"><thead><tr><th scope="col">Criado em</th><th scope="col">Tipo</th><th scope="col">Estado</th><th scope="col">Tamanho</th><th scope="col">Ações</th></tr></thead><tbody id="backups-body">${tableState(5, "Carregando backups…", "loading")}</tbody></table></div></section>
        <section id="manifest-panel" class="panel section-card" aria-labelledby="manifest-title" hidden><div class="section-heading"><div><h2 id="manifest-title">Manifesto do backup</h2><p>Metadados retornados pelo serviço para o backup selecionado.</p></div><button type="button" class="button button-quiet" data-action="close-manifest">Fechar</button></div><pre id="manifest-content" class="preview-text-content" role="status"></pre></section>
      </div>`;
  }
  async function initBackups(user, target) {
    const canManage = user.role === "admin" || user.permissions && (user.permissions.manageUsers || user.permissions.manageBackups);
    if (!canManage) { noAccess(target, "Backups exigem a permissão manageBackups."); return; }
    target.innerHTML = backupsMarkup();
    let backups = [];
    let recoveryBlocked = false;
    const body = document.getElementById("backups-body"), warning = document.getElementById("backup-warning");
    const manifestPanel = document.getElementById("manifest-panel"), manifestContent = document.getElementById("manifest-content");
    function blockForRestoreRecovery(message) {
      recoveryBlocked = true;
      warning.textContent = message;
      warning.hidden = false;
      warning.setAttribute("role", "alert");
      target.querySelectorAll("button").forEach((button) => { button.disabled = true; });
    }
    function blockOnRestoreRecovery(error, message) {
      if (error?.status === 503 && (error.payload?.restartRequired || error.payload?.recoveryRequired)) {
        blockForRestoreRecovery(message);
        return true;
      }
      return false;
    }
    function renderBackups() {
      if (!backups.length) { body.innerHTML = tableState(5, "Nenhum backup encontrado.", "empty"); return; }
      const labels = { success: "Concluído", completed: "Concluído", failed: "Falhou", creating: "Criando", running: "Em andamento" };
      body.innerHTML = backups.map((backup, index) => {
        const status = Object.prototype.hasOwnProperty.call(labels, backup.status) ? backup.status : "unknown";
        const badge = status === "success" || status === "completed" ? "badge-success" : status === "failed" ? "badge-danger" : status === "creating" || status === "running" ? "badge-warning" : "";
        const actions = `<div class="row-actions"><button type="button" class="button button-quiet button-small" data-action="download-backup" data-backup-index="${index}">Baixar</button><button type="button" class="button button-quiet button-small" data-action="show-manifest" data-backup-index="${index}">Manifesto</button><button type="button" class="button button-primary button-small" data-action="restore-backup" data-backup-index="${index}">Restaurar</button><button type="button" class="button button-danger button-small" data-action="delete-backup" data-backup-index="${index}">Excluir</button></div>`;
        return `<tr><td><time datetime="${esc(backup.createdAt || "")}">${esc(ui.formatDate(backup.createdAt))}</time></td><td>${esc(backup.type || "—")}</td><td><span class="badge ${badge}">${esc(labels[backup.status] || backup.status || "Desconhecido")}</span></td><td>${esc(ui.formatBytes(backup.sizeBytes))}</td><td>${actions}</td></tr>`;
      }).join("");
    }
    async function loadLatestStatus() {
      try {
        const result = await api.get("/backups/latest-status"), latest = result && result.latest;
        if (latest && latest.status === "failed") {
          warning.textContent = "O backup mais recente falhou. Consulte a auditoria para obter detalhes operacionais.";
          warning.hidden = false;
        } else { warning.textContent = ""; warning.hidden = true; }
      } catch (error) {
        const message = publicError(error, "Não foi possível consultar o resultado do backup mais recente.");
        warning.textContent = message; warning.hidden = !message;
        blockOnRestoreRecovery(error, message);
      }
    }
    async function loadBackups() {
      body.innerHTML = tableState(5, "Carregando backups…", "loading");
      await loadLatestStatus();
      try { backups = asArray((await api.get("/backups")).backups); renderBackups(); }
      catch (error) {
        backups = [];
        const message = publicError(error, "Não foi possível carregar os backups.");
        body.innerHTML = tableState(5, message, "error");
        blockOnRestoreRecovery(error, message);
      }
    }
    document.getElementById("create-backup").addEventListener("click", async (event) => {
      const button = event.currentTarget, feedback = document.getElementById("backup-feedback");
      button.disabled = true; setFeedback(feedback, "Criando backup…");
      try { await api.post("/backups", { notes: "Backup manual via painel" }); setFeedback(feedback, "Backup criado.", "success"); ui.toast("Backup criado.", "success"); await loadBackups(); }
      catch (error) {
        const message = publicError(error, "Não foi possível criar o backup.");
        if (message) setFeedback(feedback, message, "error");
        blockOnRestoreRecovery(error, message);
      }
      finally { button.disabled = recoveryBlocked; }
    });
    target.addEventListener("click", async (event) => {
      const button = event.target.closest("button[data-action]"); if (!button) return;
      const action = button.dataset.action;
      if (action === "refresh-backups") { button.disabled = true; await loadBackups(); button.disabled = recoveryBlocked; return; }
      if (action === "close-manifest") { manifestPanel.hidden = true; manifestContent.textContent = ""; return; }
      const backup = backups[Number(button.dataset.backupIndex)]; if (!backup) return;
      if (action === "download-backup") {
        button.disabled = true;
        try { await api.download(`/backups/${encodeURIComponent(backup.id)}/download`, String(backup.filename || "rootark-backup.zip")); ui.toast("Download iniciado.", "success"); }
        catch (error) {
          const message = publicError(error, "Não foi possível baixar o backup.");
          blockOnRestoreRecovery(error, message);
          if (message) ui.toast(message, "error");
        }
        finally { button.disabled = recoveryBlocked; }
        return;
      }
      if (action === "show-manifest") {
        manifestPanel.hidden = false; manifestContent.textContent = "Carregando manifesto…";
        try { manifestContent.textContent = JSON.stringify(await api.get(`/backups/${encodeURIComponent(backup.id)}/manifest`), null, 2); }
        catch (error) {
          const message = publicError(error, "Não foi possível carregar o manifesto.");
          manifestContent.textContent = message;
          blockOnRestoreRecovery(error, message);
        }
        manifestPanel.scrollIntoView({ block: "nearest" });
        return;
      }
      if (action === "restore-backup") {
        const result = await ui.dialog({
          eyebrow: "RESTAURAÇÃO", title: "Restaurar este backup?",
          content: `<p>Os dados atuais serão substituídos. O serviço cria um backup pré-restauração antes de continuar.</p><div class="field-row"><label for="restore-confirmation">Digite <strong>RESTORE</strong> para confirmar</label><input class="field" id="restore-confirmation" name="confirmation" type="text" pattern="RESTORE" required autocomplete="off" /></div>`,
          confirmLabel: "Restaurar backup", cancelLabel: "Cancelar", danger: true,
        });
        if (!result) return;
        const confirmation = String(result.get("confirmation") || "");
        if (confirmation !== "RESTORE") { ui.toast("Digite RESTORE exatamente para confirmar.", "error"); return; }
        button.disabled = true;
        let restartRequired = false;
        try {
          const restored = await api.post(`/backups/${encodeURIComponent(backup.id)}/restore`, { confirmation });
          restartRequired = Boolean(restored && restored.restartRecommended);
          ui.toast(restartRequired ? "Backup restaurado. Reinicie todas as instâncias do servidor para liberar o acesso." : "Backup restaurado.", "success");
          if (restartRequired) blockForRestoreRecovery("Backup restaurado. Reinicie todas as instâncias do servidor para liberar o acesso.");
          if (!restartRequired) await loadBackups();
        } catch (error) {
          restartRequired = error?.status === 503 && Boolean(error.payload?.restartRequired || error.payload?.recoveryRequired);
          const message = publicError(error, "Não foi possível restaurar o backup.");
          if (restartRequired) blockForRestoreRecovery(message);
          if (message) ui.toast(message, "error");
        }
        finally { button.disabled = restartRequired || recoveryBlocked; }
        return;
      }
      if (action === "delete-backup") {
        const accepted = await confirmAction({ eyebrow: "EXCLUSÃO DE BACKUP", title: "Excluir este backup?", content: `<p>O arquivo <strong>${esc(backup.filename || backup.id)}</strong> será removido permanentemente.</p>`, confirmLabel: "Excluir backup", danger: true });
        if (!accepted) return;
        button.disabled = true;
        try { await api.delete(`/backups/${encodeURIComponent(backup.id)}`); ui.toast("Backup excluído.", "success"); await loadBackups(); }
        catch (error) {
          const message = publicError(error, "Não foi possível excluir o backup.");
          blockOnRestoreRecovery(error, message);
          if (message) ui.toast(message, "error");
          button.disabled = recoveryBlocked;
        }
      }
    });
    await loadBackups();
  }

  const PAGE_CONFIG = {
    admin: { title: "Administração", active: "admin", eyebrow: "ROOT.ARK / GESTÃO", description: "Contas, grupos, quarentena e acessos individuais." },
    dashboard: { title: "Visão geral", active: "analytics", eyebrow: "ROOT.ARK / ANÁLISE", description: "Indicadores de uso e atividade recente." },
    audit: { title: "Auditoria", active: "audit", eyebrow: "ROOT.ARK / SEGURANÇA", description: "Registros de acesso, alterações e eventos de segurança." },
    backups: { title: "Backups", active: "backups", eyebrow: "ROOT.ARK / PROTEÇÃO", description: "Criação, consulta e restauração de backups." },
  };
  async function start() {
    if (!api || !ui || !PAGE_CONFIG[view]) return;
    const root = document.getElementById("app-root"), config = PAGE_CONFIG[view];
    root.innerHTML = '<p class="loading-state" role="status">Carregando sessão…</p>';
    let user;
    try { user = await ui.getSession(); }
    catch (error) {
      if (error && error.status === 401) { ui.redirectToLogin(); return; }
      if (error?.status === 503 && (error.payload?.restartRequired || error.payload?.recoveryRequired)) {
        root.innerHTML = `<main class="standalone-state" role="alert"><h1>Servidor em recuperação</h1><p>${esc(publicError(error, "O servidor está bloqueado para recuperação do backup."))}</p></main>`;
        return;
      }
      root.innerHTML = `<main class="standalone-state" role="alert"><h1>Não foi possível abrir esta página</h1><p>${esc(publicError(error, "A sessão não pôde ser validada. Tente novamente."))}</p><a class="button button-primary" href="/login.html">Ir para entrar</a></main>`;
      return;
    }
    const target = mount(user, Object.assign({}, config, { content: '<p class="loading-state" role="status">Carregando…</p>' }));
    if (!target) return;
    if (view === "admin") return initAdmin(user, target);
    if (view === "dashboard") return initDashboard(user, target);
    if (view === "audit") return initAudit(user, target);
    if (view === "backups") return initBackups(user, target);
  }
  start().catch((error) => {
    const target = pageContent(), message = publicError(error, "Não foi possível abrir esta página.");
    if (target && message) target.innerHTML = `<section class="panel error-state" role="alert">${esc(message)}</section>`;
  });
})();
