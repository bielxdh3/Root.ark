(function () {
  "use strict";

  const api = window.RootarkApi;
  const ui = window.RootarkUI;
  const root = document.getElementById("app-root");
  const state = {
    user: null,
    folders: [],
    folderId: null,
    files: [],
    pending: [],
    history: [],
    trash: [],
    canManageTrash: false,
    search: {},
    versions: null,
    loading: false,
    error: "",
    route: "files",
  };
  let realtimeSocket = null;
  let realtimeReconnectTimer = null;
  let realtimeRefreshTimer = null;
  let realtimeRefreshPending = false;
  let realtimeClosed = false;
  let uploadInProgress = false;
  let versionsRequestPending = false;
  const dirtyForms = new WeakSet();
  const CHUNK_BYTES = 8 * 1024 * 1024;
  const CHUNK_THRESHOLD = 5 * 1024 * 1024;
  const MAX_BATCH_FILES = 10;

  function esc(value) { return ui.escape(value); }
  function routeFromHash() {
    const hash = window.location.hash.replace(/^#\/?/, "");
    return hash === "history" || hash === "trash" ? hash : "files";
  }
  function currentFolder() { return state.folders.find((folder) => folder.id === state.folderId); }
  function fileFolderId(file) { return file && file.folderId || state.folderId; }
  function hasPermission(name) { return Boolean(state.user && state.user.permissions && state.user.permissions[name]); }
  function isAdmin() { return Boolean(state.user && ["admin", "superadmin"].includes(state.user.role)); }
  function canManageAccess() { return isAdmin() || hasPermission("manageUsers"); }
  function hasSearchInput(values) {
    const search = values || {};
    return ["q", "extension", "minSizeKb", "maxSizeKb", "startDate", "endDate", "owner", "isShared", "isEncrypted"].some((key) => search[key] !== undefined && search[key] !== null && search[key] !== "") ||
      search.scope === "all" || search.sortBy && search.sortBy !== "name" || search.sortOrder && search.sortOrder !== "asc";
  }
  function temporaryPayload(selection, amount) {
    if (selection === "keep") return null;
    if (!selection || selection === "none") return { temporary: false, expiresAt: null };
    const presets = { "1h": 3600000, "6h": 21600000, "12h": 43200000, "1d": 86400000, "3d": 259200000, "7d": 604800000, "30d": 2592000000 };
    if (presets[selection]) return { temporary: true, expiresAt: new Date(Date.now() + presets[selection]).toISOString() };
    const unit = selection === "custom-days" ? "days" : "hours";
    const durationAmount = Number(amount);
    if (!Number.isInteger(durationAmount) || durationAmount <= 0) return undefined;
    return { temporary: true, durationAmount, durationUnit: unit };
  }
  function actionButton(action, label, attrs, className) {
    const extra = attrs || {};
    const encoded = Object.keys(extra).map((key) => " data-" + key + '="' + esc(extra[key]) + '"').join("");
    return '<button type="button" class="button ' + esc(className || "button-quiet") + '" data-action="' + esc(action) + '"' + encoded + '>' + esc(label) + "</button>";
  }
  function date(value) { return ui.formatDate(value); }
  function ownerOf(file) { return file.owner || file.uploadedBy || file.createdBy || "—"; }
  function isEncrypted(file) { return Boolean(file && (file.isEncrypted || file.encrypted || file.encryption && file.encryption.isEncrypted)); }
  function captureDirtyFormControls() {
    const occurrences = new Map();
    return Array.from(root.querySelectorAll("input, select, textarea")).flatMap((control) => {
      if (!control.form || !dirtyForms.has(control.form)) return [];
      const baseKey = [control.form.id || "", control.id || "", control.name || "", control.tagName, control.type || ""].join("\0");
      const occurrence = occurrences.get(baseKey) || 0;
      occurrences.set(baseKey, occurrence + 1);
      return [{
        baseKey,
        occurrence,
        value: control.type === "file" ? undefined : control.value,
        checked: typeof control.checked === "boolean" ? control.checked : undefined,
        selectedValues: control.tagName === "SELECT" && control.multiple ? Array.from(control.selectedOptions, (option) => option.value) : undefined,
        fileNode: control.type === "file" && control.files && control.files.length ? control : null,
      }];
    });
  }
  function restoreDirtyFormControls(snapshots) {
    if (!snapshots.length) return;
    const occurrences = new Map();
    const controls = Array.from(root.querySelectorAll("input, select, textarea"));
    for (const control of controls) {
      const baseKey = [control.form && control.form.id || "", control.id || "", control.name || "", control.tagName, control.type || ""].join("\0");
      const occurrence = occurrences.get(baseKey) || 0;
      occurrences.set(baseKey, occurrence + 1);
      const snapshot = snapshots.find((item) => item.baseKey === baseKey && item.occurrence === occurrence);
      if (!snapshot) continue;
      let restored = control;
      if (snapshot.fileNode && snapshot.fileNode !== control) {
        control.replaceWith(snapshot.fileNode);
        restored = snapshot.fileNode;
      } else if (snapshot.value !== undefined) {
        restored.value = snapshot.value;
      }
      if (snapshot.checked !== undefined) restored.checked = snapshot.checked;
      if (snapshot.selectedValues) {
        for (const option of Array.from(restored.options || [])) option.selected = snapshot.selectedValues.includes(option.value);
      }
      if (restored.form) dirtyForms.add(restored.form);
    }
  }
  function historyActionLabel(action) {
    const labels = {
      upload_pending: "Enviou para aprovação", approved: "Aprovou arquivo", rejected: "Rejeitou arquivo", deleted: "Moveu arquivo para a lixeira",
      renamed: "Renomeou arquivo", moved: "Moveu arquivo", share_created: "Gerou link público", file_access_updated: "Atualizou permissões do arquivo",
      file_temporary_updated: "Atualizou expiração do arquivo", file_expired: "Arquivo temporário expirou", folder_created: "Criou pasta",
      folder_renamed: "Renomeou pasta", folder_access_updated: "Atualizou acessos da pasta", folder_temporary_updated: "Atualizou expiração da pasta",
      folder_expired: "Pasta temporária expirou", folder_deleted: "Moveu pasta para a lixeira", version_restored: "Restaurou versão", version_deleted: "Excluiu versão",
    };
    return labels[action] || "Atualizou arquivo";
  }
  function historyFileLabel(entry) {
    const details = entry.details || {};
    if (entry.action === "renamed" && details.oldName && details.newName) return details.oldName + " → " + details.newName;
    if (entry.action === "moved" && details.fromFolderName && details.toFolderName) return (entry.fileName || "Arquivo") + " (" + details.fromFolderName + " → " + details.toFolderName + ")";
    return entry.fileName || "Arquivo";
  }
  function permissionError(error) { return error && error.status === 401; }
  function reportError(error) {
    if (permissionError(error)) {
      ui.redirectToLogin();
      return;
    }
    state.error = error && error.message ? error.message : "Não foi possível carregar os dados.";
    ui.toast(state.error, "error");
    render();
  }

  function toolbar() {
    if (state.route !== "files") return "";
    const buttons = [];
    if (hasPermission("createFolders") || canManageAccess()) buttons.push(actionButton("create-folder", "Nova pasta", {}, "button-quiet"));
    if (hasPermission("upload")) buttons.push('<button type="button" class="button button-primary" data-action="focus-upload">Enviar arquivos</button>');
    return buttons.join("");
  }

  function folderActions(folder) {
    if (!folder || !folder.canEdit) return "";
    let actions = actionButton("rename-folder", "Renomear", { id: folder.id }, "button-quiet") +
      actionButton("folder-access", "Acesso", { id: folder.id }, "button-quiet") +
      actionButton("folder-expiration", "Expiração", { id: folder.id }, "button-quiet");
    if (hasPermission("delete") || canManageAccess()) actions += actionButton("delete-folder", "Mover para lixeira", { id: folder.id, name: folder.name }, "button-quiet");
    return actions;
  }

  function folderControls() {
    const options = state.folders.map((folder) => '<option value="' + esc(folder.id) + '"' + (folder.id === state.folderId ? " selected" : "") + '>' + esc(folder.name || (folder.isRoot ? "Meu espaço" : "Pasta")) + "</option>").join("");
    const selected = currentFolder();
    const selectedActions = selected && !selected.isRoot && selected.id !== "root"
      ? folderActions(selected)
      : "";
    return '<div class="workspace-controls"><label class="field-row"><span>Pasta atual</span><select class="field" id="folder-select">' + options + '</select></label><div class="workspace-folder-actions">' + selectedActions + "</div></div>";
  }

  function searchForm() {
    const values = state.search || {};
    return '<form class="workspace-search panel" id="search-form">' +
      '<label class="field-row search-name"><span>Buscar arquivos</span><input class="field" name="q" type="search" maxlength="120" placeholder="Nome do arquivo" value="' + esc(values.q || "") + '"></label>' +
      '<label class="field-row"><span>Extensão</span><input class="field" name="extension" maxlength="20" placeholder=".pdf" value="' + esc(values.extension || "") + '"></label>' +
      '<label class="field-row"><span>Ordenar</span><select class="field" name="sortBy"><option value="name"' + (values.sortBy !== "size" && values.sortBy !== "date" ? " selected" : "") + '>Nome</option><option value="date"' + (values.sortBy === "date" ? " selected" : '') + '>Data</option><option value="size"' + (values.sortBy === "size" ? " selected" : '') + '>Tamanho</option></select></label>' +
      '<label class="field-row"><span>Ordem</span><select class="field" name="sortOrder"><option value="asc"' + (values.sortOrder !== "desc" ? " selected" : '') + '>Crescente</option><option value="desc"' + (values.sortOrder === "desc" ? " selected" : '') + '>Decrescente</option></select></label>' +
      '<button class="button button-primary search-submit" type="submit">Buscar</button>' +
      (hasSearchInput(values) ? '<button class="button button-quiet search-clear" type="button" data-action="clear-search">Limpar</button>' : "") +
      '<details class="search-advanced"><summary>Filtros avançados</summary><div class="search-advanced-grid">' +
      '<label class="field-row"><span>Escopo</span><select class="field" name="scope"><option value="current"' + (values.scope !== "all" ? " selected" : "") + '>Pasta atual</option><option value="all"' + (values.scope === "all" ? " selected" : "") + '>Todas as pastas</option></select></label>' +
      '<label class="field-row"><span>Tamanho mínimo (KB)</span><input class="field" name="minSizeKb" type="number" min="0" step="1" value="' + esc(values.minSizeKb || "") + '"></label>' +
      '<label class="field-row"><span>Tamanho máximo (KB)</span><input class="field" name="maxSizeKb" type="number" min="0" step="1" value="' + esc(values.maxSizeKb || "") + '"></label>' +
      '<label class="field-row"><span>Data inicial</span><input class="field" name="startDate" type="date" value="' + esc(values.startDate || "") + '"></label>' +
      '<label class="field-row"><span>Data final</span><input class="field" name="endDate" type="date" value="' + esc(values.endDate || "") + '"></label>' +
      '<label class="field-row"><span>Responsável</span><input class="field" name="owner" maxlength="80" value="' + esc(values.owner || "") + '"></label>' +
      '<label class="field-row"><span>Compartilhamento</span><select class="field" name="isShared"><option value="">Todos</option><option value="true"' + (values.isShared === "true" ? " selected" : "") + '>Compartilhados</option><option value="false"' + (values.isShared === "false" ? " selected" : "") + '>Não compartilhados</option></select></label>' +
      '<label class="field-row"><span>Criptografia</span><select class="field" name="isEncrypted"><option value="">Todas</option><option value="true"' + (values.isEncrypted === "true" ? " selected" : "") + '>Criptografados</option><option value="false"' + (values.isEncrypted === "false" ? " selected" : "") + '>Sem criptografia</option></select></label>' +
      '</div></details>' +
      "</form>";
  }

  function renderUpload() {
    if (!hasPermission("upload")) return "";
    return '<section class="panel upload-panel" id="upload-panel"><div class="panel-heading"><div><p class="eyebrow">NOVO ENVIO</p><h2>Adicionar arquivos</h2></div><p class="muted">Os arquivos enviados aguardam aprovação antes de aparecer na pasta.</p></div>' +
      '<form id="upload-form" class="upload-form"><label class="field-row upload-dropzone" id="upload-dropzone"><span>Arquivos (até ' + MAX_BATCH_FILES + ' por envio)</span><span class="muted">Arraste arquivos para esta área ou escolha no dispositivo.</span><input class="field" type="file" name="files" id="upload-files" multiple required></label>' +
      '<label class="field-row"><span>Comentário da versão (opcional)</span><input class="field" name="versionComment" maxlength="200" placeholder="Descreva o envio"></label>' +
      '<div class="upload-security"><label class="field-row"><span>Criptografia</span><select class="field" name="encryptionLevel"><option value="none">Sem criptografia</option><option value="server-key">Chave do servidor</option><option value="user-key">Chave da conta</option><option value="password">Senha do arquivo</option><option value="dual">Chave e senha</option></select></label>' +
      '<label class="field-row" id="upload-password-row" hidden><span>Senha (mínimo de 8 caracteres)</span><input class="field" name="password" type="password" autocomplete="new-password" minlength="8"></label>' +
      '<label class="field-row"><span>Expiração do arquivo protegido</span><select class="field" name="expiresInDays" disabled><option value="">Não expira</option><option value="1">1 dia</option><option value="7">7 dias</option><option value="30">30 dias</option><option value="90">90 dias</option></select></label></div>' +
      '<div class="upload-progress" id="upload-progress" role="status" hidden></div><button class="button button-primary" type="submit">Enviar para aprovação</button></form></section>';
  }

  function folderCards() {
    const folders = state.folders.filter((folder) => !folder.isRoot && folder.id !== state.folderId);
    if (!folders.length) return "";
    return '<section class="panel"><div class="panel-heading"><div><p class="eyebrow">PASTAS</p><h2>Suas pastas</h2></div></div><div class="folder-card-grid">' + folders.map((folder) => {
      const actions = folderActions(folder);
      return '<article class="folder-card"><button type="button" class="folder-card-main" data-action="select-folder" data-id="' + esc(folder.id) + '"><span class="folder-glyph" aria-hidden="true">▱</span><span><strong>' + esc(folder.name) + '</strong><small>' + (folder.expiresAt ? 'Expira em ' + esc(date(folder.expiresAt)) : 'Pasta compartilhada') + '</small></span></button>' + (actions ? '<div class="folder-card-actions">' + actions + "</div>" : "") + "</article>";
    }).join("") + "</div></section>";
  }

  function fileActions(file) {
    const name = file.name;
    const folder = fileFolderId(file);
    const attrs = { name, folder };
    let actions = (isEncrypted(file) ? "" : actionButton("preview-file", "Pré-visualizar", attrs, "button-quiet")) +
      actionButton("download-file", isEncrypted(file) ? "Descriptografar e baixar" : "Baixar", attrs, "button-quiet") +
      actionButton("file-versions", "Versões", attrs, "button-quiet");
    if (!isEncrypted(file)) actions += actionButton("share-file", "Compartilhar", attrs, "button-quiet");
    if (file.canManageAccess || ownerOf(file) === state.user.username) actions += actionButton("file-access", "Permissões", attrs, "button-quiet");
    if (file.canEdit) {
      actions += actionButton("file-expiration", "Expiração", attrs, "button-quiet") +
        actionButton("rename-file", "Renomear", attrs, "button-quiet") +
        actionButton("move-file", "Mover", attrs, "button-quiet");
      if (hasPermission("delete") || canManageAccess()) actions += actionButton("delete-file", "Mover para lixeira", attrs, "button-quiet");
    }
    return actions;
  }

  function filesTable() {
    if (state.loading) return '<div class="loading-state" role="status">Carregando arquivos…</div>';
    if (state.error) return '<div class="feedback feedback-error" role="alert">' + esc(state.error) + '</div><button type="button" class="button button-quiet" data-action="retry">Tentar novamente</button>';
    if (!state.files.length) return '<div class="empty-state"><span class="empty-state-mark" aria-hidden="true">▱</span><h2>' + (hasSearchInput(state.search) ? 'Nenhum arquivo corresponde aos filtros' : 'Nenhum arquivo nesta pasta') + '</h2><p>Arquivos aprovados aparecerão aqui. Você pode enviar um arquivo para aprovação ou criar uma pasta.</p></div>';
    const rows = state.files.map((file) => '<tr><td data-label="Nome"><div class="file-cell"><span class="file-type-mark" aria-hidden="true">' + esc((String(file.name || "").split(".").pop() || "ARQ").slice(0, 4).toUpperCase()) + '</span><span><strong>' + esc(file.name) + '</strong><small>' + (isEncrypted(file) ? 'Criptografado' : esc(file.type || file.mimeType || "Arquivo")) + '</small>' + (state.search.scope === "all" ? '<small>Em ' + esc(file.folderName || "Pasta") + '</small>' : "") + '</span></div></td>' +
      '<td data-label="Tamanho">' + esc(ui.formatBytes(file.size)) + '</td><td data-label="Responsável">' + esc(ownerOf(file)) + '</td><td data-label="Atualizado">' + esc(date(file.modifiedAt || file.uploadedAt || file.createdAt)) + '</td><td data-label="Ações"><div class="row-actions">' + fileActions(file) + '</div></td></tr>').join("");
    return '<div class="table-wrap"><table class="data-table"><thead><tr><th>Nome</th><th>Tamanho</th><th>Responsável</th><th>Atualizado</th><th><span class="visually-hidden">Ações</span></th></tr></thead><tbody>' + rows + '</tbody></table></div>';
  }

  function pendingSection() {
    if (!hasPermission("listPending") && !hasPermission("upload")) return "";
    const cards = state.pending.map((file) => {
      const recoveryRequired = file.restoreOrphan === true && file.availability === "recovery_required";
      return '<article class="pending-row"><div class="file-cell"><span class="file-type-mark" aria-hidden="true">↑</span><span><strong>' + esc(file.name) + '</strong>' +
        (recoveryRequired ? '<span class="badge badge-warning">Recuperação necessária</span>' : "") +
        '<small>' + esc(ownerOf(file)) + ' · ' + esc(ui.formatBytes(file.size)) + '</small>' +
        (recoveryRequired ? '<small class="pending-recovery-note">Arquivo original indisponível. Solicite um novo envio.</small>' : "") +
        '</span></div><div class="row-actions">' +
        (!recoveryRequired && !isEncrypted(file) ? actionButton("preview-pending", "Pré-visualizar", { name: file.name, folder: fileFolderId(file) }, "button-quiet") : "") +
        (hasPermission("approve") ? (recoveryRequired ? '<button type="button" class="button button-primary button-small" disabled>Aprovação indisponível</button>' : actionButton("approve-file", "Aprovar", { name: file.name, folder: fileFolderId(file) }, "button-primary")) + actionButton("reject-file", "Rejeitar", { name: file.name, folder: fileFolderId(file) }, "button-quiet") : "") +
        "</div></article>";
    }).join("");
    return '<section class="panel"><div class="panel-heading"><div><p class="eyebrow">REVISÃO</p><h2>Aguardando aprovação</h2></div><span class="count-pill">' + state.pending.length + '</span></div>' + (cards || '<p class="empty-inline">Nenhum envio aguardando aprovação.</p>') + '</section>';
  }

  function versionsPanel() {
    const data = state.versions;
    if (!data) return "";
    const rows = (data.versions || []).map((version) => '<tr><td data-label="Versão">v' + esc(version.version) + (version.version === data.currentVersion ? ' <span class="status-pill">Atual</span>' : "") + '</td><td data-label="Tamanho">' + esc(ui.formatBytes(version.size)) + '</td><td data-label="Enviado por">' + esc(version.uploadedBy || "—") + '</td><td data-label="Data">' + esc(date(version.uploadedAt)) + '</td><td data-label="Comentário">' + esc(version.comment || "—") + '</td><td data-label="Ações"><div class="row-actions">' +
      actionButton("download-version", "Baixar", { name: data.fileName, version: version.version, folder: data.folderId }, "button-quiet") +
      (data.canRestore && version.version !== data.currentVersion ? actionButton("restore-version", "Restaurar", { name: data.fileName, version: version.version, folder: data.folderId }, "button-quiet") : "") +
      (data.canDeleteVersions && version.version !== data.currentVersion ? actionButton("delete-version", "Excluir", { name: data.fileName, version: version.version, folder: data.folderId }, "button-quiet") : "") + "</div></td></tr>").join("");
    const actionRows = (data.actionHistory || []).map((entry) => '<tr><td data-label="Ação">' + esc(historyActionLabel(entry.action)) + '</td><td data-label="Responsável">' + esc(entry.actor || "sistema") + '</td><td data-label="Data">' + esc(date(entry.timestamp)) + '</td><td data-label="Arquivo">' + esc(historyFileLabel(entry)) + '</td><td data-label="Pasta">' + esc(entry.details && entry.details.folderName || "—") + '</td></tr>').join("");
    return '<section class="panel versions-panel"><div class="panel-heading"><div><p class="eyebrow">HISTÓRICO DE ARQUIVO</p><h2 tabindex="-1">' + esc(data.fileName) + '</h2></div>' + actionButton("close-versions", "Fechar", {}, "button-quiet") + '</div><div class="table-wrap"><table class="data-table"><thead><tr><th>Versão</th><th>Tamanho</th><th>Enviado por</th><th>Data</th><th>Comentário</th><th>Ações</th></tr></thead><tbody>' + (rows || '<tr><td colspan="6">Nenhuma versão disponível.</td></tr>') + '</tbody></table></div><h3>Histórico do arquivo</h3><div class="table-wrap"><table class="data-table"><thead><tr><th>Ação</th><th>Responsável</th><th>Data</th><th>Arquivo</th><th>Pasta</th></tr></thead><tbody>' + (actionRows || '<tr><td colspan="5">Nenhuma ação registrada.</td></tr>') + '</tbody></table></div></section>';
  }

  function protectedPanel() {
    return '<section class="panel protected-client-panel"><div class="panel-heading"><div><p class="eyebrow">ACESSO LOCAL</p><h2>Busca protegida</h2><p class="muted">A busca local usa apenas um índice criptografado já desbloqueado neste dispositivo.</p></div></div><p id="protectedClientStatus" class="muted" role="status">Verificando disponibilidade offline…</p><div class="protected-search-row"><label class="field-row"><span>Termo local</span><input class="field" id="protectedSearchInput" type="search" autocomplete="off"></label><button class="button button-quiet" id="protectedSearchButton" type="button">Buscar local</button></div><p id="protectedSearchResult" class="muted" role="status">Nenhum dado protegido foi carregado nesta sessão.</p></section>';
  }

  function filesPage() {
    const heading = state.search.scope === "all" ? "Resultados em todas as pastas" : (currentFolder() && currentFolder().name) || "Arquivos";
    return folderControls() + searchForm() + protectedPanel() + renderUpload() + folderCards() + pendingSection() +
      '<section class="panel"><div class="panel-heading"><div><p class="eyebrow">ARQUIVOS APROVADOS</p><h2>' + esc(heading) + '</h2></div><span class="count-pill">' + state.files.length + '</span></div>' + filesTable() + '</section>' + versionsPanel();
  }

  function historyPage() {
    const rows = state.history.map((item) => '<tr><td data-label="Ação">' + esc(historyActionLabel(item.action || item.type)) + '</td><td data-label="Arquivo">' + esc(item.fileName || item.filename || item.name || "—") + '</td><td data-label="Responsável">' + esc(item.actor || item.username || item.user || item.performedBy || "—") + '</td><td data-label="Data">' + esc(date(item.timestamp || item.createdAt || item.at)) + '</td></tr>').join("");
    return '<section class="panel"><div class="panel-heading"><div><p class="eyebrow">ATIVIDADE RECENTE</p><h2>Histórico</h2></div></div>' +
      (state.loading ? '<div class="loading-state" role="status">Carregando histórico…</div>' : state.error ? '<div class="feedback feedback-error" role="alert">' + esc(state.error) + '</div><button type="button" class="button button-quiet" data-action="retry">Tentar novamente</button>' : rows ? '<div class="table-wrap"><table class="data-table"><thead><tr><th>Ação</th><th>Arquivo</th><th>Responsável</th><th>Data</th></tr></thead><tbody>' + rows + '</tbody></table></div>' : '<div class="empty-state"><h2>Sem atividade recente</h2><p>As ações realizadas no seu espaço aparecerão aqui.</p></div>') + '</section>';
  }

  function trashPage() {
    const rows = state.trash.map((item) => {
      const name = item.originalFileName || item.originalFolderName || item.name || "Item";
      const type = item.itemType === "folder" ? "Pasta" : "Arquivo";
      return '<tr><td data-label="Nome">' + esc(name) + '<small class="table-secondary">Origem: ' + esc(item.originalFolderName || "Arquivos atuais") + '</small></td><td data-label="Tipo">' + type + '</td><td data-label="Tamanho">' + esc(ui.formatBytes(item.sizeBytes || item.size)) + '</td><td data-label="Removido por">' + esc(item.deletedBy || "—") + '</td><td data-label="Data">' + esc(date(item.deletedAt || item.trashedAt)) + '</td><td data-label="Ações"><div class="row-actions">' +
        actionButton("restore-trash", "Restaurar", { id: item.id }, "button-quiet") +
        (state.canManageTrash ? actionButton("delete-trash", "Excluir permanentemente", { id: item.id, name }, "button-quiet") : "") + '</div></td></tr>';
    }).join("");
    const emptyButton = state.canManageTrash && state.trash.length ? actionButton("empty-trash", "Esvaziar lixeira", {}, "button-danger") : "";
    return '<section class="panel"><div class="panel-heading"><div><p class="eyebrow">ITENS REMOVIDOS</p><h2>Lixeira</h2><p class="muted">Os itens podem ser restaurados enquanto estiverem na lixeira.</p></div>' + emptyButton + '</div>' +
      (state.loading ? '<div class="loading-state" role="status">Carregando lixeira…</div>' : state.error ? '<div class="feedback feedback-error" role="alert">' + esc(state.error) + '</div><button type="button" class="button button-quiet" data-action="retry">Tentar novamente</button>' : rows ? '<div class="table-wrap"><table class="data-table"><thead><tr><th>Nome</th><th>Tipo</th><th>Tamanho</th><th>Removido por</th><th>Data</th><th>Ações</th></tr></thead><tbody>' + rows + '</tbody></table></div>' : '<div class="empty-state"><h2>A lixeira está vazia</h2><p>Itens removidos aparecerão aqui.</p></div>') + '</section>';
  }

  function render() {
    if (!state.user) return;
    const titles = { files: ["Arquivos", "Organize e encontre os arquivos do seu espaço."], history: ["Histórico", "Acompanhe as atividades recentes do seu espaço."], trash: ["Lixeira", "Restaure itens removidos ou gerencie a lixeira."] };
    const title = titles[state.route] || titles.files;
    const content = state.route === "history" ? historyPage() : state.route === "trash" ? trashPage() : filesPage();
    ui.mount({ user: state.user, title: title[0], description: title[1], active: state.route === "files" ? "files" : state.route, toolbar: toolbar(), content });
    window.dispatchEvent(new Event("rootark:workspace-rendered"));
  }

  async function loadFolders() {
    state.folders = await api.get("/folders");
    if (!state.folderId || !state.folders.some((folder) => folder.id === state.folderId)) {
      const defaultFolder = state.folders.find((folder) => folder.isRoot) || state.folders.find((folder) => folder.id === "root") || state.folders[0];
      state.folderId = defaultFolder ? defaultFolder.id : null;
    }
  }

  async function loadFiles() {
    if (!state.folderId) { state.files = []; return; }
    state.loading = true;
    state.error = "";
    render();
    try {
      const values = state.search || {};
      const filters = { folderId: values.scope === "all" ? "all" : state.folderId };
      ["q", "extension", "startDate", "endDate", "owner", "isShared", "isEncrypted"].forEach((key) => {
        if (values[key] !== undefined && values[key] !== null && values[key] !== "") filters[key] = values[key];
      });
      ["minSizeKb", "maxSizeKb"].forEach((key) => {
        if (values[key] !== undefined && values[key] !== null && values[key] !== "") {
          const value = Number(values[key]);
          if (Number.isFinite(value) && value >= 0) filters[key === "minSizeKb" ? "minSize" : "maxSize"] = Math.round(value * 1024);
        }
      });
      if (values.sortBy && values.sortBy !== "name") filters.sortBy = values.sortBy;
      if (values.sortOrder && values.sortOrder !== "asc") filters.sortOrder = values.sortOrder;
      const hasFilters = hasSearchInput(values);
      const result = hasFilters ? await api.get(api.query("/files/search", filters)) : await api.get(api.query("/list", filters));
      state.files = Array.isArray(result) ? result : [];
      if (hasPermission("listPending") || hasPermission("upload")) {
        try {
          await api.post(api.query("/pending/repair", { folderId: state.folderId }), {});
          const pending = await api.get(api.query("/pending", { folderId: state.folderId }));
          state.pending = Array.isArray(pending) ? pending : [];
        } catch (error) {
          if (error.status === 401) throw error;
          state.pending = [];
        }
      } else state.pending = [];
      state.versions = null;
    } catch (error) {
      if (permissionError(error)) return ui.redirectToLogin();
      state.error = error.message || "Não foi possível carregar os arquivos.";
      state.files = [];
      state.pending = [];
    } finally {
      state.loading = false;
      render();
    }
  }

  async function loadRoute() {
    state.route = routeFromHash();
    state.error = "";
    if (state.route === "files") return loadFiles();
    state.loading = true;
    render();
    try {
      if (state.route === "history") {
        const payload = await api.get("/history");
        state.history = Array.isArray(payload) ? payload : Array.isArray(payload.items) ? payload.items : [];
      } else {
        const payload = await api.get("/trash");
        state.trash = Array.isArray(payload) ? payload : Array.isArray(payload.items) ? payload.items : [];
        state.canManageTrash = Boolean(payload && payload.canManageTrash);
      }
    } catch (error) {
      state.error = error.message || "Não foi possível carregar esta página.";
      if (permissionError(error)) return ui.redirectToLogin();
    } finally {
      state.loading = false;
      render();
    }
  }

  function hasActiveWorkspaceInteraction() {
    if (state.loading || document.querySelector("dialog[open]")) return true;
    const activeElement = document.activeElement;
    if (activeElement && (activeElement.matches("input, select, textarea") || activeElement.isContentEditable)) return true;
    return Array.from(document.forms).some((form) => dirtyForms.has(form));
  }

  function flushRealtimeRefresh() {
    if (realtimeClosed || !realtimeRefreshPending) return;
    if (hasActiveWorkspaceInteraction()) {
      realtimeRefreshTimer = window.setTimeout(flushRealtimeRefresh, 300);
      return;
    }
    realtimeRefreshPending = false;
    realtimeRefreshTimer = null;
    (async () => {
      try {
        await loadFolders();
        await loadRoute();
      } catch (_) {}
    })();
  }

  function scheduleRealtimeRefresh() {
    realtimeRefreshPending = true;
    window.clearTimeout(realtimeRefreshTimer);
    realtimeRefreshTimer = window.setTimeout(flushRealtimeRefresh, 150);
  }

  function schedulePendingRefresh() {
    if (realtimeRefreshPending) scheduleRealtimeRefresh();
  }

  document.addEventListener("input", (event) => {
    if (event.target && event.target.form) dirtyForms.add(event.target.form);
  }, true);
  document.addEventListener("change", (event) => {
    if (event.target && event.target.form) dirtyForms.add(event.target.form);
  }, true);
  document.addEventListener("focusout", schedulePendingRefresh, true);
  document.addEventListener("close", schedulePendingRefresh, true);
  document.addEventListener("reset", (event) => {
    const form = event.target;
    if (!form || form.tagName !== "FORM") return;
    window.setTimeout(() => {
      dirtyForms.delete(form);
      schedulePendingRefresh();
    }, 0);
  }, true);
  window.addEventListener("rootark:workspace-rendered", schedulePendingRefresh);

  function connectRealtime() {
    if (!window.WebSocket || realtimeClosed) return;
    const connect = () => {
      if (realtimeClosed) return;
      try {
        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        realtimeSocket = new WebSocket(protocol + "//" + window.location.host + "/ws");
      } catch (_) {
        realtimeReconnectTimer = window.setTimeout(connect, 3000);
        return;
      }
      realtimeSocket.addEventListener("message", (event) => {
        let message;
        try { message = JSON.parse(event.data); } catch (_) { return; }
        if (message.event === "data:changed") scheduleRealtimeRefresh();
      });
      realtimeSocket.addEventListener("close", () => {
        if (!realtimeClosed) realtimeReconnectTimer = window.setTimeout(connect, 3000);
      });
    };
    connect();
  }

  function stopRealtime() {
    realtimeClosed = true;
    window.clearTimeout(realtimeReconnectTimer);
    window.clearTimeout(realtimeRefreshTimer);
    if (realtimeSocket) realtimeSocket.close();
  }

  window.addEventListener("pagehide", stopRealtime, { once: true });

  async function dialogConfirm(options) {
    return ui.dialog(options);
  }

  async function chooseExpiration(title, currentExpiresAt, defaultSelection) {
    const options = [
      ["none", "Não temporário"], ["1h", "1 hora"], ["6h", "6 horas"], ["12h", "12 horas"],
      ["1d", "1 dia"], ["3d", "3 dias"], ["7d", "7 dias"], ["30d", "30 dias"],
      ["custom-hours", "Personalizado em horas"], ["custom-days", "Personalizado em dias"],
    ];
    const currentMessage = currentExpiresAt ? '<p class="muted">Expiração atual: ' + esc(date(currentExpiresAt)) + '</p>' : "";
    const keepOption = currentExpiresAt ? '<option value="keep" selected>Manter expiração atual</option>' : "";
    const selectOptions = options.map(([value, label]) => '<option value="' + value + '"' + (value === (defaultSelection || "none") && !currentExpiresAt ? " selected" : "") + '>' + label + '</option>').join("");
    const form = await dialogConfirm({
      title,
      confirmLabel: "Salvar",
      content: currentMessage + '<label class="field-row"><span>Expiração</span><select class="field" name="expiration">' + keepOption + selectOptions + '</select></label>' +
        '<label class="field-row"><span>Quantidade para prazo personalizado</span><input class="field" name="durationAmount" type="number" min="1" step="1" value="1"></label>',
    });
    if (!form) return null;
    const payload = temporaryPayload(String(form.get("expiration") || "none"), form.get("durationAmount"));
    if (payload === undefined) {
      ui.toast("Informe uma quantidade inteira maior que zero.", "error");
      return null;
    }
    return payload;
  }

  async function createFolder() {
    const form = await dialogConfirm({ title: "Criar pasta", eyebrow: "NOVO ESPAÇO", confirmLabel: "Continuar", content: '<label class="field-row"><span>Nome da pasta</span><input class="field" name="name" maxlength="80" required autofocus></label><label class="field-row"><span>Contas com acesso (separadas por vírgula)</span><input class="field" name="allowedUsers" value="' + esc(state.user.username) + '"></label>' });
    if (!form) return;
    const name = String(form.get("name") || "").trim();
    if (!name) return ui.toast("Informe o nome da pasta.", "error");
    const expiration = await chooseExpiration("Expiração da pasta", null, "none");
    if (!expiration) return;
    try {
      const folder = await api.post("/folders", { name, allowedUsers: String(form.get("allowedUsers") || ""), ...expiration });
      await loadFolders();
      state.folderId = folder.id;
      window.location.hash = "";
      await loadFiles();
      ui.toast("Pasta criada.", "success");
    } catch (error) { reportError(error); }
  }

  async function renameFolder(id) {
    const folder = state.folders.find((item) => item.id === id);
    if (!folder) return;
    const form = await dialogConfirm({ title: "Renomear pasta", confirmLabel: "Salvar", content: '<label class="field-row"><span>Novo nome</span><input class="field" name="name" maxlength="80" value="' + esc(folder.name) + '" required></label>' });
    if (!form) return;
    try {
      await api.put("/folders/" + encodeURIComponent(id) + "/name", { name: String(form.get("name") || "").trim() });
      await loadFolders();
      await loadFiles();
      ui.toast("Pasta renomeada.", "success");
    } catch (error) { reportError(error); }
  }

  async function setFolderExpiration(id) {
    const folder = state.folders.find((item) => item.id === id);
    if (!folder || folder.isRoot || folder.id === "root") return;
    const payload = await chooseExpiration("Expiração da pasta", folder.expiresAt);
    if (!payload) return;
    try {
      await api.put("/folders/" + encodeURIComponent(id) + "/temporary", payload);
      await loadFolders();
      await loadFiles();
      ui.toast("Expiração da pasta atualizada.", "success");
    } catch (error) { reportError(error); }
  }

  async function setFileExpiration(name, folderId) {
    const file = state.files.find((item) => item.name === name && fileFolderId(item) === folderId);
    const payload = await chooseExpiration("Expiração do arquivo", file && file.expiresAt);
    if (!payload) return;
    try {
      await api.put("/file-temporary", { folderId, name, ...payload });
      await loadFiles();
      ui.toast("Expiração do arquivo atualizada.", "success");
    } catch (error) { reportError(error); }
  }

  async function renameFile(name, folderId) {
    const form = await dialogConfirm({ title: "Renomear arquivo", confirmLabel: "Salvar", content: '<label class="field-row"><span>Novo nome do arquivo</span><input class="field" name="newName" maxlength="255" value="' + esc(name) + '" required></label>' });
    if (!form) return;
    const newName = String(form.get("newName") || "").trim();
    if (!newName || newName === name) return;
    try {
      await api.put("/rename", { oldName: name, newName, folderId });
      await loadFiles();
      ui.toast("Arquivo renomeado.", "success");
    } catch (error) { reportError(error); }
  }

  async function moveFile(name, fromFolderId) {
    const targets = state.folders.filter((folder) => folder.id !== fromFolderId);
    if (!targets.length) return ui.toast("Acesse outra pasta para mover este arquivo.", "error");
    const options = targets.map((folder) => '<option value="' + esc(folder.id) + '">' + esc(folder.name) + '</option>').join("");
    const form = await dialogConfirm({ title: "Mover arquivo", confirmLabel: "Mover", content: '<label class="field-row"><span>Pasta de destino</span><select class="field" name="toFolderId">' + options + '</select></label>' });
    if (!form) return;
    try {
      await api.put("/move", { name, fromFolderId, toFolderId: String(form.get("toFolderId") || "") });
      await loadFiles();
      ui.toast("Arquivo movido.", "success");
    } catch (error) { reportError(error); }
  }

  function userAccessRows(users, current) {
    const grants = current || {};
    return (users || []).map((user) => {
      const username = String(user.username || "");
      const grant = grants[username] || {};
      const disabled = user.username === state.user.username && isAdmin() ? " disabled" : "";
      return '<div class="access-user-row"><strong>' + esc(username) + '</strong><label><input type="checkbox" name="read" value="' + esc(username) + '"' + (grant.read ? " checked" : "") + disabled + '> Leitura</label><label><input type="checkbox" name="edit" value="' + esc(username) + '"' + (grant.edit ? " checked" : "") + disabled + '> Edição</label></div>';
    }).join("");
  }

  async function editFolderAccess(id) {
    try {
      const data = await api.get("/folders/" + encodeURIComponent(id) + "/access");
      const form = await dialogConfirm({ title: "Acesso da pasta", eyebrow: "COMPARTILHAMENTO", confirmLabel: "Salvar acesso", content: '<p class="muted">Responsável: ' + esc(data.owner || "—") + '</p><div class="access-list">' + userAccessRows(data.eligibleUsers, data.users) + '</div>' });
      if (!form) return;
      const read = new Set(form.getAll("read").map(String));
      const edit = new Set(form.getAll("edit").map(String));
      const users = {};
      (data.eligibleUsers || []).forEach((user) => {
        if (read.has(user.username) || edit.has(user.username)) users[user.username] = { read: read.has(user.username), edit: edit.has(user.username) };
      });
      await api.put("/folders/" + encodeURIComponent(id) + "/access", { users });
      await loadFolders();
      render();
      ui.toast("Acesso da pasta atualizado.", "success");
    } catch (error) { reportError(error); }
  }

  async function removeFolder(id, name) {
    const form = await dialogConfirm({ title: "Mover pasta para a lixeira?", eyebrow: "MOVER PARA A LIXEIRA", confirmLabel: "Mover pasta", danger: true, content: '<p>A pasta <strong>' + esc(name) + '</strong> e seu conteúdo serão movidos para a lixeira.</p>' });
    if (!form) return;
    try {
      await api.delete("/folders/" + encodeURIComponent(id));
      await loadFolders();
      await loadFiles();
      ui.toast("Pasta movida para a lixeira.", "success");
    } catch (error) { reportError(error); }
  }

  async function editFileAccess(name, folderId) {
    try {
      const data = await api.get(api.query("/file-access", { name, folderId }));
      const content = '<p class="muted">Responsável: ' + esc(data.owner || "—") + (data.inherited ? ' · Permissões herdadas da pasta' : '') + '</p><label class="access-public"><input type="checkbox" name="public"' + (data.public ? " checked" : "") + '> Acesso para quem pode abrir esta pasta</label><p class="muted">A pasta continua controlando quem pode ver o arquivo. Com esta opção ligada e sem acessos individuais, o arquivo herda as permissões da pasta.</p><div class="access-list">' + userAccessRows(data.eligibleUsers, data.users) + '</div>';
      const form = await dialogConfirm({ title: "Permissões do arquivo", eyebrow: "ACESSO AO ARQUIVO", confirmLabel: "Salvar permissões", content });
      if (!form) return;
      const read = new Set(form.getAll("read").map(String));
      const edit = new Set(form.getAll("edit").map(String));
      const users = {};
      (data.eligibleUsers || []).forEach((user) => {
        if (read.has(user.username) || edit.has(user.username)) users[user.username] = { read: read.has(user.username), edit: edit.has(user.username) };
      });
      await api.put("/file-access", { name, folderId, public: form.get("public") === "on", users });
      ui.toast("Permissões do arquivo atualizadas.", "success");
    } catch (error) { reportError(error); }
  }

  async function shareFile(name, folderId) {
    const form = await dialogConfirm({ title: "Criar link público", eyebrow: "COMPARTILHAR ARQUIVO", confirmLabel: "Gerar link", content: '<p>Qualquer pessoa com o link poderá acessar o arquivo dentro dos limites definidos.</p><label class="field-row"><span>Expira em</span><select class="field" name="expiresInMinutes"><option value="15">15 minutos</option><option value="60" selected>1 hora</option><option value="1440">24 horas</option><option value="10080">7 dias</option></select></label><label class="field-row"><span>Visualizações máximas (0 = ilimitadas)</span><input class="field" name="maxViews" type="number" min="0" max="1000" value="0"></label><label class="field-row"><span>Downloads máximos (0 = ilimitados)</span><input class="field" name="maxDownloads" type="number" min="0" max="1000" value="0"></label><label class="field-row"><span>Senha opcional</span><input class="field" name="password" type="password" autocomplete="new-password"></label>' });
    if (!form) return;
    try {
      const result = await api.post("/share", {
        name,
        folderId,
        expiresInMinutes: Number(form.get("expiresInMinutes")) || 60,
        maxViews: Number(form.get("maxViews")) || 0,
        maxDownloads: Number(form.get("maxDownloads")) || 0,
        password: String(form.get("password") || ""),
      });
      const shareUrl = result.url || "";
      const token = shareUrl.split("/").filter(Boolean).pop() || "";
      await dialogConfirm({ title: "Link criado", eyebrow: "COMPARTILHAMENTO ATIVO", confirmLabel: "Concluir", content: '<p>Copie e envie este link somente às pessoas autorizadas.</p><label class="field-row"><span>Link público</span><input class="field" id="share-link-value" readonly value="' + esc(shareUrl) + '"></label>' + actionButton("copy-share-link", "Copiar link", { url: shareUrl }, "button-quiet") + (token ? '<img class="share-qr" alt="QR Code do link público" src="/share/' + esc(token) + '/qr">' : "") + (result.expiresAt ? '<p class="muted">Expira em ' + esc(date(result.expiresAt)) + '</p>' : "") });
    } catch (error) { reportError(error); }
  }

  function closePreview(dialog, objectUrl) {
    if (dialog.open) dialog.close();
    dialog.remove();
    if (objectUrl) URL.revokeObjectURL(objectUrl);
  }

  async function previewFile(name, scope, folderId) {
    const dialog = document.createElement("dialog");
    dialog.className = "preview-dialog";
    const header = document.createElement("div");
    header.className = "preview-dialog-heading";
    const title = document.createElement("h2");
    title.id = "file-preview-title";
    title.textContent = name;
    dialog.setAttribute("aria-labelledby", title.id);
    const close = document.createElement("button");
    close.type = "button";
    close.className = "button button-quiet";
    close.textContent = "Fechar";
    header.append(title, close);
    const body = document.createElement("div");
    body.className = "preview-dialog-body";
    body.setAttribute("aria-live", "polite");
    body.textContent = "Carregando pré-visualização…";
    dialog.append(header, body);
    document.body.append(dialog);
    let objectUrl = "";
    close.addEventListener("click", () => closePreview(dialog, objectUrl));
    dialog.addEventListener("click", (event) => { if (event.target === dialog) closePreview(dialog, objectUrl); });
    dialog.addEventListener("close", () => {
      if (objectUrl) URL.revokeObjectURL(objectUrl);
      dialog.remove();
    }, { once: true });
    dialog.showModal();
    try {
      const ext = (name.match(/\.[^.]+$/) || [""])[0].toLowerCase();
      if ([".png", ".jpg", ".jpeg", ".gif", ".webp"].includes(ext)) {
        const blob = await api.get(api.query("/preview/file/" + encodeURIComponent(scope) + "/" + encodeURIComponent(name), { folderId }), { responseType: "blob" });
        objectUrl = URL.createObjectURL(blob);
        const image = document.createElement("img");
        image.className = "file-preview-image";
        image.alt = "Pré-visualização de " + name;
        image.src = objectUrl;
        body.replaceChildren(image);
      } else if (ext === ".pdf") {
        const blob = await api.get(api.query("/preview/file/" + encodeURIComponent(scope) + "/" + encodeURIComponent(name), { folderId }), { responseType: "blob" });
        objectUrl = URL.createObjectURL(blob);
        const frame = document.createElement("iframe");
        frame.title = "Pré-visualização de " + name;
        frame.className = "file-preview-pdf";
        frame.src = objectUrl;
        body.replaceChildren(frame);
      } else {
        const result = await api.get(api.query("/preview/text/" + encodeURIComponent(scope) + "/" + encodeURIComponent(name), { folderId }));
        const pre = document.createElement("pre");
        pre.className = "preview-text-content";
        pre.textContent = result.content || "Sem conteúdo disponível para pré-visualização.";
        body.replaceChildren(pre);
      }
    } catch (error) {
      body.textContent = error.message || "Não foi possível gerar a pré-visualização. Baixe o arquivo para abrir.";
    }
  }

  function createUploadId() {
    if (window.crypto && typeof window.crypto.randomUUID === "function") return window.crypto.randomUUID();
    if (window.crypto && typeof window.crypto.getRandomValues === "function") {
      const values = new Uint8Array(16);
      window.crypto.getRandomValues(values);
      values[6] = (values[6] & 15) | 64;
      values[8] = (values[8] & 63) | 128;
      const hex = Array.from(values, (value) => value.toString(16).padStart(2, "0")).join("");
      return hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-" + hex.slice(12, 16) + "-" + hex.slice(16, 20) + "-" + hex.slice(20);
    }
    throw new Error("Este navegador não consegue iniciar um envio seguro.");
  }

  function appendEncryption(form, options) {
    form.append("encryptionLevel", options.level || "none");
    if (options.password) form.append("password", options.password);
    if (options.expiresInDays) form.append("expiresInDays", options.expiresInDays);
  }

  async function uploadSingle(file, settings, versionComment) {
    const form = new FormData();
    form.append("file", file, file.name);
    form.append("versionComment", versionComment || "");
    appendEncryption(form, settings);
    try { return await api.postForm(api.query("/upload", { folderId: state.folderId }), form); }
    finally { form.delete("password"); }
  }

  async function uploadChunked(file, settings, versionComment, progress) {
    const uploadId = createUploadId();
    const totalChunks = Math.ceil(file.size / CHUNK_BYTES);
    let payload = null;
    for (let index = 0; index < totalChunks; index += 1) {
      const form = new FormData();
      form.append("uploadId", uploadId);
      form.append("originalName", file.name);
      form.append("chunkIndex", String(index));
      form.append("totalChunks", String(totalChunks));
      if (index === 0 && versionComment) form.append("versionComment", versionComment);
      if (index === 0) appendEncryption(form, {
        ...settings,
        password: totalChunks === 1 ? settings.password : "",
      });
      if (index === totalChunks - 1 && totalChunks > 1 && settings.password) form.append("password", settings.password);
      form.append("chunk", file.slice(index * CHUNK_BYTES, Math.min(file.size, (index + 1) * CHUNK_BYTES)), file.name);
      try { payload = await api.postForm(api.query("/upload-chunk", { folderId: state.folderId }), form); }
      finally { form.delete("password"); }
      progress(Math.min(99, Math.round(((index + 1) / totalChunks) * 100)));
    }
    return payload;
  }

  function syncUploadEncryptionControls(formElement) {
    const level = formElement.querySelector('[name="encryptionLevel"]')?.value || "none";
    const needsPassword = ["password", "dual"].includes(level);
    const passwordRow = formElement.querySelector("#upload-password-row");
    if (passwordRow) passwordRow.hidden = !needsPassword;
    if (!needsPassword) {
      const passwordInput = formElement.querySelector('[name="password"]');
      if (passwordInput) passwordInput.value = "";
    }
    const expiration = formElement.querySelector('[name="expiresInDays"]');
    if (expiration) expiration.disabled = level === "none";
  }

  async function submitUpload(formElement, filesOverride) {
    if (uploadInProgress) {
      ui.toast("Já existe um envio em andamento.", "error");
      return;
    }
    if (versionsRequestPending) {
      ui.toast("Aguarde o carregamento das versões antes de enviar.", "error");
      return;
    }
    const formData = new FormData(formElement);
    const files = Array.from(filesOverride || document.getElementById("upload-files").files || []);
    if (!files.length) return;
    if (files.length > MAX_BATCH_FILES) return ui.toast("Envie no máximo " + MAX_BATCH_FILES + " arquivos por vez.", "error");
    const level = String(formData.get("encryptionLevel") || "none");
    const password = String(formData.get("password") || "");
    if ((level === "password" || level === "dual") && password.length < 8) return ui.toast("A senha de criptografia deve ter no mínimo 8 caracteres.", "error");
    dirtyForms.add(formElement);
    const settings = { level, password, expiresInDays: String(formData.get("expiresInDays") || "") };
    const versionComment = String(formData.get("versionComment") || "").trim();
    const progress = document.getElementById("upload-progress");
    uploadInProgress = true;
    try {
      progress.hidden = false;
      formElement.querySelector('button[type="submit"]').disabled = true;
      for (let i = 0; i < files.length; i += 1) {
        const file = files[i];
        progress.textContent = "Enviando " + file.name + " (" + (i + 1) + "/" + files.length + ")…";
        if (file.size >= CHUNK_THRESHOLD) await uploadChunked(file, settings, versionComment, (percent) => { progress.textContent = "Enviando " + file.name + " — " + percent + "%"; });
        else await uploadSingle(file, settings, versionComment);
      }
      formElement.reset();
      syncUploadEncryptionControls(formElement);
      progress.textContent = "Envio concluído. Os arquivos aguardam aprovação.";
      await loadFiles();
      ui.toast("Arquivos enviados para aprovação.", "success");
    } catch (error) {
      progress.textContent = error.message || "O envio não foi concluído.";
      ui.toast(progress.textContent, "error");
    } finally {
      uploadInProgress = false;
      formElement.querySelector('button[type="submit"]').disabled = false;
      const passwordField = formElement.querySelector('[name="password"]');
      if (passwordField) passwordField.value = "";
      formData.set("password", "");
      settings.password = "";
    }
  }

  async function confirmThen(title, content, action, danger) {
    const result = await dialogConfirm({ title, content, confirmLabel: danger ? "Confirmar ação" : "Confirmar", danger: Boolean(danger) });
    if (!result) return false;
    await action();
    return true;
  }

  async function openFile(name, download, folderId) {
    try {
      const file = state.files.find((item) => item.name === name && fileFolderId(item) === folderId);
      if (isEncrypted(file)) return downloadEncryptedFile(name, folderId);
      await openPlainFile(name, download, folderId);
    } catch (error) { reportError(error); }
  }

  async function openPlainFile(name, download, folderId) {
    const token = await api.post("/file-open-token", { name, folderId, download: Boolean(download) });
    window.location.assign(download ? token.downloadUrl : token.url);
  }

  function saveBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename || "download";
    anchor.hidden = true;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function downloadEncryptedFile(name, folderId) {
    let password = "";
    try {
      let metadata = await api.get(api.query("/encrypted/" + encodeURIComponent(name) + "/metadata", { folderId }));
      if (!metadata || !metadata.isEncrypted) {
        const cached = state.files.find((file) => file.name === name && fileFolderId(file) === folderId);
        metadata = cached && cached.encryption ? cached.encryption : { isEncrypted: false };
      }
      if (!metadata.isEncrypted) return openPlainFile(name, true, folderId);
      if (metadata.requiresPassword) {
        const form = await dialogConfirm({ title: "Senha do arquivo", eyebrow: "ARQUIVO CRIPTOGRAFADO", confirmLabel: "Descriptografar", content: '<p>Informe a senha para baixar <strong>' + esc(metadata.originalFilename || name) + '</strong>.</p><label class="field-row"><span>Senha</span><input class="field" name="password" type="password" autocomplete="current-password" required></label>' });
        if (!form) return;
        password = String(form.get("password") || "");
      }
      const blob = await api.request(api.query("/encrypted-download/" + encodeURIComponent(name), { folderId }), {
        method: "POST",
        json: { password },
        responseType: "blob",
      });
      saveBlob(blob, metadata.originalFilename || name);
      ui.toast("Arquivo descriptografado para esta transferência.", "success");
    } catch (error) {
      if (permissionError(error)) reportError(error);
      else ui.toast(error && error.message ? error.message : "Não foi possível descriptografar o arquivo.", "error");
    }
    finally { password = ""; }
  }

  async function fileVersions(name, folderId, focusTrigger) {
    if (uploadInProgress) {
      ui.toast("Aguarde o envio terminar antes de abrir as versões.", "error");
      return;
    }
    if (versionsRequestPending) return;
    versionsRequestPending = true;
    try {
      if (focusTrigger && typeof focusTrigger.focus === "function") focusTrigger.focus({ preventScroll: true });
      const focusAtStart = document.activeElement;
      await api.post(api.query("/versions/" + encodeURIComponent(name) + "/initialize", { folderId }), {});
      state.versions = await api.get(api.query("/versions/" + encodeURIComponent(name), { folderId }));
      state.versions.folderId = folderId;
      state.versions.isEncrypted = isEncrypted(state.files.find((item) => item.name === name && fileFolderId(item) === folderId));
      const shouldFocusHeading = document.activeElement === focusAtStart;
      const activeElement = document.activeElement;
      const activeAction = !shouldFocusHeading && activeElement.closest ? activeElement.closest("[data-action]") : null;
      const activeDetails = !shouldFocusHeading && activeElement.closest ? activeElement.closest("details") : null;
      const focusTarget = !shouldFocusHeading && root.contains(activeElement)
        ? activeAction && root.contains(activeAction)
          ? { action: { ...activeAction.dataset } }
          : activeElement.id
            ? { id: activeElement.id }
            : activeElement.name
              ? { name: activeElement.name, tagName: activeElement.tagName, type: activeElement.type || "" }
              : activeElement.tagName === "SUMMARY" && activeDetails
                ? { summaryText: String(activeElement.textContent || "").replace(/\s+/g, " ").trim(), detailsClassName: activeDetails.className || "" }
                : null
        : null;
      const dirtyFormControls = captureDirtyFormControls();
      const advancedDetailsOpen = Boolean(root.querySelector("details.search-advanced")?.open);
      render();
      restoreDirtyFormControls(dirtyFormControls);
      const nextAdvancedDetails = root.querySelector("details.search-advanced");
      if (nextAdvancedDetails) nextAdvancedDetails.open = advancedDetailsOpen;
      if (shouldFocusHeading) document.querySelector(".versions-panel h2")?.focus();
      else if (focusTarget) {
        const selector = "[data-action], input, select, textarea, button, a[href], summary, [tabindex]:not([tabindex=\"-1\"])";
        const replacement = Array.from(root.querySelectorAll(selector)).find((item) => {
          if (focusTarget.action) return Object.entries(focusTarget.action).every(([key, value]) => item.dataset[key] === value);
          if (focusTarget.id) return item.id === focusTarget.id;
          if (focusTarget.summaryText !== undefined) {
            const details = item.closest("details");
            return item.tagName === "SUMMARY" && String(item.textContent || "").replace(/\s+/g, " ").trim() === focusTarget.summaryText
              && (details?.className || "") === focusTarget.detailsClassName;
          }
          return item.name === focusTarget.name && item.tagName === focusTarget.tagName && (item.type || "") === focusTarget.type;
        });
        if (replacement) replacement.focus();
      }
      if (shouldFocusHeading) document.querySelector(".versions-panel")?.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) { reportError(error); }
    finally { versionsRequestPending = false; }
  }

  async function restoreVersion(name, version, folderId) {
    const path = api.query("/restore/" + encodeURIComponent(name) + "/v/" + encodeURIComponent(version), { folderId });
    await confirmThen("Restaurar versão?", '<p>A versão <strong>v' + esc(version) + '</strong> será restaurada como a nova versão atual.</p>', async () => {
      try { await api.post(path, {}); ui.toast("Versão restaurada.", "success"); await loadFiles(); } catch (error) { reportError(error); }
    });
  }

  async function deleteVersion(name, version, folderId) {
    const path = api.query("/versions/" + encodeURIComponent(name) + "/v/" + encodeURIComponent(version), { folderId });
    await confirmThen("Excluir versão antiga?", '<p>A versão <strong>v' + esc(version) + '</strong> será removida permanentemente.</p>', async () => {
      try { await api.delete(path); ui.toast("Versão excluída.", "success"); await fileVersions(name, folderId); } catch (error) { reportError(error); }
    }, true);
  }

  async function approve(name, yes, folderId) {
    const verb = yes ? "Aprovar" : "Rejeitar";
    await confirmThen(verb + " envio?", '<p>Confirma ' + verb.toLowerCase() + ' o arquivo <strong>' + esc(name) + '</strong>?</p>', async () => {
      try {
        const path = api.query("/" + (yes ? "approve" : "reject") + "/" + encodeURIComponent(name), { folderId });
        const result = await api.post(path, {});
        let message;
        let tone = "success";
        if (yes && result && (result.cloudSyncPending || result.cloudCleanupPending || result.trashCancellationPending)) {
          const pending = [];
          if (result.cloudSyncPending) pending.push("sincronização na nuvem");
          if (result.cloudCleanupPending) pending.push("limpeza do envio temporário");
          if (result.trashCancellationPending) pending.push("cancelamento da exclusão remota anterior");
          message = "Arquivo aprovado. Pendências em segundo plano: " + pending.join(", ") + ".";
          tone = undefined;
        } else {
          message = yes ? "Arquivo aprovado." : "Arquivo rejeitado.";
        }
        await loadFiles();
        ui.toast(message, tone);
      } catch (error) { reportError(error); }
    }, !yes);
  }

  async function moveFileToTrash(name, folderId) {
    await confirmThen("Mover arquivo para a lixeira?", '<p><strong>' + esc(name) + '</strong> poderá ser restaurado pela lixeira.</p>', async () => {
      try {
        await api.post(api.query("/delete/" + encodeURIComponent(name), { folderId }), {});
        ui.toast("Arquivo movido para a lixeira.", "success");
        await loadFiles();
      } catch (error) { reportError(error); }
    }, true);
  }

  async function restoreTrash(id) {
    try {
      await api.post("/trash/" + encodeURIComponent(id) + "/restore", {});
      ui.toast("Item restaurado.", "success");
      await loadRoute();
    } catch (error) { reportError(error); }
  }

  async function permanentlyDeleteTrash(id, name) {
    const form = await dialogConfirm({ title: "Excluir permanentemente?", eyebrow: "AÇÃO IRREVERSÍVEL", confirmLabel: "Excluir permanentemente", danger: true, content: '<p>O item <strong>' + esc(name) + '</strong> será apagado sem possibilidade de restauração.</p><label class="field-row"><span>Digite DELETE para confirmar</span><input class="field" name="confirmation" autocomplete="off" required></label>' });
    if (!form || form.get("confirmation") !== "DELETE") {
      if (form) ui.toast("A confirmação não corresponde.", "error");
      return;
    }
    try { await api.delete("/trash/" + encodeURIComponent(id)); ui.toast("Item excluído permanentemente.", "success"); await loadRoute(); }
    catch (error) { reportError(error); }
  }

  async function emptyTrash() {
    const form = await dialogConfirm({ title: "Esvaziar toda a lixeira?", eyebrow: "AÇÃO IRREVERSÍVEL", confirmLabel: "Excluir itens", danger: true, content: '<p>Todos os itens visíveis serão excluídos permanentemente.</p><label class="field-row"><span>Digite DELETE para confirmar</span><input class="field" name="confirmation" autocomplete="off" required></label>' });
    if (!form || form.get("confirmation") !== "DELETE") {
      if (form) ui.toast("A confirmação não corresponde.", "error");
      return;
    }
    try { await api.delete("/trash", { json: { confirmation: "DELETE" } }); ui.toast("Lixeira esvaziada.", "success"); await loadRoute(); }
    catch (error) { reportError(error); }
  }

  async function onClick(event) {
    const button = event.target.closest("[data-action]");
    if (!button || !root.contains(button)) return;
    const action = button.dataset.action;
    const name = button.dataset.name || "";
    const id = button.dataset.id || "";
    const folderId = button.dataset.folder || state.folderId;
    if (action === "create-folder") return createFolder();
    if (action === "focus-upload") { document.getElementById("upload-panel")?.scrollIntoView({ behavior: "smooth", block: "center" }); document.getElementById("upload-files")?.click(); return; }
    if (action === "select-folder") { state.folderId = id; state.search = {}; return loadFiles(); }
    if (action === "rename-folder") return renameFolder(id);
    if (action === "folder-access") return editFolderAccess(id);
    if (action === "folder-expiration") return setFolderExpiration(id);
    if (action === "delete-folder") return removeFolder(id, button.dataset.name || "pasta");
    if (action === "preview-file") return previewFile(name, "public", folderId);
    if (action === "preview-pending") return previewFile(name, "pending", folderId);
    if (action === "download-file") return openFile(name, true, folderId);
    if (action === "share-file") return shareFile(name, folderId);
    if (action === "file-access") return editFileAccess(name, folderId);
    if (action === "file-versions") return fileVersions(name, folderId, button);
    if (action === "file-expiration") return setFileExpiration(name, folderId);
    if (action === "rename-file") return renameFile(name, folderId);
    if (action === "move-file") return moveFile(name, folderId);
    if (action === "close-versions") {
      const { fileName, folderId } = state.versions || {};
      state.versions = null;
      render();
      const opener = Array.from(root.querySelectorAll('[data-action="file-versions"]')).find((item) => item.dataset.name === fileName && item.dataset.folder === folderId);
      if (opener && opener.isConnected) opener.focus();
      return;
    }
    if (action === "delete-file") return moveFileToTrash(name, folderId);
    if (action === "approve-file") return approve(name, true, folderId);
    if (action === "reject-file") return approve(name, false, folderId);
    if (action === "copy-share-link") {
      const input = document.getElementById("share-link-value");
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) await navigator.clipboard.writeText(button.dataset.url || input && input.value || "");
        else if (input) { input.select(); document.execCommand("copy"); }
        ui.toast("Link copiado.", "success");
      } catch (_) {
        if (input) input.select();
        ui.toast("Não foi possível copiar automaticamente. O link está selecionado.", "error");
      }
      return;
    }
    if (action === "download-version") {
      const version = button.dataset.version;
      try {
        const token = await api.post("/version-open-token", { name, version: Number(version), folderId });
        let frame = document.getElementById("version-download-frame");
        if (!frame) {
          frame = document.createElement("iframe");
          frame.id = "version-download-frame";
          frame.title = "Download da versão";
          frame.hidden = true;
          document.body.append(frame);
        }
        frame.src = token.downloadUrl;
      } catch (error) { reportError(error); }
      return;
    }
    if (action === "restore-version") return restoreVersion(name, button.dataset.version, folderId);
    if (action === "delete-version") return deleteVersion(name, button.dataset.version, folderId);
    if (action === "restore-trash") return restoreTrash(id);
    if (action === "delete-trash") return permanentlyDeleteTrash(id, name);
    if (action === "empty-trash") return emptyTrash();
    if (action === "clear-search") { state.search = {}; return loadFiles(); }
    if (action === "retry") { state.error = ""; return loadRoute(); }
  }

  function onChange(event) {
    if (event.target.id === "folder-select") {
      state.folderId = event.target.value;
      state.search = {};
      loadFiles();
    }
    if (event.target.name === "encryptionLevel") {
      syncUploadEncryptionControls(event.target.form);
    }
  }

  function onSubmit(event) {
    if (event.target.id === "upload-form") {
      event.preventDefault();
      return submitUpload(event.target);
    }
    if (event.target.id === "search-form") {
      event.preventDefault();
      const form = new FormData(event.target);
      state.search = {
        q: String(form.get("q") || "").trim(),
        extension: String(form.get("extension") || "").trim(),
        scope: String(form.get("scope") || "current"),
        minSizeKb: String(form.get("minSizeKb") || ""),
        maxSizeKb: String(form.get("maxSizeKb") || ""),
        startDate: String(form.get("startDate") || ""),
        endDate: String(form.get("endDate") || ""),
        owner: String(form.get("owner") || "").trim(),
        isShared: String(form.get("isShared") || ""),
        isEncrypted: String(form.get("isEncrypted") || ""),
        sortBy: String(form.get("sortBy") || "name"),
        sortOrder: String(form.get("sortOrder") || "asc"),
      };
      return loadFiles();
    }
  }

  root.addEventListener("click", onClick);
  root.addEventListener("change", onChange);
  root.addEventListener("submit", onSubmit);
  root.addEventListener("dragover", (event) => {
    const dropzone = event.target.closest && event.target.closest("#upload-dropzone");
    if (!dropzone) return;
    event.preventDefault();
    dropzone.classList.add("dragover");
  });
  root.addEventListener("dragleave", (event) => {
    const dropzone = event.target.closest && event.target.closest("#upload-dropzone");
    if (dropzone && (!event.relatedTarget || !dropzone.contains(event.relatedTarget))) dropzone.classList.remove("dragover");
  });
  root.addEventListener("drop", (event) => {
    const dropzone = event.target.closest && event.target.closest("#upload-dropzone");
    if (!dropzone) return;
    event.preventDefault();
    dropzone.classList.remove("dragover");
    const files = Array.from(event.dataTransfer && event.dataTransfer.files || []);
    const form = document.getElementById("upload-form");
    if (form && files.length) submitUpload(form, files);
  });
  window.addEventListener("hashchange", loadRoute);

  async function start() {
    try {
      state.user = await ui.getSession();
      if (!state.user || !state.user.permissions || !state.user.permissions.listFiles) {
        root.innerHTML = '<main class="standalone-state"><h1>Sem acesso aos arquivos</h1><p>Esta conta não tem permissão para acessar o espaço de arquivos.</p><button type="button" class="button button-primary" data-standalone-logout>Sair da conta</button></main>';
        root.querySelector("[data-standalone-logout]").addEventListener("click", ui.logout);
        return;
      }
      await loadFolders();
      state.route = routeFromHash();
      await loadRoute();
      connectRealtime();
    } catch (error) {
      if (permissionError(error)) return ui.redirectToLogin();
      root.innerHTML = '<main class="standalone-state"><h1>Não foi possível abrir o espaço</h1><p>' + esc(error.message || "Tente novamente mais tarde.") + '</p><a class="button button-primary" href="/login.html">Voltar ao acesso</a></main>';
    }
  }

  start();
})();
