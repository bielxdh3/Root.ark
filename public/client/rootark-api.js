(function () {
  "use strict";

  class ApiError extends Error {
    constructor(status, payload) {
      const message = payload && typeof payload === "object" && typeof payload.error === "string"
        ? payload.error
        : "Não foi possível concluir a solicitação.";
      super(message);
      this.name = "ApiError";
      this.status = status;
      this.payload = payload;
    }
  }

  function csrfToken() {
    const part = document.cookie.split(";").map((value) => value.trim()).find((value) => value.startsWith("rootark_csrf="));
    if (!part) return "";
    try { return decodeURIComponent(part.slice("rootark_csrf=".length)); } catch (_) { return part.slice("rootark_csrf=".length); }
  }

  async function request(path, options) {
    const opts = options || {};
    const method = String(opts.method || "GET").toUpperCase();
    const headers = new Headers(opts.headers || {});
    headers.set("Accept", headers.get("Accept") || "application/json");

    let body = opts.body;
    if (Object.prototype.hasOwnProperty.call(opts, "json")) {
      headers.set("Content-Type", "application/json");
      body = JSON.stringify(opts.json);
    }
    if (body instanceof FormData) headers.delete("Content-Type");

    if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
      const csrf = csrfToken();
      if (csrf) headers.set("X-CSRF-Token", csrf);
    }
    if (opts.token) headers.set("Authorization", "Bearer " + opts.token);

    let response;
    try {
      response = await fetch(path, {
        method,
        credentials: "same-origin",
        headers,
        body,
        signal: opts.signal,
        cache: "no-store",
      });
    } catch (error) {
      if (error && error.name === "AbortError") throw error;
      throw new ApiError(0, { error: "Conexão indisponível. Verifique a rede e tente novamente." });
    }

    if (response.status === 204) return null;
    if (opts.responseType === "blob") {
      if (!response.ok) {
        let payload = {};
        try { payload = await response.json(); } catch (_) {}
        throw new ApiError(response.status, payload);
      }
      return response.blob();
    }

    const contentType = response.headers.get("content-type") || "";
    let payload = null;
    if (contentType.includes("application/json")) {
      try { payload = await response.json(); } catch (_) { payload = {}; }
    } else {
      payload = await response.text();
    }
    if (!response.ok) throw new ApiError(response.status, payload);
    return payload;
  }

  function query(path, values) {
    const params = new URLSearchParams();
    Object.entries(values || {}).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== "") params.set(key, String(value));
    });
    const suffix = params.toString();
    return suffix ? path + (path.includes("?") ? "&" : "?") + suffix : path;
  }

  function download(path, filename, options) {
    return request(path, Object.assign({}, options, { responseType: "blob" })).then((blob) => {
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename || "download";
      anchor.hidden = true;
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
  }

  window.RootarkApi = Object.freeze({
    ApiError,
    request,
    get: (path, options) => request(path, Object.assign({}, options, { method: "GET" })),
    post: (path, json, options) => request(path, Object.assign({}, options, { method: "POST", json })),
    postForm: (path, form, options) => request(path, Object.assign({}, options, { method: "POST", body: form })),
    put: (path, json, options) => request(path, Object.assign({}, options, { method: "PUT", json })),
    patch: (path, json, options) => request(path, Object.assign({}, options, { method: "PATCH", json })),
    delete: (path, options) => request(path, Object.assign({}, options, { method: "DELETE" })),
    query,
    download,
  });
})();
