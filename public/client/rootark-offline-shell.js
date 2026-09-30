(function () {
  "use strict";

  if (!("serviceWorker" in navigator)) return;

  navigator.serviceWorker.register("/service-worker.js", { scope: "/" }).catch(() => {});
}());
