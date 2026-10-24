"use strict";

// Disposable single-process test fixture. No files, network, descendants or
// persistent work. The parent supervisor must observe its actual OS exit.
process.send?.({ status: "child-ready", pid: process.pid });
setInterval(() => {}, 1000);
