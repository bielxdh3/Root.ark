const fs = require("node:fs");
const http = require("node:http");
const { errorMonitor } = require("node:events");

const PREFIX = "ROOTARK_UPLOAD_FIXTURE";

function safeCode(error) {
  return typeof error?.code === "string" && /^[A-Z0-9_]{1,40}$/.test(error.code) ? error.code : "unknown";
}

function endpoint(address) {
  if (address === "127.0.0.1") return "loopback4";
  if (address === "::1") return "loopback6";
  if (address === "::ffff:127.0.0.1") return "mapped-loopback4";
  if (address === "0.0.0.0" || address === "::") return "wildcard";
  return "unknown";
}

function family(value) {
  return value === "IPv4" || value === "IPv6" ? value : "unknown";
}

// Only installed in the disposable server child. Observe the listener without
// consuming error events or changing its bind options or request handling.
function installFixtureListenerProbe() {
  const report = (...fields) => {
    try { fs.writeSync(1, `${PREFIX} ${fields.join(" ")}\n`); }
    catch { /* Diagnostics cannot change the server's outcome. */ }
  };
  const createServer = http.createServer;
  let nextId = 0;
  http.createServer = function (...args) {
    const server = Reflect.apply(createServer, this, args);
    const id = ++nextId;
    const close = server.close;
    server.close = function (...closeArgs) {
      report(id, "closing");
      return Reflect.apply(close, this, closeArgs);
    };
    server.on("listening", () => {
      const address = server.address();
      if (address && typeof address === "object") {
        report(id, "listen", family(address.family), endpoint(address.address), address.port);
      }
    });
    server.on("connection", (socket) => report(id, "accept", family(socket.remoteFamily), endpoint(socket.remoteAddress)));
    server.on("close", () => report(id, "close"));
    server.on(errorMonitor, (error) => report(id, "error", safeCode(error)));
    return server;
  };
  process.on("uncaughtExceptionMonitor", (error) => report("uncaught", safeCode(error)));
  process.on("exit", (code) => report("exit", code));
}

function childState(child) {
  if (Number.isInteger(child.exitCode)) return `exit:${child.exitCode}`;
  if (typeof child.signalCode === "string" && /^SIG[A-Z0-9]+$/.test(child.signalCode)) return `signal:${child.signalCode}`;
  // ChildProcess reports its exit asynchronously. Null is not proof of life.
  return "pending";
}

async function observeChildClose(child) {
  if (childState(child) !== "pending" && child.stdout?.readableEnded && child.stderr?.readableEnded) return;
  // Observe only; never issue a second request or send a signal. Wait for the
  // stdio close event so the child's final probe records can be included.
  await new Promise((resolve) => {
    const done = () => {
      clearTimeout(timer);
      child.removeListener("close", done);
      resolve();
    };
    const timer = setTimeout(done, 1000);
    child.once("close", done);
  });
}

function summarizeListener(harness) {
  const lines = harness.stdout.join("").split(/\r?\n/);
  const endpointPattern = "loopback4|loopback6|mapped-loopback4|wildcard|unknown";
  const listenPattern = new RegExp(`^${PREFIX} (\\d+) listen (IPv4|IPv6|unknown) (${endpointPattern}) (\\d{1,5})$`);
  const acceptPattern = new RegExp(`^${PREFIX} (\\d+) accept (IPv4|IPv6|unknown) (${endpointPattern})$`);
  let listener = null;
  let accepts = 0, lastAccept = "none", closed = false, closing = false;
  let listenerError = "none", uncaught = "none", processExit = "none";
  for (const line of lines) {
    const listen = line.match(listenPattern);
    if (listen && Number(listen[4]) === harness.port) {
      listener = listen;
      accepts = 0;
      lastAccept = "none";
      closed = false;
      closing = false;
      listenerError = "none";
    }
    const accept = line.match(acceptPattern);
    if (listener && accept?.[1] === listener[1]) {
      accepts++;
      lastAccept = `${accept[2]}/${accept[3]}`;
    }
    if (listener && line === `${PREFIX} ${listener[1]} close`) closed = true;
    if (listener && line === `${PREFIX} ${listener[1]} closing`) closing = true;
    const error = line.match(/^ROOTARK_UPLOAD_FIXTURE (\d+) error ([A-Z0-9_]{1,40}|unknown)$/);
    if (listener && error?.[1] === listener[1]) listenerError = error[2];
    const fatal = line.match(/^ROOTARK_UPLOAD_FIXTURE uncaught ([A-Z0-9_]{1,40}|unknown)$/);
    if (fatal) uncaught = fatal[1];
    const exit = line.match(/^ROOTARK_UPLOAD_FIXTURE exit (\d{1,3})$/);
    if (exit) processExit = exit[1];
  }
  const observed = listener ? `${listener[2]}/${listener[3]}/match` : "unobserved";
  return `listener=${observed} accepts=${accepts} closed=${listener ? closed : "unknown"} closing=${listener ? closing : "unknown"} lastAccept=${lastAccept} listenerError=${listenerError} uncaught=${uncaught} processExit=${processExit}`;
}

async function fixtureRequest(harness, phase, invoke) {
  try { return await invoke(); }
  catch (error) {
    const code = safeCode(error);
    const syscall = ["connect", "read", "write"].includes(error?.syscall) ? error.syscall : "unknown";
    const port = Number.isInteger(error?.port) ? (error.port === harness.port ? "match" : "mismatch") : "unknown";
    const initial = childState(harness.child);
    await observeChildClose(harness.child);
    const expectedEio = /^Erro no upload em blocos: EIO\r?$/m.test(harness.stderr.join(""));
    throw new Error(`fixture ${phase} failed: code=${code} syscall=${syscall} address=${endpoint(error?.address)} port=${port} childAtError=${initial} childAfter=${childState(harness.child)} stderrChunks=${harness.stderr.length} expectedEio=${expectedEio} ${summarizeListener(harness)}`, { cause: error });
  }
}

module.exports = { installFixtureListenerProbe, fixtureRequest };
