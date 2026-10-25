"use strict";

// Disposable fixture certificates for GitHub-hosted Windows (no WSL distro)
// and developer hosts. Direct argv OpenSSL: no shell interpreter or secrets
// echoed into logs. This helper is TEST-ONLY, never a production certificate CA.
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

function restrictFixtureCertificatePermissions(dir) {
  if (process.platform === "win32") return;
  for (const name of fs.readdirSync(dir)) {
    if (!/\.(?:pem|key)$/.test(name)) continue;
    const filename = path.join(dir, name);
    const info = fs.lstatSync(filename);
    if (!info.isFile() || info.isSymbolicLink()) {
      throw new Error("ZK1_TEST_CERT_FIXTURE_INVALID");
    }
    fs.chmodSync(filename, 0o600);
  }
}

function binary() {
  if (process.platform !== "win32") return "openssl";
  const programFiles = process.env.ProgramFiles || "C:\\Program Files";
  const programFiles86 = process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)";
  const candidates = [
    path.join(programFiles, "Git", "usr", "bin", "openssl.exe"),
    path.join(programFiles, "Git", "mingw64", "bin", "openssl.exe"),
    path.join(programFiles86, "Git", "usr", "bin", "openssl.exe"),
    path.join(programFiles86, "Git", "mingw64", "bin", "openssl.exe"),
  ];
  return candidates.find((file) => fs.existsSync(file)) || "openssl.exe";
}
function runNativeOpenSsl(cwd, args) {
  if (!path.isAbsolute(cwd) || !fs.statSync(cwd).isDirectory()
    || !Array.isArray(args) || args.some((a) => typeof a !== "string")) {
    throw new Error("ZK1_TEST_CERT_FIXTURE_INVALID");
  }
  execFileSync(binary(), args, {
    cwd, stdio: "ignore", timeout: 30000, windowsHide: true,
  });
  // OpenSSL normally creates public certificates as 0644 on POSIX. The
  // standalone authority reader intentionally rejects *all* world-readable
  // trust material, including public certs. Keep only test fixtures private.
  restrictFixtureCertificatePermissions(cwd);
}
function generateNativeFixtureCertificates(dir, { caSubject, servers = [], clients = [] }) {
  if (!path.isAbsolute(dir) || !fs.statSync(dir).isDirectory()
    || typeof caSubject !== "string" || !/^[a-zA-Z0-9 _-]{1,72}$/.test(caSubject)
    || !Array.isArray(servers) || !Array.isArray(clients)
    || servers.length + clients.length < 1 || servers.length + clients.length > 12) {
    throw new Error("ZK1_TEST_CERT_FIXTURE_INVALID");
  }
  const names = [...servers, ...clients];
  if (names.some((name) => typeof name !== "string" || !/^[a-z][a-z0-9-]{0,32}$/.test(name))
    || new Set(names).size !== names.length) {
    throw new Error("ZK1_TEST_CERT_FIXTURE_INVALID");
  }
  runNativeOpenSsl(dir, ["req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=" + caSubject, "-days", "1"]);
  for (const name of names) {
    const server = servers.includes(name);
    const subject = server ? "localhost" : name;
    runNativeOpenSsl(dir, ["req", "-newkey", "rsa:2048", "-nodes",
      "-keyout", name + ".key", "-out", name + ".csr", "-subj", "/CN=" + subject]);
    fs.writeFileSync(path.join(dir, name + ".ext"), [
      server ? "extendedKeyUsage=serverAuth" : "extendedKeyUsage=clientAuth",
      "keyUsage=digitalSignature,keyEncipherment",
      ...(server ? ["subjectAltName=DNS:localhost,IP:127.0.0.1"] : []),
      "",
    ].join("\n"), { flag: "wx", mode: 0o600 });
    runNativeOpenSsl(dir, ["x509", "-req", "-in", name + ".csr",
      "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
      "-out", name + ".pem", "-days", "1", "-extfile", name + ".ext"]);
  }
}
module.exports = { runNativeOpenSsl, generateNativeFixtureCertificates,
  restrictFixtureCertificatePermissions };
