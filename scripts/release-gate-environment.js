"use strict";

const projectPackageName = require("../package.json").name;
const missingModulePattern = /(?:^|\n)(?:Error(?: \[ERR_MODULE_NOT_FOUND\])?:\s*)?Cannot find (?:module|package)\s+['"]([^'"]+)['"]/gim;

function isResolvablePackage(specifier) {
  const parts = specifier.split(/[\\/]/);
  const packageName = specifier.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
  if (!packageName || (specifier.startsWith("@") && parts.length < 2)) return false;
  try {
    require.resolve(packageName, { paths: [__dirname] });
    return true;
  } catch {
    return false;
  }
}

function isDependencyOrNetworkUnavailable(output) {
  const text = String(output || "");
  const missingSpecifiers = Array.from(text.matchAll(missingModulePattern), (match) => match[1]);
  const hasLocalModuleFailure = missingSpecifiers.some((specifier) => {
    const isLocalOrBuiltinSpecifier = /^(?:\.{1,2}(?:[\\/]|$)|[\\/]|[A-Za-z]:[\\/]|[A-Za-z][A-Za-z\d+.-]*:|#)/.test(specifier);
    const isProjectSelfReference = specifier === projectPackageName || specifier.startsWith(`${projectPackageName}/`);
    return isLocalOrBuiltinSpecifier || isProjectSelfReference || isResolvablePackage(specifier);
  });
  return !hasLocalModuleFailure && (missingSpecifiers.length > 0
    || /(?:^|\n)npm (?:ERR!|error) (?:code )?(?:ECONNRESET|ECONNREFUSED|EHOSTUNREACH|ENETUNREACH|ETIMEDOUT|EAI_AGAIN|ENOTFOUND)\b/im.test(text)
    || /(?:^|\n)npm (?:ERR!|error) network request to .+ failed/im.test(text));
}

module.exports = { isDependencyOrNetworkUnavailable };
