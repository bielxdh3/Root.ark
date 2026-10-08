"use strict";

function isDependencyOrNetworkUnavailable(output) {
  const text = String(output || "");
  const missingModule = text.match(/(?:^|\n)(?:Error(?: \[ERR_MODULE_NOT_FOUND\])?:\s*)?Cannot find (?:module|package)\s+['"]([^'"]+)['"]/im);
  const specifier = missingModule?.[1];
  const isLocalOrBuiltinSpecifier = specifier && /^(?:\.{1,2}(?:[\\/]|$)|[\\/]|[A-Za-z]:[\\/]|[A-Za-z][A-Za-z\d+.-]*:|#)/.test(specifier);
  const projectPackageName = require("../package.json").name;
  const isProjectSelfReference = specifier === projectPackageName || specifier?.startsWith(`${projectPackageName}/`);
  return Boolean(specifier && !isLocalOrBuiltinSpecifier && !isProjectSelfReference)
    || /(?:^|\n)npm (?:ERR!|error) (?:code )?(?:ECONNRESET|ECONNREFUSED|EHOSTUNREACH|ENETUNREACH|ETIMEDOUT|EAI_AGAIN|ENOTFOUND)\b/im.test(text)
    || /(?:^|\n)npm (?:ERR!|error) network request to .+ failed/im.test(text);
}

module.exports = { isDependencyOrNetworkUnavailable };
