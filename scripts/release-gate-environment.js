"use strict";

function isDependencyOrNetworkUnavailable(output) {
  const text = String(output || "");
  return /(?:^|\n)(?:Error \[ERR_MODULE_NOT_FOUND\]:|Error: Cannot find (?:module|package)\b|MODULE_NOT_FOUND\b)/im.test(text)
    || /(?:^|\n)npm (?:ERR!|error) (?:code )?(?:ECONNRESET|ECONNREFUSED|EHOSTUNREACH|ENETUNREACH|ETIMEDOUT|EAI_AGAIN|ENOTFOUND)\b/im.test(text)
    || /(?:^|\n)npm (?:ERR!|error) network request to .+ failed/im.test(text);
}

module.exports = { isDependencyOrNetworkUnavailable };
