"use strict";

const projectPackage = require("../package.json");
const packageLock = require("../package-lock.json");
const projectPackageName = projectPackage.name;
const declaredPackageNames = new Set([
  ...Object.keys(projectPackage.dependencies || {}),
  ...Object.keys(projectPackage.devDependencies || {}),
  ...Object.keys(projectPackage.optionalDependencies || {}),
  ...Object.keys(projectPackage.peerDependencies || {}),
]);
for (const packagePath of Object.keys(packageLock.packages || {})) {
  const marker = "node_modules/";
  const markerIndex = packagePath.lastIndexOf(marker);
  if (markerIndex >= 0) declaredPackageNames.add(packagePath.slice(markerIndex + marker.length));
}
const missingModulePattern = /(?:^|\n)(?:Error(?: \[ERR_MODULE_NOT_FOUND\])?:\s*)?Cannot find (?:module|package)\s+['"]([^'"]+)['"]/gim;

function packageNameFromSpecifier(specifier) {
  const parts = specifier.split(/[\\/]/);
  if (specifier.startsWith("@")) return parts.length >= 2 && parts[0] && parts[1] ? parts.slice(0, 2).join("/") : null;
  return parts[0] || null;
}

function isResolvablePackage(specifier) {
  const packageName = packageNameFromSpecifier(specifier);
  if (!packageName) return false;
  try {
    require.resolve(packageName, { paths: [__dirname] });
    return true;
  } catch {
    return false;
  }
}

function isLocalOrProjectSpecifier(specifier) {
  const isLocalOrBuiltinSpecifier = /^(?:\.{1,2}(?:[\\/]|$)|[\\/]|[A-Za-z]:[\\/]|[A-Za-z][A-Za-z\d+.-]*:|#)/.test(specifier);
  const isProjectSelfReference = specifier === projectPackageName || specifier.startsWith(`${projectPackageName}/`);
  return isLocalOrBuiltinSpecifier || isProjectSelfReference;
}

function isDependencyOrNetworkUnavailable(output, { resolvePackage = isResolvablePackage } = {}) {
  const text = String(output || "");
  const missingSpecifiers = Array.from(text.matchAll(missingModulePattern), (match) => match[1]);
  const hasLocalModuleFailure = missingSpecifiers.some((specifier) => isLocalOrProjectSpecifier(specifier) || resolvePackage(specifier));
  const hasUnavailableDeclaredPackage = missingSpecifiers.some((specifier) => {
    if (isLocalOrProjectSpecifier(specifier)) return false;
    const packageName = packageNameFromSpecifier(specifier);
    return Boolean(packageName && declaredPackageNames.has(packageName) && !resolvePackage(packageName));
  });
  const hasUnknownExternalModuleFailure = missingSpecifiers.some((specifier) => {
    if (isLocalOrProjectSpecifier(specifier) || resolvePackage(specifier)) return false;
    const packageName = packageNameFromSpecifier(specifier);
    return !packageName || !declaredPackageNames.has(packageName);
  });
  return !hasLocalModuleFailure && !hasUnknownExternalModuleFailure && (hasUnavailableDeclaredPackage
    || /(?:^|\n)npm (?:ERR!|error) (?:code )?(?:ECONNRESET|ECONNREFUSED|EHOSTUNREACH|ENETUNREACH|ETIMEDOUT|EAI_AGAIN|ENOTFOUND)\b/im.test(text)
    || /(?:^|\n)npm (?:ERR!|error) network request to .+ failed/im.test(text));
}

module.exports = { isDependencyOrNetworkUnavailable };
