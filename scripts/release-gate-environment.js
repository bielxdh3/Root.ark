"use strict";

const projectPackage = require("../package.json");
const lockfile = require("../package-lock.json");
const projectPackageName = projectPackage.name;
const declaredPackageNames = new Set([
  ...Object.keys(projectPackage.dependencies || {}),
  ...Object.keys(projectPackage.devDependencies || {}),
  ...Object.keys(projectPackage.optionalDependencies || {}),
  ...Object.keys(projectPackage.peerDependencies || {}),
]);
const lockedPackageNames = new Set(Object.keys(lockfile.packages || {}).flatMap((location) => {
  const marker = "node_modules/";
  const markerIndex = location.lastIndexOf(marker);
  return markerIndex < 0 ? [] : [location.slice(markerIndex + marker.length)];
}));
const missingModulePattern = /(?:^|\n)(?:Error(?: \[ERR_MODULE_NOT_FOUND\])?:\s*)?Cannot find (?:module|package)\s+['"]([^'"]+)['"](?:(?: imported from )([^\r\n]+))?/gim;

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

function isImportedFromLockedPackage(importer) {
  if (!importer) return false;
  const normalizedImporter = String(importer).replace(/[\\/]+/g, "/").toLowerCase();
  return Array.from(lockedPackageNames).some((packageName) => {
    const marker = `node_modules/${packageName}`.toLowerCase();
    const markerIndex = normalizedImporter.lastIndexOf(marker);
    if (markerIndex < 0) return false;
    const nextCharacter = normalizedImporter[markerIndex + marker.length];
    return nextCharacter === undefined || nextCharacter === "/";
  });
}

function getMissingModuleFailures(text) {
  const matches = Array.from(text.matchAll(missingModulePattern));
  return matches.map((match, index) => {
    const end = matches[index + 1]?.index ?? text.length;
    const failureText = text.slice(match.index, end);
    const requireStackImporter = failureText.match(/Require stack:\s*\r?\n\s*-\s*([^\r\n]+)/i)?.[1];
    return {
      specifier: match[1],
      importer: match[2] || requireStackImporter,
    };
  });
}

function isDependencyOrNetworkUnavailable(output, { resolvePackage = isResolvablePackage } = {}) {
  const text = String(output || "");
  const missingFailures = getMissingModuleFailures(text);
  const isDeclaredDependencyFailure = ({ specifier, importer }) => {
    if (isLocalOrProjectSpecifier(specifier)) return false;
    const packageName = packageNameFromSpecifier(specifier);
    if (!packageName) return false;
    if (declaredPackageNames.has(packageName)) return !resolvePackage(packageName);
    return lockedPackageNames.has(packageName) && isImportedFromLockedPackage(importer) && !resolvePackage(packageName);
  };
  const hasLocalModuleFailure = missingFailures.some(({ specifier }) => isLocalOrProjectSpecifier(specifier) || resolvePackage(specifier));
  const hasUnavailableDeclaredPackage = missingFailures.some(isDeclaredDependencyFailure);
  const hasUnknownExternalModuleFailure = missingFailures.some(({ specifier, importer }) => {
    if (isLocalOrProjectSpecifier(specifier) || resolvePackage(specifier)) return false;
    const packageName = packageNameFromSpecifier(specifier);
    return !packageName || !isDeclaredDependencyFailure({ specifier, importer });
  });
  return !hasLocalModuleFailure && !hasUnknownExternalModuleFailure && (hasUnavailableDeclaredPackage
    || /(?:^|\n)npm (?:ERR!|error) (?:code )?(?:ECONNRESET|ECONNREFUSED|EHOSTUNREACH|ENETUNREACH|ETIMEDOUT|EAI_AGAIN|ENOTFOUND)\b/im.test(text)
    || /(?:^|\n)npm (?:ERR!|error) network request to .+ failed/im.test(text));
}

module.exports = { isDependencyOrNetworkUnavailable };
