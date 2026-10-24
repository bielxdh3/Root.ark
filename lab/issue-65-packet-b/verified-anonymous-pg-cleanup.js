"use strict";

// A narrowly scoped cleanup gate for three disposable PostgreSQL 18 Docker
// test runners. It NEVER enumerates all volumes and never accepts a named,
// bind, foreign, or ambiguous volume as our fixture's private data mount.
function refuse() {
  const error = new Error("ZK65_DISPOSABLE_CLEANUP_REFUSED");
  error.code = error.message;
  throw error;
}

function removeVerifiedDisposablePg({
  docker, inspectVolume, containerId, containerName, labLabel,
} = {}) {
  if (typeof docker !== "function" || typeof inspectVolume !== "function"
    || typeof containerId !== "string"
    || !/^[a-f0-9]{64}$/.test(containerId)
    || typeof containerName !== "string"
    || !/^rootark-zk65-[a-z0-9-]{8,80}$/.test(containerName)
    || !["issue65-get-egress", "issue65-mtls-writer", "issue65-shared-gate"]
      .includes(labLabel)) refuse();

  let actual, mounts;
  try {
    actual = docker(["container", "inspect", "--format",
      '{{.Id}}|{{index .Config.Labels "rootark.lab"}}|{{index .Config.Labels "rootark.owner"}}',
      containerName]);
    mounts = JSON.parse(docker(["container", "inspect", "--format",
      "{{json .Mounts}}", containerName]));
  } catch (_) { refuse(); }
  if (actual !== `${containerId}|${labLabel}|disposable-local`
    || !Array.isArray(mounts) || mounts.length !== 1) refuse();

  const volume = mounts[0];
  if (!volume || volume.Type !== "volume"
    || volume.Destination !== "/var/lib/postgresql"
    || typeof volume.Name !== "string"
    || !/^[a-f0-9]{64}$/.test(volume.Name)) refuse();

  try {
    // -v removes only Docker's anonymous volumes attached to this exact
    // container. The runner provisions no explicit mounts, and this proof
    // deliberately rejects unexpected or named mounts before deletion.
    docker(["rm", "-f", "-v", containerId]);
    const remaining = inspectVolume(volume.Name);
    // Exit status 1 also means Docker daemon unreachable/permission denied.
    // Accept ONLY the exact missing-volume response for this very volume;
    // never misreport a transport error as verified data erasure.
    const missing = [
      `Error response from daemon: get ${volume.Name}: no such volume`,
      `Error: No such volume: ${volume.Name}`,
    ];
    if (!remaining || remaining.error || remaining.status !== 1
      || typeof remaining.stderr !== "string"
      || !missing.includes(remaining.stderr.trim())
      || !["", "[]"].includes(String(remaining.stdout || "").trim())) refuse();
  } catch (_) { refuse(); }
  return Object.freeze({ containerRemoved: true, anonymousVolumeRemoved: true });
}

module.exports = { removeVerifiedDisposablePg };
