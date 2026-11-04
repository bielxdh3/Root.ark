"use strict";

// Refuse any Docker deletion without all three independently checked
// identifiers: the exact newly created container ID, label and anonymous
// PostgreSQL 18 data volume. Never enumerate or prune unrelated volumes.
function refuse() {
  const error = Error("ZK65_DISPOSABLE_CLEANUP_REFUSED");
  error.code = error.message;
  throw error;
}

function removeVerifiedDisposablePg({
  docker, inspectVolume, containerId, containerName, labLabel,
} = {}) {
  if (typeof docker !== "function" || typeof inspectVolume !== "function"
    || typeof containerId !== "string" || !/^[a-f0-9]{64}$/.test(containerId)
    || typeof containerName !== "string"
    || !/^rootark-zk65-(gate|replay)-[a-f0-9]{12}$/.test(containerName)
    || !["issue65-shared-gate", "issue65-approval-replay"].includes(labLabel)
    || (labLabel === "issue65-shared-gate" && !containerName.startsWith("rootark-zk65-gate-"))
    || (labLabel === "issue65-approval-replay" && !containerName.startsWith("rootark-zk65-replay-"))) {
    refuse();
  }
  let identity, mounts;
  try {
    identity = docker(["container", "inspect", "--format",
      '{{.Id}}|{{index .Config.Labels "rootark.lab"}}|{{index .Config.Labels "rootark.owner"}}',
      containerName]);
    mounts = JSON.parse(docker(["container", "inspect", "--format",
      "{{json .Mounts}}", containerName]));
  } catch (_) { refuse(); }
  if (identity !== `${containerId}|${labLabel}|disposable-local`
    || !Array.isArray(mounts) || mounts.length !== 1) refuse();
  const volume = mounts[0];
  if (!volume || volume.Type !== "volume"
    || volume.Destination !== "/var/lib/postgresql"
    || typeof volume.Name !== "string"
    || !/^[a-f0-9]{64}$/.test(volume.Name)) refuse();
  try {
    if (docker(["rm", "-f", "-v", containerId]) !== containerId) refuse();
    const remaining = inspectVolume(volume.Name);
    const exactMissing = [
      `Error response from daemon: get ${volume.Name}: no such volume`,
      `Error: No such volume: ${volume.Name}`,
    ];
    if (!remaining || remaining.error || remaining.status !== 1
      || !exactMissing.includes(String(remaining.stderr || "").trim())
      || !["", "[]"].includes(String(remaining.stdout || "").trim())) refuse();
  } catch (_) { refuse(); }
  return { containerRemoved: true, anonymousVolumeRemoved: true };
}

module.exports = { removeVerifiedDisposablePg };
