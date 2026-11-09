# #66 — independent-UID root-owned ext4 custody experiment

**Test-only. Product / PR #300 RELEASE NO-GO.** No production module imports
this experiment, and `openNativeRootSession()` remains unconditionally closed.
This proves a *narrower OS property* than a complete RootSession: a directory
and marker owned by **root** beneath a root-owned sticky parent cannot be
renamed or modified by two competing processes running as ordinary UID 1000.
The test verifies a native held-directory read before, during and after those
failed mutations. It does not show that Root.ark has obtained an authorized,
writable, durable recovery root from an independent custodian.

## Scope and safe setup

- Host: WSL Ubuntu, **Node 22**, Linux `openat2`, `/var/tmp` on **ext4**, mode
  `01777`, owned by UID 0. The ordinary test process must not run as root.
- The privileged setup script `provision-owner-root.sh` must be invoked
  explicitly **as root**, using one newly generated leaf of the exact form
  `rootark-issue66-owner-` plus 16 lowercase hex digits. It refuses a
  different parent, non-ext4, non-root ownership or altered sticky mode.
- It creates exactly one new directory `/var/tmp/<leaf>` with owner UID 0 and
  mode `0555`, and a root-owned Unicode filename `café-中-😀.txt` with mode
  `0444`. It does **not** modify `/var/tmp` permissions, create users, change
  mounts, remove files, or touch another directory. `mkdir` fails on collision.
- Provide that same leaf to the unprivileged Node test as the environment
  variable `ROOTARK_ISSUE66_OWNER_LEAF`, and set
  `ROOTARK_ISSUE66_OWNER_PROBE=1`. Without opt-in, Node's test is SKIP.
- All fixtures (including root-owned and unprivileged build directories) are
  retained for inspection. There is no recursive deletion or cleanup script.

The actual setup invocation uses `wsl.exe --user root --exec /bin/sh` with
the on-disk `provision-owner-root.sh` and a validated, random leaf argument.
The test itself runs from the checked-in worktree with the ordinary WSL user:

```sh
ROOTARK_ISSUE66_OWNER_PROBE=1 \
ROOTARK_ISSUE66_OWNER_LEAF=rootark-issue66-owner-0123456789abcdef \
node --test test/issue-66-independent-owner-posix-root.test.js
```

Replace the example suffix above with the **actual random** leaf returned by
your own privileged setup; do not reuse this illustrative value.

Only the root provisioning step is privileged; native compile/read and the
two attacker processes are all executed as the unprivileged user. The C
program opens `/` then `var/tmp` and the fixed-format leaf using `openat2`
with `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_XDEV`; verifies ext4,
root ownership, sticky parent, fixed directory and file modes; enumerates
the same held directory object, reads the exact Unicode marker through its
descriptor and rechecks the retained file identity. Both in-process and
separate same-UID attacker processes attempt rename and in-place write;
every operation must fail `EACCES`/`EPERM`. A new native process repeats the
read after the attackers, without inheriting a prior file descriptor.

## What this DOES NOT demonstrate

- The caller supplies a name for a **read-only test fixture**, not an
  owner-signed authorization; it cannot use that string to authorize a
  production recovery, signed DELETE, or native writer privileges.
- The example relies on a root-owned fixture that the ordinary UID **cannot
  write**. A full cache recovery must additionally establish a trusted,
  independently controlled writer service or custody protocol without
  granting that same UID the ability to replace the trusted root.
- A root-owned sticky `/var/tmp` prevents *this particular* unprivileged
  attacker from replacing this *one root-owned leaf*. It does not stop a
  process with root privileges, a malicious mount namespace, or a kernel
  attacker. No actual successful A→B→A attack, forced power cut or hostile
  bind mount is performed.
- `fsync`/power-loss ordering, monotonic anti-rollback, native write/journal
  phases, Unicode normalization collisions, a `16,385`-entry recovery, cold
  reboot, mapped executable and compiler toolchain trust, and Windows SID
  custody are **not** proved by this small read-only experiment.
- The C source, gcc and its child toolchain, output executable and launch by
  pathname have no independently attested image bytes. A same-UID hostile
  compiler or test runner would invalidate the security claim.

**Decision:** retain as an isolated, opt-in OS-level proof. Do not activate
the product `RootSession`, push or merge PR #300, deploy, or modify `Root/main`
on the basis of this experiment.
