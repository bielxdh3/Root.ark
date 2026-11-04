#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'W110_ROOT_REQUIRED_FOR_REAL_FOREIGN_UID_TEST'
  exit 3
fi
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
if [ ! -f "$repo/test/issue-65-full-multiprovider-http-restore.test.js" ]; then
  echo 'W110_WORKTREE_UNAVAILABLE'
  exit 3
fi
unsafe=$(mktemp -d /tmp/zk65-w110-unsafe-XXXXXXXX)
case "$unsafe" in /tmp/zk65-w110-unsafe-*) ;; *) exit 3 ;; esac
trap 'rm -rf -- "$unsafe"' EXIT
if [ "${W110_ATTACK_DRIFT:-0}" = 1 ]; then chmod 0700 "$unsafe"
else chmod 0777 "$unsafe"; fi
export TMPDIR=/tmp
export W110_UNSAFE_TMPDIR="$unsafe"
export W110_ATTACK=1
export NODE_OPTIONS="--require=$repo/test/support/issue-65-w110-restore-attack-preload.js"
cd "$repo"
node --test test/issue-65-w110-real-restore-tmpdir.test.js
