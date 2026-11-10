#!/bin/sh
# Must run explicitly as root in disposable WSL ext4: ONLY create one new leaf
# under the root-owned sticky /var/tmp; never chmod parents or clean up.
set -eu
# POSIX grep -E anchors apply PER LINE, not to a whole argument. Never pass a
# string containing a second line or a slash to privileged path construction.
validate_leaf() {
  test "$#" -eq 1 || return 1
  case "$1" in
    rootark-issue66-owner-????????????????) ;;
    *) return 1 ;;
  esac
  suffix=${1#rootark-issue66-owner-}
  case "$suffix" in
    *[!0123456789abcdef]*) return 1 ;;
  esac
  return 0
}

# This unprivileged, read-only validation interface permits malicious-name
# regression tests without ever asking WSL root to execute an unsafe input.
if [ "$#" -eq 2 ] && [ "$1" = '--validate-only' ]; then
  validate_leaf "$2" || exit 41
  exit 0
fi

test "$(id -u)" -eq 0 || exit 41
test "$#" -eq 1 || exit 41
validate_leaf "$1" || exit 41
leaf="$1"
test "$(stat -c '%u:%a' /var/tmp)" = '0:1777' || exit 41
test "$(stat -f -c '%t' /var/tmp)" = 'ef53' || exit 41
dir="/var/tmp/$leaf"
umask 077
mkdir -m 0700 -- "$dir"
printf 'TRUSTED_ROOT_CANARY_V1\n' > "$dir/café-中-😀.txt"
chmod 0444 -- "$dir/café-中-😀.txt"
chmod 0555 -- "$dir"
printf 'ROOTARK_OWNER_PROVISIONED_V1\n'
