#!/bin/sh
# Must run explicitly as root in disposable WSL ext4: ONLY create one new leaf
# under the root-owned sticky /var/tmp; never chmod parents or clean up.
set -eu
test "$(id -u)" -eq 0 || exit 41
test "$#" -eq 1 || exit 41
leaf="$1"
printf '%s' "$leaf" | grep -Eq '^rootark-issue66-owner-[0-9a-f]{16}$' || exit 41
test "$(stat -c '%u:%a' /var/tmp)" = '0:1777' || exit 41
test "$(stat -f -c '%t' /var/tmp)" = 'ef53' || exit 41
dir="/var/tmp/$leaf"
umask 077
mkdir -m 0700 -- "$dir"
printf 'TRUSTED_ROOT_CANARY_V1\n' > "$dir/café-中-😀.txt"
chmod 0444 -- "$dir/café-中-😀.txt"
chmod 0555 -- "$dir"
printf 'ROOTARK_OWNER_PROVISIONED_V1\n'
