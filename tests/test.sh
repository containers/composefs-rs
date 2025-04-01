#!/bin/sh

set -eux

if [ "$(id -u)" != '0' -o -z "${1:-}" ]; then
    echo "*** run as: unshare -Umr $0 /path/to/tmpdir"
    false
fi

top="$1"
test -d "${top}"
test -w "${top}"

mkd() {
    mkdir -p "$1"
    echo "$1"
}

assert_fail() {
    if "$@"; then
        echo "*** unexpectedly passed: $*"
        false
    fi
}

imageid='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
null=''

# this is present in the initramfs itself
config="${top}/config"
tee "${config}" <<EOF
EOF

# this is the filesystem directly on the block device
blkdev="$(mkd "${top}/blkdev")"
repo="$(mkd "${blkdev}/composefs")"
state="$(mkd "${blkdev}/state")"
deployment="$(mkd "${state}/${imageid}")"
dply_etc="$(mkd "${deployment}/etc")"
dply_etc_u="$(mkd "${dply_etc}/upper")"
dply_etc_w="$(mkd "${dply_etc}/work")"
dply_var="$(mkd "${deployment}/var")"

# fake composefs content (because we can't mount erofs)
root="$(mkd "${top}/root-fs")"
root_etc="$(mkd "${root}/etc")"
root_var="$(mkd "${root}/var")"
root_sysroot="$(mkd "${root}/sysroot")"
mount -o bind,ro "${root}" "${root}"  # see open_root_fs()

# this emulates the initramfs initially mounting the block device on /sysroot
sysroot="$(mkd "${top}/sysroot")"
mount -o bind "${blkdev}" "${sysroot}"

composefs-setup-root \
    --config "${config}" \
    --cmdline "composefs=${imageid}" \
    --root-fs "${root}" \
    --sysroot "${sysroot}" \
    ${null}

grep "${top}" /proc/mounts

# these are in the newly mounted root filesystem now
var="${sysroot}/var"
etc="${sysroot}/etc"

assert_fail touch "${sysroot}/a"  # read-only
touch "${etc}/file.conf"
touch "${var}/db"

# make sure those went into the expected places
test -f "${dply_etc}/upper/file.conf"
test -f "${dply_var}/db"

find "${top}"

umount -R "${sysroot}"  # this should entirely reverse the impact of the pivot
umount -R "${root}"  # reverse the ro-bindmount above
assert_fail grep "${top}" /proc/mounts  # make sure nothing else is mounted

find "${top}"

# from here we can inspect the after-effects
