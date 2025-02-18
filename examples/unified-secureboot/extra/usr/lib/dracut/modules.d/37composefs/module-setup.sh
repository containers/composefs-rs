#!/usr/bin/bash

check() {
    return 0
}

depends() {
    return 0
}

install() {
    inst \
        "${moddir}/composefs-pivot-sysroot" /bin/composefs-pivot-sysroot
    inst \
        "${moddir}/composefs-pivot-sysroot.service" \
        "${systemdsystemunitdir}/composefs-pivot-sysroot.service"

    $SYSTEMCTL -q --root "${initdir}" add-wants \
        'initrd-root-fs.target' 'composefs-pivot-sysroot.service'
}
