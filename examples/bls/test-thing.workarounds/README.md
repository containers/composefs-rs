# Guest support workarounds

These are extra files that you can add to virtual machine guests to enable
support for missing features required by `test.thing`:

 - [debian/](debian/): enables ephemeral ssh key support
 - [fedora-42/](fedora-42/): enables ephemeral ssh key support ([this is
   supported without a workaround in Fedora 43 and
   later](https://src.fedoraproject.org/rpms/openssh/pull-request/101))
 - [rhel9/](rhel9/): enables sshd vsock listener (with ephemeral ssh key
   support) and sends the expected `sd_notify` message when the guest reaches
   `multi-user.target`

`test.thing` can also work with guests lacking support for ephemeral ssh keys
by including a fixed ssh key in the image, or by using the
`ssh.authorized_keys.root` credential (since systemd 252), but this requires
modifying root's home directory at runtime and only works if another ssh key
isn't already present, so it isn't enabled by default.
