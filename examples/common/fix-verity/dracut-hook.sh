# dracut hook for fixing fs-verity on composefs sysroot
mount -o remount,rw /sysroot
(
  cd /sysroot/composefs/objects
  echo >&2 'Enabling fsverity on composefs objects'
  for i in */*; do
      fsverity enable $i;
  done
  echo >&2 'done!'
)
umount /sysroot
sync
poweroff -ff
