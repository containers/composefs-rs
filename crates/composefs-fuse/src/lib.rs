//! FUSE filesystem implementation for composefs trees.
//!
//! This crate provides a userspace filesystem implementation that exposes composefs
//! directory trees through FUSE. It supports read-only access to files, directories,
//! symlinks, and extended attributes, with data served from a composefs repository.

#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    ffi::OsStr,
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    rc::Rc,
    time::{Duration, SystemTime},
};

use anyhow::Context;
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyOpen,
    Request, Session, SessionACL,
};
use rustix::{
    buffer::spare_capacity,
    fs::{open, Mode, OFlags},
    io::{pread, Errno},
    mount::{
        fsconfig_create, fsconfig_set_flag, fsconfig_set_string, fsmount, FsMountFlags,
        MountAttrFlags,
    },
};

use composefs::{
    fsverity::FsVerityHashValue,
    mount::FsHandle,
    repository::Repository,
    tree::{Directory, Inode, Leaf, LeafContent, RegularFile, Stat},
};

const TTL: Duration = Duration::from_secs(1_000_000);

#[derive(Debug, Clone)]
enum InodeRef<'a, ObjectID: FsVerityHashValue> {
    Directory(&'a Directory<ObjectID>, u64),
    Leaf(&'a Rc<Leaf<ObjectID>>),
}

#[derive(Debug)]
enum OpenHandle {
    Fd(OwnedFd),
    Data(Box<[u8]>),
}

impl<'a, ObjectID: FsVerityHashValue> InodeRef<'a, ObjectID> {
    fn new(inode: &'a Inode<ObjectID>, parent: u64) -> Self {
        match inode {
            Inode::Directory(dir) => InodeRef::Directory(dir, parent),
            Inode::Leaf(leaf) => InodeRef::Leaf(leaf),
        }
    }

    fn ino(&self) -> u64 {
        match self {
            InodeRef::Directory(dir, ..) => *dir as *const Directory<ObjectID> as u64,
            InodeRef::Leaf(leaf) => Rc::as_ptr(leaf) as u64,
        }
    }

    fn nlink(&self) -> u32 {
        (match self {
            InodeRef::Directory(dir, ..) => {
                2 + dir
                    .inodes()
                    .filter(|i| matches!(i, Inode::Directory(..)))
                    .count()
            }
            InodeRef::Leaf(leaf) => Rc::strong_count(leaf),
        }) as u32
    }

    fn rdev(&self) -> u32 {
        (match self {
            InodeRef::Directory(..) => 0,
            InodeRef::Leaf(leaf) => match &leaf.content {
                LeafContent::BlockDevice(rdev) | LeafContent::CharacterDevice(rdev) => *rdev,
                _ => 0,
            },
        }) as u32
    }

    fn kind(&self) -> FileType {
        match self {
            InodeRef::Directory(..) => FileType::Directory,
            InodeRef::Leaf(leaf) => Self::leaf_kind(leaf),
        }
    }

    fn leaf_kind(leaf: &Leaf<ObjectID>) -> FileType {
        match leaf.content {
            LeafContent::BlockDevice(..) => FileType::BlockDevice,
            LeafContent::CharacterDevice(..) => FileType::CharDevice,
            LeafContent::Fifo => FileType::NamedPipe,
            LeafContent::Regular(..) => FileType::RegularFile,
            LeafContent::Socket => FileType::Socket,
            LeafContent::Symlink(..) => FileType::Symlink,
        }
    }

    fn stat(&self) -> &'a Stat {
        match self {
            InodeRef::Directory(dir, ..) => &dir.stat,
            InodeRef::Leaf(leaf) => &leaf.stat,
        }
    }

    fn size(&self) -> u64 {
        match self {
            InodeRef::Directory(..) => 0,
            InodeRef::Leaf(leaf) => match &leaf.content {
                LeafContent::Regular(RegularFile::Inline(data)) => data.len() as u64,
                LeafContent::Regular(RegularFile::External(.., size)) => *size,
                _ => 0,
            },
        }
    }

    fn fileattr(&self) -> FileAttr {
        let stat = self.stat();
        let mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(stat.st_mtim_sec as u64);

        FileAttr {
            ino: self.ino(),
            size: self.size(),
            blocks: 1,
            atime: mtime,
            mtime,
            ctime: mtime,
            crtime: mtime,
            kind: self.kind(),
            perm: stat.st_mode as u16,
            nlink: self.nlink(),
            uid: stat.st_uid,
            gid: stat.st_gid,
            rdev: self.rdev(),
            blksize: 4096,
            flags: 0,
        }
    }
}

#[derive(Debug)]
struct TreeFuse<'a, ObjectID: FsVerityHashValue> {
    repo: &'a Repository<ObjectID>,
    inodes: HashMap<u64, InodeRef<'a, ObjectID>>,
    attrs: HashMap<u64, FileAttr>,
    handles: HashMap<u64, OpenHandle>,
    next_fh: u64,
}

impl<'a, ObjectID: FsVerityHashValue> TreeFuse<'a, ObjectID> {
    fn inode_ref(&mut self, inode: &'a Inode<ObjectID>, parent: u64) -> InodeRef<'a, ObjectID> {
        let iref = InodeRef::new(inode, parent);
        self.inodes.insert(iref.ino(), iref.clone());
        iref
    }

    fn iref_fileattr(&mut self, iref: &InodeRef<ObjectID>) -> &FileAttr {
        self.attrs.insert(iref.ino(), iref.fileattr());
        self.attrs.get(&iref.ino()).unwrap()
    }

    fn inode_fileattr(&mut self, inode: &'a Inode<ObjectID>, parent: u64) -> &FileAttr {
        let iref = self.inode_ref(inode, parent);
        self.attrs.insert(iref.ino(), iref.fileattr());
        self.attrs.get(&iref.ino()).unwrap()
    }
}

impl<ObjectID: FsVerityHashValue> Filesystem for TreeFuse<'_, ObjectID> {
    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: fuser::ReplyStatfs) {
        reply.statfs(0, 0, 0, 0, 0, 4096, 255, 4096);
    }

    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        log::trace!("lookup {parent} {name:?}");
        let Some(InodeRef::Directory(dir, ..)) = self.inodes.get(&parent) else {
            log::error!("lookup({parent}, {name:?}) parent does not exist");
            return reply.error(Errno::BADF.raw_os_error());
        };

        // dir is &&Directory which means it holds a reference to the image and also a reference to
        // self.  Dereference to drop the spurious self-reference to allow further mutability.
        let dir = *dir;

        match dir.lookup(name) {
            Some(inode) => reply.entry(&TTL, self.inode_fileattr(inode, parent), 0),
            None => reply.error(Errno::NOENT.raw_os_error()),
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        if let Some(attrs) = self.attrs.get(&ino) {
            return reply.attr(&TTL, attrs);
        }

        let Some(iref) = self.inodes.get(&ino) else {
            log::error!("getattr({ino}) inode does not exist");
            return reply.error(Errno::BADF.raw_os_error());
        };

        // iref is &InodeRef which means it holds a reference to self.  Drop that.
        let iref = iref.clone();

        reply.attr(&TTL, self.iref_fileattr(&iref));
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let Some(InodeRef::Leaf(leaf, ..)) = self.inodes.get(&ino) else {
            return reply.error(Errno::INVAL.raw_os_error());
        };

        let LeafContent::Symlink(target) = &leaf.content else {
            return reply.error(Errno::INVAL.raw_os_error());
        };

        reply.data(target.as_bytes());
    }

    fn opendir(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        mut offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let Some(InodeRef::Directory(dir, parent)) = self.inodes.get(&ino) else {
            log::error!("readdir({ino}) inode is not a directory");
            return reply.error(Errno::BADF.raw_os_error());
        };

        if offset == 0 {
            offset += 1;
            if reply.add(ino, offset, FileType::Directory, ".") {
                return reply.ok();
            }
        }

        if offset == 1 {
            offset += 1;
            if reply.add(*parent, offset, FileType::Directory, "..") {
                return reply.ok();
            }
        }

        for (name, inode) in dir.sorted_entries().skip(offset as usize - 2) {
            let iref = self.inode_ref(inode, ino);

            offset += 1;
            if reply.add(iref.ino(), offset, iref.kind(), name) {
                break;
            }
        }

        reply.ok();
    }

    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        reply: fuser::ReplyEmpty,
    ) {
        reply.ok();
    }

    fn getxattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        name: &OsStr,
        size: u32,
        reply: fuser::ReplyXattr,
    ) {
        let Some(iref) = self.inodes.get(&ino) else {
            log::error!("getxattr({ino}, {name:?}, {size}) inode does not exist");
            return reply.error(Errno::BADF.raw_os_error());
        };

        let xattrs = iref.stat().xattrs.borrow();
        let Some(value) = xattrs.get(name) else {
            return reply.error(Errno::NODATA.raw_os_error());
        };

        if size == 0 {
            return reply.size(value.len() as u32);
        } else if value.len() > size as usize {
            return reply.error(Errno::RANGE.raw_os_error());
        }

        reply.data(value);
    }

    fn listxattr(&mut self, _req: &Request<'_>, ino: u64, size: u32, reply: fuser::ReplyXattr) {
        let Some(iref) = self.inodes.get(&ino) else {
            log::error!("listxattr({ino}, {size}) inode does not exist");
            return reply.error(Errno::BADF.raw_os_error());
        };

        let mut list = vec![];
        for name in iref.stat().xattrs.borrow().keys() {
            list.extend_from_slice(name.as_bytes());
            list.push(b'\0');
        }

        if size == 0 {
            return reply.size(list.len() as u32);
        } else if list.len() > size as usize {
            return reply.error(Errno::RANGE.raw_os_error());
        }

        reply.data(&list);
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        log::trace!("open({ino})");
        let Some(iref) = self.inodes.get(&ino) else {
            log::error!("open({ino}) inode does not exist");
            return reply.error(Errno::BADF.raw_os_error());
        };

        let InodeRef::Leaf(leaf) = iref else {
            log::error!("open({ino}) inode is a directory");
            return reply.error(Errno::BADF.raw_os_error());
        };

        let handle = match &leaf.content {
            LeafContent::Regular(RegularFile::External(id, ..)) => {
                let Ok(fd) = self.repo.open_object(id) else {
                    log::error!("open({ino}) open object failed");
                    return reply.error(Errno::INVAL.raw_os_error());
                };
                OpenHandle::Fd(fd)
            }
            LeafContent::Regular(RegularFile::Inline(data)) => OpenHandle::Data(data.clone()),
            _ => {
                log::error!("open({ino}) non-regular file");
                return reply.error(Errno::BADF.raw_os_error());
            }
        };

        let fh = self.next_fh;
        self.next_fh += 1;
        log::debug!("self.handles.insert({fh}, {handle:?})");
        self.handles.insert(fh, handle);
        reply.opened(fh, 0);
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyData,
    ) {
        match self.handles.get(&fh) {
            Some(OpenHandle::Fd(fd)) => {
                let mut data = Vec::with_capacity(size as usize);
                match pread(fd, spare_capacity(&mut data), offset as u64) {
                    Ok(_) => reply.data(&data),
                    Err(errno) => reply.error(errno.raw_os_error()),
                }
            }
            Some(OpenHandle::Data(data)) => {
                if offset as usize > data.len() {
                    reply.data(b"");
                } else {
                    let mut data = &data[offset as usize..];
                    if data.len() > size as usize {
                        data = &data[..size as usize];
                    }
                    reply.data(data);
                }
            }
            None => {
                log::error!("Handle doesn't exist: pread({fh}, {size}, {offset})");
                reply.error(Errno::BADF.raw_os_error());
            }
        }
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        match self.handles.remove(&fh) {
            Some(_) => reply.ok(),
            None => {
                log::error!("Handle doesn't exist: close({fh})");
                reply.error(Errno::BADF.raw_os_error())
            }
        }
    }
}

/// Opens /dev/fuse.
///
/// After you do this, you can mount it using mount_fuse() and then start serving requests using
/// serve_tree_fuse().  You might want to do this in different threads, which is why these
/// operations are defined separately.
pub fn open_fuse() -> anyhow::Result<OwnedFd> {
    open("/dev/fuse", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
        .context("Unable to open fuse device /dev/fuse")
}

/// Mounts a FUSE filesystem with the given /dev/fuse fd.
///
/// This does the necessary dance of creating the mount object, given a /dev/fuse device node.  In
/// order for this to be useful, you'll also need to call serve_tree_fuse() to actually satisfy the
/// requests for data.
pub fn mount_fuse(dev_fuse: impl AsFd) -> anyhow::Result<OwnedFd> {
    let fusefs = FsHandle::open("fuse")?;
    fsconfig_set_flag(fusefs.as_fd(), "ro")?;
    fsconfig_set_flag(fusefs.as_fd(), "default_permissions")?;
    fsconfig_set_flag(fusefs.as_fd(), "allow_other")?;
    fsconfig_set_string(fusefs.as_fd(), "source", "composefs-fuse")?;
    fsconfig_set_string(fusefs.as_fd(), "rootmode", "040555")?;
    fsconfig_set_string(fusefs.as_fd(), "user_id", "0")?;
    fsconfig_set_string(fusefs.as_fd(), "group_id", "0")?;
    fsconfig_set_string(
        fusefs.as_fd(),
        "fd",
        format!("{}", dev_fuse.as_fd().as_raw_fd()),
    )?;
    fsconfig_create(fusefs.as_fd())?;
    Ok(fsmount(
        fusefs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )?)
}

/// Serves a FUSE filesystem exposing the content of `root`, backed by `repo`.
///
/// You should have called mount_fuse() on the dev_fuse fd to establish a mount point.
pub fn serve_tree_fuse<'a, ObjectID: FsVerityHashValue>(
    dev_fuse: OwnedFd,
    root: &'a Directory<ObjectID>,
    repo: &'a Repository<ObjectID>,
) -> std::io::Result<()> {
    let fs = TreeFuse::<ObjectID> {
        repo,
        inodes: HashMap::from([(1, InodeRef::Directory(root, 1))]),
        attrs: Default::default(),
        handles: Default::default(),
        next_fh: 1,
    };
    Session::from_fd(fs, dev_fuse, SessionACL::All).run()
}
