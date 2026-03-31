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
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use anyhow::Context;
use fuser::{
    Config, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo, OpenFlags,
    ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyOpen, Request, Session,
};
use rustix::{
    buffer::spare_capacity,
    fs::{open, Mode, OFlags},
    io::pread,
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
enum InodeRef<ObjectID: FsVerityHashValue> {
    Directory(Arc<Directory<ObjectID>>, u64),
    Leaf(Arc<Leaf<ObjectID>>),
}

#[derive(Debug)]
enum OpenHandle {
    Fd(OwnedFd),
    Data(Box<[u8]>),
}

impl<ObjectID: FsVerityHashValue> InodeRef<ObjectID> {
    fn new(inode: &Inode<ObjectID>, parent: u64) -> Self {
        match inode {
            Inode::Directory(dir) => InodeRef::Directory(Arc::clone(dir), parent),
            Inode::Leaf(leaf) => InodeRef::Leaf(Arc::clone(leaf)),
        }
    }

    fn ino(&self) -> u64 {
        match self {
            InodeRef::Directory(dir, ..) => Arc::as_ptr(dir) as u64,
            InodeRef::Leaf(leaf) => Arc::as_ptr(leaf) as u64,
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
            InodeRef::Leaf(leaf) => Arc::strong_count(leaf),
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

    fn stat(&self) -> &Stat {
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
            ino: INodeNo(self.ino()),
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

/// Mutable state for the FUSE filesystem, protected by a Mutex since fuser 0.17
/// requires `Filesystem` methods to take `&self` (not `&mut self`).
#[derive(Debug)]
struct TreeFuseState<ObjectID: FsVerityHashValue> {
    inodes: HashMap<u64, InodeRef<ObjectID>>,
    attrs: HashMap<u64, FileAttr>,
    handles: HashMap<u64, OpenHandle>,
    next_fh: u64,
}

#[derive(Debug)]
struct TreeFuse<ObjectID: FsVerityHashValue> {
    repo: Arc<Repository<ObjectID>>,
    state: Mutex<TreeFuseState<ObjectID>>,
}

impl<ObjectID: FsVerityHashValue> TreeFuse<ObjectID> {
    fn inode_ref(
        state: &mut TreeFuseState<ObjectID>,
        inode: &Inode<ObjectID>,
        parent: u64,
    ) -> InodeRef<ObjectID> {
        let iref = InodeRef::new(inode, parent);
        state.inodes.insert(iref.ino(), iref.clone());
        iref
    }

    fn iref_fileattr(state: &mut TreeFuseState<ObjectID>, iref: &InodeRef<ObjectID>) -> FileAttr {
        let attr = iref.fileattr();
        state.attrs.insert(iref.ino(), attr);
        attr
    }

    fn inode_fileattr(
        state: &mut TreeFuseState<ObjectID>,
        inode: &Inode<ObjectID>,
        parent: u64,
    ) -> FileAttr {
        let iref = Self::inode_ref(state, inode, parent);
        let attr = iref.fileattr();
        state.attrs.insert(iref.ino(), attr);
        attr
    }
}

impl<ObjectID: FsVerityHashValue> Filesystem for TreeFuse<ObjectID> {
    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: fuser::ReplyStatfs) {
        reply.statfs(0, 0, 0, 0, 0, 4096, 255, 4096);
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let parent = parent.0;
        log::trace!("lookup {parent} {name:?}");
        let mut state = self.state.lock().unwrap();

        // Clone the directory Arc to release the borrow on state
        let dir = match state.inodes.get(&parent) {
            Some(InodeRef::Directory(dir, ..)) => Arc::clone(dir),
            _ => {
                log::error!(
                    "lookup({parent}, {name:?}) parent does not exist or is not a directory"
                );
                return reply.error(fuser::Errno::EBADF);
            }
        };

        match dir.lookup(name) {
            Some(inode) => {
                let attr = Self::inode_fileattr(&mut state, inode, parent);
                reply.entry(&TTL, &attr, Generation(0));
            }
            None => reply.error(fuser::Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let ino = ino.0;
        let mut state = self.state.lock().unwrap();
        if let Some(attrs) = state.attrs.get(&ino) {
            return reply.attr(&TTL, attrs);
        }

        let Some(iref) = state.inodes.get(&ino) else {
            log::error!("getattr({ino}) inode does not exist");
            return reply.error(fuser::Errno::EBADF);
        };

        // Clone to release the borrow on state
        let iref = iref.clone();
        let attr = Self::iref_fileattr(&mut state, &iref);
        reply.attr(&TTL, &attr);
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let ino = ino.0;
        let state = self.state.lock().unwrap();
        let Some(InodeRef::Leaf(leaf)) = state.inodes.get(&ino) else {
            return reply.error(fuser::Errno::EINVAL);
        };

        let LeafContent::Symlink(target) = &leaf.content else {
            return reply.error(fuser::Errno::EINVAL);
        };

        reply.data(target.as_bytes());
    }

    fn opendir(&self, _req: &Request, _ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        reply.opened(FileHandle(0), FopenFlags::empty());
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        mut offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let ino = ino.0;
        let mut state = self.state.lock().unwrap();

        // Clone the directory Arc and parent to release the borrow on state
        let (dir, parent) = match state.inodes.get(&ino) {
            Some(InodeRef::Directory(dir, parent)) => (Arc::clone(dir), *parent),
            _ => {
                log::error!("readdir({ino}) inode is not a directory");
                return reply.error(fuser::Errno::EBADF);
            }
        };

        if offset == 0 {
            offset += 1;
            if reply.add(INodeNo(ino), offset, FileType::Directory, ".") {
                return reply.ok();
            }
        }

        if offset == 1 {
            offset += 1;
            if reply.add(INodeNo(parent), offset, FileType::Directory, "..") {
                return reply.ok();
            }
        }

        for (name, inode) in dir.sorted_entries().skip(offset as usize - 2) {
            let iref = Self::inode_ref(&mut state, inode, ino);

            offset += 1;
            if reply.add(INodeNo(iref.ino()), offset, iref.kind(), name) {
                break;
            }
        }

        reply.ok();
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        reply: fuser::ReplyEmpty,
    ) {
        reply.ok();
    }

    fn getxattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        name: &OsStr,
        size: u32,
        reply: fuser::ReplyXattr,
    ) {
        let ino = ino.0;
        let state = self.state.lock().unwrap();
        let Some(iref) = state.inodes.get(&ino) else {
            log::error!("getxattr({ino}, {name:?}, {size}) inode does not exist");
            return reply.error(fuser::Errno::EBADF);
        };

        let xattrs = iref.stat().xattrs.read().unwrap();
        let Some(value) = xattrs.get(name) else {
            return reply.error(fuser::Errno::ENODATA);
        };

        if size == 0 {
            return reply.size(value.len() as u32);
        } else if value.len() > size as usize {
            return reply.error(fuser::Errno::ERANGE);
        }

        reply.data(value);
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: fuser::ReplyXattr) {
        let ino = ino.0;
        let state = self.state.lock().unwrap();
        let Some(iref) = state.inodes.get(&ino) else {
            log::error!("listxattr({ino}, {size}) inode does not exist");
            return reply.error(fuser::Errno::EBADF);
        };

        let mut list = vec![];
        for name in iref.stat().xattrs.read().unwrap().keys() {
            list.extend_from_slice(name.as_bytes());
            list.push(b'\0');
        }

        if size == 0 {
            return reply.size(list.len() as u32);
        } else if list.len() > size as usize {
            return reply.error(fuser::Errno::ERANGE);
        }

        reply.data(&list);
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let ino = ino.0;
        log::trace!("open({ino})");
        let mut state = self.state.lock().unwrap();

        // Clone the leaf Arc to release the borrow on state
        let leaf = match state.inodes.get(&ino) {
            Some(InodeRef::Leaf(leaf)) => Arc::clone(leaf),
            Some(_) => {
                log::error!("open({ino}) inode is a directory");
                return reply.error(fuser::Errno::EBADF);
            }
            None => {
                log::error!("open({ino}) inode does not exist");
                return reply.error(fuser::Errno::EBADF);
            }
        };

        let handle = match &leaf.content {
            LeafContent::Regular(RegularFile::External(id, ..)) => {
                let Ok(fd) = self.repo.open_object(id) else {
                    log::error!("open({ino}) open object failed");
                    return reply.error(fuser::Errno::EINVAL);
                };
                OpenHandle::Fd(fd)
            }
            LeafContent::Regular(RegularFile::Inline(data)) => OpenHandle::Data(data.clone()),
            _ => {
                log::error!("open({ino}) non-regular file");
                return reply.error(fuser::Errno::EBADF);
            }
        };

        let fh = state.next_fh;
        state.next_fh += 1;
        log::debug!("state.handles.insert({fh}, {handle:?})");
        state.handles.insert(fh, handle);
        reply.opened(FileHandle(fh), FopenFlags::empty());
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: fuser::ReplyData,
    ) {
        let fh = fh.0;
        let state = self.state.lock().unwrap();
        match state.handles.get(&fh) {
            Some(OpenHandle::Fd(fd)) => {
                let mut data = Vec::with_capacity(size as usize);
                match pread(fd, spare_capacity(&mut data), offset) {
                    Ok(_) => reply.data(&data),
                    Err(errno) => reply.error(fuser::Errno::from_i32(errno.raw_os_error())),
                }
            }
            Some(OpenHandle::Data(data)) => {
                let offset = offset as usize;
                if offset > data.len() {
                    reply.data(b"");
                } else {
                    let mut data = &data[offset..];
                    if data.len() > size as usize {
                        data = &data[..size as usize];
                    }
                    reply.data(data);
                }
            }
            None => {
                log::error!("Handle doesn't exist: pread({fh}, {size}, {offset})");
                reply.error(fuser::Errno::EBADF);
            }
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        let fh = fh.0;
        let mut state = self.state.lock().unwrap();
        match state.handles.remove(&fh) {
            Some(_) => reply.ok(),
            None => {
                log::error!("Handle doesn't exist: close({fh})");
                reply.error(fuser::Errno::EBADF)
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
pub fn serve_tree_fuse<ObjectID: FsVerityHashValue>(
    dev_fuse: OwnedFd,
    root: Arc<Directory<ObjectID>>,
    repo: Arc<Repository<ObjectID>>,
) -> std::io::Result<()> {
    let root_ref = InodeRef::Directory(root, 1);
    let root_ino = root_ref.ino();
    let fs = TreeFuse::<ObjectID> {
        repo,
        state: Mutex::new(TreeFuseState {
            inodes: HashMap::from([(root_ino, root_ref)]),
            attrs: Default::default(),
            handles: Default::default(),
            next_fh: 1,
        }),
    };
    let session = Session::from_fd(fs, dev_fuse, fuser::SessionACL::All, Config::default())?;
    session.spawn()?.join()
}
