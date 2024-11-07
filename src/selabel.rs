use std::{
    ffi::{c_char, c_int, c_uint, c_void, CStr, CString, OsStr, OsString},
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    rc::Rc,
};

use anyhow::{Context, Result};
use rustix::fs::FileType;
use tempfile::TempDir;

use crate::{
    fs::write_to_path,
    image::{DirEnt, Directory, FileSystem, Inode, Leaf, LeafContent, Stat},
    repository::Repository,
};

#[repr(C)]
struct SelinuxOpt {
    key: c_int,
    value: *const c_char,
}

const SELABEL_OPT_PATH: c_int = 3;
const SELABEL_CTX_FILE: c_uint = 0;

#[link(name = "selinux")]
unsafe extern "C" {
    fn selabel_open(backend: c_uint, opts: *const SelinuxOpt, n_opts: c_uint) -> *mut c_void;
    fn selabel_close(handle: *mut c_void);
    fn selabel_lookup(
        handle: *mut c_void,
        context: *mut *mut c_char,
        key: *const c_char,
        r#type: c_int,
    ) -> c_int;
    fn freecon(con: *mut c_char);
}

struct Label {
    ctx: *mut c_char,
}

impl Label {
    fn get(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.ctx) }
    }

    fn as_bytes(&self) -> &[u8] {
        self.get().to_bytes()
    }
}

impl Drop for Label {
    fn drop(&mut self) {
        unsafe { freecon(self.ctx) }
    }
}

struct Handle {
    #[expect(dead_code)] // we only have this here to keep it alive
    policy_dir: TempDir,
    handle: *mut c_void,
}

impl Handle {
    fn new(policy: &Directory, repo: &Repository) -> Result<Self> {
        let policy_dir = TempDir::new()?;
        let path = policy_dir.path();
        write_to_path(repo, policy, &path)?;

        let path_c = CString::new(path.join("file_contexts").as_os_str().as_bytes())
            .expect("TempDir::path() return an invalid path?");
        let opt = SelinuxOpt {
            key: SELABEL_OPT_PATH,
            value: path_c.as_ptr(),
        };

        unsafe {
            let handle = selabel_open(SELABEL_CTX_FILE, &opt, 1);
            if handle.is_null() {
                Err(std::io::Error::last_os_error()).context("selabel_open")
            } else {
                Ok(Handle { handle, policy_dir })
            }
        }
    }

    fn lookup(&self, key: impl AsRef<OsStr>, ifmt: FileType) -> Result<Option<Label>> {
        let c_key = CString::new(key.as_ref().as_bytes())?;
        let mut ctx: *mut c_char = core::ptr::null_mut();
        unsafe {
            if selabel_lookup(
                self.handle,
                &mut ctx,
                c_key.as_ptr(),
                ifmt.as_raw_mode() as i32,
            ) != 0
            {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::NotFound {
                    Ok(None)
                } else {
                    Err(error)
                        .with_context(|| format!("Unable to find policy for {ifmt:?} {c_key:?}"))
                }
            } else {
                Ok(Some(Label { ctx }))
            }
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { selabel_close(self.handle) }
    }
}

fn relabel(stat: &mut Stat, path: &PathBuf, ifmt: FileType, policy: &Handle) -> Result<()> {
    if let Some(label) = policy.lookup(&path, ifmt)? {
        stat.xattrs.push((
            OsString::from("security.selinux"),
            Vec::from(label.as_bytes()),
        ))
    }
    Ok(())
}

fn relabel_leaf(leaf: &mut Leaf, path: &PathBuf, policy: &Handle) -> Result<()> {
    let ifmt = match leaf.content {
        LeafContent::InlineFile(..) | LeafContent::ExternalFile(..) => FileType::RegularFile,
        LeafContent::Fifo => FileType::Fifo,
        LeafContent::Socket => FileType::Socket,
        LeafContent::Symlink(..) => FileType::Symlink,
        LeafContent::BlockDevice(..) => FileType::BlockDevice,
        LeafContent::CharacterDevice(..) => FileType::CharacterDevice,
    };
    relabel(&mut leaf.stat, path, ifmt, policy)
}

fn relabel_dir(dir: &mut Directory, path: &mut PathBuf, policy: &Handle) -> Result<()> {
    relabel(&mut dir.stat, path, FileType::Directory, policy)?;

    for DirEnt { name, inode } in dir.entries.iter_mut() {
        path.push(name);
        match inode {
            Inode::Directory(ref mut dir) => {
                relabel_dir(dir.as_mut(), path, policy)?;
            }
            Inode::Leaf(ref mut leaf) => {
                // hardlinks make life difficult here but we can be kinda sure this is safe, no?
                // perhaps we need Rc<RefCell<Leaf>> or unsafe or something else...
                let ptr = Rc::as_ptr(leaf);
                unsafe {
                    let mut_ptr = ptr as *mut Leaf;
                    relabel_leaf(&mut *mut_ptr, path, policy)?;
                }
            }
        }
        path.pop();
    }
    Ok(())
}

pub fn selabel(fs: &mut FileSystem, repo: &Repository) -> Result<()> {
    let policy = fs
        .root
        .recurse(OsStr::new("etc"))?
        .recurse(OsStr::new("selinux"))?
        .recurse(OsStr::new("targeted"))?
        .recurse(OsStr::new("contexts"))?
        .recurse(OsStr::new("files"))?;

    let handle = Handle::new(&policy, repo)?;
    let mut path = PathBuf::from("/");
    relabel_dir(&mut fs.root, &mut path, &handle)
}
