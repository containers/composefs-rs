//! SELinux security context labeling for filesystem trees.
//!
//! This module implements SELinux policy parsing and file labeling functionality.
//! It reads SELinux policy files (file_contexts, file_contexts.subs, etc.) and applies
//! appropriate security.selinux extended attributes to filesystem nodes. The implementation
//! uses regex automata for efficient pattern matching against file paths and types.

use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    fs::File,
    io::{BufRead, BufReader, Read},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use anyhow::{bail, ensure, Context, Result};
use regex_automata::{hybrid::dfa, util::syntax, Anchored, Input};

use composefs::{
    fsverity::FsVerityHashValue,
    repository::Repository,
    tree::{Directory, FileSystem, Inode, Leaf, LeafContent, RegularFile, Stat},
};

/* We build the entire SELinux policy into a single "lazy DFA" such that:
 *
 *  - the input string is the filename plus a single character representing the type of the file,
 *    using the 'file type' codes listed in selabel_file(5): 'b', 'c', 'd', 'p', 'l', 's', and '-'
 *
 *  - the output pattern ID is the index of the selected context
 *
 * The 'subs' mapping is handled as a hash table.  We consult it each time we enter a directory and
 * perform the substitution a single time at that point instead of doing it for each contained
 * file.
 *
 * We could maybe add a string table to deduplicate contexts to save memory (as they are often
 * repeated).  It's not an order-of-magnitude kind of gain, though, and it would increase code
 * complexity, and slightly decrease efficiency.
 *
 * Note: we are not 100% compatible with PCRE here, so it's theoretically possible that someone
 * could write a policy that we can't properly handle...
 */

fn process_subs_file(file: impl Read, aliases: &mut HashMap<OsString, OsString>) -> Result<()> {
    // r"\s*([^\s]+)\s+([^\s]+)\s*";
    for (line_nr, item) in BufReader::new(file).lines().enumerate() {
        let line = item?;
        let mut parts = line.split_whitespace();
        let alias = match parts.next() {
            None => continue, // empty line or line with only whitespace
            Some(comment) if comment.starts_with("#") => continue,
            Some(alias) => alias,
        };
        let Some(original) = parts.next() else {
            bail!("{line_nr}: missing original path");
        };
        ensure!(parts.next().is_none(), "{line_nr}: trailing data");

        aliases.insert(OsString::from(alias), OsString::from(original));
    }
    Ok(())
}

fn process_spec_file(
    file: impl Read,
    regexps: &mut Vec<String>,
    contexts: &mut Vec<String>,
) -> Result<()> {
    // r"\s*([^\s]+)\s+(?:-([-bcdpls])\s+)?([^\s]+)\s*";
    for (line_nr, item) in BufReader::new(file).lines().enumerate() {
        let line = item?;

        let mut parts = line.split_whitespace();
        let regex = match parts.next() {
            None => continue, // empty line or line with only whitespace
            Some(comment) if comment.starts_with("#") => continue,
            Some(regex) => regex,
        };

        /* TODO: https://github.com/rust-lang/rust/issues/51114
         *  match parts.next() {
         *      Some(opt) if let Some(ifmt) = opt.strip_prefix("-") => ...
         */
        let Some(next) = parts.next() else {
            bail!("{line_nr}: missing separator after regex");
        };
        if let Some(ifmt) = next.strip_prefix("-") {
            ensure!(
                ["b", "c", "d", "p", "l", "s", "-"].contains(&ifmt),
                "{line_nr}: invalid type code -{ifmt}"
            );
            let Some(context) = parts.next() else {
                bail!("{line_nr}: missing context field");
            };
            regexps.push(format!("^({regex}){ifmt}$"));
            contexts.push(context.to_string());
        } else {
            let context = next;
            regexps.push(format!("^({regex}).$"));
            contexts.push(context.to_string());
        }
        ensure!(parts.next().is_none(), "{line_nr}: trailing data");
    }

    Ok(())
}

struct Policy {
    aliases: HashMap<OsString, OsString>,
    dfa: dfa::DFA,
    cache: dfa::Cache,
    contexts: Vec<String>,
}

/// Open a file in the composefs store, handling inline vs external files.
pub fn openat<'a, H: FsVerityHashValue>(
    dir: &'a Directory<H>,
    filename: impl AsRef<OsStr>,
    repo: &Repository<H>,
) -> Result<Option<Box<dyn Read + 'a>>> {
    match dir.get_file_opt(filename.as_ref())? {
        Some(file) => match file {
            RegularFile::Inline(data) => Ok(Some(Box::new(&**data))),
            RegularFile::External(id, ..) => Ok(Some(Box::new(File::from(repo.open_object(id)?)))),
        },
        None => Ok(None),
    }
}

impl Policy {
    pub fn build<H: FsVerityHashValue>(dir: &Directory<H>, repo: &Repository<H>) -> Result<Self> {
        let mut aliases = HashMap::new();
        let mut regexps = vec![];
        let mut contexts = vec![];

        for suffix in ["", ".local", ".homedirs"] {
            if let Some(file) = openat(dir, format!("file_contexts{suffix}"), repo)? {
                process_spec_file(file, &mut regexps, &mut contexts)
                    .with_context(|| format!("SELinux spec file file_contexts{suffix}"))?;
            } else if suffix.is_empty() {
                bail!("SELinux policy is missing mandatory file_contexts file");
            }
        }

        for suffix in [".subs", ".subs_dist"] {
            if let Some(file) = openat(dir, format!("file_contexts{suffix}"), repo)? {
                process_subs_file(file, &mut aliases)
                    .with_context(|| format!("SELinux subs file file_contexts{suffix}"))?;
            }
        }

        // The DFA matches the first-found.  We want to match the last-found.
        regexps.reverse();
        contexts.reverse();

        let mut builder = dfa::Builder::new();
        builder.syntax(
            syntax::Config::new()
                .unicode(false)
                .utf8(false)
                .line_terminator(0),
        );
        builder.configure(
            dfa::Config::new()
                .cache_capacity(10_000_000)
                .skip_cache_capacity_check(true),
        );
        let dfa = builder.build_many(&regexps)?;
        let cache = dfa.create_cache();

        Ok(Policy {
            aliases,
            dfa,
            cache,
            contexts,
        })
    }

    pub fn check_aliased(&self, filename: &OsStr) -> Option<&OsStr> {
        self.aliases.get(filename).map(|x| x.as_os_str())
    }

    // mut because it touches the cache
    pub fn lookup(&mut self, filename: &OsStr, ifmt: u8) -> Option<&str> {
        let key = &[filename.as_bytes(), &[ifmt]].concat();
        let input = Input::new(&key).anchored(Anchored::Yes);

        match self
            .dfa
            .try_search_fwd(&mut self.cache, &input)
            .expect("regex troubles")
        {
            Some(halfmatch) => match self.contexts[halfmatch.pattern()].as_str() {
                "<<none>>" => None,
                ctx => Some(ctx),
            },
            None => None,
        }
    }
}

fn relabel(stat: &Stat, path: &Path, ifmt: u8, policy: &mut Policy) {
    let security_selinux = OsStr::new("security.selinux"); // no literal syntax for this yet
    let mut xattrs = stat.xattrs.borrow_mut();

    if let Some(label) = policy.lookup(path.as_os_str(), ifmt) {
        xattrs.insert(Box::from(security_selinux), Box::from(label.as_bytes()));
    } else {
        xattrs.remove(security_selinux);
    }
}

fn relabel_leaf<H: FsVerityHashValue>(leaf: &Leaf<H>, path: &Path, policy: &mut Policy) {
    let ifmt = match leaf.content {
        LeafContent::Regular(..) => b'-',
        LeafContent::Fifo => b'p', // NB: 'pipe', not 'fifo'
        LeafContent::Socket => b's',
        LeafContent::Symlink(..) => b'l',
        LeafContent::BlockDevice(..) => b'b',
        LeafContent::CharacterDevice(..) => b'c',
    };
    relabel(&leaf.stat, path, ifmt, policy);
}

fn relabel_inode<H: FsVerityHashValue>(inode: &Inode<H>, path: &mut PathBuf, policy: &mut Policy) {
    match inode {
        Inode::Directory(ref dir) => relabel_dir(dir, path, policy),
        Inode::Leaf(ref leaf) => relabel_leaf(leaf, path, policy),
    }
}

fn relabel_dir<H: FsVerityHashValue>(dir: &Directory<H>, path: &mut PathBuf, policy: &mut Policy) {
    relabel(&dir.stat, path, b'd', policy);

    for (name, inode) in dir.sorted_entries() {
        path.push(name);
        match policy.check_aliased(path.as_os_str()) {
            Some(original) => relabel_inode(inode, &mut PathBuf::from(original), policy),
            None => relabel_inode(inode, path, policy),
        }
        path.pop();
    }
}

fn parse_config(file: impl Read) -> Result<Option<String>> {
    for line in BufReader::new(file).lines() {
        if let Some((key, value)) = line?.split_once('=') {
            // this might be a comment, but then key will start with '#'
            if key.trim().eq_ignore_ascii_case("SELINUXTYPE") {
                return Ok(Some(value.trim().to_string()));
            }
        }
    }
    Ok(None)
}

pub fn selabel<H: FsVerityHashValue>(fs: &mut FileSystem<H>, repo: &Repository<H>) -> Result<()> {
    // if /etc/selinux/config doesn't exist then it's not an error
    let Some(etc_selinux) = fs.root.get_directory_opt("etc/selinux".as_ref())? else {
        return Ok(());
    };

    let Some(etc_selinux_config) = openat(etc_selinux, "config", repo)? else {
        return Ok(());
    };

    let Some(policy) = parse_config(etc_selinux_config)? else {
        return Ok(());
    };

    let dir = etc_selinux
        .get_directory(policy.as_ref())?
        .get_directory("contexts/files".as_ref())?;

    let mut policy = Policy::build(dir, repo)?;
    let mut path = PathBuf::from("/");
    relabel_dir(&fs.root, &mut path, &mut policy);
    Ok(())
}
