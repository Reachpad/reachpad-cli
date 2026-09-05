//! The snapshot: which files go up, and the bytes they go up as.
//!
//! Three separable pieces, in this order:
//!
//! 1. [`Excludes`] — `.reachpadignore` plus the four things that are excluded
//!    whatever the file says (`node_modules`, `.git`, `.env*`, and the
//!    `.reachpad/` bookkeeping directory). `reachpad.json` is deliberately NOT
//!    excluded: the manifest travels with the source so a `pull` into an empty
//!    folder produces a linked project.
//! 2. [`collect`] — the walk, with the per-file and per-tree limits API.md
//!    states (25 MiB a file, 5,000 files) enforced here rather than at the PUT,
//!    so `check` can refuse without a network round trip.
//! 3. [`tar_gz`] / [`untar_gz`] — ustar in, ustar out. Hand-written because
//!    ustar is 512-byte header blocks and nothing else; the gzip either side of
//!    it is flate2's.
//!
//! Nothing here follows a symlink. A snapshot is a tree of regular files with
//! relative paths, which is exactly what the front door will accept, and a
//! symlink is the shape that turns a tarball into a way to read `/etc/shadow`.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use crate::errors::CliError;

/// API.md: no single file over 25 MiB.
pub const MAX_FILE_BYTES: u64 = 25 * 1024 * 1024;
/// API.md: no more than 5,000 entries in a snapshot.
pub const MAX_FILES: usize = 5_000;
/// API.md: the gzipped tarball itself is at most 50 MiB.
pub const MAX_TARBALL_BYTES: u64 = 50 * 1024 * 1024;
/// The whole tree, UNCOMPRESSED, before anything is packed.
///
/// The per-file and per-count limits alone allow 5,000 x 25 MiB = 122 GiB, and
/// the 50 MiB ceiling is on the tarball, which is only known after the tree has
/// been read and compressed. Without this the answer to "you published your
/// video folder" was the allocator killing the process, not a sentence naming
/// the limit. 512 MiB is far above anything that compresses under 50 MiB and
/// far below anything that hurts.
pub const MAX_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;
/// The largest file a ustar size field can carry: 11 octal digits, so 8 GiB
/// minus one byte. Well above [`MAX_FILE_BYTES`]; this is the guard on
/// [`append`], which is public and does not go through [`collect`].
pub const MAX_USTAR_FILE_BYTES: u64 = (1u64 << 33) - 1;
/// The most a snapshot may EXPAND to on the way in. `untar_gz` reads bytes a
/// server chose; a 50 KiB gzip of zeros expands to gigabytes, and
/// `read_to_end` on it is an out-of-memory kill triggered by a `pull`.
const MAX_INFLATED_BYTES: u64 = 2 * MAX_SNAPSHOT_BYTES;
/// The ignore file, beside the manifest.
pub const IGNORE_FILE: &str = ".reachpadignore";
/// Where `pull` and `publish` record what the tree last agreed with, for
/// `sync`'s three-way comparison.
pub const BASE_DIR: &str = ".reachpad";

/// Excluded whatever `.reachpadignore` says. `node_modules` and `.git` are
/// weight and history; `.env*` is the file people keep their keys in and the
/// one thing that must never be uploaded by accident.
const ALWAYS: &[&str] = &["node_modules", ".git", ".env*", BASE_DIR];

// ---------------------------------------------------------------------------
// Which files
// ---------------------------------------------------------------------------

/// One ignore pattern, in the subset of gitignore syntax this needs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pattern {
    /// Matched against the whole relative path when the pattern had a `/` in
    /// its middle, and against each path component otherwise.
    anchored: bool,
    /// `build/` matches the directory and everything under it, never a file.
    dir_only: bool,
    text: String,
}

#[derive(Debug, Clone, Default)]
pub struct Excludes {
    patterns: Vec<Pattern>,
}

impl Excludes {
    /// The always-excluded set plus whatever `.reachpadignore` in `root` says.
    /// A missing ignore file is the common case, not an error.
    pub fn read(root: &Path) -> Result<Excludes, CliError> {
        let mut excludes = Excludes::default();
        for always in ALWAYS {
            excludes.push(always);
        }
        match std::fs::read_to_string(root.join(IGNORE_FILE)) {
            Ok(text) => {
                for line in text.lines() {
                    excludes.push(line);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(super::failure(format!(
                    "reading {}: {e}",
                    root.join(IGNORE_FILE).display()
                )))
            }
        }
        Ok(excludes)
    }

    fn push(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return;
        }
        let dir_only = line.ends_with('/');
        let trimmed = line.trim_end_matches('/');
        let trimmed = trimmed.strip_prefix('/').unwrap_or(trimmed);
        if trimmed.is_empty() {
            return;
        }
        self.patterns.push(Pattern {
            anchored: line.starts_with('/') || trimmed.contains('/'),
            dir_only,
            text: trimmed.to_owned(),
        });
    }

    /// Is this relative path excluded? `is_dir` decides whether a `build/`
    /// pattern applies.
    pub fn excludes(&self, relative: &str, is_dir: bool) -> bool {
        self.patterns.iter().any(|pattern| {
            if pattern.dir_only && !is_dir {
                return false;
            }
            if pattern.anchored {
                // `docs/build` also excludes `docs/build/index.html`.
                glob(&pattern.text, relative)
                    || relative
                        .strip_prefix(&pattern.text)
                        .is_some_and(|rest| rest.starts_with('/'))
            } else {
                relative.split('/').any(|part| glob(&pattern.text, part))
            }
        })
    }
}

/// `*` (any run of characters), `?` (one character), everything else literal.
/// No `**`: a pattern with a `/` is already matched against the whole path,
/// which is what `**` is normally reached for.
fn glob(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    // The classic two-pointer wildcard match: linear, no recursion, no
    // backtracking blow-up on `a*a*a*a*b`.
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut resume) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            pi += 1;
            resume = ti;
        } else if let Some(s) = star {
            pi = s + 1;
            resume += 1;
            ti = resume;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// One file destined for the snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Relative, `/`-separated, never starting with `/` and never holding `..`.
    pub path: String,
    pub bytes: u64,
}

/// Walk `root` and return the snapshot's files, sorted by path so two walks of
/// the same tree produce the same tarball.
pub fn collect(root: &Path, excludes: &Excludes) -> Result<Vec<Entry>, CliError> {
    let mut entries = Vec::new();
    walk(root, root, excludes, &mut entries)?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    enforce_limits(&entries)?;
    Ok(entries)
}

/// Every limit a snapshot has, checked on the walk's result and BEFORE a byte
/// is read, compressed or uploaded.
pub fn enforce_limits(entries: &[Entry]) -> Result<(), CliError> {
    if entries.len() > MAX_FILES {
        return Err(super::failure(format!(
            "this folder holds {} files and a snapshot takes at most {MAX_FILES}. \
             Add what does not belong in the app to {IGNORE_FILE}.",
            entries.len()
        )));
    }
    if let Some(big) = entries.iter().find(|e| e.bytes > MAX_FILE_BYTES) {
        return Err(super::failure(format!(
            "{} is {} and a single file may be at most 25 MiB.",
            big.path,
            human_bytes(big.bytes)
        )));
    }
    let total: u64 = entries.iter().map(|e| e.bytes).sum();
    if total > MAX_SNAPSHOT_BYTES {
        return Err(super::failure(format!(
            "this folder holds {} and a snapshot is packed in memory, so it is capped at \
             {}. Add what does not belong in the app to {IGNORE_FILE}.",
            human_bytes(total),
            human_bytes(MAX_SNAPSHOT_BYTES)
        )));
    }
    Ok(())
}

fn walk(
    root: &Path,
    dir: &Path,
    excludes: &Excludes,
    out: &mut Vec<Entry>,
) -> Result<(), CliError> {
    let listing = std::fs::read_dir(dir)
        .map_err(|e| super::failure(format!("reading {}: {e}", dir.display())))?;
    for item in listing {
        let item = item.map_err(|e| super::failure(format!("reading {}: {e}", dir.display())))?;
        let path = item.path();
        let Ok(relative) = path.strip_prefix(root) else {
            continue;
        };
        let Some(relative) = relative_str(relative) else {
            return Err(super::failure(format!(
                "{} is not a name a snapshot can carry (paths are UTF-8 and \
                 `/`-separated).",
                path.display()
            )));
        };
        // `symlink_metadata`, so a link to a directory is not descended into
        // and a link to a file is not read through.
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| super::failure(format!("reading {}: {e}", path.display())))?;
        if excludes.excludes(&relative, meta.is_dir()) {
            continue;
        }
        if meta.is_dir() {
            walk(root, &path, excludes, out)?;
        } else if meta.is_file() {
            out.push(Entry {
                path: relative,
                bytes: meta.len(),
            });
        }
        // Symlinks, sockets and devices are silently left behind: a snapshot
        // is a tree of regular files.
    }
    Ok(())
}

fn relative_str(relative: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(part) => parts.push(part.to_str()?.to_owned()),
            _ => return None,
        }
    }
    Some(parts.join("/"))
}

pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [(&str, u64); 3] = [("MiB", 1 << 20), ("KiB", 1 << 10), ("B", 1)];
    for (unit, size) in UNITS {
        if bytes >= size {
            return if size == 1 {
                format!("{bytes} B")
            } else {
                format!("{}.{} {unit}", bytes / size, (bytes % size) * 10 / size)
            };
        }
    }
    "0 B".to_owned()
}

// ---------------------------------------------------------------------------
// The tarball
// ---------------------------------------------------------------------------

const BLOCK: usize = 512;

/// Build the gzipped ustar tarball for `entries`, read from `root`.
///
/// Every header field a snapshot needs is deterministic — mode 0644, uid/gid 0,
/// mtime 0 — so publishing the same tree twice produces the same bytes and the
/// same `source_hash`. A modification time would make every publish a new
/// snapshot even when nothing changed.
pub fn tar_gz(root: &Path, entries: &[Entry]) -> Result<Vec<u8>, CliError> {
    enforce_limits(entries)?;
    // Straight into the encoder, one file at a time: the uncompressed tar is
    // never materialized, so the peak is the compressed output plus the single
    // largest file rather than the whole tree twice over.
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut block = Vec::with_capacity(BLOCK);
    for entry in entries {
        let path = root.join(entry.path.replace('/', std::path::MAIN_SEPARATOR_STR));
        let content = std::fs::read(&path)
            .map_err(|e| super::failure(format!("reading {}: {e}", path.display())))?;
        block.clear();
        append(&mut block, &entry.path, &content)?;
        encoder
            .write_all(&block)
            .map_err(|e| super::failure(format!("compressing the snapshot: {e}")))?;
    }
    encoder
        .write_all(&[0u8; BLOCK * 2])
        .and_then(|()| encoder.finish())
        .map_err(|e| super::failure(format!("compressing the snapshot: {e}")))
}

/// Append one ustar file entry. Public so tests can build a tarball without a
/// tree on disk.
pub fn append(tar: &mut Vec<u8>, path: &str, content: &[u8]) -> Result<(), CliError> {
    let (prefix, name) = split_name(path)?;
    // The ustar size field is 11 octal digits and a NUL. A file past that has
    // no representation here, and the old code wrote one digit too many over
    // the NUL (or panicked on the slice) rather than saying so.
    if content.len() as u64 > MAX_USTAR_FILE_BYTES {
        return Err(super::failure(format!(
            "{path} is {} and a ustar entry carries at most {}.",
            human_bytes(content.len() as u64),
            human_bytes(MAX_USTAR_FILE_BYTES)
        )));
    }
    let mut header = [0u8; BLOCK];
    write_field(&mut header[0..100], name.as_bytes());
    write_octal(&mut header[100..108], 0o644, 7)?;
    write_octal(&mut header[108..116], 0, 7)?; // uid
    write_octal(&mut header[116..124], 0, 7)?; // gid
    write_octal(&mut header[124..136], content.len() as u64, 11)?;
    write_octal(&mut header[136..148], 0, 11)?; // mtime
    header[156] = b'0'; // typeflag: a regular file
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    write_field(&mut header[345..500], prefix.as_bytes());
    // The checksum is computed with its own field read as eight spaces.
    header[148..156].fill(b' ');
    let sum: u32 = header.iter().map(|b| u32::from(*b)).sum();
    write_octal(&mut header[148..154], u64::from(sum), 6)?;
    header[154] = 0;
    header[155] = b' ';

    tar.extend_from_slice(&header);
    tar.extend_from_slice(content);
    let padding = (BLOCK - content.len() % BLOCK) % BLOCK;
    tar.extend(std::iter::repeat_n(0u8, padding));
    Ok(())
}

/// ustar carries a path as `prefix` + `/` + `name`, 155 and 100 bytes. A path
/// that fits neither is refused by name rather than silently truncated.
fn split_name(path: &str) -> Result<(&str, &str), CliError> {
    if path.len() <= 100 {
        return Ok(("", path));
    }
    // The longest prefix that leaves a name of at most 100 bytes.
    if let Some(cut) = path
        .match_indices('/')
        .map(|(at, _)| at)
        .find(|at| path.len() - at - 1 <= 100 && *at <= 155)
    {
        return Ok((&path[..cut], &path[cut + 1..]));
    }
    Err(super::failure(format!(
        "{path} is too long for a snapshot (a path is at most 100 characters, or 155 \
         of folders and 100 of file name)."
    )))
}

fn write_field(field: &mut [u8], value: &[u8]) {
    field[..value.len()].copy_from_slice(value);
}

/// Write `value` as a NUL-terminated octal string into a ustar header field.
///
/// Fallible rather than panicking: `field[..text.len()]` on a value too wide
/// for its field is a slice out of range, and one digit too many silently eats
/// the terminator. Both are reachable from [`append`], which is public.
fn write_octal(field: &mut [u8], value: u64, digits: usize) -> Result<(), CliError> {
    let text = format!("{value:0digits$o}");
    if text.len() > digits || digits > field.len() {
        return Err(super::failure(format!(
            "{value} does not fit a {}-byte ustar header field",
            field.len()
        )));
    }
    field[..text.len()].copy_from_slice(text.as_bytes());
    // The checksum field is six digits in a six-byte slice and carries its
    // terminator outside it; every other field has room for one.
    if text.len() < field.len() {
        field[text.len()] = 0;
    }
    Ok(())
}

/// The other direction: gunzip and read a ustar tarball back into
/// path → content. Refuses absolute paths, `..` and anything but a regular
/// file, because extracting a snapshot writes to a person's disk.
pub fn untar_gz(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, CliError> {
    untar_gz_capped(bytes, MAX_INFLATED_BYTES)
}

/// [`untar_gz`] with the ceiling spelled out, so the refusal can be tested
/// without building a gigabyte of zeros.
fn untar_gz_capped(bytes: &[u8], cap: u64) -> Result<BTreeMap<String, Vec<u8>>, CliError> {
    let mut tar = Vec::new();
    // `take(cap + 1)`, so hitting the ceiling is distinguishable from a
    // snapshot that happens to be exactly the ceiling.
    flate2::read::GzDecoder::new(bytes)
        .take(cap.saturating_add(1))
        .read_to_end(&mut tar)
        .map_err(|e| super::failure(format!("this is not a gzipped snapshot ({e})")))?;
    if tar.len() as u64 > cap {
        return Err(super::failure(format!(
            "this snapshot expands past {} and was not written to disk.",
            human_bytes(cap)
        )));
    }
    let mut files = BTreeMap::new();
    let mut at = 0usize;
    while at + BLOCK <= tar.len() {
        let header = &tar[at..at + BLOCK];
        if header.iter().all(|b| *b == 0) {
            break;
        }
        at += BLOCK;
        let name = field_str(&header[0..100]);
        let prefix = field_str(&header[345..500]);
        let size = read_octal(&header[124..136])?;
        let typeflag = header[156];
        let size = usize::try_from(size)
            .map_err(|_| super::failure("a snapshot entry claims an impossible size"))?;
        if at + size > tar.len() {
            return Err(super::failure("the snapshot is truncated"));
        }
        // '0' and NUL are both spellings of "regular file"; '5' is a directory,
        // which carries no bytes and is recreated by the extraction anyway.
        if matches!(typeflag, b'0' | 0) {
            let path = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            check_extract_path(&path)?;
            files.insert(path, tar[at..at + size].to_vec());
        }
        at += size + (BLOCK - size % BLOCK) % BLOCK;
    }
    Ok(files)
}

/// The rule for every path that comes off the network before it names a file
/// on this machine.
pub fn check_extract_path(path: &str) -> Result<(), CliError> {
    let bad = path.is_empty()
        || path.starts_with('/')
        || path.starts_with("./")
        || path.contains('\\')
        || path.split('/').any(|part| part == ".." || part.is_empty());
    if bad {
        return Err(super::failure(format!(
            "the snapshot names a file this CLI will not write: {path:?}"
        )));
    }
    Ok(())
}

fn field_str(field: &[u8]) -> String {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

fn read_octal(field: &[u8]) -> Result<u64, CliError> {
    let text = field_str(field);
    let text = text.trim().trim_end_matches('\0');
    if text.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(text, 8)
        .map_err(|_| super::failure("a snapshot entry has an unreadable size"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("reach-pack-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(root: &Path, path: &str, content: &str) {
        let full = root.join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, content).unwrap();
    }

    #[test]
    fn the_four_always_excluded_things_are_excluded_and_the_manifest_is_not() {
        let root = scratch("always");
        write(&root, "index.html", "<h1>hi</h1>");
        write(&root, "reachpad.json", "{}");
        write(&root, ".env", "SECRET=1");
        write(&root, ".env.local", "SECRET=2");
        write(&root, ".git/config", "[core]");
        write(&root, "node_modules/left-pad/index.js", "module.exports=1");
        write(&root, ".reachpad/base/files.json", "{}");
        let files = collect(&root, &Excludes::read(&root).unwrap()).unwrap();
        let paths: Vec<&str> = files.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["index.html", "reachpad.json"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reachpadignore_takes_names_folders_and_globs() {
        let root = scratch("ignore");
        write(
            &root,
            IGNORE_FILE,
            "# a comment\n\ndist/\n*.log\n/only-at-root\nsrc/gen\n",
        );
        write(&root, "index.html", "x");
        write(&root, "dist/bundle.js", "x");
        write(&root, "app.log", "x");
        write(&root, "logs/app.log", "x");
        write(&root, "only-at-root", "x");
        write(&root, "nested/only-at-root", "x");
        write(&root, "src/gen/a.js", "x");
        write(&root, "src/keep.js", "x");
        let files = collect(&root, &Excludes::read(&root).unwrap()).unwrap();
        let paths: Vec<&str> = files.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                ".reachpadignore",
                "index.html",
                "nested/only-at-root",
                "src/keep.js"
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_directory_pattern_never_matches_a_file_of_that_name() {
        let excludes = {
            let mut e = Excludes::default();
            e.push("build/");
            e
        };
        assert!(excludes.excludes("build", true));
        assert!(!excludes.excludes("build", false));
        assert!(excludes.excludes("src/build", true));
    }

    #[test]
    fn globbing_is_the_usual_star_and_question_mark() {
        assert!(glob("*.log", "app.log"));
        assert!(!glob("*.log", "app.log.gz"));
        assert!(glob(".env*", ".env"));
        assert!(glob(".env*", ".env.production"));
        assert!(glob("a?c", "abc"));
        assert!(!glob("a?c", "ac"));
        assert!(glob("*", "anything"));
        // The pathological pattern the two-pointer matcher exists for.
        assert!(!glob("a*a*a*a*a*a*b", &"a".repeat(40)));
    }

    #[test]
    fn a_tarball_round_trips_through_gzip_and_back() {
        let root = scratch("tar");
        write(&root, "index.html", "<h1>Todo</h1>");
        write(&root, "assets/app.css", "body{margin:0}");
        // A path that needs the ustar prefix field, not the name field.
        let deep = format!("{}/deep.txt", ["folder"; 12].join("/"));
        write(&root, &deep, "deep");
        let entries = collect(&root, &Excludes::read(&root).unwrap()).unwrap();
        let bytes = tar_gz(&root, &entries).unwrap();
        // It really is gzip: the two magic bytes, then the deflate stream.
        assert_eq!(&bytes[..2], &[0x1f, 0x8b]);
        let back = untar_gz(&bytes).unwrap();
        assert_eq!(back.len(), 3);
        assert_eq!(back["index.html"], b"<h1>Todo</h1>");
        assert_eq!(back["assets/app.css"], b"body{margin:0}");
        assert_eq!(back[&deep], b"deep");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_ustar_header_is_one_gnu_tar_would_accept() {
        let mut tar = Vec::new();
        append(&mut tar, "index.html", b"hi").unwrap();
        assert_eq!(&tar[257..263], b"ustar\0");
        assert_eq!(&tar[263..265], b"00");
        assert_eq!(tar[156], b'0');
        // The checksum in the header equals the one computed over it.
        let stored = read_octal(&tar[148..156]).unwrap();
        let mut blanked = tar[..BLOCK].to_vec();
        blanked[148..156].fill(b' ');
        let sum: u32 = blanked.iter().map(|b| u32::from(*b)).sum();
        assert_eq!(stored, u64::from(sum));
        // Content is padded to the block size, so the next header is aligned.
        assert_eq!(tar.len(), BLOCK * 2);
    }

    #[test]
    fn extraction_refuses_every_path_that_escapes_the_tree() {
        for bad in [
            "/etc/passwd",
            "../outside",
            "a/../../b",
            "./a",
            "a//b",
            "a\\b",
            "",
        ] {
            assert!(check_extract_path(bad).is_err(), "{bad:?}");
        }
        for good in ["index.html", "a/b/c.js", ".reachpadignore"] {
            assert!(check_extract_path(good).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn a_symlink_is_left_out_rather_than_followed() {
        let root = scratch("symlink");
        write(&root, "index.html", "x");
        std::os::unix::fs::symlink("/etc/passwd", root.join("passwd")).unwrap();
        std::os::unix::fs::symlink("/etc", root.join("etc")).unwrap();
        let files = collect(&root, &Excludes::read(&root).unwrap()).unwrap();
        let paths: Vec<&str> = files.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["index.html"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The per-file and per-count limits together allow 122 GiB, and the only
    /// other ceiling was on the COMPRESSED tarball — known after the whole tree
    /// had been read into one `Vec` and gzipped into another. A tree of a few
    /// gigabytes therefore met the allocator rather than a sentence.
    #[test]
    fn a_tree_too_big_to_pack_is_refused_by_size_before_it_is_packed() {
        let tree = |count: usize| -> Vec<Entry> {
            (0..count)
                .map(|i| Entry {
                    path: format!("asset-{i}.bin"),
                    bytes: MAX_FILE_BYTES,
                })
                .collect()
        };
        // 20 x 25 MiB = 500 MiB: every per-file limit met, under the ceiling.
        assert!(enforce_limits(&tree(20)).is_ok());
        // 21 of the same: still every per-file limit met, 525 MiB in total.
        let refusal = enforce_limits(&tree(21)).unwrap_err();
        assert!(refusal.message.contains("512.0 MiB"), "{}", refusal.message);
        assert!(refusal.message.contains(IGNORE_FILE), "{}", refusal.message);
    }

    /// A gzip of zeros is tiny and expands without bound. `pull` hands whatever
    /// the server sent straight to the decoder, so the ceiling is the only
    /// thing between a hostile (or wrong) origin and an out-of-memory kill.
    #[test]
    fn a_snapshot_that_expands_without_bound_is_refused_rather_than_read() {
        use std::io::Write as _;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&vec![0u8; 4 * 1024 * 1024]).unwrap();
        let bomb = encoder.finish().unwrap();
        // Small on the wire, enormous once inflated.
        assert!(bomb.len() < 64 * 1024, "{} bytes", bomb.len());
        let refusal = untar_gz_capped(&bomb, 64 * 1024).unwrap_err();
        assert!(
            refusal.message.contains("expands past"),
            "{}",
            refusal.message
        );
        // The control: a real snapshot under the ceiling still reads.
        let mut tar = Vec::new();
        append(&mut tar, "index.html", b"hi").unwrap();
        tar.extend_from_slice(&[0u8; BLOCK * 2]);
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar).unwrap();
        let good = encoder.finish().unwrap();
        assert_eq!(
            untar_gz_capped(&good, 64 * 1024).unwrap()["index.html"],
            b"hi"
        );
    }

    /// The ustar size field is 11 octal digits and a NUL. `write_octal` wrote
    /// `field[..text.len()]` with no check: 8 GiB took the terminator, and 64
    /// GiB panicked on the slice. Both are reachable through `append`, which is
    /// public and does not go through `collect`'s 25 MiB limit.
    #[test]
    fn a_header_field_too_small_for_its_value_is_a_refusal_and_not_a_panic() {
        let mut field = [0u8; 12];
        assert!(write_octal(&mut field, 25 * 1024 * 1024, 11).is_ok());
        assert_eq!(field[11], 0, "the terminator survives a normal value");
        // The checksum's six digits in a six-byte field still write.
        assert!(write_octal(&mut [0u8; 6], 0o377100, 6).is_ok());
        // 8 GiB: twelve octal digits, which used to overwrite the NUL.
        assert!(write_octal(&mut field, 1u64 << 33, 11).is_err());
        // 64 GiB: thirteen, which used to panic on the slice.
        assert!(write_octal(&mut field, 1u64 << 36, 11).is_err());
    }

    #[test]
    fn a_file_over_the_limit_is_refused_by_name_before_anything_is_uploaded() {
        let root = scratch("toobig");
        let big = vec![b'x'; (MAX_FILE_BYTES + 1) as usize];
        std::fs::write(root.join("big.bin"), &big).unwrap();
        let refusal = collect(&root, &Excludes::read(&root).unwrap()).unwrap_err();
        assert!(refusal.message.contains("big.bin"), "{}", refusal.message);
        assert!(refusal.message.contains("25 MiB"), "{}", refusal.message);
        let _ = std::fs::remove_dir_all(&root);
    }
}
