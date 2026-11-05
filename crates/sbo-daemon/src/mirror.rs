//! The filesystem mirror layout (audit 2026-11 Q24 / D21 / D58).
//!
//! The state DB is authoritative; the mirror is a best-effort, human-readable
//! view of the repository. Its layout is collision-free: an object and a
//! collection with the same name at the same parent can never claim one
//! filesystem entry, and a temp file can never collide with an object.
//!
//! ```text
//! object     /c/x        ->  <repo>/c.d/x
//! collection /c/x/       ->  <repo>/c.d/x.d/
//! object     /c/x.d      ->  <repo>/c.d/x%2Ed    (only a trailing `.d` is escaped)
//! temp file for <name>   ->  <name>%tmp
//! ```
//!
//! Every path segment and id has already passed the identifier grammar
//! (`sbo_types::Id`), which rejects `.` and `..`, so no segment can escape
//! the repo root. `%` is not an id character, so the two escapes above are
//! unambiguous and the encoding is injective.

use sbo_core::message::Path;
use std::path::{Path as FsPath, PathBuf};

/// Directory suffix for a collection segment.
pub const COLLECTION_SUFFIX: &str = ".d";
/// Escaped form of a trailing `.d` on an object file name.
const ESCAPED_DOT_D: &str = "%2Ed";
/// Temp-file suffix (never a valid object file name).
const TEMP_SUFFIX: &str = "%tmp";

/// The file name of an object with id `id`.
pub fn object_file_name(id: &str) -> String {
    match id.strip_suffix(COLLECTION_SUFFIX) {
        Some(stem) => format!("{stem}{ESCAPED_DOT_D}"),
        None => id.to_string(),
    }
}

/// The id of the object stored at file name `name`, or `None` for a
/// collection directory or a temp file.
pub fn object_id_from_file_name(name: &str) -> Option<String> {
    if name.ends_with(COLLECTION_SUFFIX) || name.ends_with(TEMP_SUFFIX) {
        return None;
    }
    match name.strip_suffix(ESCAPED_DOT_D) {
        Some(stem) => Some(format!("{stem}{COLLECTION_SUFFIX}")),
        None => Some(name.to_string()),
    }
}

/// The directory name of a collection segment.
pub fn collection_dir_name(segment: &str) -> String {
    format!("{segment}{COLLECTION_SUFFIX}")
}

/// The on-disk directory of collection `path` under `root`.
pub fn collection_dir(root: &FsPath, path: &Path) -> PathBuf {
    let mut p = root.to_path_buf();
    for seg in path.segments() {
        p.push(collection_dir_name(seg.as_str()));
    }
    p
}

/// The on-disk file of the object `(path, id)` under `root`.
pub fn object_file(root: &FsPath, path: &Path, id: &str) -> PathBuf {
    let mut p = collection_dir(root, path);
    p.push(object_file_name(id));
    p
}

/// The temp file used for an atomic write of `file`.
pub fn temp_file(file: &FsPath) -> PathBuf {
    let mut name = file.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(TEMP_SUFFIX);
    file.with_file_name(name)
}

/// Write `bytes` to the mirror file for `(path, id)` atomically. Best-effort:
/// the error is returned for logging, never for aborting state (Q24).
pub fn write_object(root: &FsPath, path: &Path, id: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
    let file = object_file(root, path, id);
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = temp_file(&file);
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, &file)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_collision_free() {
        let root = FsPath::new("/repo");
        let c = Path::parse("/c/").unwrap();
        let cx = Path::parse("/c/x/").unwrap();
        // object /c/x and collection /c/x/ take different entries.
        assert_eq!(object_file(root, &c, "x"), PathBuf::from("/repo/c.d/x"));
        assert_eq!(collection_dir(root, &cx), PathBuf::from("/repo/c.d/x.d"));
        // object /c/x.d does not collide with collection /c/x/.
        assert_eq!(object_file(root, &c, "x.d"), PathBuf::from("/repo/c.d/x%2Ed"));
        assert_eq!(object_id_from_file_name("x%2Ed").as_deref(), Some("x.d"));
        assert_eq!(object_id_from_file_name("x").as_deref(), Some("x"));
        assert_eq!(object_id_from_file_name("x.d"), None);
        assert_eq!(object_id_from_file_name("x%tmp"), None);
        // a.b and a.tmp no longer share a temp file.
        assert_ne!(temp_file(FsPath::new("/r/a.b")), temp_file(FsPath::new("/r/a.tmp")));
        assert_eq!(temp_file(FsPath::new("/r/a.b")), PathBuf::from("/r/a.b%tmp"));
    }

    #[test]
    fn file_names_round_trip() {
        for id in ["x", "x.d", "a.d.d", "post.v1", "alice@example.com", "role:mod", "%"] {
            if sbo_core::message::Id::new(id).is_err() { continue; }
            assert_eq!(object_id_from_file_name(&object_file_name(id)).as_deref(), Some(id), "{id}");
        }
    }

    #[test]
    fn write_then_nest_does_not_fail() {
        let dir = tempfile::tempdir().unwrap();
        let c = Path::parse("/c/").unwrap();
        let cx = Path::parse("/c/x/").unwrap();
        write_object(dir.path(), &c, "x", b"obj").unwrap();
        write_object(dir.path(), &cx, "y", b"nested").unwrap();
        assert_eq!(std::fs::read(object_file(dir.path(), &c, "x")).unwrap(), b"obj");
        assert_eq!(std::fs::read(object_file(dir.path(), &cx, "y")).unwrap(), b"nested");
    }
}
